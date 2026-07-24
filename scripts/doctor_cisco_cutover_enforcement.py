#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import selectors
import shutil
import signal
import stat
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Optional

CONTRACT_SCHEMA_VERSION = 3
COLLECTOR_SCHEMA_VERSION = 2
API_HOST = "github.com"
API_ROOT = "https://api.github.com"
API_VERSION = "2026-03-10"
API_ACCEPT = "application/vnd.github+json"
API_PER_PAGE = 100
MAX_API_PAGES = 100
MAX_API_CALLS = 4_096
MAX_API_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_API_STDERR_BYTES = 64 * 1024
MAX_API_TOTAL_BYTES = 64 * 1024 * 1024
MAX_API_SECONDS = 30
MAX_COLLECTION_SECONDS = 180
MAX_WORKFLOW_RUNS = 1_000
MAX_RUN_ATTEMPTS = 20
MAX_JOB_ATTEMPT_QUERIES = 1_000
MAX_JSON_BYTES = 512 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 65_536
MAX_JSON_CONTAINER_ITEMS = 16_384
MAX_JSON_INTEGER_DIGITS = 64
MAX_JSON_STRING_CHARS = 128 * 1024
SHA1_PATTERN = re.compile(r"[0-9a-f]{40}")
HTTP_STATUS_PATTERN = re.compile(rb"\(HTTP ([1-5][0-9]{2})\)")


class EnforcementDoctorError(ValueError):
    def __init__(
        self,
        reason_code: str,
        reason: str,
        *,
        api_failure: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(reason)
        self.reason_code = reason_code
        self.api_failure = api_failure


def _blocked(
    reason_code: str,
    reason: str,
    *,
    api_failure: Optional[dict[str, Any]] = None,
) -> EnforcementDoctorError:
    return EnforcementDoctorError(
        reason_code,
        reason,
        api_failure=api_failure,
    )


def _reject_json_float(value: str) -> None:
    raise _blocked("invalid-json", f"JSON floating-point value is forbidden: {value}")


def _reject_json_constant(value: str) -> None:
    raise _blocked("invalid-json", f"non-finite JSON value is forbidden: {value}")


def _parse_json_integer(value: str) -> int:
    digits = value.removeprefix("-")
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise _blocked(
            "invalid-json",
            "JSON integer exceeds the configured digit ceiling",
        )
    return int(value)


def _object_without_duplicates(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for key, value in pairs:
        if key in parsed:
            raise _blocked("invalid-json", f"duplicate JSON key: {key}")
        parsed[key] = value
    return parsed


def _check_json_resources(parsed: object, *, label: str) -> None:
    pending: list[tuple[object, int]] = [(parsed, 1)]
    nodes = 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise _blocked("invalid-json", f"{label} exceeds max JSON nodes")
        if type(value) is dict:
            if depth > MAX_JSON_DEPTH:
                raise _blocked("invalid-json", f"{label} exceeds max JSON depth")
            if len(value) > MAX_JSON_CONTAINER_ITEMS:
                raise _blocked("invalid-json", f"{label} object is too large")
            for key, item in value.items():
                if type(key) is not str or len(key) > MAX_JSON_STRING_CHARS:
                    raise _blocked("invalid-json", f"{label} has an invalid key")
                pending.append((item, depth + 1))
        elif type(value) is list:
            if depth > MAX_JSON_DEPTH:
                raise _blocked("invalid-json", f"{label} exceeds max JSON depth")
            if len(value) > MAX_JSON_CONTAINER_ITEMS:
                raise _blocked("invalid-json", f"{label} array is too large")
            pending.extend((item, depth + 1) for item in value)
        elif type(value) is str:
            if len(value) > MAX_JSON_STRING_CHARS:
                raise _blocked("invalid-json", f"{label} string is too large")
        elif type(value) not in (int, bool, type(None)):
            raise _blocked("invalid-json", f"{label} has an invalid scalar")


def _parse_json_bytes(payload: bytes, *, label: str) -> object:
    try:
        decoded = payload.decode("utf-8", errors="strict")
        parsed = json.loads(
            decoded,
            object_pairs_hook=_object_without_duplicates,
            parse_int=_parse_json_integer,
            parse_float=_reject_json_float,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise _blocked("invalid-json", f"{label} is not strict JSON") from error
    _check_json_resources(parsed, label=label)
    return parsed


def _read_fd_bounded(fd: int, *, label: str) -> bytes:
    chunks: list[bytes] = []
    retained = 0
    while True:
        chunk = os.read(fd, min(64 * 1024, MAX_JSON_BYTES + 1 - retained))
        if not chunk:
            break
        chunks.append(chunk)
        retained += len(chunk)
        if retained > MAX_JSON_BYTES:
            raise _blocked("unsafe-input", f"{label} exceeds max bytes")
    return b"".join(chunks)


def _read_json(
    path: pathlib.Path,
    *,
    label: str,
) -> tuple[dict[str, Any], str]:
    missing_flags = [
        flag for flag in ("O_NOFOLLOW", "O_NONBLOCK") if not hasattr(os, flag)
    ]
    if missing_flags:
        raise _blocked(
            "unsafe-input",
            f"{label} safe-open flags are unavailable: {','.join(missing_flags)}",
        )
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise _blocked(
            "unsafe-input", f"cannot safely open {label}: {error}"
        ) from error
    try:
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise _blocked("unsafe-input", f"{label} must be a regular file")
            if before.st_size > MAX_JSON_BYTES:
                raise _blocked("unsafe-input", f"{label} exceeds max bytes")
            first = _read_fd_bounded(fd, label=label)
            os.lseek(fd, 0, os.SEEK_SET)
            second = _read_fd_bounded(fd, label=label)
            after = os.fstat(fd)
        except OSError as error:
            raise _blocked(
                "unsafe-input",
                f"cannot safely read {label}: {error}",
            ) from error
    finally:
        os.close(fd)
    object_identity_before = (before.st_dev, before.st_ino)
    object_identity_after = (after.st_dev, after.st_ino)
    if object_identity_after != object_identity_before:
        raise _blocked("unsafe-input", f"{label} object identity changed")
    access_policy_before = (stat.S_IMODE(before.st_mode), before.st_uid, before.st_gid)
    access_policy_after = (stat.S_IMODE(after.st_mode), after.st_uid, after.st_gid)
    if access_policy_after != access_policy_before:
        raise _blocked("unsafe-input", f"{label} access policy changed")
    if first != second or len(first) != before.st_size or len(second) != after.st_size:
        raise _blocked("unsafe-input", f"{label} content changed while it was read")
    parsed = _parse_json_bytes(first, label=label)
    if type(parsed) is not dict:
        raise _blocked("invalid-json", f"{label} must be a JSON object")
    return parsed, hashlib.sha256(first).hexdigest()


def _exact_dict(value: object, *, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise _blocked("invalid-evidence", f"{label} must be an object")
    return value


def _exact_list(value: object, *, label: str) -> list[Any]:
    if type(value) is not list:
        raise _blocked("invalid-evidence", f"{label} must be an array")
    return value


def _exact_string(value: object, *, label: str) -> str:
    if type(value) is not str or not value:
        raise _blocked("invalid-evidence", f"{label} must be non-empty text")
    return value


def _exact_bool(value: object, *, label: str) -> bool:
    if type(value) is not bool:
        raise _blocked("invalid-evidence", f"{label} must be a boolean")
    return value


def _exact_nonnegative_integer(value: object, *, label: str) -> int:
    if type(value) is not int or value < 0:
        raise _blocked("invalid-evidence", f"{label} must be a nonnegative integer")
    return value


def _exact_positive_integer(value: object, *, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise _blocked("invalid-evidence", f"{label} must be a positive integer")
    return value


def _exact_sha1(value: object, *, label: str) -> str:
    if type(value) is not str or SHA1_PATTERN.fullmatch(value) is None:
        raise _blocked("invalid-evidence", f"{label} must be exact lowercase SHA-1")
    if set(value) == {"0"}:
        raise _blocked("invalid-evidence", f"{label} must not be all-zero")
    return value


def _exact_keys(
    value: dict[str, Any],
    expected: set[str],
    *,
    label: str,
) -> None:
    if set(value) != expected:
        raise _blocked("invalid-evidence", f"{label} fields differ")


def _json_copy(value: object, *, label: str) -> object:
    _check_json_resources(value, label=label)
    return json.loads(
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace(
            "+00:00",
            "Z",
        )
    )


def _repo_parts(full_name: str, *, label: str) -> tuple[str, str]:
    parts = full_name.split("/")
    if (
        len(parts) != 2
        or any(not part for part in parts)
        or any(part in {".", ".."} for part in parts)
    ):
        raise _blocked("invalid-contract", f"{label} must be owner/name")
    return parts[0], parts[1]


def _load_contract(contract: dict[str, Any]) -> dict[str, Any]:
    _exact_keys(
        contract,
        {
            "schema_version",
            "source_organization",
            "target_repository",
            "ruleset",
            "required_workflow",
            "applicability_selector",
            "disallowed_status_contexts",
        },
        label="contract",
    )
    if contract["schema_version"] != CONTRACT_SCHEMA_VERSION:
        raise _blocked("invalid-contract", "contract schema version differs")
    organization = _exact_dict(
        contract["source_organization"],
        label="contract source organization",
    )
    _exact_keys(
        organization,
        {"id", "login"},
        label="contract source organization",
    )
    _exact_positive_integer(organization["id"], label="organization ID")
    _exact_string(organization["login"], label="organization login")
    target = _exact_dict(contract["target_repository"], label="contract target")
    _exact_keys(target, {"id", "full_name", "default_branch"}, label="contract target")
    _exact_positive_integer(target["id"], label="contract repository ID")
    target_name = _exact_string(
        target["full_name"],
        label="contract repository name",
    )
    target_owner, _ = _repo_parts(target_name, label="contract repository name")
    if target_owner != organization["login"]:
        raise _blocked(
            "invalid-contract",
            "target repository is outside the source organization",
        )
    _exact_string(target["default_branch"], label="contract default branch")
    ruleset = _exact_dict(contract["ruleset"], label="contract ruleset")
    _exact_keys(
        ruleset,
        {
            "source_type",
            "source",
            "target",
            "enforcement",
            "conditions",
            "bypass_actors",
        },
        label="contract ruleset",
    )
    if (
        ruleset["source_type"] != "Organization"
        or ruleset["source"] != organization["login"]
        or ruleset["target"] != "branch"
        or ruleset["enforcement"] != "active"
        or ruleset["bypass_actors"] != []
    ):
        raise _blocked(
            "invalid-contract",
            "contract ruleset identity or enforcement differs",
        )
    expected_conditions = {
        "ref_name": {
            "include": ["~DEFAULT_BRANCH"],
            "exclude": [],
        },
        "repository_id": {
            "repository_ids": [target["id"]],
        },
    }
    if ruleset["conditions"] != expected_conditions:
        raise _blocked(
            "invalid-contract",
            "contract must target the exact repository ID and default branch",
        )
    workflow = _exact_dict(contract["required_workflow"], label="contract workflow")
    _exact_keys(
        workflow,
        {
            "repository_id",
            "repository_full_name",
            "path",
            "ref",
            "state",
            "event",
            "check_name",
            "provider",
            "do_not_enforce_on_create",
            "require_exact_sha",
        },
        label="contract workflow",
    )
    _exact_positive_integer(
        workflow["repository_id"],
        label="workflow source repository ID",
    )
    workflow_name = _exact_string(
        workflow["repository_full_name"],
        label="workflow source repository name",
    )
    workflow_owner, _ = _repo_parts(
        workflow_name,
        label="workflow source repository name",
    )
    if workflow_owner != organization["login"]:
        raise _blocked(
            "invalid-contract",
            "workflow source repository is outside the source organization",
        )
    _exact_string(workflow["path"], label="workflow path")
    workflow_ref = _exact_string(workflow["ref"], label="workflow ref")
    if not workflow_ref.startswith("refs/heads/"):
        raise _blocked("invalid-contract", "workflow ref must be an exact branch ref")
    _exact_string(workflow["state"], label="workflow state")
    _exact_string(workflow["event"], label="workflow event")
    _exact_string(workflow["check_name"], label="workflow check name")
    provider = _exact_dict(workflow["provider"], label="workflow provider")
    _exact_keys(provider, {"id", "slug"}, label="workflow provider")
    _exact_positive_integer(provider["id"], label="workflow provider app ID")
    _exact_string(provider["slug"], label="workflow provider app slug")
    if workflow["require_exact_sha"] is not True:
        raise _blocked(
            "invalid-contract", "contract must require an exact workflow SHA"
        )
    if workflow["do_not_enforce_on_create"] is not False:
        raise _blocked(
            "invalid-contract", "contract permits enforcement bypass on create"
        )
    applicability = _exact_dict(
        contract["applicability_selector"],
        label="contract applicability selector",
    )
    expected_applicability = {
        "target_pr_number_variable": "CISCO_CUTOVER_TARGET_PR_NUMBER",
        "target_head_sha_variable": "CISCO_CUTOVER_TARGET_HEAD_SHA",
        "selector_job_name": "cisco-cutover-selector",
        "target_job_name": workflow["check_name"],
        "neutral_job_name": "cisco-cutover-neutral",
        "non_target_classification": "not_applicable",
    }
    if applicability != expected_applicability:
        raise _blocked(
            "invalid-contract",
            "contract applicability selector differs",
        )
    disallowed = _exact_list(
        contract["disallowed_status_contexts"],
        label="contract disallowed status contexts",
    )
    if disallowed != [workflow["check_name"]]:
        raise _blocked("invalid-contract", "contract status-context denylist differs")
    return contract


def _kill_process(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass


def _api_failure(
    endpoint_class: str,
    *,
    http_status: Optional[int],
    failure_kind: str,
) -> dict[str, Any]:
    return {
        "endpoint_class": endpoint_class,
        "failure_kind": failure_kind,
        "http_status": http_status,
    }


def _api_endpoint_class(endpoint: str) -> str:
    components = endpoint.strip("/").split("/")
    if endpoint == "/user":
        return "authenticated-user"
    if len(components) == 2 and components[0] == "orgs":
        return "organization"
    if (
        len(components) == 4
        and components[:1] == ["orgs"]
        and components[2] == "rulesets"
    ):
        return "organization-ruleset"
    if (
        len(components) == 4
        and components[:1] == ["enterprises"]
        and components[2] == "rulesets"
    ):
        return "enterprise-ruleset"
    if len(components) >= 3 and components[0] == "repos":
        suffix = components[3:]
        if not suffix:
            return "repository"
        if suffix[:1] == ["pulls"]:
            return "pull-request"
        if suffix[:1] == ["rulesets"]:
            return "effective-rulesets" if len(suffix) == 1 else "repository-ruleset"
        if suffix[:2] == ["actions", "variables"]:
            return "actions-variable"
        if suffix[:2] == ["actions", "workflows"]:
            return "workflow-metadata"
        if suffix[:2] == ["actions", "runs"]:
            return (
                "workflow-jobs"
                if "attempts" in suffix and suffix[-1:] == ["jobs"]
                else "workflow-runs"
            )
        if suffix[:1] == ["commits"]:
            return "check-runs" if suffix[-1:] == ["check-runs"] else "commit"
    return "github-api"


def _http_status_from_stderr(stderr: bytes) -> Optional[int]:
    matches = HTTP_STATUS_PATTERN.findall(stderr)
    if not matches:
        return None
    return int(matches[-1], 10)


def _api_request_error(
    *,
    endpoint_class: str,
    stderr: bytes,
    authentication_preflight: bool,
) -> EnforcementDoctorError:
    status = _http_status_from_stderr(stderr)
    if authentication_preflight:
        return _blocked(
            "blocked-authentication",
            "GitHub authentication preflight failed",
            api_failure=_api_failure(
                endpoint_class,
                http_status=status,
                failure_kind="authentication",
            ),
        )
    lowered = stderr.lower()
    if status == 401:
        reason_code = "blocked-authentication"
        reason = "GitHub API authentication was rejected"
        failure_kind = "authentication"
    elif status == 403 and b"rate limit" in lowered:
        reason_code = "rate-limited"
        reason = "GitHub API rate limit blocked the read"
        failure_kind = "rate-limit"
    elif status == 403:
        reason_code = "blocked-permission"
        reason = "GitHub API permission blocked the read"
        failure_kind = "permission"
    elif status == 404:
        reason_code = "not-found"
        reason = "GitHub API object was not found or is not visible"
        failure_kind = "not-found"
    elif status == 429:
        reason_code = "rate-limited"
        reason = "GitHub API rate limit blocked the read"
        failure_kind = "rate-limit"
    elif status is not None and 500 <= status <= 599:
        reason_code = "api-unavailable"
        reason = "GitHub API service failed the read"
        failure_kind = "server-error"
    else:
        reason_code = "api-unavailable"
        reason = "GitHub API read failed without a recognized HTTP status"
        failure_kind = "unclassified"
    return _blocked(
        reason_code,
        reason,
        api_failure=_api_failure(
            endpoint_class,
            http_status=status,
            failure_kind=failure_kind,
        ),
    )


def _bounded_subprocess(
    command: list[str],
    *,
    endpoint_class: str,
    timeout_seconds: int,
    stdout_limit: int,
    stderr_limit: int,
) -> tuple[int, bytes, bytes]:
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=(os.name == "posix"),
        )
    except OSError as error:
        raise _blocked(
            "collector-unavailable",
            "cannot start the fixed GitHub CLI collector",
            api_failure=_api_failure(
                endpoint_class,
                http_status=None,
                failure_kind="process-start",
            ),
        ) from error
    assert process.stdout is not None
    assert process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, ("stdout", stdout_limit))
    selector.register(process.stderr, selectors.EVENT_READ, ("stderr", stderr_limit))
    chunks: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
    retained: dict[str, int] = {"stdout": 0, "stderr": 0}
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_process(process)
                process.wait()
                raise _blocked(
                    "api-timeout",
                    "GitHub API collector command exceeded its deadline",
                    api_failure=_api_failure(
                        endpoint_class,
                        http_status=None,
                        failure_kind="timeout",
                    ),
                )
            events = selector.select(timeout=min(0.25, remaining))
            if not events:
                continue
            for key, _ in events:
                stream_name, stream_limit = key.data
                chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                retained[stream_name] += len(chunk)
                if retained[stream_name] > stream_limit:
                    _kill_process(process)
                    process.wait()
                    raise _blocked(
                        "api-response-too-large",
                        f"GitHub collector {stream_name} exceeded its byte ceiling",
                        api_failure=_api_failure(
                            endpoint_class,
                            http_status=None,
                            failure_kind="response-too-large",
                        ),
                    )
                chunks[stream_name].append(chunk)
        return_code = process.wait(
            timeout=max(0.1, deadline - time.monotonic()),
        )
    except subprocess.TimeoutExpired as error:
        _kill_process(process)
        process.wait()
        raise _blocked(
            "api-timeout",
            "GitHub API collector command exceeded its deadline",
            api_failure=_api_failure(
                endpoint_class,
                http_status=None,
                failure_kind="timeout",
            ),
        ) from error
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return return_code, b"".join(chunks["stdout"]), b"".join(chunks["stderr"])


class GitHubApiClient:
    def __init__(self) -> None:
        executable = shutil.which("gh")
        if executable is None:
            raise _blocked(
                "collector-unavailable",
                "the GitHub CLI executable is unavailable",
            )
        resolved = pathlib.Path(executable).resolve(strict=True)
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise _blocked(
                "collector-unavailable",
                "the resolved GitHub CLI is not an executable file",
            )
        self.executable = str(resolved)
        self.calls = 0
        self.total_bytes = 0
        self.deadline = time.monotonic() + MAX_COLLECTION_SECONDS

    def _run(
        self,
        command: list[str],
        *,
        endpoint_class: str,
        stdout_limit: int,
        authentication_preflight: bool = False,
    ) -> bytes:
        if self.calls >= MAX_API_CALLS:
            raise _blocked(
                "api-call-limit",
                "GitHub collector exceeded its API call ceiling",
                api_failure=_api_failure(
                    endpoint_class,
                    http_status=None,
                    failure_kind="call-limit",
                ),
            )
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise _blocked(
                "api-timeout",
                "GitHub evidence collection exceeded its total deadline",
                api_failure=_api_failure(
                    endpoint_class,
                    http_status=None,
                    failure_kind="timeout",
                ),
            )
        self.calls += 1
        return_code, stdout, stderr = _bounded_subprocess(
            command,
            endpoint_class=endpoint_class,
            timeout_seconds=max(1, min(MAX_API_SECONDS, int(remaining))),
            stdout_limit=stdout_limit,
            stderr_limit=MAX_API_STDERR_BYTES,
        )
        if return_code != 0:
            raise _api_request_error(
                endpoint_class=endpoint_class,
                stderr=stderr,
                authentication_preflight=authentication_preflight,
            )
        self.total_bytes += len(stdout) + len(stderr)
        if self.total_bytes > MAX_API_TOTAL_BYTES:
            raise _blocked(
                "api-response-too-large",
                "GitHub collector exceeded its aggregate response ceiling",
                api_failure=_api_failure(
                    endpoint_class,
                    http_status=None,
                    failure_kind="response-too-large",
                ),
            )
        return stdout

    def auth_preflight(self) -> dict[str, Any]:
        self._run(
            [
                self.executable,
                "auth",
                "status",
                "--hostname",
                API_HOST,
            ],
            endpoint_class="authentication-preflight",
            stdout_limit=MAX_API_STDERR_BYTES,
            authentication_preflight=True,
        )
        user = self.get_json("/user")
        user_object = _exact_dict(user, label="authenticated GitHub user")
        return {
            "id": _exact_positive_integer(
                user_object.get("id"),
                label="authenticated GitHub user ID",
            ),
            "login": _exact_string(
                user_object.get("login"),
                label="authenticated GitHub user login",
            ),
        }

    def get_json(
        self,
        endpoint: str,
        parameters: Optional[dict[str, object]] = None,
    ) -> object:
        if not endpoint.startswith("/") or "?" in endpoint or "#" in endpoint:
            raise _blocked("invalid-api-endpoint", "collector endpoint is not fixed")
        command = [
            self.executable,
            "api",
            "--hostname",
            API_HOST,
            "--method",
            "GET",
            "-H",
            f"Accept: {API_ACCEPT}",
            "-H",
            f"X-GitHub-Api-Version: {API_VERSION}",
            endpoint,
        ]
        for key, value in sorted((parameters or {}).items()):
            if not re.fullmatch(r"[a-z_]+", key):
                raise _blocked(
                    "invalid-api-endpoint",
                    "collector query parameter name is not fixed",
                )
            if type(value) not in (str, int, bool):
                raise _blocked(
                    "invalid-api-endpoint",
                    "collector query parameter value is invalid",
                )
            rendered = str(value).lower() if type(value) is bool else str(value)
            command.extend(["-f", f"{key}={rendered}"])
        endpoint_class = _api_endpoint_class(endpoint)
        payload = self._run(
            command,
            endpoint_class=endpoint_class,
            stdout_limit=MAX_API_RESPONSE_BYTES,
        )
        try:
            return _parse_json_bytes(payload, label=f"GitHub API {endpoint_class}")
        except EnforcementDoctorError as error:
            if error.reason_code != "invalid-json":
                raise
            raise _blocked(
                "api-unavailable",
                "GitHub API returned malformed JSON",
                api_failure=_api_failure(
                    endpoint_class,
                    http_status=200,
                    failure_kind="malformed-json",
                ),
            ) from error


def _record_object_read(
    trace: dict[str, Any],
    *,
    phase: str,
    label: str,
    endpoint: str,
) -> None:
    trace["object_reads"].append(
        {
            "endpoint": endpoint,
            "label": label,
            "phase": phase,
        }
    )


def _get_object(
    client: Any,
    trace: dict[str, Any],
    *,
    phase: str,
    label: str,
    endpoint: str,
) -> dict[str, Any]:
    parsed = client.get_json(endpoint)
    value = _exact_dict(parsed, label=label)
    _record_object_read(
        trace,
        phase=phase,
        label=label,
        endpoint=endpoint,
    )
    return value


def _collect_pages(
    client: Any,
    trace: dict[str, Any],
    *,
    phase: str,
    label: str,
    endpoint: str,
    parameters: dict[str, object],
    item_key: Optional[str],
    result_cap: Optional[int] = None,
) -> list[Any]:
    items: list[Any] = []
    reported_total: Optional[int] = None
    last_nonempty_page = 0
    terminal_page = 0
    for page in range(1, MAX_API_PAGES + 1):
        page_parameters = dict(parameters)
        page_parameters.update({"page": page, "per_page": API_PER_PAGE})
        response = client.get_json(endpoint, page_parameters)
        if item_key is None:
            page_items = _exact_list(response, label=f"{label} page")
            page_total = None
        else:
            page_object = _exact_dict(response, label=f"{label} page")
            page_items = _exact_list(
                page_object.get(item_key),
                label=f"{label} page items",
            )
            page_total = _exact_nonnegative_integer(
                page_object.get("total_count"),
                label=f"{label} reported total",
            )
            if reported_total is None:
                reported_total = page_total
            elif page_total != reported_total:
                raise _blocked(
                    "api-pagination-incomplete",
                    f"{label} total changed during pagination",
                )
        if len(page_items) > API_PER_PAGE:
            raise _blocked(
                "api-pagination-incomplete",
                f"{label} page exceeds the requested page size",
            )
        if not page_items:
            terminal_page = page
            break
        last_nonempty_page = page
        items.extend(page_items)
        if result_cap is not None and len(items) > result_cap:
            raise _blocked(
                "api-search-cap-exceeded",
                f"{label} exceeds the complete-search result cap",
            )
    if terminal_page == 0:
        raise _blocked(
            "api-pagination-incomplete",
            f"{label} did not reach an explicit empty terminal page",
        )
    if reported_total is not None and reported_total != len(items):
        raise _blocked(
            "api-pagination-incomplete",
            f"{label} item count differs from the API total",
        )
    trace["page_bounds"].append(
        {
            "endpoint": endpoint,
            "first_page": 1,
            "item_count": len(items),
            "label": label,
            "last_nonempty_page": last_nonempty_page,
            "parameters": _json_copy(parameters, label=f"{label} parameters"),
            "per_page": API_PER_PAGE,
            "phase": phase,
            "reported_total_count": reported_total,
            "terminal_empty_page": terminal_page,
        }
    )
    return items


def _normalize_organization(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": _exact_positive_integer(
            value.get("id"),
            label="organization ID",
        ),
        "login": _exact_string(
            value.get("login"),
            label="organization login",
        ),
    }


def _normalize_repository(value: dict[str, Any]) -> dict[str, Any]:
    owner = _exact_dict(value.get("owner"), label="repository owner")
    return {
        "archived": _exact_bool(value.get("archived"), label="repository archived"),
        "default_branch": _exact_string(
            value.get("default_branch"),
            label="repository default branch",
        ),
        "disabled": _exact_bool(value.get("disabled"), label="repository disabled"),
        "full_name": _exact_string(
            value.get("full_name"),
            label="repository full name",
        ),
        "id": _exact_positive_integer(value.get("id"), label="repository ID"),
        "owner": {
            "id": _exact_positive_integer(
                owner.get("id"),
                label="repository owner ID",
            ),
            "login": _exact_string(
                owner.get("login"),
                label="repository owner login",
            ),
            "type": _exact_string(
                owner.get("type"),
                label="repository owner type",
            ),
        },
    }


def _normalize_pr_repo(value: object, *, label: str) -> dict[str, Any]:
    repository = _exact_dict(value, label=label)
    return {
        "full_name": _exact_string(
            repository.get("full_name"),
            label=f"{label} full name",
        ),
        "id": _exact_positive_integer(
            repository.get("id"),
            label=f"{label} ID",
        ),
    }


def _normalize_pull_request(value: dict[str, Any]) -> dict[str, Any]:
    base = _exact_dict(value.get("base"), label="pull request base")
    head = _exact_dict(value.get("head"), label="pull request head")
    return {
        "base": {
            "ref": _exact_string(base.get("ref"), label="pull request base ref"),
            "repository": _normalize_pr_repo(
                base.get("repo"),
                label="pull request base repository",
            ),
            "sha": _exact_sha1(base.get("sha"), label="pull request base SHA"),
        },
        "head": {
            "repository": _normalize_pr_repo(
                head.get("repo"),
                label="pull request head repository",
            ),
            "sha": _exact_sha1(head.get("sha"), label="pull request head SHA"),
        },
        "html_url": _exact_string(
            value.get("html_url"),
            label="pull request HTML URL",
        ),
        "id": _exact_positive_integer(value.get("id"), label="pull request ID"),
        "merged": _exact_bool(value.get("merged"), label="pull request merged"),
        "number": _exact_positive_integer(
            value.get("number"),
            label="pull request number",
        ),
        "state": _exact_string(value.get("state"), label="pull request state"),
        "url": _exact_string(value.get("url"), label="pull request API URL"),
    }


def _normalize_ruleset(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "bypass_actors": _json_copy(
            _exact_list(value.get("bypass_actors"), label="ruleset bypass actors"),
            label="ruleset bypass actors",
        ),
        "conditions": _json_copy(
            _exact_dict(value.get("conditions"), label="ruleset conditions"),
            label="ruleset conditions",
        ),
        "enforcement": _exact_string(
            value.get("enforcement"),
            label="ruleset enforcement",
        ),
        "id": _exact_positive_integer(value.get("id"), label="ruleset ID"),
        "name": _exact_string(value.get("name"), label="ruleset name"),
        "rules": _json_copy(
            _exact_list(value.get("rules"), label="ruleset rules"),
            label="ruleset rules",
        ),
        "source": _exact_string(value.get("source"), label="ruleset source"),
        "source_type": _exact_string(
            value.get("source_type"),
            label="ruleset source type",
        ),
        "target": _exact_string(value.get("target"), label="ruleset target"),
    }


def _normalize_ruleset_summary(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "enforcement": _exact_string(
            value.get("enforcement"),
            label="ruleset summary enforcement",
        ),
        "id": _exact_positive_integer(
            value.get("id"),
            label="ruleset summary ID",
        ),
        "name": _exact_string(
            value.get("name"),
            label="ruleset summary name",
        ),
        "source": _exact_string(
            value.get("source"),
            label="ruleset summary source",
        ),
        "source_type": _exact_string(
            value.get("source_type"),
            label="ruleset summary source type",
        ),
        "target": _exact_string(
            value.get("target"),
            label="ruleset summary target",
        ),
    }


def _ruleset_detail_endpoint(summary: dict[str, Any]) -> str:
    source = summary["source"]
    source_type = summary["source_type"]
    ruleset_id = summary["id"]
    safe_component = re.compile(r"[A-Za-z0-9_.-]+")
    if source_type == "Organization":
        if safe_component.fullmatch(source) is None:
            raise _blocked(
                "ruleset-identity-mismatch",
                "organization ruleset source is not an exact login",
            )
        return f"/orgs/{source}/rulesets/{ruleset_id}"
    if source_type == "Repository":
        owner, repository = _repo_parts(source, label="repository ruleset source")
        if (
            safe_component.fullmatch(owner) is None
            or safe_component.fullmatch(repository) is None
        ):
            raise _blocked(
                "ruleset-identity-mismatch",
                "repository ruleset source is not an exact full name",
            )
        return f"/repos/{source}/rulesets/{ruleset_id}"
    if source_type == "Enterprise":
        if safe_component.fullmatch(source) is None:
            raise _blocked(
                "ruleset-identity-mismatch",
                "enterprise ruleset source is not an exact slug",
            )
        return f"/enterprises/{source}/rulesets/{ruleset_id}"
    raise _blocked(
        "unsupported-ruleset-source",
        "effective ruleset has an unsupported source type",
    )


def _normalize_workflow(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "html_url": _exact_string(
            value.get("html_url"),
            label="workflow HTML URL",
        ),
        "id": _exact_positive_integer(value.get("id"), label="workflow ID"),
        "path": _exact_string(value.get("path"), label="workflow path"),
        "state": _exact_string(value.get("state"), label="workflow state"),
        "url": _exact_string(value.get("url"), label="workflow API URL"),
    }


def _normalize_commit(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "html_url": _exact_string(
            value.get("html_url"),
            label="workflow source commit HTML URL",
        ),
        "sha": _exact_sha1(
            value.get("sha"),
            label="workflow source commit SHA",
        ),
        "url": _exact_string(
            value.get("url"),
            label="workflow source commit API URL",
        ),
    }


def _normalize_actions_variable(value: dict[str, Any]) -> dict[str, str]:
    return {
        "name": _exact_string(
            value.get("name"),
            label="Actions variable name",
        ),
        "value": _exact_string(
            value.get("value"),
            label="Actions variable value",
        ),
    }


def _normalize_pr_link(value: object, *, label: str) -> dict[str, Any]:
    link = _exact_dict(value, label=label)
    base = _exact_dict(link.get("base"), label=f"{label} base")
    head = _exact_dict(link.get("head"), label=f"{label} head")
    base_repo = _exact_dict(base.get("repo"), label=f"{label} base repository")
    head_repo = _exact_dict(head.get("repo"), label=f"{label} head repository")
    return {
        "base": {
            "ref": _exact_string(base.get("ref"), label=f"{label} base ref"),
            "repository_id": _exact_positive_integer(
                base_repo.get("id"),
                label=f"{label} base repository ID",
            ),
            "sha": _exact_sha1(base.get("sha"), label=f"{label} base SHA"),
        },
        "head": {
            "repository_id": _exact_positive_integer(
                head_repo.get("id"),
                label=f"{label} head repository ID",
            ),
            "sha": _exact_sha1(head.get("sha"), label=f"{label} head SHA"),
        },
        "id": _exact_positive_integer(link.get("id"), label=f"{label} ID"),
        "number": _exact_positive_integer(
            link.get("number"),
            label=f"{label} number",
        ),
        "url": _exact_string(link.get("url"), label=f"{label} URL"),
    }


def _normalize_run(value: dict[str, Any]) -> dict[str, Any]:
    conclusion = value.get("conclusion")
    if conclusion is not None:
        _exact_string(conclusion, label="workflow run conclusion")
    repository = _exact_dict(
        value.get("repository"),
        label="workflow run repository",
    )
    head_repository = _exact_dict(
        value.get("head_repository"),
        label="workflow run head repository",
    )
    pull_requests = _exact_list(
        value.get("pull_requests"),
        label="workflow run pull requests",
    )
    return {
        "check_suite_id": _exact_positive_integer(
            value.get("check_suite_id"),
            label="workflow run check suite ID",
        ),
        "check_suite_url": _exact_string(
            value.get("check_suite_url"),
            label="workflow run check suite URL",
        ),
        "conclusion": conclusion,
        "event": _exact_string(value.get("event"), label="workflow run event"),
        "head_repository": {
            "full_name": _exact_string(
                head_repository.get("full_name"),
                label="workflow run head repository name",
            ),
            "id": _exact_positive_integer(
                head_repository.get("id"),
                label="workflow run head repository ID",
            ),
        },
        "head_sha": _exact_sha1(
            value.get("head_sha"),
            label="workflow run head SHA",
        ),
        "html_url": _exact_string(
            value.get("html_url"),
            label="workflow run HTML URL",
        ),
        "id": _exact_positive_integer(value.get("id"), label="workflow run ID"),
        "jobs_url": _exact_string(
            value.get("jobs_url"),
            label="workflow run jobs URL",
        ),
        "path": _exact_string(value.get("path"), label="workflow run path"),
        "pull_requests": [
            _normalize_pr_link(item, label="workflow run pull request")
            for item in pull_requests
        ],
        "repository": {
            "full_name": _exact_string(
                repository.get("full_name"),
                label="workflow run repository name",
            ),
            "id": _exact_positive_integer(
                repository.get("id"),
                label="workflow run repository ID",
            ),
        },
        "run_attempt": _exact_positive_integer(
            value.get("run_attempt"),
            label="workflow run attempt",
        ),
        "status": _exact_string(value.get("status"), label="workflow run status"),
        "url": _exact_string(value.get("url"), label="workflow run API URL"),
        "workflow_id": _exact_positive_integer(
            value.get("workflow_id"),
            label="workflow run workflow ID",
        ),
        "workflow_url": _exact_string(
            value.get("workflow_url"),
            label="workflow run workflow URL",
        ),
    }


def _normalize_job(value: dict[str, Any], *, run_attempt: int) -> dict[str, Any]:
    conclusion = value.get("conclusion")
    if conclusion is not None:
        _exact_string(conclusion, label="workflow job conclusion")
    return {
        "check_run_url": _exact_string(
            value.get("check_run_url"),
            label="workflow job check-run URL",
        ),
        "conclusion": conclusion,
        "head_sha": _exact_sha1(
            value.get("head_sha"),
            label="workflow job head SHA",
        ),
        "html_url": _exact_string(
            value.get("html_url"),
            label="workflow job HTML URL",
        ),
        "id": _exact_positive_integer(value.get("id"), label="workflow job ID"),
        "name": _exact_string(value.get("name"), label="workflow job name"),
        "run_attempt": run_attempt,
        "run_id": _exact_positive_integer(
            value.get("run_id"),
            label="workflow job run ID",
        ),
        "run_url": _exact_string(
            value.get("run_url"),
            label="workflow job run URL",
        ),
        "status": _exact_string(
            value.get("status"),
            label="workflow job status",
        ),
        "url": _exact_string(value.get("url"), label="workflow job API URL"),
        "workflow_name": _exact_string(
            value.get("workflow_name"),
            label="workflow job workflow name",
        ),
    }


def _normalize_check_run(value: dict[str, Any]) -> dict[str, Any]:
    app = _exact_dict(value.get("app"), label="check-run app")
    check_suite = _exact_dict(value.get("check_suite"), label="check-run suite")
    pull_requests = _exact_list(
        value.get("pull_requests"),
        label="check-run pull requests",
    )
    conclusion = value.get("conclusion")
    if conclusion is not None:
        _exact_string(conclusion, label="check-run conclusion")
    return {
        "app": {
            "id": _exact_positive_integer(app.get("id"), label="check-run app ID"),
            "slug": _exact_string(app.get("slug"), label="check-run app slug"),
        },
        "check_suite_id": _exact_positive_integer(
            check_suite.get("id"),
            label="check-run suite ID",
        ),
        "conclusion": conclusion,
        "details_url": _exact_string(
            value.get("details_url"),
            label="check-run details URL",
        ),
        "head_sha": _exact_sha1(
            value.get("head_sha"),
            label="check-run head SHA",
        ),
        "html_url": _exact_string(
            value.get("html_url"),
            label="check-run HTML URL",
        ),
        "id": _exact_positive_integer(value.get("id"), label="check-run ID"),
        "name": _exact_string(value.get("name"), label="check-run name"),
        "pull_requests": [
            _normalize_pr_link(item, label="check-run pull request")
            for item in pull_requests
        ],
        "status": _exact_string(value.get("status"), label="check-run status"),
        "url": _exact_string(value.get("url"), label="check-run API URL"),
    }


def _assert_static_identity(
    snapshot: dict[str, Any],
    contract: dict[str, Any],
    *,
    expected_ruleset_id: int,
    expected_workflow_id: int,
    expected_workflow_sha: str,
    candidate_head_sha: str,
    pull_request_number: int,
) -> None:
    organization = snapshot["organization"]
    if organization != contract["source_organization"]:
        raise _blocked(
            "organization-identity-mismatch",
            "organization identity does not match the contract",
        )
    target = contract["target_repository"]
    repository = snapshot["repository"]
    expected_repository = {
        "archived": False,
        "default_branch": target["default_branch"],
        "disabled": False,
        "full_name": target["full_name"],
        "id": target["id"],
        "owner": {
            "id": organization["id"],
            "login": organization["login"],
            "type": "Organization",
        },
    }
    if repository != expected_repository:
        raise _blocked(
            "repository-identity-mismatch",
            "target repository identity or availability differs",
        )
    pull_request = snapshot["pull_request"]
    if (
        pull_request["number"] != pull_request_number
        or pull_request["state"] != "open"
        or pull_request["merged"] is not False
        or pull_request["head"]["sha"] != candidate_head_sha
        or pull_request["head"]["repository"]
        != {"id": target["id"], "full_name": target["full_name"]}
        or pull_request["base"]["repository"]
        != {"id": target["id"], "full_name": target["full_name"]}
        or pull_request["base"]["ref"] != target["default_branch"]
    ):
        raise _blocked(
            "pull-request-identity-mismatch",
            "pull request number, repository, head, base, or lifecycle differs",
        )
    expected_pr_url = (
        f"{API_ROOT}/repos/{target['full_name']}/pulls/{pull_request_number}"
    )
    if pull_request["url"] != expected_pr_url:
        raise _blocked(
            "pull-request-identity-mismatch",
            "pull request API URL differs",
        )
    selector = contract["applicability_selector"]
    expected_selector_variables = {
        "selector_target_pr_number": {
            "name": selector["target_pr_number_variable"],
            "value": str(pull_request_number),
        },
        "selector_target_head_sha": {
            "name": selector["target_head_sha_variable"],
            "value": candidate_head_sha,
        },
    }
    for field, expected_variable in expected_selector_variables.items():
        if snapshot[field] != expected_variable:
            raise _blocked(
                "selector-mismatch",
                "administrator applicability selector differs from the target PR",
            )
    ruleset = snapshot["selected_ruleset"]
    if ruleset["id"] != expected_ruleset_id:
        raise _blocked(
            "ruleset-identity-mismatch",
            "selected organization ruleset ID differs",
        )
    workflow_contract = contract["required_workflow"]
    source_repository = snapshot["workflow_source_repository"]
    if (
        source_repository["id"] != workflow_contract["repository_id"]
        or source_repository["full_name"] != workflow_contract["repository_full_name"]
        or source_repository["archived"] is not False
        or source_repository["disabled"] is not False
        or source_repository["owner"]
        != {
            "id": organization["id"],
            "login": organization["login"],
            "type": "Organization",
        }
    ):
        raise _blocked(
            "workflow-source-repository-mismatch",
            "workflow source repository identity or availability differs",
        )
    expected_ref = f"refs/heads/{source_repository['default_branch']}"
    if workflow_contract["ref"] != expected_ref:
        raise _blocked(
            "workflow-source-repository-mismatch",
            "workflow ref is not the source repository default branch",
        )
    workflow = snapshot["workflow"]
    expected_workflow_url = (
        f"{API_ROOT}/repos/{workflow_contract['repository_full_name']}"
        f"/actions/workflows/{expected_workflow_id}"
    )
    if (
        workflow["id"] != expected_workflow_id
        or workflow["path"] != workflow_contract["path"]
        or workflow["state"] != workflow_contract["state"]
        or workflow["url"] != expected_workflow_url
    ):
        raise _blocked(
            "workflow-identity-mismatch",
            "workflow metadata does not match the pinned source identity",
        )
    source_commit = snapshot["workflow_source_commit"]
    expected_commit_url = (
        f"{API_ROOT}/repos/{workflow_contract['repository_full_name']}"
        f"/commits/{expected_workflow_sha}"
    )
    if (
        source_commit["sha"] != expected_workflow_sha
        or source_commit["url"] != expected_commit_url
    ):
        raise _blocked(
            "workflow-identity-mismatch",
            "workflow source commit differs from the pinned SHA",
        )


def _collect_snapshot(
    client: Any,
    trace: dict[str, Any],
    contract: dict[str, Any],
    *,
    phase: str,
    expected_ruleset_id: int,
    expected_workflow_id: int,
    expected_workflow_sha: str,
    candidate_head_sha: str,
    pull_request_number: int,
) -> dict[str, Any]:
    organization_name = contract["source_organization"]["login"]
    target_name = contract["target_repository"]["full_name"]
    workflow_contract = contract["required_workflow"]
    workflow_source_name = workflow_contract["repository_full_name"]
    organization = _normalize_organization(
        _get_object(
            client,
            trace,
            phase=phase,
            label="organization",
            endpoint=f"/orgs/{organization_name}",
        )
    )
    repository = _normalize_repository(
        _get_object(
            client,
            trace,
            phase=phase,
            label="target repository",
            endpoint=f"/repos/{target_name}",
        )
    )
    pull_request = _normalize_pull_request(
        _get_object(
            client,
            trace,
            phase=phase,
            label="pull request",
            endpoint=f"/repos/{target_name}/pulls/{pull_request_number}",
        )
    )
    selector_contract = contract["applicability_selector"]
    selector_target_pr_number = _normalize_actions_variable(
        _get_object(
            client,
            trace,
            phase=phase,
            label="selector target pull-request number",
            endpoint=(
                f"/repos/{target_name}/actions/variables/"
                f"{selector_contract['target_pr_number_variable']}"
            ),
        )
    )
    selector_target_head_sha = _normalize_actions_variable(
        _get_object(
            client,
            trace,
            phase=phase,
            label="selector target head SHA",
            endpoint=(
                f"/repos/{target_name}/actions/variables/"
                f"{selector_contract['target_head_sha_variable']}"
            ),
        )
    )
    effective_ruleset_values = _collect_pages(
        client,
        trace,
        phase=phase,
        label="effective repository rulesets",
        endpoint=f"/repos/{target_name}/rulesets",
        parameters={"includes_parents": True, "targets": "branch"},
        item_key=None,
    )
    effective_rulesets: list[dict[str, Any]] = []
    effective_ruleset_ids: set[int] = set()
    for value in effective_ruleset_values:
        summary = _normalize_ruleset_summary(
            _exact_dict(value, label="effective ruleset summary")
        )
        if summary["id"] in effective_ruleset_ids:
            raise _blocked(
                "api-pagination-incomplete",
                "effective ruleset ID was repeated during pagination",
            )
        effective_ruleset_ids.add(summary["id"])
        detail = _normalize_ruleset(
            _get_object(
                client,
                trace,
                phase=phase,
                label=f"effective ruleset {summary['id']} detail",
                endpoint=_ruleset_detail_endpoint(summary),
            )
        )
        if any(detail[field] != summary[field] for field in summary):
            raise _blocked(
                "ruleset-identity-mismatch",
                "effective ruleset summary and source detail differ",
            )
        effective_rulesets.append(detail)
    selected_ruleset = _normalize_ruleset(
        _get_object(
            client,
            trace,
            phase=phase,
            label="selected organization ruleset",
            endpoint=f"/orgs/{organization_name}/rulesets/{expected_ruleset_id}",
        )
    )
    workflow_source_repository = _normalize_repository(
        _get_object(
            client,
            trace,
            phase=phase,
            label="workflow source repository",
            endpoint=f"/repos/{workflow_source_name}",
        )
    )
    workflow = _normalize_workflow(
        _get_object(
            client,
            trace,
            phase=phase,
            label="workflow metadata",
            endpoint=(
                f"/repos/{workflow_source_name}/actions/workflows/"
                f"{expected_workflow_id}"
            ),
        )
    )
    workflow_source_commit = _normalize_commit(
        _get_object(
            client,
            trace,
            phase=phase,
            label="workflow source commit",
            endpoint=(f"/repos/{workflow_source_name}/commits/{expected_workflow_sha}"),
        )
    )
    partial_snapshot = {
        "effective_rulesets": effective_rulesets,
        "organization": organization,
        "pull_request": pull_request,
        "repository": repository,
        "selector_target_head_sha": selector_target_head_sha,
        "selector_target_pr_number": selector_target_pr_number,
        "selected_ruleset": selected_ruleset,
        "workflow": workflow,
        "workflow_source_commit": workflow_source_commit,
        "workflow_source_repository": workflow_source_repository,
    }
    _assert_static_identity(
        partial_snapshot,
        contract,
        expected_ruleset_id=expected_ruleset_id,
        expected_workflow_id=expected_workflow_id,
        expected_workflow_sha=expected_workflow_sha,
        candidate_head_sha=candidate_head_sha,
        pull_request_number=pull_request_number,
    )
    expected_pr_link = _expected_pr_link(pull_request)
    same_name_checks_by_id: dict[int, dict[str, Any]] = {}
    for check_head_sha in sorted({candidate_head_sha, pull_request["base"]["sha"]}):
        check_values = _collect_pages(
            client,
            trace,
            phase=phase,
            label=f"selected PR {check_head_sha} check runs",
            endpoint=f"/repos/{target_name}/commits/{check_head_sha}/check-runs",
            parameters={"filter": "all"},
            item_key="check_runs",
        )
        for value in check_values:
            raw_check = _exact_dict(value, label="selected PR check run")
            check_name = _exact_string(
                raw_check.get("name"),
                label="selected PR check-run name",
            )
            if check_name != workflow_contract["check_name"]:
                continue
            check = _normalize_check_run(raw_check)
            if check["head_sha"] != check_head_sha:
                raise _blocked(
                    "check-run-identity-mismatch",
                    "check-run search returned another commit",
                )
            if expected_pr_link not in check["pull_requests"]:
                continue
            existing = same_name_checks_by_id.get(check["id"])
            if existing is not None:
                raise _blocked(
                    "check-run-identity-mismatch",
                    "same check-run ID was repeated during collection",
                )
            same_name_checks_by_id[check["id"]] = check
    same_name_checks = list(same_name_checks_by_id.values())
    all_runs_by_id: dict[int, dict[str, Any]] = {}
    check_suite_ids = sorted({check["check_suite_id"] for check in same_name_checks})
    for check_suite_id in check_suite_ids:
        run_values = _collect_pages(
            client,
            trace,
            phase=phase,
            label=f"check suite {check_suite_id} workflow runs",
            endpoint=f"/repos/{target_name}/actions/runs",
            parameters={"check_suite_id": check_suite_id},
            item_key="workflow_runs",
            result_cap=MAX_WORKFLOW_RUNS,
        )
        for value in run_values:
            run = _normalize_run(_exact_dict(value, label="check-suite workflow run"))
            if run["check_suite_id"] != check_suite_id:
                raise _blocked(
                    "workflow-run-linkage-mismatch",
                    "workflow-run search returned another check suite",
                )
            existing = all_runs_by_id.get(run["id"])
            if existing is not None:
                raise _blocked(
                    "workflow-run-linkage-mismatch",
                    "same workflow run ID was repeated during collection",
                )
            all_runs_by_id[run["id"]] = run
        if len(all_runs_by_id) > MAX_WORKFLOW_RUNS:
            raise _blocked(
                "api-search-cap-exceeded",
                "candidate workflow runs exceed the complete-search cap",
            )
    all_runs = list(all_runs_by_id.values())
    same_name_urls = {check["url"] for check in same_name_checks}
    relevant_jobs: list[dict[str, Any]] = []
    job_queries = 0
    for run in all_runs:
        if run["run_attempt"] > MAX_RUN_ATTEMPTS:
            raise _blocked(
                "api-search-cap-exceeded",
                "workflow run attempt exceeds the complete-search cap",
            )
        for attempt in range(1, run["run_attempt"] + 1):
            job_queries += 1
            if job_queries > MAX_JOB_ATTEMPT_QUERIES:
                raise _blocked(
                    "api-search-cap-exceeded",
                    "workflow job attempt queries exceed the complete-search cap",
                )
            job_values = _collect_pages(
                client,
                trace,
                phase=phase,
                label=f"workflow run {run['id']} attempt {attempt} jobs",
                endpoint=(
                    f"/repos/{target_name}/actions/runs/{run['id']}"
                    f"/attempts/{attempt}/jobs"
                ),
                parameters={},
                item_key="jobs",
            )
            for value in job_values:
                raw_job = _exact_dict(value, label="workflow job")
                if (
                    raw_job.get("name") == workflow_contract["check_name"]
                    or raw_job.get("check_run_url") in same_name_urls
                ):
                    relevant_jobs.append(_normalize_job(raw_job, run_attempt=attempt))
    relevant_run_ids = {job["run_id"] for job in relevant_jobs}
    relevant_runs = [run for run in all_runs if run["id"] in relevant_run_ids]
    snapshot = dict(partial_snapshot)
    snapshot.update(
        {
            "check_runs": same_name_checks,
            "jobs": relevant_jobs,
            "workflow_runs": relevant_runs,
        }
    )
    return snapshot


def _status_contexts(rulesets: list[Any]) -> set[str]:
    contexts: set[str] = set()
    for ruleset_value in rulesets:
        ruleset = _exact_dict(ruleset_value, label="ruleset")
        if ruleset.get("enforcement") != "active":
            continue
        rules = _exact_list(ruleset.get("rules"), label="ruleset rules")
        for rule_value in rules:
            rule = _exact_dict(rule_value, label="ruleset rule")
            if rule.get("type") != "required_status_checks":
                continue
            parameters = _exact_dict(
                rule.get("parameters"),
                label="required status parameters",
            )
            checks = _exact_list(
                parameters.get("required_status_checks"),
                label="required status checks",
            )
            for check_value in checks:
                check = _exact_dict(check_value, label="required status check")
                contexts.add(
                    _exact_string(
                        check.get("context"),
                        label="required status context",
                    )
                )
    return contexts


def _ruleset_protected_fields(ruleset: dict[str, Any]) -> dict[str, Any]:
    return {
        "bypass_actors": ruleset["bypass_actors"],
        "conditions": ruleset["conditions"],
        "enforcement": ruleset["enforcement"],
        "id": ruleset["id"],
        "rules": ruleset["rules"],
        "source": ruleset["source"],
        "source_type": ruleset["source_type"],
        "target": ruleset["target"],
    }


def _validate_ruleset(
    snapshot: dict[str, Any],
    *,
    contract: dict[str, Any],
    expected_ruleset_id: int,
    expected_workflow_sha: str,
) -> None:
    rulesets = _exact_list(
        snapshot["effective_rulesets"],
        label="effective rulesets",
    )
    disallowed = set(contract["disallowed_status_contexts"])
    spoofable = sorted(_status_contexts(rulesets) & disallowed)
    if spoofable:
        raise _blocked(
            "spoofable-status-rule",
            "same-name required_status_checks is not workflow identity enforcement",
        )
    effective_selected = [
        _exact_dict(value, label="effective ruleset")
        for value in rulesets
        if type(value) is dict and value.get("id") == expected_ruleset_id
    ]
    if len(effective_selected) != 1:
        raise _blocked(
            "ruleset-not-effective",
            "pinned organization ruleset is absent or ambiguous in target scope",
        )
    selected = _exact_dict(
        snapshot["selected_ruleset"],
        label="selected organization ruleset",
    )
    if _ruleset_protected_fields(effective_selected[0]) != _ruleset_protected_fields(
        selected
    ):
        raise _blocked(
            "ruleset-identity-mismatch",
            "effective and organization ruleset evidence differ",
        )
    expected = contract["ruleset"]
    for field in ("source_type", "source", "target"):
        if selected.get(field) != expected[field]:
            raise _blocked(
                "ruleset-identity-mismatch",
                f"ruleset {field} differs from the Organization contract",
            )
    if selected.get("enforcement") != "active":
        raise _blocked("ruleset-not-active", "required workflow ruleset is not active")
    if selected.get("bypass_actors") != []:
        raise _blocked(
            "ruleset-bypass-configured",
            "required workflow ruleset has bypass actors",
        )
    if selected.get("conditions") != expected["conditions"]:
        raise _blocked(
            "ruleset-scope-mismatch",
            "ruleset does not target the exact repository ID and default branch",
        )
    rules = _exact_list(selected.get("rules"), label="selected ruleset rules")
    workflow_rules = [
        _exact_dict(rule, label="workflow rule")
        for rule in rules
        if type(rule) is dict and rule.get("type") == "workflows"
    ]
    if len(workflow_rules) != 1:
        raise _blocked(
            "required-workflow-rule-missing",
            "selected ruleset must contain exactly one workflows rule",
        )
    parameters = _exact_dict(
        workflow_rules[0].get("parameters"),
        label="workflow rule parameters",
    )
    _exact_keys(
        parameters,
        {"do_not_enforce_on_create", "workflows"},
        label="workflow rule parameters",
    )
    workflow_contract = contract["required_workflow"]
    if (
        parameters.get("do_not_enforce_on_create")
        is not workflow_contract["do_not_enforce_on_create"]
    ):
        raise _blocked(
            "required-workflow-binding-mismatch",
            "workflow rule permits an unapproved create bypass",
        )
    bindings = _exact_list(
        parameters.get("workflows"),
        label="required workflow bindings",
    )
    if len(bindings) != 1:
        raise _blocked(
            "required-workflow-binding-mismatch",
            "workflow rule must have exactly one binding",
        )
    binding = _exact_dict(bindings[0], label="required workflow binding")
    if binding.get("sha") is None or binding.get("ref") is None:
        raise _blocked(
            "workflow-binding-not-immutable",
            "workflow rule lacks exact ref and SHA binding",
        )
    _exact_keys(
        binding,
        {"repository_id", "path", "ref", "sha"},
        label="required workflow binding",
    )
    expected_binding = {
        "repository_id": workflow_contract["repository_id"],
        "path": workflow_contract["path"],
        "ref": workflow_contract["ref"],
        "sha": expected_workflow_sha,
    }
    if binding != expected_binding:
        raise _blocked(
            "required-workflow-binding-mismatch",
            "required workflow source repository, path, ref, or SHA differs",
        )


def _expected_pr_link(pull_request: dict[str, Any]) -> dict[str, Any]:
    return {
        "base": {
            "ref": pull_request["base"]["ref"],
            "repository_id": pull_request["base"]["repository"]["id"],
            "sha": pull_request["base"]["sha"],
        },
        "head": {
            "repository_id": pull_request["head"]["repository"]["id"],
            "sha": pull_request["head"]["sha"],
        },
        "id": pull_request["id"],
        "number": pull_request["number"],
        "url": pull_request["url"],
    }


def _run_path_matches(path: str, workflow_path: str, workflow_ref: str) -> bool:
    if path == workflow_path:
        return True
    branch = workflow_ref.removeprefix("refs/heads/")
    return (
        path == f"{workflow_path}@{branch}" or path == f"{workflow_path}@{workflow_ref}"
    )


def _validate_candidate_evidence(
    snapshot: dict[str, Any],
    *,
    contract: dict[str, Any],
    expected_workflow_id: int,
    candidate_head_sha: str,
) -> dict[str, Any]:
    workflow_contract = contract["required_workflow"]
    target = contract["target_repository"]
    pull_request = snapshot["pull_request"]
    expected_pr_link = _expected_pr_link(pull_request)
    runs: dict[int, dict[str, Any]] = {}
    for run_value in _exact_list(snapshot["workflow_runs"], label="workflow runs"):
        run = _exact_dict(run_value, label="workflow run")
        if run["id"] in runs:
            raise _blocked(
                "workflow-run-linkage-mismatch",
                "collected workflow run ID is duplicated",
            )
        runs[run["id"]] = run
    jobs = _exact_list(snapshot["jobs"], label="workflow jobs")
    checks = _exact_list(snapshot["check_runs"], label="candidate check runs")
    jobs_by_check_url: dict[str, list[dict[str, Any]]] = {}
    for job_value in jobs:
        job = _exact_dict(job_value, label="workflow job")
        jobs_by_check_url.setdefault(job["check_run_url"], []).append(job)
    current_lineage: list[dict[str, Any]] = []
    full_lineage: list[dict[str, Any]] = []
    for check_value in checks:
        check = _exact_dict(check_value, label="candidate check run")
        if check["head_sha"] not in {
            candidate_head_sha,
            pull_request["base"]["sha"],
        }:
            raise _blocked(
                "candidate-head-mismatch",
                "same-name check-run evidence includes an unrelated head",
            )
        if expected_pr_link not in check["pull_requests"]:
            raise _blocked(
                "candidate-pr-mismatch",
                "same-name check run is not natively linked to the selected PR",
            )
        if check["app"] != workflow_contract["provider"]:
            raise _blocked(
                "candidate-duplicate-context",
                "same-name check was produced by another provider identity",
            )
        expected_check_url = (
            f"{API_ROOT}/repos/{target['full_name']}/check-runs/{check['id']}"
        )
        if check["url"] != expected_check_url:
            raise _blocked(
                "check-run-identity-mismatch",
                "check-run URL does not bind its immutable repository object",
            )
        matched_jobs = jobs_by_check_url.get(check["url"], [])
        if len(matched_jobs) != 1:
            raise _blocked(
                "check-run-linkage-missing",
                "same-name check must link to exactly one Actions job",
            )
        job = matched_jobs[0]
        run = runs.get(job["run_id"])
        if run is None:
            raise _blocked(
                "workflow-run-linkage-missing",
                "check-run job does not link to a collected workflow run",
            )
        expected_run_url = (
            f"{API_ROOT}/repos/{target['full_name']}/actions/runs/{run['id']}"
        )
        expected_job_url = (
            f"{API_ROOT}/repos/{target['full_name']}/actions/jobs/{job['id']}"
        )
        expected_suite_url = (
            f"{API_ROOT}/repos/{target['full_name']}"
            f"/check-suites/{check['check_suite_id']}"
        )
        expected_workflow_url = (
            f"{API_ROOT}/repos/{workflow_contract['repository_full_name']}"
            f"/actions/workflows/{expected_workflow_id}"
        )
        if (
            run["url"] != expected_run_url
            or run["jobs_url"] != f"{expected_run_url}/jobs"
            or run["check_suite_url"] != expected_suite_url
            or run["workflow_url"] != expected_workflow_url
            or job["run_url"] != expected_run_url
            or job["url"] != expected_job_url
            or job["head_sha"] != run["head_sha"]
            or check["head_sha"] != run["head_sha"]
            or run["head_sha"] != pull_request["base"]["sha"]
            or run["repository"]
            != {"id": target["id"], "full_name": target["full_name"]}
            or run["head_repository"]
            != {"id": target["id"], "full_name": target["full_name"]}
            or expected_pr_link not in run["pull_requests"]
            or run["check_suite_id"] != check["check_suite_id"]
        ):
            raise _blocked(
                "workflow-run-linkage-mismatch",
                "PR, run, job, check-suite, repository, head, or URL linkage differs",
            )
        lineage = {
            "check_run": check,
            "job": job,
            "run": run,
        }
        full_lineage.append(lineage)
        if job["run_attempt"] == run["run_attempt"]:
            current_lineage.append(lineage)
    if not current_lineage:
        raise _blocked(
            "trusted-check-missing",
            "no current-attempt same-name check is linked to the selected PR",
        )
    trusted: list[dict[str, Any]] = []
    for lineage in current_lineage:
        run = lineage["run"]
        job = lineage["job"]
        check = lineage["check_run"]
        if (
            run["workflow_id"] != expected_workflow_id
            or not _run_path_matches(
                run["path"],
                workflow_contract["path"],
                workflow_contract["ref"],
            )
            or run["event"] != workflow_contract["event"]
            or job["name"] != workflow_contract["check_name"]
            or check["name"] != workflow_contract["check_name"]
        ):
            raise _blocked(
                "candidate-duplicate-context",
                "current same-name check is outside the pinned workflow identity",
            )
        trusted.append(lineage)
    if len(trusted) != 1:
        raise _blocked(
            "trusted-check-ambiguous",
            "exactly one current trusted workflow check must bind the selected PR",
        )
    selected = trusted[0]
    run = selected["run"]
    job = selected["job"]
    check = selected["check_run"]
    if run["status"] != "completed" or run["conclusion"] != "success":
        raise _blocked(
            "trusted-workflow-run-failed",
            "trusted required-workflow run is incomplete or not successful",
        )
    if job["status"] != "completed" or job["conclusion"] != "success":
        raise _blocked(
            "trusted-job-failed",
            "trusted workflow job is incomplete or not successful",
        )
    if check["status"] != "completed" or check["conclusion"] != "success":
        raise _blocked(
            "trusted-check-failed",
            "trusted workflow check is incomplete or not successful",
        )
    return {
        "check_run": selected["check_run"],
        "job": selected["job"],
        "run": selected["run"],
        "same_name_lineage": sorted(
            full_lineage,
            key=lambda value: (
                value["run"]["id"],
                value["job"]["run_attempt"],
                value["job"]["id"],
                value["check_run"]["id"],
            ),
        ),
    }


def validate_enforcement(
    contract: dict[str, Any],
    snapshot: dict[str, Any],
    *,
    expected_ruleset_id: int,
    expected_workflow_id: int,
    expected_workflow_sha: str,
    candidate_head_sha: str,
    pull_request_number: int,
) -> dict[str, Any]:
    contract = _load_contract(contract)
    _exact_keys(
        snapshot,
        {
            "organization",
            "repository",
            "pull_request",
            "selector_target_head_sha",
            "selector_target_pr_number",
            "effective_rulesets",
            "selected_ruleset",
            "workflow_source_repository",
            "workflow",
            "workflow_source_commit",
            "workflow_runs",
            "jobs",
            "check_runs",
        },
        label="collected snapshot",
    )
    _assert_static_identity(
        snapshot,
        contract,
        expected_ruleset_id=expected_ruleset_id,
        expected_workflow_id=expected_workflow_id,
        expected_workflow_sha=expected_workflow_sha,
        candidate_head_sha=candidate_head_sha,
        pull_request_number=pull_request_number,
    )
    _validate_ruleset(
        snapshot,
        contract=contract,
        expected_ruleset_id=expected_ruleset_id,
        expected_workflow_sha=expected_workflow_sha,
    )
    trusted = _validate_candidate_evidence(
        snapshot,
        contract=contract,
        expected_workflow_id=expected_workflow_id,
        candidate_head_sha=candidate_head_sha,
    )
    protected = {
        "organization": snapshot["organization"],
        "repository": snapshot["repository"],
        "pull_request": snapshot["pull_request"],
        "selector_target_head_sha": snapshot["selector_target_head_sha"],
        "selector_target_pr_number": snapshot["selector_target_pr_number"],
        "selected_ruleset": _ruleset_protected_fields(snapshot["selected_ruleset"]),
        "workflow_source_repository": snapshot["workflow_source_repository"],
        "workflow": snapshot["workflow"],
        "workflow_source_commit": snapshot["workflow_source_commit"],
        "same_name_lineage": trusted["same_name_lineage"],
    }
    return {
        "protected": protected,
        "trusted_check_run": trusted["check_run"],
        "trusted_job": trusted["job"],
        "trusted_run": trusted["run"],
    }


def collect_and_validate(
    client: Any,
    contract: dict[str, Any],
    *,
    expected_ruleset_id: int,
    expected_workflow_id: int,
    expected_workflow_sha: str,
    candidate_head_sha: str,
    pull_request_number: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    contract = _load_contract(contract)
    trace: dict[str, Any] = {
        "object_reads": [],
        "page_bounds": [],
    }
    started_at = _utc_now()
    authenticated_user = client.auth_preflight()
    initial = _collect_snapshot(
        client,
        trace,
        contract,
        phase="initial",
        expected_ruleset_id=expected_ruleset_id,
        expected_workflow_id=expected_workflow_id,
        expected_workflow_sha=expected_workflow_sha,
        candidate_head_sha=candidate_head_sha,
        pull_request_number=pull_request_number,
    )
    initial_admission = validate_enforcement(
        contract,
        initial,
        expected_ruleset_id=expected_ruleset_id,
        expected_workflow_id=expected_workflow_id,
        expected_workflow_sha=expected_workflow_sha,
        candidate_head_sha=candidate_head_sha,
        pull_request_number=pull_request_number,
    )
    revalidation = _collect_snapshot(
        client,
        trace,
        contract,
        phase="revalidation",
        expected_ruleset_id=expected_ruleset_id,
        expected_workflow_id=expected_workflow_id,
        expected_workflow_sha=expected_workflow_sha,
        candidate_head_sha=candidate_head_sha,
        pull_request_number=pull_request_number,
    )
    revalidated_admission = validate_enforcement(
        contract,
        revalidation,
        expected_ruleset_id=expected_ruleset_id,
        expected_workflow_id=expected_workflow_id,
        expected_workflow_sha=expected_workflow_sha,
        candidate_head_sha=candidate_head_sha,
        pull_request_number=pull_request_number,
    )
    if initial_admission["protected"] != revalidated_admission["protected"]:
        raise _blocked(
            "api-snapshot-raced",
            "protected API identity, content, or target scope changed during collection",
        )
    completed_at = _utc_now()
    collector_receipt = {
        "api_host": API_HOST,
        "api_version": API_VERSION,
        "authenticated_user": authenticated_user,
        "completed_at": completed_at,
        "mode": "live-gh-rest",
        "object_reads": trace["object_reads"],
        "page_bounds": trace["page_bounds"],
        "schema_version": COLLECTOR_SCHEMA_VERSION,
        "started_at": started_at,
    }
    evidence = {
        "collector": collector_receipt,
        "initial": initial,
        "revalidation": revalidation,
        "schema_version": COLLECTOR_SCHEMA_VERSION,
    }
    return evidence, revalidated_admission


def _positive_integer_argument(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _sha1_argument(value: str) -> str:
    if SHA1_PATTERN.fullmatch(value) is None or set(value) == {"0"}:
        raise argparse.ArgumentTypeError("must be exact nonzero lowercase SHA-1")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Collect and verify identity-bound GitHub required-workflow "
            "enforcement for the Cisco provider cutover."
        )
    )
    parser.add_argument("--contract", required=True, type=pathlib.Path)
    parser.add_argument(
        "--pull-request-number",
        required=True,
        type=_positive_integer_argument,
    )
    parser.add_argument(
        "--expected-ruleset-id",
        required=True,
        type=_positive_integer_argument,
    )
    parser.add_argument(
        "--expected-workflow-id",
        required=True,
        type=_positive_integer_argument,
    )
    parser.add_argument(
        "--expected-workflow-sha",
        required=True,
        type=_sha1_argument,
    )
    parser.add_argument(
        "--candidate-head-sha",
        required=True,
        type=_sha1_argument,
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    contract_sha256 = None
    evidence_sha256 = None
    try:
        contract, contract_sha256 = _read_json(args.contract, label="contract")
        client = GitHubApiClient()
        evidence, admission = collect_and_validate(
            client,
            contract,
            expected_ruleset_id=args.expected_ruleset_id,
            expected_workflow_id=args.expected_workflow_id,
            expected_workflow_sha=args.expected_workflow_sha,
            candidate_head_sha=args.candidate_head_sha,
            pull_request_number=args.pull_request_number,
        )
        evidence_sha256 = hashlib.sha256(_canonical_json_bytes(evidence)).hexdigest()
    except EnforcementDoctorError as error:
        blocked_receipt = {
            "classification": "blocked_until_trusted",
            "contract_sha256": contract_sha256,
            "evidence_sha256": evidence_sha256,
            "operation": "cisco-cutover-enforcement-doctor",
            "reason": str(error),
            "reason_code": error.reason_code,
            "schema_version": 3,
        }
        if error.api_failure is not None:
            blocked_receipt["api_failure"] = error.api_failure
        print(
            json.dumps(
                blocked_receipt,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 1
    trusted_run = admission["trusted_run"]
    trusted_job = admission["trusted_job"]
    trusted_check = admission["trusted_check_run"]
    workflow_contract = contract["required_workflow"]
    revalidated_snapshot = evidence["revalidation"]
    pull_request = revalidated_snapshot["pull_request"]
    selected_ruleset = revalidated_snapshot["selected_ruleset"]
    workflow_metadata = revalidated_snapshot["workflow"]
    print(
        json.dumps(
            {
                "applicability_selector": {
                    "target_head_sha": revalidated_snapshot["selector_target_head_sha"],
                    "target_pr_number": revalidated_snapshot[
                        "selector_target_pr_number"
                    ],
                },
                "candidate": {
                    "base_ref": pull_request["base"]["ref"],
                    "base_repository_id": pull_request["base"]["repository"]["id"],
                    "base_sha": pull_request["base"]["sha"],
                    "head_repository_full_name": pull_request["head"]["repository"][
                        "full_name"
                    ],
                    "head_repository_id": pull_request["head"]["repository"]["id"],
                    "head_sha": args.candidate_head_sha,
                    "pull_request_id": pull_request["id"],
                    "pull_request_number": args.pull_request_number,
                    "pull_request_url": pull_request["url"],
                },
                "classification": "admitted",
                "collection": evidence["collector"],
                "contract_sha256": contract_sha256,
                "evidence_sha256": evidence_sha256,
                "operation": "cisco-cutover-enforcement-doctor",
                "organization": contract["source_organization"],
                "repository": contract["target_repository"],
                "ruleset": {
                    "bypass_actors": selected_ruleset["bypass_actors"],
                    "conditions": selected_ruleset["conditions"],
                    "enforcement": selected_ruleset["enforcement"],
                    "id": args.expected_ruleset_id,
                    "source": contract["ruleset"]["source"],
                    "source_type": contract["ruleset"]["source_type"],
                    "target": selected_ruleset["target"],
                },
                "schema_version": 3,
                "trusted_execution": {
                    "check_run": {
                        "app": trusted_check["app"],
                        "check_suite_id": trusted_check["check_suite_id"],
                        "conclusion": trusted_check["conclusion"],
                        "details_url": trusted_check["details_url"],
                        "head_sha": trusted_check["head_sha"],
                        "html_url": trusted_check["html_url"],
                        "id": trusted_check["id"],
                        "name": trusted_check["name"],
                        "status": trusted_check["status"],
                        "url": trusted_check["url"],
                    },
                    "job": {
                        "check_run_url": trusted_job["check_run_url"],
                        "conclusion": trusted_job["conclusion"],
                        "head_sha": trusted_job["head_sha"],
                        "html_url": trusted_job["html_url"],
                        "id": trusted_job["id"],
                        "name": trusted_job["name"],
                        "run_attempt": trusted_job["run_attempt"],
                        "run_id": trusted_job["run_id"],
                        "run_url": trusted_job["run_url"],
                        "status": trusted_job["status"],
                        "url": trusted_job["url"],
                        "workflow_name": trusted_job["workflow_name"],
                    },
                    "run": {
                        "check_suite_id": trusted_run["check_suite_id"],
                        "check_suite_url": trusted_run["check_suite_url"],
                        "conclusion": trusted_run["conclusion"],
                        "event": trusted_run["event"],
                        "head_repository_id": trusted_run["head_repository"]["id"],
                        "head_sha": trusted_run["head_sha"],
                        "html_url": trusted_run["html_url"],
                        "id": trusted_run["id"],
                        "path": trusted_run["path"],
                        "run_attempt": trusted_run["run_attempt"],
                        "status": trusted_run["status"],
                        "url": trusted_run["url"],
                        "workflow_id": trusted_run["workflow_id"],
                    },
                    "workflow": {
                        "html_url": workflow_metadata["html_url"],
                        "id": args.expected_workflow_id,
                        "path": workflow_contract["path"],
                        "ref": workflow_contract["ref"],
                        "repository_full_name": workflow_contract[
                            "repository_full_name"
                        ],
                        "repository_id": workflow_contract["repository_id"],
                        "sha": args.expected_workflow_sha,
                        "state": workflow_metadata["state"],
                        "url": workflow_metadata["url"],
                    },
                },
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
