#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import pwd
import re
import secrets
import select
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Callable, Optional

CONTRACT_SCHEMA_VERSION = 4
COLLECTOR_SCHEMA_VERSION = 3
DOCTOR_SCHEMA_VERSION = 5
AUTH_HOST = "github.com"
API_ORIGIN_HOST = "api.github.com"
API_ROOT = f"https://{API_ORIGIN_HOST}"
API_VERSION = "2026-03-10"
API_ACCEPT = "application/vnd.github+json"
API_PER_PAGE = 100
MAX_API_PAGES = 100
MAX_API_CALLS = 16_384
MAX_API_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_API_STDERR_BYTES = 64 * 1024
MAX_API_TOTAL_BYTES = 64 * 1024 * 1024
MAX_API_SECONDS = 30
MAX_COLLECTION_SECONDS = 180
MAX_CHECK_SUITES = 2_000
MAX_CHECK_RUNS = 10_000
MAX_WORKFLOW_RUNS = 1_000
MAX_RUN_ATTEMPTS = 20
MAX_JOB_ATTEMPT_QUERIES = 1_000
MAX_JSON_BYTES = 512 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 65_536
MAX_JSON_CONTAINER_ITEMS = 16_384
MAX_JSON_INTEGER_DIGITS = 64
MAX_JSON_STRING_CHARS = 128 * 1024
MAX_GH_EXECUTABLE_BYTES = 256 * 1024 * 1024
MAX_GH_CONFIG_BYTES = 1024 * 1024
MAX_GH_CONFIG_LINE_BYTES = 16 * 1024
GH_PROCESS_TERM_GRACE_SECONDS = 1.0
GH_PROCESS_REAP_DEADLINE_SECONDS = 5.0
GH_PROCESS_CLEANUP_POLL_SECONDS = 0.01
GH_PROCESS_DRAIN_CHUNKS_PER_TICK = 16
GH_TERMINATION_SIGNAL_NAMES = ("SIGHUP", "SIGINT", "SIGQUIT", "SIGTERM")
MAX_DARWIN_ACL_BYTES = 64 * 1024
MAX_DARWIN_ACL_ENTRIES = 128
GH_EXECUTABLE_ENVIRONMENT_PROFILE = "minimal-snapshotted-auth-v3"
GH_EXECUTION_SOURCE = "owner-private-snapshot"
GH_RUNTIME_COMPONENTS = (".codex", "cisco-cutover-doctor")
CURL_EXECUTABLE = pathlib.Path("/usr/bin/curl")
CURL_OPERATION_TIMED_OUT_EXIT_CODE = 28
CURL_WRITE_OUT_FORMAT = (
    "\nCISCO_STATUS=%{http_code}\nCISCO_RATE=%header{x-ratelimit-remaining}\n"
)
CURL_TRAILER_PATTERN = re.compile(
    rb"\nCISCO_STATUS=([0-9]{3})\nCISCO_RATE=([0-9]*)\n\Z"
)
DARWIN_LIBSYSTEM_PATH = "/usr/lib/libSystem.B.dylib"
DARWIN_ACL_TYPE_EXTENDED = 0x00000100
DARWIN_ACL_EXTENDED_ALLOW = 1
DARWIN_ACL_EXTENDED_DENY = 2
DARWIN_ACL_FIRST_ENTRY = 0
DARWIN_ACL_NEXT_ENTRY = -1
DARWIN_ACL_INHERITANCE_FLAGS = (1 << 4, 1 << 5, 1 << 6, 1 << 7, 1 << 8)
DARWIN_ACL_PROFILE = "darwin-fd-no-extended-grants-v1"
LINUX_ACL_PROFILE = "linux-posix-mode-mask-v1"
GH_SNAPSHOT_CONFIG = (
    b"version: 1\n"
    b"git_protocol: https\n"
    b"prompt: disabled\n"
    b"prefer_editor_prompt: disabled\n"
    b"pager:\n"
    b"aliases:\n"
    b"http_unix_socket:\n"
    b"browser:\n"
    b"color_labels: disabled\n"
    b"accessible_colors: disabled\n"
    b"accessible_prompter: disabled\n"
    b"spinner: disabled\n"
)
GH_TRANSPORT_REDIRECT_KEYS = frozenset(
    {
        "api_host",
        "api_url",
        "base_url",
        "endpoint",
        "http_proxy",
        "http_unix_socket",
        "https_proxy",
        "proxy",
        "socket",
        "transport",
        "unix_socket",
    }
)
CUTOVER_INPUT_VARIABLES = (
    "CISCO_CUTOVER_TARGET_PR_NUMBER",
    "CISCO_CUTOVER_TARGET_HEAD_SHA",
    "CISCO_CUTOVER_RECEIPT_BASE64",
    "CISCO_CUTOVER_EXPECTED_CANONICAL_COMMIT",
    "CISCO_CUTOVER_EXPECTED_PRIVATE_RELEASE_COMMIT",
    "CISCO_CUTOVER_EXPECTED_RELEASE_MANIFEST_SHA256",
    "CISCO_CUTOVER_EXPECTED_RECEIPT_SHA256",
    "CISCO_CUTOVER_EXPECTED_WORKFLOW_ID",
    "CISCO_CUTOVER_EXPECTED_WORKFLOW_SHA",
    "CISCO_CUTOVER_EXPECTED_INSTALLATION_SCOPE_ID",
    "CISCO_CUTOVER_EXPECTED_POINTER_GENERATION",
    "CISCO_CUTOVER_EXPECTED_POINTER_STATE_SHA256",
)
SHA1_PATTERN = re.compile(r"[0-9a-f]{40}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
RFC3339_UTC_PATTERN = re.compile(
    r"(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})"
    r"T(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?P<fraction>\.[0-9]{1,9})?Z"
)
HTTP_STATUS_PATTERN = re.compile(rb"\(HTTP ([1-5][0-9]{2})\)")


class EnforcementDoctorError(ValueError):
    def __init__(
        self,
        reason_code: str,
        reason: str,
        *,
        api_failure: Optional[dict[str, Any]] = None,
        cleanup_failure: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(reason)
        self.reason_code = reason_code
        self.api_failure = api_failure
        self.cleanup_failure = cleanup_failure


def _blocked(
    reason_code: str,
    reason: str,
    *,
    api_failure: Optional[dict[str, Any]] = None,
    cleanup_failure: Optional[dict[str, Any]] = None,
) -> EnforcementDoctorError:
    return EnforcementDoctorError(
        reason_code,
        reason,
        api_failure=api_failure,
        cleanup_failure=cleanup_failure,
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


def _exact_sha256(value: object, *, label: str) -> str:
    if type(value) is not str or SHA256_PATTERN.fullmatch(value) is None:
        raise _blocked("invalid-evidence", f"{label} must be exact lowercase SHA-256")
    if set(value) == {"0"}:
        raise _blocked("invalid-evidence", f"{label} must not be all-zero")
    return value


def _normalize_rfc3339_utc(value: object, *, label: str) -> str:
    if type(value) is not str:
        raise _blocked("invalid-evidence", f"{label} must be RFC3339 UTC text")
    matched = RFC3339_UTC_PATTERN.fullmatch(value)
    if matched is None:
        raise _blocked(
            "invalid-evidence",
            f"{label} must be strict RFC3339 UTC with a Z suffix",
        )
    try:
        datetime(
            int(matched["year"]),
            int(matched["month"]),
            int(matched["day"]),
            int(matched["hour"]),
            int(matched["minute"]),
            int(matched["second"]),
            tzinfo=timezone.utc,
        )
    except ValueError as error:
        raise _blocked(
            "invalid-evidence",
            f"{label} is not a valid RFC3339 UTC timestamp",
        ) from error
    return value


def _optional_rfc3339_utc(
    value: object,
    *,
    label: str,
) -> Optional[str]:
    if value is None:
        return None
    return _normalize_rfc3339_utc(value, label=label)


def _rfc3339_utc_sort_key(value: str) -> tuple[int, ...]:
    matched = RFC3339_UTC_PATTERN.fullmatch(value)
    if matched is None:
        raise _blocked(
            "invalid-evidence",
            "normalized timestamp no longer matches RFC3339 UTC",
        )
    fraction = (matched["fraction"] or ".0")[1:].ljust(9, "0")
    return (
        int(matched["year"]),
        int(matched["month"]),
        int(matched["day"]),
        int(matched["hour"]),
        int(matched["minute"]),
        int(matched["second"]),
        int(fraction),
    )


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
            "cutover_input_variables",
            "pointer_authority",
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
    cutover_input_variables = _exact_list(
        contract["cutover_input_variables"],
        label="contract cutover input variables",
    )
    if cutover_input_variables != list(CUTOVER_INPUT_VARIABLES) or len(
        cutover_input_variables
    ) != len(set(cutover_input_variables)):
        raise _blocked(
            "invalid-contract",
            "contract cutover input variables differ in name, order, or uniqueness",
        )
    pointer_authority = _exact_dict(
        contract["pointer_authority"],
        label="contract pointer authority",
    )
    status = _exact_string(
        pointer_authority.get("status"),
        label="contract pointer authority status",
    )
    if status == "unavailable":
        _exact_keys(
            pointer_authority,
            {"status", "reason"},
            label="contract unavailable pointer authority",
        )
        if pointer_authority["reason"] != "private-live-authority-not-configured":
            raise _blocked(
                "invalid-contract",
                "contract unavailable pointer-authority reason differs",
            )
    else:
        raise _blocked(
            "invalid-contract",
            "contract pointer-authority status is not implemented",
        )
    disallowed = _exact_list(
        contract["disallowed_status_contexts"],
        label="contract disallowed status contexts",
    )
    if disallowed != [workflow["check_name"]]:
        raise _blocked("invalid-contract", "contract status-context denylist differs")
    return contract


GROUP_SIGNAL_OPEN = "signal-open"
GROUP_KILL_SENT_BEFORE_REAP = "kill-sent-before-reap"
GROUP_MISSING_BEFORE_REAP = "group-missing-before-reap"
GROUP_NO_SIGNALABLE_MEMBERS_BEFORE_REAP = "no-signalable-members-before-reap"
GROUP_DIRECT_PROCESS_ONLY = "direct-process-only"
GROUP_SIGNAL_UNPROVEN_BEFORE_REAP = "signal-unproven-before-reap"
SAFE_TERMINAL_GROUP_STATES = {
    GROUP_KILL_SENT_BEFORE_REAP,
    GROUP_MISSING_BEFORE_REAP,
    GROUP_NO_SIGNALABLE_MEMBERS_BEFORE_REAP,
    GROUP_DIRECT_PROCESS_ONLY,
}


class _DeferredTerminationSignal(BaseException):
    def __init__(self, signal_number: int) -> None:
        self.signal_number = signal_number
        super().__init__(f"deferred termination signal {signal_number}")


class _TerminationSignalGuard:
    """Defer termination across a credential-bearing client transaction."""

    def __init__(self) -> None:
        self._requested_signals = tuple(
            dict.fromkeys(
                getattr(signal, name)
                for name in GH_TERMINATION_SIGNAL_NAMES
                if hasattr(signal, name)
            )
        )
        self._managed_signals: tuple[int, ...] = ()
        self._original_handlers: dict[int, Any] = {}
        self._original_mask: set[signal.Signals] | None = None
        self._state = "new"
        self._deferred_signal: int | None = None
        self._errors: list[BaseException] = []

    @property
    def deferred_signal(self) -> int | None:
        return self._deferred_signal

    @property
    def errors(self) -> tuple[BaseException, ...]:
        return tuple(self._errors)

    @property
    def state(self) -> str:
        return self._state

    def _record_signal(self, signal_number: int) -> None:
        if self._deferred_signal is None:
            self._deferred_signal = signal_number

    def _handle_signal(self, signal_number: int, _frame: object) -> None:
        self._record_signal(signal_number)
        if self._state == "running":
            raise _DeferredTerminationSignal(signal_number)

    def start(self) -> None:
        required_names = (
            "pthread_sigmask",
            "sigpending",
            "sigwait",
            "SIG_BLOCK",
            "SIG_SETMASK",
        )
        if (
            os.name != "posix"
            or threading.current_thread() is not threading.main_thread()
            or threading.active_count() != 1
            or any(not hasattr(signal, name) for name in required_names)
            or not self._requested_signals
        ):
            raise OSError("termination-signal deferral is unavailable")

        requested = set(self._requested_signals)
        installed: list[int] = []
        try:
            self._original_mask = signal.pthread_sigmask(
                signal.SIG_BLOCK,
                requested,
            )
            for signal_number in self._requested_signals:
                if signal_number in self._original_mask:
                    continue
                original_handler = signal.getsignal(signal_number)
                if original_handler == signal.SIG_IGN:
                    continue
                self._original_handlers[signal_number] = original_handler
                signal.signal(signal_number, self._handle_signal)
                installed.append(signal_number)
            self._managed_signals = tuple(installed)
            self._state = "blocked"
        except BaseException:
            for signal_number in reversed(installed):
                try:
                    signal.signal(
                        signal_number,
                        self._original_handlers[signal_number],
                    )
                except BaseException:
                    pass
            if self._original_mask is not None:
                try:
                    signal.pthread_sigmask(
                        signal.SIG_SETMASK,
                        self._original_mask,
                    )
                except BaseException:
                    pass
            self._state = "failed"
            raise

    def activate(self) -> None:
        if self._state != "blocked" or self._original_mask is None:
            raise RuntimeError("termination-signal guard activation is invalid")
        self._state = "running"
        signal.pthread_sigmask(signal.SIG_SETMASK, self._original_mask)
        if self._deferred_signal is not None:
            raise _DeferredTerminationSignal(self._deferred_signal)

    def publish(self, _managed: _ManagedProcess) -> None:
        self.activate()

    def check_deferred(self) -> None:
        if self._state == "blocked":
            self._drain_pending()
        if self._deferred_signal is not None:
            raise _DeferredTerminationSignal(self._deferred_signal)

    def prepare_publication(self) -> None:
        if self._state != "running":
            raise RuntimeError("termination-signal guard publication is invalid")
        error_count = len(self._errors)
        signal.pthread_sigmask(
            signal.SIG_BLOCK,
            set(self._requested_signals),
        )
        self._state = "blocked"
        self._drain_pending()
        if len(self._errors) != error_count:
            raise OSError("termination-signal publication fence is inconclusive")
        if self._deferred_signal is not None:
            raise _DeferredTerminationSignal(self._deferred_signal)

    def _drain_pending(self) -> None:
        try:
            pending = set(signal.sigpending()).intersection(self._managed_signals)
        except BaseException as error:
            self._errors.append(error)
            return
        for signal_number in self._managed_signals:
            if signal_number not in pending:
                continue
            try:
                received = signal.sigwait({signal_number})
            except BaseException as error:
                self._errors.append(error)
                continue
            if received != signal_number:
                self._errors.append(
                    RuntimeError(
                        "termination-signal drain returned an unexpected signal"
                    )
                )
                continue
            self._record_signal(signal_number)

    def begin_cleanup(self) -> None:
        if self._state in ("cleanup", "fenced", "closed"):
            return
        self._state = "cleanup"
        try:
            signal.pthread_sigmask(
                signal.SIG_BLOCK,
                set(self._requested_signals),
            )
        except BaseException as error:
            self._errors.append(error)
        self._drain_pending()

    def finish(self) -> None:
        self.begin_cleanup()
        self._drain_pending()
        handlers_restored = True
        for signal_number in reversed(self._managed_signals):
            try:
                signal.signal(
                    signal_number,
                    self._original_handlers[signal_number],
                )
            except BaseException as error:
                self._errors.append(error)
                handlers_restored = False
        if not handlers_restored or self._original_mask is None:
            self._state = "fenced"
            return
        try:
            signal.pthread_sigmask(
                signal.SIG_SETMASK,
                self._original_mask,
            )
        except BaseException as error:
            self._errors.append(error)
            self._state = "fenced"
            return
        self._state = "closed"


class _ManagedProcess:
    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self.process = process
        self.pid = process.pid
        self.process_group = process.pid if os.name == "posix" else None
        self.leader_state = "unreaped"
        self.group_state = GROUP_SIGNAL_OPEN

    def mark_reaped(self) -> None:
        if self.group_state == GROUP_SIGNAL_OPEN:
            self.group_state = GROUP_SIGNAL_UNPROVEN_BEFORE_REAP
        self.leader_state = "reaped"


def _leader_exited_without_reap(managed: _ManagedProcess) -> bool:
    if managed.leader_state != "unreaped" or os.name != "posix":
        return False
    if all(
        hasattr(os, name)
        for name in ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")
    ):
        try:
            result = os.waitid(
                os.P_PID,
                managed.pid,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        except (ChildProcessError, OSError):
            return False
        return result is not None and getattr(result, "si_pid", 0) == managed.pid
    if not (
        sys.platform == "darwin"
        and hasattr(select, "kqueue")
        and hasattr(select, "kevent")
        and hasattr(select, "KQ_FILTER_PROC")
        and hasattr(select, "KQ_NOTE_EXIT")
    ):
        return False
    try:
        queue = select.kqueue()
    except OSError:
        return False
    try:
        change = select.kevent(
            managed.pid,
            filter=select.KQ_FILTER_PROC,
            flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_ONESHOT,
            fflags=select.KQ_NOTE_EXIT,
        )
        try:
            events = queue.control([change], 1, 0)
        except ProcessLookupError:
            # With SIGCHLD at its default disposition and no competing thread,
            # an already-gone EVFILT_PROC target is this unreaped child.
            return True
        return any(
            event.ident == managed.pid and event.fflags & select.KQ_NOTE_EXIT
            for event in events
        )
    except OSError:
        return False
    finally:
        try:
            queue.close()
        except OSError:
            pass


def _signal_managed_process(
    managed: _ManagedProcess,
    signal_number: int,
) -> str:
    if managed.leader_state != "unreaped":
        return "prohibited"
    try:
        if os.name == "posix":
            if (
                managed.group_state != GROUP_SIGNAL_OPEN
                or managed.process_group is None
            ):
                return "prohibited"
            os.killpg(managed.process_group, signal_number)
        elif signal_number == signal.SIGTERM:
            managed.process.terminate()
        else:
            managed.process.kill()
    except ProcessLookupError:
        return "missing"
    except PermissionError:
        return "permission"
    except Exception:
        return "failed"
    return "sent"


def _seal_process_group_before_reap(
    managed: _ManagedProcess,
) -> list[str]:
    if managed.group_state != GROUP_SIGNAL_OPEN:
        return (
            []
            if managed.group_state in SAFE_TERMINAL_GROUP_STATES
            else ["process-group-not-quiescent"]
        )
    if os.name != "posix":
        outcome = _signal_managed_process(managed, signal.SIGKILL)
        if outcome in ("sent", "missing"):
            managed.group_state = GROUP_DIRECT_PROCESS_ONLY
            return []
        managed.group_state = GROUP_SIGNAL_UNPROVEN_BEFORE_REAP
        return ["process-group-not-quiescent"]
    outcome = _signal_managed_process(managed, signal.SIGKILL)
    if outcome == "sent":
        managed.group_state = GROUP_KILL_SENT_BEFORE_REAP
    elif outcome == "missing" and managed.leader_state == "unreaped":
        managed.group_state = GROUP_MISSING_BEFORE_REAP
    elif (
        outcome == "permission"
        and sys.platform == "darwin"
        and _leader_exited_without_reap(managed)
    ):
        # Darwin returns EPERM when the retained zombie leader is the only
        # group member. A living same-UID member would make killpg succeed.
        managed.group_state = GROUP_NO_SIGNALABLE_MEMBERS_BEFORE_REAP
    else:
        managed.group_state = GROUP_SIGNAL_UNPROVEN_BEFORE_REAP
        if managed.leader_state == "unreaped":
            try:
                os.kill(managed.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
        return ["process-group-not-quiescent"]
    return []


def _drain_process_streams_once(
    open_stream_fds: set[int],
) -> list[str]:
    failures: list[str] = []
    for fd in tuple(open_stream_fds):
        for _ in range(GH_PROCESS_DRAIN_CHUNKS_PER_TICK):
            try:
                chunk = os.read(fd, 64 * 1024)
            except BlockingIOError:
                break
            except InterruptedError:
                continue
            except OSError:
                failures.append("stream-drain-read")
                open_stream_fds.discard(fd)
                break
            if not chunk:
                open_stream_fds.discard(fd)
                break
    return failures


def _terminate_drain_reap_impl(
    managed: _ManagedProcess,
) -> list[str]:
    failures: list[str] = []
    process = managed.process
    streams = tuple(
        stream for stream in (process.stdout, process.stderr) if stream is not None
    )
    open_stream_fds: set[int] = set()
    for stream in streams:
        try:
            fd = stream.fileno()
            os.set_blocking(fd, False)
        except Exception:
            failures.append("stream-drain-setup")
            continue
        open_stream_fds.add(fd)

    if managed.group_state == GROUP_SIGNAL_OPEN:
        _signal_managed_process(managed, signal.SIGTERM)
        term_deadline = time.monotonic() + GH_PROCESS_TERM_GRACE_SECONDS
        while time.monotonic() < term_deadline:
            failures.extend(_drain_process_streams_once(open_stream_fds))
            time.sleep(
                min(
                    GH_PROCESS_CLEANUP_POLL_SECONDS,
                    max(0.0, term_deadline - time.monotonic()),
                )
            )
        failures.extend(_seal_process_group_before_reap(managed))

    reap_deadline = time.monotonic() + GH_PROCESS_REAP_DEADLINE_SECONDS
    reap_wait_failed = False
    while time.monotonic() < reap_deadline:
        failures.extend(_drain_process_streams_once(open_stream_fds))
        if managed.leader_state != "reaped" and not reap_wait_failed:
            remaining = reap_deadline - time.monotonic()
            try:
                process.wait(
                    timeout=max(
                        0.0,
                        min(
                            GH_PROCESS_CLEANUP_POLL_SECONDS,
                            remaining,
                        ),
                    ),
                )
                managed.mark_reaped()
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                failures.append("process-reap")
                reap_wait_failed = True
        if managed.leader_state == "reaped" and not open_stream_fds:
            break
        time.sleep(
            min(
                GH_PROCESS_CLEANUP_POLL_SECONDS,
                max(0.0, reap_deadline - time.monotonic()),
            )
        )

    if managed.leader_state != "reaped" and not reap_wait_failed:
        failures.append("process-reap-timeout")
    if managed.leader_state != "reaped":
        failures.append("process-not-reaped")
    if managed.group_state not in SAFE_TERMINAL_GROUP_STATES:
        failures.append("process-group-not-quiescent")
    if open_stream_fds:
        failures.append("stream-drain-incomplete")
    return sorted(set(failures))


def _terminate_drain_reap(
    managed: _ManagedProcess,
) -> list[str]:
    try:
        return _terminate_drain_reap_impl(managed)
    except BaseException:
        failures = ["process-cleanup-internal"]
        if managed.group_state == GROUP_SIGNAL_OPEN:
            failures.extend(_seal_process_group_before_reap(managed))
        try:
            managed.process.wait(timeout=GH_PROCESS_REAP_DEADLINE_SECONDS)
            managed.mark_reaped()
        except BaseException:
            failures.append("process-reap")
        if managed.leader_state != "reaped":
            failures.append("process-not-reaped")
        if managed.group_state not in SAFE_TERMINAL_GROUP_STATES:
            failures.append("process-group-not-quiescent")
        return sorted(set(failures))


def _close_process_resources(
    selector: Optional[selectors.BaseSelector],
    managed: _ManagedProcess,
    *,
    close_streams: bool = True,
) -> list[str]:
    failures: list[str] = []
    process = managed.process
    if selector is not None:
        try:
            selector.close()
        except Exception:
            failures.append("selector-close")
    if close_streams:
        for label, stream in (
            ("stdout-close", process.stdout),
            ("stderr-close", process.stderr),
        ):
            if stream is None:
                continue
            try:
                stream.close()
            except Exception:
                failures.append(label)
    return failures


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
            if "attempts" in suffix and suffix[-1:] == ["jobs"]:
                return "workflow-jobs"
            if "attempts" in suffix:
                return "workflow-run-attempt"
            return "workflow-runs"
        if suffix[:1] == ["commits"]:
            return "check-suites" if suffix[-1:] == ["check-suites"] else "commit"
        if suffix[:1] == ["check-suites"] and suffix[-1:] == ["check-runs"]:
            return "check-runs"
    return "github-api"


def _http_status_from_stderr(stderr: bytes) -> Optional[int]:
    matches = HTTP_STATUS_PATTERN.findall(stderr)
    if not matches:
        return None
    return int(matches[-1], 10)


def _api_request_error(
    *,
    endpoint_class: str,
    return_code: int,
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
    if return_code == CURL_OPERATION_TIMED_OUT_EXIT_CODE:
        reason_code = "api-timeout"
        reason = "GitHub API transport timed out"
        failure_kind = "timeout"
    elif status == 401:
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


def _api_http_status_error(
    *,
    endpoint_class: str,
    http_status: int,
    rate_limited: bool = False,
) -> EnforcementDoctorError:
    if http_status == 401:
        reason_code = "blocked-authentication"
        reason = "GitHub API authentication was rejected"
        failure_kind = "authentication"
    elif http_status == 403 and rate_limited:
        reason_code = "rate-limited"
        reason = "GitHub API rate limit blocked the read"
        failure_kind = "rate-limit"
    elif http_status == 403:
        reason_code = "blocked-permission"
        reason = "GitHub API permission blocked the read"
        failure_kind = "permission"
    elif http_status == 404:
        reason_code = "not-found"
        reason = "GitHub API object was not found or is not visible"
        failure_kind = "not-found"
    elif http_status == 429:
        reason_code = "rate-limited"
        reason = "GitHub API rate limit blocked the read"
        failure_kind = "rate-limit"
    elif 500 <= http_status <= 599:
        reason_code = "api-unavailable"
        reason = "GitHub API service failed the read"
        failure_kind = "server-error"
    else:
        reason_code = "api-unavailable"
        reason = "GitHub API request failed"
        failure_kind = "http-error"
    return _blocked(
        reason_code,
        reason,
        api_failure=_api_failure(
            endpoint_class,
            http_status=http_status,
            failure_kind=failure_kind,
        ),
    )


def _sha256_fd_bounded(
    fd: int,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> tuple[str, int]:
    digest = hashlib.sha256()
    offset = 0
    while True:
        if deadline_check is not None:
            deadline_check()
        try:
            chunk = os.pread(
                fd, min(64 * 1024, MAX_GH_EXECUTABLE_BYTES + 1 - offset), offset
            )
        except OSError:
            raise
        if deadline_check is not None:
            deadline_check()
        if not chunk:
            break
        offset += len(chunk)
        if offset > MAX_GH_EXECUTABLE_BYTES:
            raise ValueError("executable exceeds the byte ceiling")
        digest.update(chunk)
    return digest.hexdigest(), offset


def _file_content_generation(
    status_value: os.stat_result,
) -> tuple[int, int, int]:
    """Return signals that require refreshing a cached content receipt.

    Identity, size, and access policy are still validated independently.
    A generation change is not itself a policy violation: it only forces a
    bounded content reread so benign metadata churn can retain the receipt.
    """

    return (
        status_value.st_size,
        status_value.st_mtime_ns,
        status_value.st_ctime_ns,
    )


def _read_fd_payload_bounded(
    fd: int,
    *,
    label: str,
    limit: int,
    deadline_check: Callable[[], None] | None = None,
) -> bytes:
    chunks: list[bytes] = []
    offset = 0
    while True:
        if deadline_check is not None:
            deadline_check()
        try:
            chunk = os.pread(fd, min(64 * 1024, limit + 1 - offset), offset)
        except OSError as error:
            raise _blocked(
                "collector-unavailable",
                f"{label} could not be read safely",
            ) from error
        if deadline_check is not None:
            deadline_check()
        if not chunk:
            break
        chunks.append(chunk)
        offset += len(chunk)
        if offset > limit:
            raise _blocked(
                "collector-unavailable",
                f"{label} exceeds its byte ceiling",
            )
    return b"".join(chunks)


def _directory_status(status_value: os.stat_result) -> dict[str, int]:
    return {
        "device": status_value.st_dev,
        "gid": status_value.st_gid,
        "inode": status_value.st_ino,
        "mode": stat.S_IMODE(status_value.st_mode),
        "uid": status_value.st_uid,
    }


def _file_status(status_value: os.stat_result) -> dict[str, int]:
    return {
        "device": status_value.st_dev,
        "gid": status_value.st_gid,
        "inode": status_value.st_ino,
        "links": status_value.st_nlink,
        "mode": stat.S_IMODE(status_value.st_mode),
        "size": status_value.st_size,
        "uid": status_value.st_uid,
    }


def _fixed_curl_trust_binding(
    *,
    deadline_check: Callable[[], None] | None = None,
) -> tuple[dict[str, int], tuple[str, int, str]]:
    for directory in (
        pathlib.Path("/"),
        pathlib.Path("/usr"),
        CURL_EXECUTABLE.parent,
    ):
        _check_deadline(deadline_check)
        try:
            directory_status = os.lstat(directory)
        except OSError as error:
            raise _blocked(
                "collector-unavailable",
                "fixed curl trust-root directory is unavailable",
            ) from error
        if (
            stat.S_ISLNK(directory_status.st_mode)
            or not stat.S_ISDIR(directory_status.st_mode)
            or directory_status.st_uid != 0
            or stat.S_IMODE(directory_status.st_mode) & 0o022
        ):
            raise _blocked(
                "collector-unavailable",
                "fixed curl trust-root directory is replaceable",
            )

    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    descriptor: int | None = None
    try:
        _check_deadline(deadline_check)
        descriptor = os.open(CURL_EXECUTABLE, flags)
        descriptor_status = os.fstat(descriptor)
        path_status = os.lstat(CURL_EXECUTABLE)
        access_policy = _stable_fd_access_policy_binding(descriptor)
        _check_deadline(deadline_check)
    except EnforcementDoctorError:
        raise
    except OSError as error:
        raise _blocked(
            "collector-unavailable",
            "fixed curl transport is unavailable",
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if (
        not stat.S_ISREG(descriptor_status.st_mode)
        or not stat.S_ISREG(path_status.st_mode)
        or descriptor_status.st_uid != 0
        or stat.S_IMODE(descriptor_status.st_mode) & 0o022
        or stat.S_IMODE(descriptor_status.st_mode) & 0o111 == 0
        or _file_status(descriptor_status) != _file_status(path_status)
    ):
        raise _blocked(
            "collector-unavailable",
            "fixed curl transport identity or access policy is invalid",
        )
    return _file_status(descriptor_status), access_policy


def _object_identity(status_value: os.stat_result) -> tuple[int, int]:
    return (status_value.st_dev, status_value.st_ino)


def _binding_identity(binding: dict[str, int]) -> tuple[int, int]:
    return (binding["device"], binding["inode"])


def _verified_descriptor_path(fd: int) -> Optional[pathlib.Path]:
    candidate: Optional[str] = None
    try:
        if sys.platform == "darwin" and hasattr(fcntl, "F_GETPATH"):
            raw_path = fcntl.fcntl(fd, fcntl.F_GETPATH, b"\0" * 1024)
            candidate = os.fsdecode(raw_path.split(b"\0", 1)[0])
        elif sys.platform.startswith("linux"):
            candidate = os.readlink(f"/proc/self/fd/{fd}")
    except (OSError, ValueError):
        return None
    if candidate is None:
        return None
    path = pathlib.Path(candidate)
    if not path.is_absolute() or path == pathlib.Path("/"):
        return None
    try:
        descriptor = os.fstat(fd)
        path_status = os.stat(path, follow_symlinks=False)
    except OSError:
        return None
    if _object_identity(descriptor) != _object_identity(path_status) or stat.S_IFMT(
        descriptor.st_mode
    ) != stat.S_IFMT(path_status.st_mode):
        return None
    return path


class _DarwinAclRuntime:
    def __init__(self) -> None:
        self._libc = ctypes.CDLL(DARWIN_LIBSYSTEM_PATH, use_errno=True)
        self._libc.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
        self._libc.acl_get_fd_np.restype = ctypes.c_void_p
        self._libc.acl_get_entry.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._libc.acl_get_entry.restype = ctypes.c_int
        self._libc.acl_get_tag_type.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
        ]
        self._libc.acl_get_tag_type.restype = ctypes.c_int
        self._libc.acl_get_flagset_np.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._libc.acl_get_flagset_np.restype = ctypes.c_int
        self._libc.acl_get_flag_np.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self._libc.acl_get_flag_np.restype = ctypes.c_int
        self._libc.acl_size.argtypes = [ctypes.c_void_p]
        self._libc.acl_size.restype = ctypes.c_ssize_t
        self._libc.acl_copy_ext.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_ssize_t,
        ]
        self._libc.acl_copy_ext.restype = ctypes.c_ssize_t
        self._libc.acl_free.argtypes = [ctypes.c_void_p]
        self._libc.acl_free.restype = ctypes.c_int

    @staticmethod
    def _error(operation: str, *, fallback: int = errno.EIO) -> OSError:
        error_number = ctypes.get_errno() or fallback
        return OSError(error_number, f"Darwin ACL {operation} failed")

    def binding(self, fd: int) -> tuple[str, int, str]:
        ctypes.set_errno(0)
        acl = self._libc.acl_get_fd_np(fd, DARWIN_ACL_TYPE_EXTENDED)
        if not acl:
            error_number = ctypes.get_errno()
            if error_number == errno.ENOENT:
                return (
                    DARWIN_ACL_PROFILE,
                    0,
                    "no-extended-grants-or-inheritance",
                )
            raise self._error("descriptor query")
        try:
            ctypes.set_errno(0)
            external_size = self._libc.acl_size(acl)
            if external_size <= 0 or external_size > MAX_DARWIN_ACL_BYTES:
                raise OSError(
                    errno.EOVERFLOW,
                    "Darwin ACL external representation exceeds its byte ceiling",
                )
            external = ctypes.create_string_buffer(external_size)
            ctypes.set_errno(0)
            copied = self._libc.acl_copy_ext(external, acl, external_size)
            if copied != external_size:
                raise self._error("external copy")

            entry = ctypes.c_void_p()
            entry_id = DARWIN_ACL_FIRST_ENTRY
            entry_count = 0
            while True:
                ctypes.set_errno(0)
                result = self._libc.acl_get_entry(
                    acl,
                    entry_id,
                    ctypes.byref(entry),
                )
                if result != 0:
                    if ctypes.get_errno() == errno.EINVAL and entry_count > 0:
                        break
                    raise self._error("entry enumeration")
                entry_count += 1
                if entry_count > MAX_DARWIN_ACL_ENTRIES:
                    raise OSError(
                        errno.EOVERFLOW,
                        "Darwin ACL entry count exceeds its ceiling",
                    )

                tag = ctypes.c_int()
                ctypes.set_errno(0)
                if self._libc.acl_get_tag_type(entry, ctypes.byref(tag)) != 0:
                    raise self._error("entry tag query")
                if tag.value == DARWIN_ACL_EXTENDED_ALLOW:
                    # Owner mode already supplies every required owner right.
                    # Rejecting every extended allow is the bounded,
                    # directory-service-free superset of rejecting grants to
                    # another principal.
                    raise OSError(
                        errno.EACCES,
                        "Darwin extended ACL grants are not allowed",
                    )
                if tag.value != DARWIN_ACL_EXTENDED_DENY:
                    raise OSError(
                        errno.EINVAL,
                        "Darwin ACL contains an unsupported entry tag",
                    )

                flagset = ctypes.c_void_p()
                ctypes.set_errno(0)
                if (
                    self._libc.acl_get_flagset_np(
                        entry,
                        ctypes.byref(flagset),
                    )
                    != 0
                ):
                    raise self._error("entry flag-set query")
                for flag in DARWIN_ACL_INHERITANCE_FLAGS:
                    ctypes.set_errno(0)
                    present = self._libc.acl_get_flag_np(flagset, flag)
                    if present < 0:
                        raise self._error("entry inheritance query")
                    if present:
                        raise OSError(
                            errno.EACCES,
                            "Darwin inherited or inheritable ACL entries "
                            "are not allowed",
                        )
                entry_id = DARWIN_ACL_NEXT_ENTRY

            binding = (
                DARWIN_ACL_PROFILE,
                0,
                "no-extended-grants-or-inheritance",
            )
        except BaseException:
            self._libc.acl_free(acl)
            raise
        if self._libc.acl_free(acl) != 0:
            raise self._error("release")
        return binding


_DARWIN_ACL_RUNTIME: Optional[_DarwinAclRuntime] = None


def _fd_access_policy_binding(fd: int) -> tuple[str, int, str]:
    if sys.platform == "darwin":
        global _DARWIN_ACL_RUNTIME
        if _DARWIN_ACL_RUNTIME is None:
            try:
                _DARWIN_ACL_RUNTIME = _DarwinAclRuntime()
            except (AttributeError, OSError) as error:
                raise OSError(
                    errno.ENOTSUP,
                    "fixed Darwin descriptor ACL runtime is unavailable",
                ) from error
        return _DARWIN_ACL_RUNTIME.binding(fd)
    if sys.platform.startswith("linux"):
        # Linux POSIX access-ACL effective masks are reflected in the group
        # mode bits that the caller binds. Newly created private objects are
        # checked again after fchmod, so inherited defaults cannot silently
        # widen the effective group/other policy.
        return (LINUX_ACL_PROFILE, 0, "mode-bits-authoritative")
    raise OSError(
        errno.ENOTSUP,
        "descriptor ACL policy is unsupported on this platform",
    )


def _stable_fd_access_policy_binding(fd: int) -> tuple[str, int, str]:
    first = _fd_access_policy_binding(fd)
    second = _fd_access_policy_binding(fd)
    if first != second:
        raise OSError(
            errno.EAGAIN,
            "descriptor access policy changed while it was inspected",
        )
    return first


def _require_safe_directory_status(
    status_value: os.stat_result,
    *,
    label: str,
    owner_private: bool,
) -> None:
    mode = stat.S_IMODE(status_value.st_mode)
    if not stat.S_ISDIR(status_value.st_mode):
        raise _blocked("collector-unavailable", f"{label} must be a directory")
    if status_value.st_uid not in (0, os.geteuid()):
        raise _blocked(
            "collector-unavailable",
            f"{label} is owned by an untrusted principal",
        )
    if mode & 0o022:
        raise _blocked(
            "collector-unavailable",
            f"{label} can be renamed by an untrusted principal",
        )
    if owner_private and (status_value.st_uid != os.geteuid() or mode != 0o700):
        raise _blocked(
            "collector-unavailable",
            f"{label} must be owner-private",
        )


def _check_deadline(deadline_check: Callable[[], None] | None) -> None:
    if deadline_check is not None:
        deadline_check()


class _BoundDirectory:
    def __init__(
        self,
        path: pathlib.Path,
        *,
        label: str,
        create_final: bool = False,
        deadline_check: Callable[[], None] | None = None,
    ) -> None:
        self.path = path
        self.label = label
        self._fds: list[int] = []
        self._bindings: list[dict[str, int]] = []
        self._access_policy_bindings: list[tuple[str, int, str]] = []
        self._relations: list[tuple[int, str, int]] = []
        self._closed = False
        _check_deadline(deadline_check)
        if (
            not path.is_absolute()
            or path == pathlib.Path("/")
            or any(part in ("", ".", "..") for part in path.parts[1:])
        ):
            raise _blocked(
                "collector-unavailable",
                f"{label} must be a normalized absolute non-root path",
            )
        missing_flags = [
            name
            for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
            if not hasattr(os, name)
        ]
        if missing_flags:
            raise _blocked(
                "collector-unavailable",
                f"{label} safe directory flags are unavailable",
            )
        flags = (
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_NOFOLLOW
            | os.O_NONBLOCK
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            _check_deadline(deadline_check)
            root_fd = os.open("/", flags)
            self._fds.append(root_fd)
            root_status = os.fstat(root_fd)
            _check_deadline(deadline_check)
            _require_safe_directory_status(
                root_status,
                label=f"{label} root ancestor",
                owner_private=False,
            )
            self._bindings.append(_directory_status(root_status))
            self._access_policy_bindings.append(
                _stable_fd_access_policy_binding(root_fd)
            )
            _check_deadline(deadline_check)
            parent_fd = root_fd
            components = path.parts[1:]
            for index, component in enumerate(components):
                _check_deadline(deadline_check)
                is_final = index == len(components) - 1
                created = False
                try:
                    child_fd = os.open(component, flags, dir_fd=parent_fd)
                except FileNotFoundError:
                    if not (create_final and is_final):
                        raise
                    os.mkdir(component, 0o700, dir_fd=parent_fd)
                    created = True
                    child_fd = os.open(component, flags, dir_fd=parent_fd)
                self._fds.append(child_fd)
                child_descriptor = os.fstat(child_fd)
                child_path = os.stat(
                    component,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                if _directory_status(child_descriptor) != _directory_status(child_path):
                    raise _blocked(
                        "collector-unavailable",
                        f"{label} component identity is unstable",
                    )
                child_access_policy = _stable_fd_access_policy_binding(child_fd)
                _check_deadline(deadline_check)
                _require_safe_directory_status(
                    child_descriptor,
                    label=f"{label} component {component!r}",
                    owner_private=is_final and not created,
                )
                if created:
                    if (
                        not stat.S_ISDIR(child_descriptor.st_mode)
                        or child_descriptor.st_uid != os.geteuid()
                        or stat.S_IMODE(child_descriptor.st_mode) & 0o077
                    ):
                        raise _blocked(
                            "collector-unavailable",
                            f"{label} newly created component is not private",
                        )
                    os.fchmod(child_fd, 0o700)
                    _check_deadline(deadline_check)
                    child_descriptor = os.fstat(child_fd)
                    child_path = os.stat(
                        component,
                        dir_fd=parent_fd,
                        follow_symlinks=False,
                    )
                    if _directory_status(child_descriptor) != _directory_status(
                        child_path
                    ):
                        raise _blocked(
                            "collector-unavailable",
                            f"{label} created component identity changed",
                        )
                    _require_safe_directory_status(
                        child_descriptor,
                        label=f"{label} created component",
                        owner_private=True,
                    )
                    child_access_policy = _stable_fd_access_policy_binding(child_fd)
                    _check_deadline(deadline_check)
                binding = _directory_status(child_descriptor)
                self._bindings.append(binding)
                self._access_policy_bindings.append(child_access_policy)
                self._relations.append((parent_fd, component, child_fd))
                parent_fd = child_fd
            self.fd = self._fds[-1]
            self.revalidate(deadline_check=deadline_check)
        except EnforcementDoctorError:
            self.close()
            raise
        except OSError as error:
            self.close()
            raise _blocked(
                "collector-unavailable",
                f"{label} cannot be opened without following components",
            ) from error

    def revalidate(
        self,
        *,
        deadline_check: Callable[[], None] | None = None,
    ) -> None:
        _check_deadline(deadline_check)
        if self._closed or not self._fds:
            raise _blocked(
                "collector-inconclusive",
                f"{self.label} binding is unavailable",
            )
        try:
            for fd, expected, expected_access_policy in zip(
                self._fds,
                self._bindings,
                self._access_policy_bindings,
            ):
                _check_deadline(deadline_check)
                current = os.fstat(fd)
                if (
                    not stat.S_ISDIR(current.st_mode)
                    or _directory_status(current) != expected
                    or _stable_fd_access_policy_binding(fd) != expected_access_policy
                ):
                    raise self._inconclusive()
            for relation, expected in zip(self._relations, self._bindings[1:]):
                _check_deadline(deadline_check)
                parent_fd, component, child_fd = relation
                child_descriptor = os.fstat(child_fd)
                child_path = os.stat(
                    component,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                if (
                    _directory_status(child_descriptor) != expected
                    or _directory_status(child_path) != expected
                ):
                    raise self._inconclusive()
            _check_deadline(deadline_check)
        except EnforcementDoctorError:
            raise
        except OSError as error:
            raise self._inconclusive() from error

    def revalidate_identity(self) -> None:
        """Bind cleanup to the retained directory objects, not mutable policy."""
        if self._closed or not self._fds:
            raise _blocked(
                "collector-inconclusive",
                f"{self.label} binding is unavailable",
            )
        try:
            for fd, expected in zip(self._fds, self._bindings):
                current = os.fstat(fd)
                if not stat.S_ISDIR(current.st_mode) or _object_identity(
                    current
                ) != _binding_identity(expected):
                    raise self._inconclusive()
            for relation, expected in zip(self._relations, self._bindings[1:]):
                parent_fd, component, child_fd = relation
                child_descriptor = os.fstat(child_fd)
                child_path = os.stat(
                    component,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                expected_identity = _binding_identity(expected)
                if (
                    not stat.S_ISDIR(child_descriptor.st_mode)
                    or not stat.S_ISDIR(child_path.st_mode)
                    or _object_identity(child_descriptor) != expected_identity
                    or _object_identity(child_path) != expected_identity
                ):
                    raise self._inconclusive()
        except EnforcementDoctorError:
            raise
        except OSError as error:
            raise self._inconclusive() from error

    def _inconclusive(self) -> EnforcementDoctorError:
        return _blocked(
            "collector-inconclusive",
            f"{self.label} identity or access policy changed",
        )

    def set_owner_mode(
        self,
        mode: int,
        *,
        deadline_check: Callable[[], None] | None = None,
    ) -> None:
        if mode not in (0o500, 0o700):
            raise _blocked(
                "collector-unavailable",
                f"{self.label} requested an unsupported access policy",
            )
        self.revalidate(deadline_check=deadline_check)
        try:
            _check_deadline(deadline_check)
            os.fchmod(self.fd, mode)
            descriptor = os.fstat(self.fd)
            access_policy = _stable_fd_access_policy_binding(self.fd)
            _check_deadline(deadline_check)
            if (
                not stat.S_ISDIR(descriptor.st_mode)
                or descriptor.st_uid != os.geteuid()
                or stat.S_IMODE(descriptor.st_mode) != mode
            ):
                raise self._inconclusive()
            self._bindings[-1] = _directory_status(descriptor)
            self._access_policy_bindings[-1] = access_policy
            self.revalidate(deadline_check=deadline_check)
        except EnforcementDoctorError:
            raise
        except OSError as error:
            raise self._inconclusive() from error

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for fd in reversed(self._fds):
            try:
                os.close(fd)
            except OSError:
                pass
        self._fds = []


class _BoundRegularFile:
    def __init__(
        self,
        parent: _BoundDirectory,
        name: str,
        *,
        label: str,
        max_bytes: int,
        deadline_check: Callable[[], None] | None = None,
    ) -> None:
        self.parent = parent
        self.name = name
        self.label = label
        self.max_bytes = max_bytes
        self.fd: Optional[int] = None
        _check_deadline(deadline_check)
        if (
            not name
            or "/" in name
            or name in (".", "..")
            or not hasattr(os, "O_NOFOLLOW")
            or not hasattr(os, "O_NONBLOCK")
        ):
            raise _blocked(
                "collector-unavailable",
                f"{label} safe file binding is unavailable",
            )
        flags = (
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        )
        local_fd: Optional[int] = None
        try:
            parent.revalidate(deadline_check=deadline_check)
            _check_deadline(deadline_check)
            local_fd = os.open(name, flags, dir_fd=parent.fd)
            descriptor_before = os.fstat(local_fd)
            path_before = os.stat(
                name,
                dir_fd=parent.fd,
                follow_symlinks=False,
            )
            access_policy_before = _stable_fd_access_policy_binding(local_fd)
            _check_deadline(deadline_check)
            first = _read_fd_payload_bounded(
                local_fd,
                label=label,
                limit=max_bytes,
                deadline_check=deadline_check,
            )
            second = _read_fd_payload_bounded(
                local_fd,
                label=label,
                limit=max_bytes,
                deadline_check=deadline_check,
            )
            descriptor_after = os.fstat(local_fd)
            path_after = os.stat(
                name,
                dir_fd=parent.fd,
                follow_symlinks=False,
            )
            access_policy_after = _stable_fd_access_policy_binding(local_fd)
            _check_deadline(deadline_check)
            if (
                not stat.S_ISREG(descriptor_before.st_mode)
                or not stat.S_ISREG(path_before.st_mode)
                or not stat.S_ISREG(descriptor_after.st_mode)
                or not stat.S_ISREG(path_after.st_mode)
                or descriptor_before.st_uid != os.geteuid()
                or descriptor_before.st_nlink != 1
                or stat.S_IMODE(descriptor_before.st_mode) & 0o077
                or _file_status(descriptor_before) != _file_status(path_before)
                or _file_status(descriptor_before) != _file_status(descriptor_after)
                or _file_status(descriptor_before) != _file_status(path_after)
                or access_policy_before != access_policy_after
                or first != second
                or len(first) != descriptor_before.st_size
            ):
                raise _blocked(
                    "collector-unavailable",
                    f"{label} identity, access policy, or content is unsafe",
                )
            binding = _file_status(descriptor_before)
            _check_deadline(deadline_check)
            sha256 = hashlib.sha256(first).hexdigest()
            _check_deadline(deadline_check)
            parent.revalidate(deadline_check=deadline_check)
            self.payload = first
            self.binding = binding
            self.access_policy_binding = access_policy_before
            self.sha256 = sha256
            self.content_generation = _file_content_generation(descriptor_after)
            self.fd = local_fd
            local_fd = None
        except EnforcementDoctorError:
            raise
        except OSError as error:
            raise _blocked(
                "collector-unavailable",
                f"{label} cannot be opened safely",
            ) from error
        finally:
            if local_fd is not None:
                try:
                    os.close(local_fd)
                except OSError:
                    pass

    def revalidate(
        self,
        *,
        deadline_check: Callable[[], None] | None = None,
    ) -> None:
        if self.fd is None:
            raise self._inconclusive()
        if deadline_check is not None:
            deadline_check()
        self.parent.revalidate(deadline_check=deadline_check)
        try:
            descriptor_before = os.fstat(self.fd)
            path_before = os.stat(
                self.name,
                dir_fd=self.parent.fd,
                follow_symlinks=False,
            )
            access_policy_before = _stable_fd_access_policy_binding(self.fd)
            generation_before = _file_content_generation(descriptor_before)
            path_generation_before = _file_content_generation(path_before)
            first: bytes | None = None
            second: bytes | None = None
            if (
                generation_before != self.content_generation
                or path_generation_before != self.content_generation
            ):
                first = _read_fd_payload_bounded(
                    self.fd,
                    label=self.label,
                    limit=self.max_bytes,
                    deadline_check=deadline_check,
                )
                second = _read_fd_payload_bounded(
                    self.fd,
                    label=self.label,
                    limit=self.max_bytes,
                    deadline_check=deadline_check,
                )
            descriptor_after = os.fstat(self.fd)
            path_after = os.stat(
                self.name,
                dir_fd=self.parent.fd,
                follow_symlinks=False,
            )
            access_policy_after = _stable_fd_access_policy_binding(self.fd)
            generation_after = _file_content_generation(descriptor_after)
            path_generation_after = _file_content_generation(path_after)
        except EnforcementDoctorError as error:
            if error.reason_code == "api-timeout":
                raise
            raise self._inconclusive() from error
        except OSError as error:
            raise self._inconclusive() from error
        if (
            not stat.S_ISREG(descriptor_before.st_mode)
            or _file_status(descriptor_before) != self.binding
            or _file_status(path_before) != self.binding
            or _file_status(descriptor_after) != self.binding
            or _file_status(path_after) != self.binding
            or access_policy_before != self.access_policy_binding
            or access_policy_after != self.access_policy_binding
            or generation_before != path_generation_before
            or generation_after != path_generation_after
            or generation_before != generation_after
            or (first is None and generation_after != self.content_generation)
            or (
                first is not None
                and (
                    first != second or hashlib.sha256(first).hexdigest() != self.sha256
                )
            )
        ):
            raise self._inconclusive()
        if first is not None:
            self.content_generation = generation_after
        if deadline_check is not None:
            deadline_check()
        self.parent.revalidate(deadline_check=deadline_check)
        if deadline_check is not None:
            deadline_check()

    def _inconclusive(self) -> EnforcementDoctorError:
        return _blocked(
            "collector-inconclusive",
            f"{self.label} identity, access policy, or content changed",
        )

    def close(self) -> None:
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None


def _default_gh_runtime_parent(
    *,
    deadline_check: Callable[[], None] | None = None,
) -> pathlib.Path:
    _check_deadline(deadline_check)
    try:
        account = pwd.getpwuid(os.geteuid())
    except (KeyError, OSError) as error:
        raise _blocked(
            "collector-unavailable",
            "the effective account home directory is unavailable",
        ) from error
    _check_deadline(deadline_check)
    home = pathlib.Path(account.pw_dir)
    if not home.is_absolute() or home == pathlib.Path("/"):
        raise _blocked(
            "collector-unavailable",
            "the effective account home directory is unsafe",
        )
    return home.joinpath(*GH_RUNTIME_COMPONENTS)


def _validate_config_text(payload: bytes, *, label: str) -> str:
    try:
        decoded = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise _blocked(
            "collector-unavailable",
            f"{label} must be strict UTF-8",
        ) from error
    if "\r" in decoded:
        raise _blocked(
            "collector-unavailable",
            f"{label} must use canonical LF line endings",
        )
    for line in decoded.splitlines():
        if (
            "\x00" in line
            or "\t" in line
            or len(line.encode("utf-8")) > MAX_GH_CONFIG_LINE_BYTES
        ):
            raise _blocked(
                "collector-unavailable",
                f"{label} contains an unsafe line",
            )
    return decoded


def _validate_no_transport_redirects(payload: bytes) -> None:
    decoded = _validate_config_text(payload, label="GitHub CLI config.yml")
    for raw_line in decoded.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.fullmatch(
            r"(?:\"([A-Za-z0-9_.-]+)\"|'([A-Za-z0-9_.-]+)'|"
            r"([A-Za-z0-9_.-]+))\s*:\s*(.*)",
            stripped,
        )
        if match is None:
            continue
        key = next(value for value in match.groups()[:3] if value is not None).lower()
        if key not in GH_TRANSPORT_REDIRECT_KEYS:
            continue
        value = match.group(4).split(" #", 1)[0].strip()
        if value not in ("", "''", '""', "~", "null"):
            raise _blocked(
                "collector-unavailable",
                f"GitHub CLI transport redirect {key!r} is forbidden",
            )


def _minimal_github_hosts(payload: bytes) -> tuple[bytes, bytes | None]:
    decoded = _validate_config_text(payload, label="GitHub CLI hosts.yml")
    github_sections = 0
    in_github = False
    github_lines: list[tuple[int, str]] = []
    for raw_line in decoded.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if indent == 0:
            root = re.fullmatch(r"([A-Za-z0-9.-]+):", stripped)
            if root is None:
                raise _blocked(
                    "collector-unavailable",
                    "GitHub CLI hosts.yml has an unsupported root entry",
                )
            in_github = root.group(1) == AUTH_HOST
            if in_github:
                github_sections += 1
            continue
        if in_github:
            github_lines.append((indent, stripped))
    if github_sections != 1:
        raise _blocked(
            "collector-unavailable",
            "GitHub CLI hosts.yml must contain one exact github.com entry",
        )

    host_values: dict[str, str] = {}
    users: dict[str, Optional[str]] = {}
    current_section = ""
    current_user = ""
    saw_users = False
    for indent, stripped in github_lines:
        entry = re.fullmatch(r"([A-Za-z0-9_.-]+):(?: (.*))?", stripped)
        if entry is None:
            raise _blocked(
                "collector-unavailable",
                "GitHub CLI github.com config is not a simple mapping",
            )
        key = entry.group(1)
        value = entry.group(2) or ""
        if indent == 4:
            current_user = ""
            if key == "users":
                if value:
                    raise _blocked(
                        "collector-unavailable",
                        "GitHub CLI users entry must be a mapping",
                    )
                if saw_users:
                    raise _blocked(
                        "collector-unavailable",
                        "GitHub CLI users entry is duplicated",
                    )
                saw_users = True
                current_section = "users"
                continue
            current_section = ""
            if key not in ("git_protocol", "oauth_token", "user"):
                raise _blocked(
                    "collector-unavailable",
                    f"GitHub CLI github.com key {key!r} is not admitted",
                )
            if key in host_values or not value:
                raise _blocked(
                    "collector-unavailable",
                    f"GitHub CLI github.com key {key!r} is invalid",
                )
            host_values[key] = value
            continue
        if indent == 8 and current_section == "users":
            if value or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", key):
                raise _blocked(
                    "collector-unavailable",
                    "GitHub CLI user entry is invalid",
                )
            if key in users:
                raise _blocked(
                    "collector-unavailable",
                    "GitHub CLI user entry is duplicated",
                )
            users[key] = None
            current_user = key
            continue
        if (
            indent == 12
            and current_section == "users"
            and current_user
            and key == "oauth_token"
            and value
            and users[current_user] is None
        ):
            users[current_user] = value
            continue
        raise _blocked(
            "collector-unavailable",
            "GitHub CLI github.com config has an unsupported shape",
        )

    active_user = host_values.get("user", "")
    if re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", active_user) is None:
        raise _blocked(
            "collector-unavailable",
            "GitHub CLI active github.com user is invalid",
        )
    protocol = host_values.get("git_protocol", "https")
    if protocol not in ("https", "ssh"):
        raise _blocked(
            "collector-unavailable",
            "GitHub CLI github.com git protocol is invalid",
        )
    root_token = host_values.get("oauth_token")
    nested_token = users.get(active_user)
    if active_user not in users and root_token is None:
        raise _blocked(
            "collector-unavailable",
            "GitHub CLI active github.com user has no bounded authentication slot",
        )
    if (
        root_token is not None
        and nested_token is not None
        and root_token != nested_token
    ):
        raise _blocked(
            "collector-unavailable",
            "GitHub CLI active github.com token slots disagree",
        )
    active_token = root_token or nested_token
    if (
        active_token is not None
        and re.fullmatch(
            r"[A-Za-z0-9_.-]{1,2048}",
            active_token,
        )
        is None
    ):
        raise _blocked(
            "collector-unavailable",
            "GitHub CLI active github.com token is not a safe scalar",
        )
    output = [
        f"{AUTH_HOST}:\n",
        f"    git_protocol: {protocol}\n",
        "    users:\n",
        f"        {active_user}:\n",
    ]
    if active_token is not None:
        output.append(f"            oauth_token: {active_token}\n")
    output.append(f"    user: {active_user}\n")
    if active_token is not None:
        output.append(f"    oauth_token: {active_token}\n")
    return (
        "".join(output).encode("utf-8"),
        None if active_token is None else active_token.encode("ascii"),
    )


def _create_private_child_directory(
    parent: _BoundDirectory,
    name: str,
    *,
    label: str,
    deadline_check: Callable[[], None] | None = None,
) -> _BoundDirectory:
    _check_deadline(deadline_check)
    if (
        not name
        or "/" in name
        or name in (".", "..")
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_NONBLOCK")
    ):
        raise _blocked(
            "collector-unavailable",
            f"{label} component is invalid",
        )
    parent.revalidate(deadline_check=deadline_check)
    try:
        _check_deadline(deadline_check)
        os.mkdir(name, 0o700, dir_fd=parent.fd)
        flags = (
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_NOFOLLOW
            | os.O_NONBLOCK
            | getattr(os, "O_CLOEXEC", 0)
        )
        child_fd = os.open(name, flags, dir_fd=parent.fd)
        try:
            _check_deadline(deadline_check)
            descriptor = os.fstat(child_fd)
            path_status = os.stat(
                name,
                dir_fd=parent.fd,
                follow_symlinks=False,
            )
            initial_access_policy = _stable_fd_access_policy_binding(child_fd)
            _check_deadline(deadline_check)
            if (
                not stat.S_ISDIR(descriptor.st_mode)
                or descriptor.st_uid != os.geteuid()
                or stat.S_IMODE(descriptor.st_mode) & 0o077
                or _directory_status(descriptor) != _directory_status(path_status)
                or initial_access_policy != _stable_fd_access_policy_binding(child_fd)
            ):
                raise _blocked(
                    "collector-unavailable",
                    f"{label} initial object is unsafe",
                )
            os.fchmod(child_fd, 0o700)
            _check_deadline(deadline_check)
            descriptor = os.fstat(child_fd)
            path_status = os.stat(
                name,
                dir_fd=parent.fd,
                follow_symlinks=False,
            )
            final_access_policy = _stable_fd_access_policy_binding(child_fd)
            _check_deadline(deadline_check)
            if (
                _directory_status(descriptor) != _directory_status(path_status)
                or stat.S_IMODE(descriptor.st_mode) != 0o700
                or final_access_policy != initial_access_policy
            ):
                raise _blocked(
                    "collector-unavailable",
                    f"{label} access policy could not be fixed",
                )
        finally:
            os.close(child_fd)
    except FileExistsError as error:
        raise _blocked(
            "collector-unavailable",
            f"{label} already exists",
        ) from error
    except EnforcementDoctorError:
        raise
    except OSError as error:
        raise _blocked(
            "collector-unavailable",
            f"{label} could not be created safely",
        ) from error
    parent.revalidate(deadline_check=deadline_check)
    try:
        return _BoundDirectory(
            parent.path / name,
            label=label,
            deadline_check=deadline_check,
        )
    except BaseException:
        try:
            os.rmdir(name, dir_fd=parent.fd)
        except OSError:
            pass
        raise


def _create_private_regular_file(
    parent: _BoundDirectory,
    name: str,
    payload: bytes,
    *,
    cleanup_anchors: list[dict[str, Any]],
    label: str,
    mode: int,
    max_bytes: int,
    deadline_check: Callable[[], None] | None = None,
) -> _BoundRegularFile:
    _check_deadline(deadline_check)
    if len(payload) > max_bytes:
        raise _blocked(
            "collector-unavailable",
            f"{label} exceeds its byte ceiling",
        )
    parent.revalidate(deadline_check=deadline_check)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW
        | os.O_NONBLOCK
        | getattr(os, "O_CLOEXEC", 0)
    )
    fd: Optional[int] = None
    cleanup_anchor: Optional[dict[str, Any]] = None
    cleanup_anchor_registered = False
    try:
        _check_deadline(deadline_check)
        fd = os.open(name, flags, mode, dir_fd=parent.fd)
        cleanup_anchor = {
            "fd": fd,
            "label": label,
            "last_known_path": parent.path / name,
        }
        cleanup_anchors.append(cleanup_anchor)
        cleanup_anchor_registered = True
        descriptor = os.fstat(fd)
        path_status = os.stat(
            name,
            dir_fd=parent.fd,
            follow_symlinks=False,
        )
        initial_access_policy = _stable_fd_access_policy_binding(fd)
        _check_deadline(deadline_check)
        if (
            not stat.S_ISREG(descriptor.st_mode)
            or descriptor.st_uid != os.geteuid()
            or descriptor.st_nlink != 1
            or stat.S_IMODE(descriptor.st_mode) & 0o077
            or _file_status(descriptor) != _file_status(path_status)
        ):
            raise _blocked(
                "collector-unavailable",
                f"{label} initial object is unsafe",
            )
        _write_all(fd, payload, deadline_check=deadline_check)
        _check_deadline(deadline_check)
        os.fchmod(fd, mode)
        _check_deadline(deadline_check)
        os.fsync(fd)
        _check_deadline(deadline_check)
        descriptor = os.fstat(fd)
        path_status = os.stat(
            name,
            dir_fd=parent.fd,
            follow_symlinks=False,
        )
        final_access_policy = _stable_fd_access_policy_binding(fd)
        _check_deadline(deadline_check)
        if (
            _file_status(descriptor) != _file_status(path_status)
            or descriptor.st_size != len(payload)
            or stat.S_IMODE(descriptor.st_mode) != mode
            or final_access_policy != initial_access_policy
        ):
            raise _blocked(
                "collector-unavailable",
                f"{label} could not be bound after creation",
            )
        parent.revalidate(deadline_check=deadline_check)
        bound_file = _BoundRegularFile(
            parent,
            name,
            label=label,
            max_bytes=max_bytes,
            deadline_check=deadline_check,
        )
        cleanup_anchors.remove(cleanup_anchor)
        cleanup_anchor_registered = False
        return bound_file
    except EnforcementDoctorError:
        raise
    except OSError as error:
        raise _blocked(
            "collector-unavailable",
            f"{label} could not be created safely",
        ) from error
    finally:
        if fd is not None and not cleanup_anchor_registered:
            try:
                os.close(fd)
            except OSError:
                pass


def _write_all(
    fd: int,
    payload: bytes,
    *,
    deadline_check: Callable[[], None] | None = None,
) -> None:
    offset = 0
    while offset < len(payload):
        _check_deadline(deadline_check)
        written = os.write(fd, payload[offset:])
        _check_deadline(deadline_check)
        if written <= 0:
            raise OSError("short write while pinning executable")
        offset += written


def _bounded_subprocess_supervised(
    command: list[str],
    *,
    environment: dict[str, str],
    execution_cwd: str,
    endpoint_class: str,
    process_registry: dict[int, _ManagedProcess],
    process_registered: Callable[[_ManagedProcess], None],
    timeout_seconds: float,
    stdout_limit: int,
    stderr_limit: int,
    absolute_deadline: float | None = None,
) -> tuple[int, bytes, bytes]:
    if os.name == "posix":
        try:
            sigchld_is_default = signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL
        except (OSError, ValueError):
            sigchld_is_default = False
        if not sigchld_is_default or threading.active_count() != 1:
            raise _blocked(
                "collector-unavailable",
                "exclusive GitHub collector child supervision is unavailable",
                api_failure=_api_failure(
                    endpoint_class,
                    http_status=None,
                    failure_kind="process-supervision",
                ),
            )
    if absolute_deadline is not None and absolute_deadline - time.monotonic() <= 0:
        raise _blocked(
            "api-timeout",
            "GitHub evidence collection exceeded its total deadline",
            api_failure=_api_failure(
                endpoint_class,
                http_status=None,
                failure_kind="timeout",
            ),
        )
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=(os.name == "posix"),
            close_fds=True,
            cwd=execution_cwd,
            env=environment,
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
    managed = _ManagedProcess(process)
    selector: Optional[selectors.BaseSelector] = None
    try:
        if process.pid in process_registry:
            raise OSError("collector process identity is already registered")
        process_registry[process.pid] = managed
        process_registered(managed)
        chunks: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
        retained: dict[str, int] = {"stdout": 0, "stderr": 0}
        deadline = time.monotonic() + timeout_seconds
        if absolute_deadline is not None:
            deadline = min(deadline, absolute_deadline)
        if process.stdout is None or process.stderr is None:
            raise OSError("collector pipes are unavailable")
        selector = selectors.DefaultSelector()
        selector.register(
            process.stdout,
            selectors.EVENT_READ,
            ("stdout", stdout_limit),
        )
        selector.register(
            process.stderr,
            selectors.EVENT_READ,
            ("stderr", stderr_limit),
        )
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
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
        group_failures = _seal_process_group_before_reap(managed)
        if group_failures:
            raise _blocked(
                "collector-inconclusive",
                "GitHub API collector process group cleanup could not be proven",
                api_failure=_api_failure(
                    endpoint_class,
                    http_status=None,
                    failure_kind="process-cleanup",
                ),
            )
        try:
            return_code = process.wait(
                timeout=max(0.001, deadline - time.monotonic()),
            )
            managed.mark_reaped()
        except subprocess.TimeoutExpired as error:
            raise _blocked(
                "api-timeout",
                "GitHub API collector command exceeded its deadline",
                api_failure=_api_failure(
                    endpoint_class,
                    http_status=None,
                    failure_kind="timeout",
                ),
            ) from error
    except BaseException as error:
        cleanup_failures = _terminate_drain_reap(managed)
        resource_failures = _close_process_resources(
            selector,
            managed,
            close_streams=not cleanup_failures,
        )
        if cleanup_failures:
            raise _blocked(
                "collector-inconclusive",
                "GitHub API collector process cleanup could not be proven",
                api_failure=_api_failure(
                    endpoint_class,
                    http_status=None,
                    failure_kind="process-cleanup",
                ),
            ) from error
        if process_registry.get(process.pid) is managed:
            process_registry.pop(process.pid)
        if resource_failures:
            raise _blocked(
                "collector-inconclusive",
                "GitHub API collector resources could not be closed safely",
                api_failure=_api_failure(
                    endpoint_class,
                    http_status=None,
                    failure_kind="process-resource",
                ),
            ) from error
        if isinstance(error, EnforcementDoctorError):
            raise
        if not isinstance(error, Exception):
            raise
        raise _blocked(
            "collector-inconclusive",
            "GitHub API collector I/O could not be supervised safely",
            api_failure=_api_failure(
                endpoint_class,
                http_status=None,
                failure_kind="process-io",
            ),
        ) from error
    if process_registry.get(process.pid) is managed:
        process_registry.pop(process.pid)
    resource_failures = _close_process_resources(selector, managed)
    if resource_failures:
        raise _blocked(
            "collector-inconclusive",
            "GitHub API collector resources could not be closed safely",
            api_failure=_api_failure(
                endpoint_class,
                http_status=None,
                failure_kind="process-resource",
            ),
        )
    return return_code, b"".join(chunks["stdout"]), b"".join(chunks["stderr"])


def _process_supervision_error(
    endpoint_class: str,
    reason: str,
    *,
    unavailable: bool,
) -> EnforcementDoctorError:
    return _blocked(
        "collector-unavailable" if unavailable else "collector-inconclusive",
        reason,
        api_failure=_api_failure(
            endpoint_class,
            http_status=None,
            failure_kind="process-supervision",
        ),
    )


def _forward_deferred_termination_signal(
    signal_number: int,
    secondary_error: BaseException | None,
) -> None:
    try:
        os.kill(os.getpid(), signal_number)
    except BaseException as signal_error:
        if secondary_error is not None:
            raise signal_error from secondary_error
        raise
    deferred = _DeferredTerminationSignal(signal_number)
    if secondary_error is not None:
        raise deferred from secondary_error
    raise deferred


def _bounded_subprocess(
    command: list[str],
    *,
    environment: dict[str, str],
    execution_cwd: str,
    endpoint_class: str,
    process_registry: dict[int, _ManagedProcess],
    timeout_seconds: float,
    stdout_limit: int,
    stderr_limit: int,
    termination_cleanup: Callable[[], None] | None = None,
    lifecycle_signal_guard: _TerminationSignalGuard | None = None,
    absolute_deadline: float | None = None,
) -> tuple[int, bytes, bytes]:
    owns_signal_guard = lifecycle_signal_guard is None
    signal_guard = lifecycle_signal_guard or _TerminationSignalGuard()
    if owns_signal_guard:
        try:
            signal_guard.start()
        except Exception as error:
            raise _process_supervision_error(
                endpoint_class,
                "GitHub API collector termination-signal supervision is unavailable",
                unavailable=True,
            ) from error
    else:
        try:
            signal_guard.prepare_publication()
        except _DeferredTerminationSignal:
            if termination_cleanup is not None:
                termination_cleanup()
            raise
        except Exception as error:
            cleanup_error: BaseException | None = None
            if termination_cleanup is not None:
                try:
                    termination_cleanup()
                except BaseException as cleanup_failure:
                    cleanup_error = cleanup_failure
            supervision_error = _process_supervision_error(
                endpoint_class,
                "GitHub API collector termination-signal publication is unavailable",
                unavailable=False,
            )
            if cleanup_error is not None:
                raise supervision_error from cleanup_error
            raise _process_supervision_error(
                endpoint_class,
                "GitHub API collector termination-signal publication is unavailable",
                unavailable=False,
            ) from error

    process_result: tuple[int, bytes, bytes] | None = None
    primary_error: BaseException | None = None
    try:
        try:
            process_result = _bounded_subprocess_supervised(
                command,
                environment=environment,
                execution_cwd=execution_cwd,
                endpoint_class=endpoint_class,
                process_registry=process_registry,
                process_registered=signal_guard.publish,
                timeout_seconds=timeout_seconds,
                stdout_limit=stdout_limit,
                stderr_limit=stderr_limit,
                absolute_deadline=absolute_deadline,
            )
        except BaseException as error:
            primary_error = error
        finally:
            if owns_signal_guard:
                signal_guard.begin_cleanup()
            elif signal_guard.state == "blocked":
                try:
                    signal_guard.activate()
                except BaseException as error:
                    if primary_error is None or isinstance(
                        error, _DeferredTerminationSignal
                    ):
                        primary_error = error
    except BaseException as error:
        if primary_error is None:
            primary_error = error

    deferred_signal = signal_guard.deferred_signal
    credential_cleanup_error: BaseException | None = None
    if deferred_signal is not None and termination_cleanup is not None:
        if not owns_signal_guard:
            termination_cleanup()
        else:
            try:
                termination_cleanup()
            except BaseException as error:
                credential_cleanup_error = error
    if not owns_signal_guard:
        if deferred_signal is not None:
            deferred = _DeferredTerminationSignal(deferred_signal)
            secondary_error = credential_cleanup_error or (
                primary_error
                if not isinstance(primary_error, _DeferredTerminationSignal)
                else None
            )
            if secondary_error is not None:
                raise deferred from secondary_error
            raise deferred
        if signal_guard.errors:
            supervision_error = _process_supervision_error(
                endpoint_class,
                "GitHub API collector termination-signal state is inconclusive",
                unavailable=False,
            )
            if primary_error is not None:
                raise supervision_error from primary_error
            raise supervision_error
        if primary_error is not None:
            raise primary_error
        assert process_result is not None
        return process_result

    signal_guard.finish()

    supervision_error = None
    if signal_guard.errors:
        supervision_error = _process_supervision_error(
            endpoint_class,
            "GitHub API collector termination-signal state could not be restored",
            unavailable=False,
        )
    if deferred_signal is not None:
        secondary_error = (
            credential_cleanup_error
            or supervision_error
            or (
                primary_error
                if not isinstance(primary_error, _DeferredTerminationSignal)
                else None
            )
        )
        if supervision_error is not None:
            deferred = _DeferredTerminationSignal(deferred_signal)
            if secondary_error is not None:
                raise deferred from secondary_error
            raise deferred
        _forward_deferred_termination_signal(
            deferred_signal,
            secondary_error,
        )
    if supervision_error is not None:
        if primary_error is not None:
            raise supervision_error from primary_error
        raise supervision_error
    if primary_error is not None:
        raise primary_error
    assert process_result is not None
    return process_result


class GitHubApiClient:
    def __init__(
        self,
        gh_executable: pathlib.Path,
        expected_gh_sha256: str,
        gh_config_dir: pathlib.Path,
        *,
        runtime_parent: Optional[pathlib.Path] = None,
    ) -> None:
        self._runtime_parent: Optional[_BoundDirectory] = None
        self._run_directory: Optional[_BoundDirectory] = None
        self._executable_snapshot_directory: Optional[_BoundDirectory] = None
        self._config_snapshot_directory: Optional[_BoundDirectory] = None
        self._transport_directory: Optional[_BoundDirectory] = None
        self._source_config_directory: Optional[_BoundDirectory] = None
        self._source_hosts_file: Optional[_BoundRegularFile] = None
        self._source_global_config_file: Optional[_BoundRegularFile] = None
        self._snapshot_hosts_file: Optional[_BoundRegularFile] = None
        self._snapshot_global_config_file: Optional[_BoundRegularFile] = None
        self._snapshot_auth_header_file: Optional[_BoundRegularFile] = None
        self._provisional_cleanup_objects: list[dict[str, Any]] = []
        self._active_processes: dict[int, _ManagedProcess] = {}
        self._source_fd: Optional[int] = None
        self._snapshot_fd: Optional[int] = None
        self._source_access_policy_binding: Optional[tuple[str, int, str]] = None
        self._snapshot_access_policy_binding: Optional[tuple[str, int, str]] = None
        self._source_content_generation: Optional[tuple[int, int, int]] = None
        self._snapshot_content_generation: Optional[tuple[int, int, int]] = None
        self._termination_signal_guard = _TerminationSignalGuard()
        self._termination_transaction_finished = False
        self._termination_transaction_finishing = False
        self._closed = False
        self._collector_inconclusive_reported = False
        self._pinned = False
        self._run_name = ""
        self._execution_cwd = ""
        self.executable = ""
        self.executable_sha256 = expected_gh_sha256
        self.execution_source = GH_EXECUTION_SOURCE
        self.environment_profile = GH_EXECUTABLE_ENVIRONMENT_PROFILE
        self.transport_executable = os.fspath(CURL_EXECUTABLE)
        self.transport_profile = "fixed-curl-no-redirect-v1"
        if SHA256_PATTERN.fullmatch(expected_gh_sha256) is None or set(
            expected_gh_sha256
        ) == {"0"}:
            raise _blocked(
                "collector-unavailable",
                "expected GitHub CLI SHA-256 is invalid",
            )
        try:
            self._termination_signal_guard.start()
        except Exception as error:
            raise _process_supervision_error(
                "authentication-preflight",
                "GitHub client termination-signal supervision is unavailable",
                unavailable=True,
            ) from error
        try:
            self.deadline = time.monotonic() + MAX_COLLECTION_SECONDS
            initialization_check = self._check_initialization_deadline
            initialization_check()
            selected_runtime_parent = runtime_parent or _default_gh_runtime_parent(
                deadline_check=initialization_check,
            )
            self._runtime_parent = _BoundDirectory(
                selected_runtime_parent,
                label="GitHub CLI fixed runtime parent",
                create_final=True,
                deadline_check=initialization_check,
            )
            self._create_run_directory(deadline_check=initialization_check)
            if self._run_directory is None:
                raise _blocked(
                    "collector-unavailable",
                    "GitHub CLI private run directory is unavailable",
                )
            self._transport_directory = _create_private_child_directory(
                self._run_directory,
                "transport",
                label="GitHub API private transport directory",
                deadline_check=initialization_check,
            )
            self._snapshot_configuration(
                gh_config_dir,
                deadline_check=initialization_check,
            )
            if self._run_directory is None:
                raise _blocked(
                    "collector-unavailable",
                    "GitHub CLI private run directory is unavailable",
                )
            self._executable_snapshot_directory = _create_private_child_directory(
                self._run_directory,
                "bin",
                label="GitHub CLI private executable snapshot directory",
                deadline_check=initialization_check,
            )
            self._pin_executable(
                gh_executable,
                expected_gh_sha256,
                deadline_check=initialization_check,
            )
            initialization_check()
            self._curl_trust_binding = _fixed_curl_trust_binding(
                deadline_check=initialization_check,
            )
            initialization_check()
            self._config_snapshot_directory.set_owner_mode(
                0o500,
                deadline_check=initialization_check,
            )
            self._executable_snapshot_directory.set_owner_mode(
                0o500,
                deadline_check=initialization_check,
            )
            if self._snapshot_auth_header_file is not None:
                self._transport_directory.set_owner_mode(
                    0o500,
                    deadline_check=initialization_check,
                )
            self._revalidate_snapshot(
                absolute_deadline=self.deadline,
                endpoint_class="collector-initialization",
            )
            self.calls = 0
            self.total_bytes = 0
            initialization_check()
            self._termination_signal_guard.check_deferred()
        except BaseException as initialization_error:
            cleanup_error = self._cleanup_noexcept()
            if cleanup_error is not None:
                raise cleanup_error from initialization_error
            raise

    def _check_initialization_deadline(self) -> None:
        self._require_deadline_remaining(
            self.deadline,
            "collector-initialization",
        )
        self._termination_signal_guard.check_deferred()

    def _create_run_directory(
        self,
        *,
        deadline_check: Callable[[], None] | None = None,
    ) -> None:
        if self._runtime_parent is None:
            raise _blocked(
                "collector-unavailable",
                "GitHub CLI fixed runtime parent is unavailable",
            )
        for _ in range(64):
            _check_deadline(deadline_check)
            run_name = f"run-{os.getpid()}-{secrets.token_hex(16)}"
            try:
                run_directory = _create_private_child_directory(
                    self._runtime_parent,
                    run_name,
                    label="GitHub CLI private run directory",
                    deadline_check=deadline_check,
                )
            except EnforcementDoctorError as error:
                if (
                    error.reason_code == "collector-unavailable"
                    and str(error) == "GitHub CLI private run directory already exists"
                ):
                    continue
                raise
            self._run_name = run_name
            self._run_directory = run_directory
            self._execution_cwd = os.fspath(run_directory.path)
            return
        raise _blocked(
            "collector-unavailable",
            "GitHub CLI private run name collision limit was reached",
        )

    def _snapshot_configuration(
        self,
        gh_config_dir: pathlib.Path,
        *,
        deadline_check: Callable[[], None] | None = None,
    ) -> None:
        _check_deadline(deadline_check)
        if not gh_config_dir.is_absolute():
            raise _blocked(
                "collector-unavailable",
                "GitHub CLI config directory must be an absolute path",
            )
        self._source_config_directory = _BoundDirectory(
            gh_config_dir,
            label="GitHub CLI source config directory",
            deadline_check=deadline_check,
        )
        self._source_hosts_file = _BoundRegularFile(
            self._source_config_directory,
            "hosts.yml",
            label="GitHub CLI source hosts.yml",
            max_bytes=MAX_GH_CONFIG_BYTES,
            deadline_check=deadline_check,
        )
        try:
            _check_deadline(deadline_check)
            os.stat(
                "config.yml",
                dir_fd=self._source_config_directory.fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            self._source_global_config_file = None
        except OSError as error:
            raise _blocked(
                "collector-unavailable",
                "GitHub CLI source config.yml cannot be inspected safely",
            ) from error
        else:
            self._source_global_config_file = _BoundRegularFile(
                self._source_config_directory,
                "config.yml",
                label="GitHub CLI source config.yml",
                max_bytes=MAX_GH_CONFIG_BYTES,
                deadline_check=deadline_check,
            )
            _check_deadline(deadline_check)
            _validate_no_transport_redirects(self._source_global_config_file.payload)
            _check_deadline(deadline_check)
        _check_deadline(deadline_check)
        minimal_hosts, configured_token = _minimal_github_hosts(
            self._source_hosts_file.payload
        )
        _check_deadline(deadline_check)
        self._source_hosts_file.payload = b""
        if self._source_global_config_file is not None:
            self._source_global_config_file.payload = b""
        if self._run_directory is None:
            raise _blocked(
                "collector-unavailable",
                "GitHub CLI private run directory is unavailable",
            )
        self._config_snapshot_directory = _create_private_child_directory(
            self._run_directory,
            "config",
            label="GitHub CLI private config snapshot directory",
            deadline_check=deadline_check,
        )
        self._snapshot_hosts_file = _create_private_regular_file(
            self._config_snapshot_directory,
            "hosts.yml",
            minimal_hosts,
            cleanup_anchors=self._provisional_cleanup_objects,
            label="GitHub CLI private hosts.yml snapshot",
            mode=0o400,
            max_bytes=MAX_GH_CONFIG_BYTES,
            deadline_check=deadline_check,
        )
        self._snapshot_global_config_file = _create_private_regular_file(
            self._config_snapshot_directory,
            "config.yml",
            GH_SNAPSHOT_CONFIG,
            cleanup_anchors=self._provisional_cleanup_objects,
            label="GitHub CLI private config.yml snapshot",
            mode=0o400,
            max_bytes=MAX_GH_CONFIG_BYTES,
            deadline_check=deadline_check,
        )
        self._snapshot_hosts_file.payload = b""
        self._snapshot_global_config_file.payload = b""
        if configured_token is not None:
            if self._transport_directory is None:
                raise _blocked(
                    "collector-unavailable",
                    "GitHub API private transport directory is unavailable",
                )
            self._snapshot_auth_header_file = _create_private_regular_file(
                self._transport_directory,
                "authorization.headers",
                b"Authorization: Bearer " + configured_token + b"\n",
                cleanup_anchors=self._provisional_cleanup_objects,
                label="GitHub API private authorization header",
                mode=0o400,
                max_bytes=MAX_GH_CONFIG_BYTES,
                deadline_check=deadline_check,
            )
            self._snapshot_auth_header_file.payload = b""
        self.config_snapshot_sha256 = hashlib.sha256(
            b"hosts.yml\0" + minimal_hosts + b"\0config.yml\0" + GH_SNAPSHOT_CONFIG
        ).hexdigest()
        _check_deadline(deadline_check)
        # Authentication is deliberately limited to the controlled minimal
        # snapshot. No ambient HOME, TMPDIR, token, loader, proxy, CA, PATH, or
        # other GH_* variables are inherited by the collector subprocess.
        self._environment = {
            "GH_CONFIG_DIR": os.fspath(self._config_snapshot_directory.path),
            "GH_NO_UPDATE_NOTIFIER": "1",
            "GH_PROMPT_DISABLED": "1",
            "LC_ALL": "C",
        }

    @staticmethod
    def _initial_source_status(
        gh_executable: pathlib.Path,
        *,
        deadline_check: Callable[[], None] | None = None,
    ) -> tuple[int, os.stat_result, tuple[str, int, str]]:
        _check_deadline(deadline_check)
        if not gh_executable.is_absolute():
            raise _blocked(
                "collector-unavailable",
                "GitHub CLI executable must be an absolute path",
            )
        if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_NONBLOCK"):
            raise _blocked(
                "collector-unavailable",
                "safe GitHub CLI executable pinning is unavailable",
            )
        try:
            path_status = os.lstat(gh_executable)
        except OSError as error:
            raise _blocked(
                "collector-unavailable",
                "GitHub CLI executable is unavailable",
            ) from error
        _check_deadline(deadline_check)
        if stat.S_ISLNK(path_status.st_mode) or not stat.S_ISREG(path_status.st_mode):
            raise _blocked(
                "collector-unavailable",
                "GitHub CLI executable must be a real regular file",
            )
        flags = (
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            source_fd = os.open(gh_executable, flags)
        except OSError as error:
            raise _blocked(
                "collector-unavailable",
                "GitHub CLI executable cannot be safely opened",
            ) from error
        try:
            _check_deadline(deadline_check)
            descriptor_status = os.fstat(source_fd)
        except OSError as error:
            os.close(source_fd)
            raise _blocked(
                "collector-unavailable",
                "GitHub CLI executable cannot be inspected",
            ) from error
        if (
            not stat.S_ISREG(descriptor_status.st_mode)
            or (descriptor_status.st_dev, descriptor_status.st_ino)
            != (path_status.st_dev, path_status.st_ino)
            or descriptor_status.st_size <= 0
            or descriptor_status.st_size > MAX_GH_EXECUTABLE_BYTES
            or stat.S_IMODE(descriptor_status.st_mode) & 0o111 == 0
        ):
            os.close(source_fd)
            raise _blocked(
                "collector-unavailable",
                "GitHub CLI executable identity, size, or execute policy is invalid",
            )
        try:
            access_policy = _stable_fd_access_policy_binding(source_fd)
        except OSError as error:
            os.close(source_fd)
            raise _blocked(
                "collector-unavailable",
                "GitHub CLI executable ACL policy is unsafe",
            ) from error
        _check_deadline(deadline_check)
        return source_fd, descriptor_status, access_policy

    def _pin_executable(
        self,
        gh_executable: pathlib.Path,
        expected_gh_sha256: str,
        *,
        deadline_check: Callable[[], None] | None = None,
    ) -> None:
        _check_deadline(deadline_check)
        if self._executable_snapshot_directory is None:
            raise _blocked(
                "collector-unavailable",
                "GitHub CLI private executable snapshot directory is unavailable",
            )
        source_fd: Optional[int]
        source_fd, source_before, source_access_policy_before = (
            self._initial_source_status(
                gh_executable,
                deadline_check=deadline_check,
            )
        )
        snapshot_write_fd: Optional[int] = None
        snapshot_cleanup_anchor: Optional[dict[str, Any]] = None
        snapshot_cleanup_anchor_registered = False
        try:
            self._executable_snapshot_directory.revalidate(
                deadline_check=deadline_check
            )
            snapshot_path = self._executable_snapshot_directory.path / "gh"
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | os.O_NONBLOCK
                | getattr(os, "O_CLOEXEC", 0)
            )
            snapshot_write_fd = os.open(
                "gh",
                flags,
                0o500,
                dir_fd=self._executable_snapshot_directory.fd,
            )
            snapshot_cleanup_anchor = {
                "fd": snapshot_write_fd,
                "label": "GitHub CLI executable snapshot",
                "last_known_path": snapshot_path,
            }
            self._provisional_cleanup_objects.append(snapshot_cleanup_anchor)
            snapshot_cleanup_anchor_registered = True
            _check_deadline(deadline_check)
            initial_snapshot_descriptor = os.fstat(snapshot_write_fd)
            initial_snapshot_path = os.stat(
                "gh",
                dir_fd=self._executable_snapshot_directory.fd,
                follow_symlinks=False,
            )
            initial_snapshot_access_policy = _stable_fd_access_policy_binding(
                snapshot_write_fd
            )
            _check_deadline(deadline_check)
            if (
                not stat.S_ISREG(initial_snapshot_descriptor.st_mode)
                or initial_snapshot_descriptor.st_uid != os.geteuid()
                or initial_snapshot_descriptor.st_nlink != 1
                or stat.S_IMODE(initial_snapshot_descriptor.st_mode) & 0o077
                or _file_status(initial_snapshot_descriptor)
                != _file_status(initial_snapshot_path)
            ):
                raise _blocked(
                    "collector-unavailable",
                    "GitHub CLI executable snapshot initial object is unsafe",
                )
            digest = hashlib.sha256()
            copied = 0
            while True:
                _check_deadline(deadline_check)
                chunk = os.pread(
                    source_fd,
                    min(64 * 1024, MAX_GH_EXECUTABLE_BYTES + 1 - copied),
                    copied,
                )
                _check_deadline(deadline_check)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > MAX_GH_EXECUTABLE_BYTES:
                    raise _blocked(
                        "collector-unavailable",
                        "GitHub CLI executable exceeds the byte ceiling",
                    )
                digest.update(chunk)
                _write_all(
                    snapshot_write_fd,
                    chunk,
                    deadline_check=deadline_check,
                )
            source_after = os.fstat(source_fd)
            source_access_policy_after = _stable_fd_access_policy_binding(source_fd)
            _check_deadline(deadline_check)
            source_access_before = (
                stat.S_IMODE(source_before.st_mode),
                source_before.st_uid,
                source_before.st_gid,
            )
            source_access_after = (
                stat.S_IMODE(source_after.st_mode),
                source_after.st_uid,
                source_after.st_gid,
            )
            if (
                (source_before.st_dev, source_before.st_ino)
                != (source_after.st_dev, source_after.st_ino)
                or source_before.st_size != source_after.st_size
                or source_access_before != source_access_after
                or source_access_policy_before != source_access_policy_after
                or copied != source_before.st_size
            ):
                raise _blocked(
                    "collector-unavailable",
                    "GitHub CLI executable changed while it was pinned",
                )
            actual_sha256 = digest.hexdigest()
            if actual_sha256 != expected_gh_sha256:
                raise _blocked(
                    "collector-digest-mismatch",
                    "GitHub CLI executable SHA-256 differs from the expected digest",
                )
            self._source_path = gh_executable
            self._source_binding = {
                "device": source_after.st_dev,
                "gid": source_after.st_gid,
                "inode": source_after.st_ino,
                "links": source_after.st_nlink,
                "mode": stat.S_IMODE(source_after.st_mode),
                "sha256": actual_sha256,
                "size": source_after.st_size,
                "uid": source_after.st_uid,
            }
            self._source_access_policy_binding = source_access_policy_after
            self._source_content_generation = _file_content_generation(source_after)
            _check_deadline(deadline_check)
            os.fchmod(snapshot_write_fd, 0o500)
            _check_deadline(deadline_check)
            os.fsync(snapshot_write_fd)
            _check_deadline(deadline_check)
            snapshot_status = os.fstat(snapshot_write_fd)
            snapshot_path_status = os.stat(
                "gh",
                dir_fd=self._executable_snapshot_directory.fd,
                follow_symlinks=False,
            )
            snapshot_access_policy = _stable_fd_access_policy_binding(snapshot_write_fd)
            snapshot_generation = _file_content_generation(snapshot_status)
            snapshot_path_generation = _file_content_generation(snapshot_path_status)
            _check_deadline(deadline_check)
            if (
                not stat.S_ISREG(snapshot_status.st_mode)
                or not stat.S_ISREG(snapshot_path_status.st_mode)
                or snapshot_status.st_size != copied
                or snapshot_status.st_uid != os.geteuid()
                or snapshot_status.st_nlink != 1
                or stat.S_IMODE(snapshot_status.st_mode) != 0o500
                or _file_status(snapshot_status) != _file_status(snapshot_path_status)
                or snapshot_access_policy != initial_snapshot_access_policy
                or snapshot_generation != snapshot_path_generation
            ):
                raise _blocked(
                    "collector-unavailable",
                    "GitHub CLI snapshot object or access policy is invalid",
                )
            _check_deadline(deadline_check)
            self._snapshot_fd = os.open(
                "gh",
                os.O_RDONLY
                | os.O_NOFOLLOW
                | os.O_NONBLOCK
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=self._executable_snapshot_directory.fd,
            )
            pinned_status_before = os.fstat(self._snapshot_fd)
            pinned_path_status_before = os.stat(
                "gh",
                dir_fd=self._executable_snapshot_directory.fd,
                follow_symlinks=False,
            )
            pinned_access_policy_before = _stable_fd_access_policy_binding(
                self._snapshot_fd
            )
            pinned_generation_before = _file_content_generation(
                pinned_status_before
            )
            pinned_path_generation_before = _file_content_generation(
                pinned_path_status_before
            )
            _check_deadline(deadline_check)
            # Bind a stable executable byte sequence on the same owner-private
            # regular-file object and access policy before trusting its digest.
            if (
                not stat.S_ISREG(pinned_status_before.st_mode)
                or not stat.S_ISREG(pinned_path_status_before.st_mode)
                or _file_status(pinned_status_before) != _file_status(snapshot_status)
                or _file_status(pinned_path_status_before)
                != _file_status(snapshot_status)
                or pinned_access_policy_before != snapshot_access_policy
                or pinned_generation_before != snapshot_generation
                or pinned_path_generation_before != snapshot_generation
            ):
                raise _blocked(
                    "collector-unavailable",
                    "GitHub CLI snapshot changed before its digest was verified",
                )
            snapshot_sha256, snapshot_retained = _sha256_fd_bounded(
                self._snapshot_fd,
                deadline_check=deadline_check,
            )
            pinned_status_after = os.fstat(self._snapshot_fd)
            pinned_path_status_after = os.stat(
                "gh",
                dir_fd=self._executable_snapshot_directory.fd,
                follow_symlinks=False,
            )
            pinned_access_policy_after = _stable_fd_access_policy_binding(
                self._snapshot_fd
            )
            pinned_generation_after = _file_content_generation(pinned_status_after)
            pinned_path_generation_after = _file_content_generation(
                pinned_path_status_after
            )
            _check_deadline(deadline_check)
            if (
                not stat.S_ISREG(pinned_status_after.st_mode)
                or not stat.S_ISREG(pinned_path_status_after.st_mode)
                or _file_status(pinned_status_after) != _file_status(snapshot_status)
                or _file_status(pinned_path_status_after)
                != _file_status(snapshot_status)
                or pinned_access_policy_after != snapshot_access_policy
                or pinned_generation_after != snapshot_generation
                or pinned_path_generation_after != snapshot_generation
                or snapshot_retained != copied
            ):
                raise _blocked(
                    "collector-unavailable",
                    "GitHub CLI snapshot changed while its digest was verified",
                )
            if (
                snapshot_sha256 != actual_sha256
                or snapshot_sha256 != expected_gh_sha256
            ):
                raise _blocked(
                    "collector-digest-mismatch",
                    "GitHub CLI snapshot SHA-256 differs from the expected digest",
                )
            self._snapshot_path = snapshot_path
            self._snapshot_binding = {
                "device": pinned_status_after.st_dev,
                "gid": pinned_status_after.st_gid,
                "inode": pinned_status_after.st_ino,
                "links": pinned_status_after.st_nlink,
                "mode": stat.S_IMODE(pinned_status_after.st_mode),
                "sha256": snapshot_sha256,
                "size": pinned_status_after.st_size,
                "uid": pinned_status_after.st_uid,
            }
            self._snapshot_access_policy_binding = pinned_access_policy_after
            self._snapshot_content_generation = pinned_generation_after
            self.executable = os.fspath(snapshot_path)
            self._source_fd = source_fd
            source_fd = None
            self._pinned = True
            self._provisional_cleanup_objects.remove(snapshot_cleanup_anchor)
            snapshot_cleanup_anchor_registered = False
            os.close(snapshot_write_fd)
            snapshot_write_fd = None
            self._executable_snapshot_directory.revalidate(
                deadline_check=deadline_check
            )
            self._revalidate_snapshot(
                absolute_deadline=self.deadline,
                endpoint_class="collector-initialization",
            )
        except EnforcementDoctorError:
            raise
        except (OSError, ValueError) as error:
            raise _blocked(
                "collector-unavailable",
                "GitHub CLI executable could not be pinned safely",
            ) from error
        finally:
            if (
                snapshot_write_fd is not None
                and not snapshot_cleanup_anchor_registered
            ):
                try:
                    os.close(snapshot_write_fd)
                except OSError:
                    pass
            if source_fd is not None:
                os.close(source_fd)

    def _collector_inconclusive(self) -> EnforcementDoctorError:
        self._collector_inconclusive_reported = True
        return _blocked(
            "collector-inconclusive",
            "pinned GitHub CLI snapshot could not be revalidated",
        )

    @staticmethod
    def _require_deadline_remaining(
        absolute_deadline: float,
        endpoint_class: str,
    ) -> float:
        remaining = absolute_deadline - time.monotonic()
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
        return remaining

    def _revalidate_snapshot(
        self,
        *,
        absolute_deadline: float | None = None,
        endpoint_class: str = "github-api",
    ) -> None:
        if (
            not self._pinned
            or self._closed
            or self._source_fd is None
            or self._snapshot_fd is None
            or self._source_access_policy_binding is None
            or self._snapshot_access_policy_binding is None
            or self._source_content_generation is None
            or self._snapshot_content_generation is None
            or not self.executable
            or self._runtime_parent is None
            or self._run_directory is None
            or self._executable_snapshot_directory is None
            or self._config_snapshot_directory is None
            or self._transport_directory is None
            or self._source_config_directory is None
            or self._source_hosts_file is None
            or self._snapshot_hosts_file is None
            or self._snapshot_global_config_file is None
        ):
            raise self._collector_inconclusive()

        def check_deadline() -> None:
            if absolute_deadline is not None:
                self._require_deadline_remaining(
                    absolute_deadline,
                    endpoint_class,
                )

        try:
            check_deadline()
            self._runtime_parent.revalidate(deadline_check=check_deadline)
            check_deadline()
            self._run_directory.revalidate(deadline_check=check_deadline)
            check_deadline()
            self._executable_snapshot_directory.revalidate(
                deadline_check=check_deadline
            )
            check_deadline()
            self._config_snapshot_directory.revalidate(deadline_check=check_deadline)
            check_deadline()
            self._transport_directory.revalidate(deadline_check=check_deadline)
            check_deadline()
            self._source_config_directory.revalidate(deadline_check=check_deadline)
            self._source_hosts_file.revalidate(deadline_check=check_deadline)
            if self._source_global_config_file is not None:
                self._source_global_config_file.revalidate(
                    deadline_check=check_deadline
                )
            self._snapshot_hosts_file.revalidate(deadline_check=check_deadline)
            self._snapshot_global_config_file.revalidate(deadline_check=check_deadline)
            if self._snapshot_auth_header_file is not None:
                self._snapshot_auth_header_file.revalidate(
                    deadline_check=check_deadline
                )
            check_deadline()
            source_descriptor_before = os.fstat(self._source_fd)
            source_path_before = os.lstat(self._source_path)
            source_access_policy_before = _stable_fd_access_policy_binding(
                self._source_fd
            )
            source_generation_before = _file_content_generation(
                source_descriptor_before
            )
            source_path_generation_before = _file_content_generation(source_path_before)
            source_digest: str | None = None
            source_retained: int | None = None
            if (
                source_generation_before != self._source_content_generation
                or source_path_generation_before != self._source_content_generation
            ):
                source_digest, source_retained = _sha256_fd_bounded(
                    self._source_fd,
                    deadline_check=check_deadline,
                )
            source_descriptor_after = os.fstat(self._source_fd)
            source_path_after = os.lstat(self._source_path)
            source_access_policy_after = _stable_fd_access_policy_binding(
                self._source_fd
            )
            source_generation_after = _file_content_generation(source_descriptor_after)
            source_path_generation_after = _file_content_generation(source_path_after)
            check_deadline()
            snapshot_descriptor_before = os.fstat(self._snapshot_fd)
            snapshot_path_before = os.lstat(self._snapshot_path)
            snapshot_access_policy_before = _stable_fd_access_policy_binding(
                self._snapshot_fd
            )
            snapshot_generation_before = _file_content_generation(
                snapshot_descriptor_before
            )
            snapshot_path_generation_before = _file_content_generation(
                snapshot_path_before
            )
            snapshot_digest: str | None = None
            snapshot_retained: int | None = None
            if (
                snapshot_generation_before != self._snapshot_content_generation
                or snapshot_path_generation_before != self._snapshot_content_generation
            ):
                snapshot_digest, snapshot_retained = _sha256_fd_bounded(
                    self._snapshot_fd,
                    deadline_check=check_deadline,
                )
            snapshot_descriptor_after = os.fstat(self._snapshot_fd)
            snapshot_path_after = os.lstat(self._snapshot_path)
            snapshot_access_policy_after = _stable_fd_access_policy_binding(
                self._snapshot_fd
            )
            snapshot_generation_after = _file_content_generation(
                snapshot_descriptor_after
            )
            snapshot_path_generation_after = _file_content_generation(
                snapshot_path_after
            )
            check_deadline()
        except EnforcementDoctorError as error:
            if error.reason_code == "api-timeout":
                raise
            raise self._collector_inconclusive() from error
        except (OSError, ValueError):
            raise self._collector_inconclusive()

        source_expected = {
            key: value for key, value in self._source_binding.items() if key != "sha256"
        }
        snapshot_expected = {
            key: value
            for key, value in self._snapshot_binding.items()
            if key != "sha256"
        }
        if (
            not stat.S_ISREG(source_descriptor_before.st_mode)
            or not stat.S_ISREG(source_path_before.st_mode)
            or not stat.S_ISREG(source_descriptor_after.st_mode)
            or not stat.S_ISREG(source_path_after.st_mode)
            or _file_status(source_descriptor_before) != source_expected
            or _file_status(source_path_before) != source_expected
            or _file_status(source_descriptor_after) != source_expected
            or _file_status(source_path_after) != source_expected
            or source_access_policy_before != self._source_access_policy_binding
            or source_access_policy_after != self._source_access_policy_binding
            or source_generation_before != source_path_generation_before
            or source_generation_after != source_path_generation_after
            or source_generation_before != source_generation_after
            or (
                source_digest is None
                and source_generation_after != self._source_content_generation
            )
            or (
                source_digest is not None
                and (
                    source_retained != self._source_binding["size"]
                    or source_digest != self._source_binding["sha256"]
                )
            )
            or not stat.S_ISREG(snapshot_descriptor_before.st_mode)
            or not stat.S_ISREG(snapshot_path_before.st_mode)
            or not stat.S_ISREG(snapshot_descriptor_after.st_mode)
            or not stat.S_ISREG(snapshot_path_after.st_mode)
            or _file_status(snapshot_descriptor_before) != snapshot_expected
            or _file_status(snapshot_path_before) != snapshot_expected
            or _file_status(snapshot_descriptor_after) != snapshot_expected
            or _file_status(snapshot_path_after) != snapshot_expected
            or snapshot_access_policy_before != self._snapshot_access_policy_binding
            or snapshot_access_policy_after != self._snapshot_access_policy_binding
            or snapshot_generation_before != snapshot_path_generation_before
            or snapshot_generation_after != snapshot_path_generation_after
            or snapshot_generation_before != snapshot_generation_after
            or (
                snapshot_digest is None
                and snapshot_generation_after != self._snapshot_content_generation
            )
            or (
                snapshot_digest is not None
                and (
                    snapshot_retained != self._snapshot_binding["size"]
                    or snapshot_digest != self._snapshot_binding["sha256"]
                )
            )
        ):
            raise self._collector_inconclusive()
        if source_digest is not None:
            self._source_content_generation = source_generation_after
        if snapshot_digest is not None:
            self._snapshot_content_generation = snapshot_generation_after
        check_deadline()

    def revalidate_for_admission(self) -> None:
        try:
            self._activate_termination_transaction()
            self._revalidate_snapshot(
                absolute_deadline=self.deadline,
                endpoint_class="admission-revalidation",
            )
        except BaseException as error:
            self._close_after_termination(error)
            raise

    def _cleanup_file_binding(
        self,
        bound_file: Optional[_BoundRegularFile],
        path: pathlib.Path,
    ) -> tuple[Optional[int], Optional[dict[str, int]]]:
        if bound_file is not None:
            return bound_file.fd, bound_file.binding
        for anchor in self._provisional_cleanup_objects:
            if anchor["last_known_path"] != path:
                continue
            fd = anchor["fd"]
            try:
                return fd, _file_status(os.fstat(fd))
            except OSError:
                return fd, None
        return None, None

    @staticmethod
    def _prepare_directory_for_cleanup(directory: _BoundDirectory) -> None:
        # Cleanup protects object identity. A mode or ACL drift is an access-
        # policy change, not an object replacement, so it must not redirect
        # fchmod or the later dirfd-relative removals to another object.
        directory.revalidate_identity()
        os.fchmod(directory.fd, 0o700)
        descriptor = os.fstat(directory.fd)
        if (
            not stat.S_ISDIR(descriptor.st_mode)
            or descriptor.st_uid != os.geteuid()
            or stat.S_IMODE(descriptor.st_mode) != 0o700
            or _object_identity(descriptor)
            != _binding_identity(directory._bindings[-1])
        ):
            raise directory._inconclusive()
        directory.revalidate_identity()

    @staticmethod
    def _unlink_cleanup_file(
        parent: _BoundDirectory,
        name: str,
        *,
        label: str,
        bound_fd: Optional[int],
        expected_binding: Optional[dict[str, int]],
    ) -> None:
        parent.revalidate_identity()
        cleanup_fd = bound_fd
        temporary_fd: Optional[int] = None
        try:
            if cleanup_fd is None:
                flags = (
                    os.O_RDONLY
                    | os.O_NOFOLLOW
                    | os.O_NONBLOCK
                    | getattr(os, "O_CLOEXEC", 0)
                )
                try:
                    temporary_fd = os.open(name, flags, dir_fd=parent.fd)
                except FileNotFoundError:
                    return
                cleanup_fd = temporary_fd
                descriptor = os.fstat(cleanup_fd)
                path_status = os.stat(
                    name,
                    dir_fd=parent.fd,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISREG(descriptor.st_mode)
                    or not stat.S_ISREG(path_status.st_mode)
                    or _object_identity(descriptor) != _object_identity(path_status)
                ):
                    raise _blocked(
                        "collector-inconclusive",
                        f"{label} cleanup identity is unstable",
                    )
                expected_identity = _object_identity(descriptor)
            else:
                if expected_binding is None:
                    raise _blocked(
                        "collector-inconclusive",
                        f"{label} cleanup binding is unavailable",
                    )
                expected_identity = _binding_identity(expected_binding)

            descriptor_before = os.fstat(cleanup_fd)
            try:
                path_before = os.stat(
                    name,
                    dir_fd=parent.fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                if (
                    _object_identity(descriptor_before) == expected_identity
                    and descriptor_before.st_nlink == 0
                ):
                    return
                raise
            if (
                not stat.S_ISREG(descriptor_before.st_mode)
                or not stat.S_ISREG(path_before.st_mode)
                or _object_identity(descriptor_before) != expected_identity
                or _object_identity(path_before) != expected_identity
            ):
                raise _blocked(
                    "collector-inconclusive",
                    f"{label} cleanup identity changed",
                )
            os.unlink(name, dir_fd=parent.fd)
            descriptor_after = os.fstat(cleanup_fd)
            if (
                not stat.S_ISREG(descriptor_after.st_mode)
                or _object_identity(descriptor_after) != expected_identity
                or descriptor_after.st_nlink != 0
            ):
                raise _blocked(
                    "collector-inconclusive",
                    f"{label} unlink could not be proven",
                )
            try:
                os.stat(
                    name,
                    dir_fd=parent.fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                raise _blocked(
                    "collector-inconclusive",
                    f"{label} name was repopulated during cleanup",
                )
            parent.revalidate_identity()
        finally:
            if temporary_fd is not None:
                try:
                    os.close(temporary_fd)
                except OSError:
                    pass

    @staticmethod
    def _remove_cleanup_directory(
        parent: _BoundDirectory,
        name: str,
        *,
        label: str,
        child: Optional[_BoundDirectory],
    ) -> None:
        parent.revalidate_identity()
        child_fd: Optional[int] = None
        temporary_fd: Optional[int] = None
        try:
            if child is None:
                flags = (
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | os.O_NOFOLLOW
                    | os.O_NONBLOCK
                    | getattr(os, "O_CLOEXEC", 0)
                )
                try:
                    temporary_fd = os.open(name, flags, dir_fd=parent.fd)
                except FileNotFoundError:
                    return
                child_fd = temporary_fd
                expected_identity = _object_identity(os.fstat(child_fd))
            else:
                child.revalidate_identity()
                child_fd = child.fd
                expected_identity = _binding_identity(child._bindings[-1])

            descriptor_before = os.fstat(child_fd)
            path_before = os.stat(
                name,
                dir_fd=parent.fd,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISDIR(descriptor_before.st_mode)
                or not stat.S_ISDIR(path_before.st_mode)
                or _object_identity(descriptor_before) != expected_identity
                or _object_identity(path_before) != expected_identity
            ):
                raise _blocked(
                    "collector-inconclusive",
                    f"{label} cleanup identity changed",
                )
            os.rmdir(name, dir_fd=parent.fd)
            try:
                os.stat(
                    name,
                    dir_fd=parent.fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                raise _blocked(
                    "collector-inconclusive",
                    f"{label} name was repopulated during cleanup",
                )
            parent.revalidate_identity()
        finally:
            if temporary_fd is not None:
                try:
                    os.close(temporary_fd)
                except OSError:
                    pass

    def _retained_runtime_locator(self) -> Optional[dict[str, Any]]:
        if (
            self._runtime_parent is None
            or self._run_directory is None
            or not self._run_name
        ):
            return None
        try:
            descriptor = os.fstat(self._run_directory.fd)
        except OSError:
            return {
                "last_known_path": os.fspath(self._run_directory.path),
                "path_binding": "unverified",
            }
        locator: dict[str, Any] = {
            "device": descriptor.st_dev,
            "inode": descriptor.st_ino,
            "links": descriptor.st_nlink,
            "last_known_path": os.fspath(self._run_directory.path),
            "path_binding": "unverified",
        }
        try:
            self._runtime_parent.revalidate_identity()
            path_status = os.stat(
                self._run_name,
                dir_fd=self._runtime_parent.fd,
                follow_symlinks=False,
            )
        except (EnforcementDoctorError, OSError):
            return locator
        if (
            stat.S_ISDIR(descriptor.st_mode)
            and stat.S_ISDIR(path_status.st_mode)
            and _object_identity(descriptor) == _object_identity(path_status)
        ):
            locator.pop("last_known_path")
            locator["path"] = os.fspath(self._run_directory.path)
            locator["path_binding"] = "verified"
        return locator

    @staticmethod
    def _retained_object_locator(
        fd: Optional[int],
        *,
        label: str,
        last_known_path: pathlib.Path,
    ) -> Optional[dict[str, Any]]:
        if fd is None:
            return None
        try:
            descriptor = os.fstat(fd)
        except OSError:
            return {
                "label": label,
                "last_known_path": os.fspath(last_known_path),
                "path_binding": "unverified",
            }
        if stat.S_ISREG(descriptor.st_mode) and descriptor.st_nlink == 0:
            return None
        current_path = _verified_descriptor_path(fd)
        if current_path is None and stat.S_ISDIR(descriptor.st_mode):
            # Darwin retains the pre-removal directory path and link count on
            # an open fd. Failure to resolve that path to the same inode is the
            # portable evidence that the removed directory is not locatable.
            return None
        locator: dict[str, Any] = {
            "device": descriptor.st_dev,
            "inode": descriptor.st_ino,
            "label": label,
            "links": descriptor.st_nlink,
            "last_known_path": os.fspath(last_known_path),
            "path_binding": "unverified",
        }
        if current_path is not None:
            if current_path == last_known_path:
                locator.pop("last_known_path")
                locator["path"] = os.fspath(current_path)
                locator["path_binding"] = "verified"
        return locator

    def _retained_cleanup_objects(self) -> list[dict[str, Any]]:
        if self._run_directory is not None:
            run_path = self._run_directory.path
        elif self._execution_cwd:
            run_path = pathlib.Path(self._execution_cwd)
        else:
            return []
        candidates = tuple(
            (
                anchor["fd"],
                anchor["label"],
                anchor["last_known_path"],
            )
            for anchor in self._provisional_cleanup_objects
        ) + (
            (
                None
                if self._snapshot_hosts_file is None
                else self._snapshot_hosts_file.fd,
                "GitHub CLI private hosts.yml snapshot",
                (
                    run_path / "config" / "hosts.yml"
                    if self._config_snapshot_directory is None
                    else self._config_snapshot_directory.path / "hosts.yml"
                ),
            ),
            (
                None
                if self._snapshot_global_config_file is None
                else self._snapshot_global_config_file.fd,
                "GitHub CLI private config.yml snapshot",
                (
                    run_path / "config" / "config.yml"
                    if self._config_snapshot_directory is None
                    else self._config_snapshot_directory.path / "config.yml"
                ),
            ),
            (
                self._snapshot_fd,
                "GitHub CLI executable snapshot",
                (
                    run_path / "bin" / "gh"
                    if self._executable_snapshot_directory is None
                    else self._executable_snapshot_directory.path / "gh"
                ),
            ),
            (
                None
                if self._snapshot_auth_header_file is None
                else self._snapshot_auth_header_file.fd,
                "GitHub API private authorization header",
                (
                    run_path / "transport" / "authorization.headers"
                    if self._transport_directory is None
                    else self._transport_directory.path / "authorization.headers"
                ),
            ),
            (
                None
                if self._config_snapshot_directory is None
                else self._config_snapshot_directory.fd,
                "GitHub CLI private config snapshot directory",
                (
                    run_path / "config"
                    if self._config_snapshot_directory is None
                    else self._config_snapshot_directory.path
                ),
            ),
            (
                None
                if self._executable_snapshot_directory is None
                else self._executable_snapshot_directory.fd,
                "GitHub CLI private executable snapshot directory",
                (
                    run_path / "bin"
                    if self._executable_snapshot_directory is None
                    else self._executable_snapshot_directory.path
                ),
            ),
            (
                None
                if self._transport_directory is None
                else self._transport_directory.fd,
                "GitHub API private transport directory",
                (
                    run_path / "transport"
                    if self._transport_directory is None
                    else self._transport_directory.path
                ),
            ),
            (
                None if self._run_directory is None else self._run_directory.fd,
                "GitHub CLI private run directory",
                run_path,
            ),
        )
        retained: list[dict[str, Any]] = []
        for fd, label, last_known_path in candidates:
            locator = self._retained_object_locator(
                fd,
                label=label,
                last_known_path=last_known_path,
            )
            if locator is not None:
                retained.append(locator)
        return retained

    def _close_resources(self) -> None:
        if self._closed:
            return
        cleanup_failures: list[str] = []
        cleanup_proofs: list[bool] = []
        unresolved_processes: list[dict[str, Any]] = []
        active_processes = getattr(self, "_active_processes", {})
        for process_id, managed in tuple(active_processes.items()):
            process_failures = _terminate_drain_reap(managed)
            if process_failures:
                cleanup_failures.append("active-process-cleanup")
                cleanup_proofs.append(False)
                unresolved_processes.append(
                    {
                        "pid": process_id,
                        "process_group": (process_id if os.name == "posix" else None),
                        "quiescence": "unproven",
                    }
                )
                continue
            process_resource_failures = _close_process_resources(
                None,
                managed,
            )
            if process_resource_failures:
                cleanup_failures.append("active-process-resource-close")
            if active_processes.get(process_id) is managed:
                active_processes.pop(process_id)
        process_cleanup_unproven = bool(unresolved_processes)
        if self._pinned:
            previously_reported_inconclusive = self._collector_inconclusive_reported
            try:
                self._revalidate_snapshot()
            except Exception:
                # Deletion can still be identity-bound and complete after an
                # access-policy anomaly, but it cannot undo a confidentiality
                # or execution-policy expansion that existed before cleanup.
                if not previously_reported_inconclusive:
                    cleanup_failures.append("pre-cleanup-revalidation")
        self._closed = True

        def attempt(
            label: str,
            action: Any,
            *,
            proof_required: bool,
        ) -> bool:
            try:
                action()
            except Exception:
                cleanup_failures.append(label)
                if proof_required:
                    cleanup_proofs.append(False)
                return False
            else:
                if proof_required:
                    cleanup_proofs.append(True)
                return True

        if not process_cleanup_unproven and self._config_snapshot_directory is not None:
            attempt(
                "config-directory-owner-mode",
                lambda: self._prepare_directory_for_cleanup(
                    self._config_snapshot_directory
                ),
                proof_required=True,
            )
            for name, bound_file, label in (
                (
                    "hosts.yml",
                    self._snapshot_hosts_file,
                    "GitHub CLI private hosts.yml snapshot",
                ),
                (
                    "config.yml",
                    self._snapshot_global_config_file,
                    "GitHub CLI private config.yml snapshot",
                ),
            ):
                bound_fd, expected_binding = self._cleanup_file_binding(
                    bound_file,
                    self._config_snapshot_directory.path / name,
                )
                attempt(
                    f"unlink-{name}",
                    lambda name=name,
                    label=label,
                    bound_fd=bound_fd,
                    expected_binding=expected_binding: (
                        self._unlink_cleanup_file(
                            self._config_snapshot_directory,
                            name,
                            label=label,
                            bound_fd=bound_fd,
                            expected_binding=expected_binding,
                        )
                    ),
                    proof_required=True,
                )

        if not process_cleanup_unproven and self._transport_directory is not None:
            attempt(
                "transport-directory-owner-mode",
                lambda: self._prepare_directory_for_cleanup(self._transport_directory),
                proof_required=True,
            )
            bound_fd, expected_binding = self._cleanup_file_binding(
                self._snapshot_auth_header_file,
                self._transport_directory.path / "authorization.headers",
            )
            attempt(
                "unlink-authorization.headers",
                lambda: self._unlink_cleanup_file(
                    self._transport_directory,
                    "authorization.headers",
                    label="GitHub API private authorization header",
                    bound_fd=bound_fd,
                    expected_binding=expected_binding,
                ),
                proof_required=True,
            )

        if (
            not process_cleanup_unproven
            and self._executable_snapshot_directory is not None
        ):
            attempt(
                "executable-directory-owner-mode",
                lambda: self._prepare_directory_for_cleanup(
                    self._executable_snapshot_directory
                ),
                proof_required=True,
            )
            executable_cleanup_fd = self._snapshot_fd
            executable_cleanup_binding = getattr(self, "_snapshot_binding", None)
            if (
                executable_cleanup_fd is None
                or executable_cleanup_binding is None
            ):
                (
                    provisional_fd,
                    provisional_binding,
                ) = self._cleanup_file_binding(
                    None,
                    self._executable_snapshot_directory.path / "gh",
                )
                if provisional_fd is not None:
                    executable_cleanup_fd = provisional_fd
                    executable_cleanup_binding = provisional_binding
            attempt(
                "unlink-gh",
                lambda: self._unlink_cleanup_file(
                    self._executable_snapshot_directory,
                    "gh",
                    label="GitHub CLI executable snapshot",
                    bound_fd=executable_cleanup_fd,
                    expected_binding=executable_cleanup_binding,
                ),
                proof_required=True,
            )

        run_directory_removed = self._run_directory is None
        if process_cleanup_unproven and self._run_directory is not None:
            run_directory_removed = False
        elif self._run_directory is not None:
            if self._config_snapshot_directory is None:
                attempt(
                    "remove-config-directory",
                    lambda: self._remove_cleanup_directory(
                        self._run_directory,
                        "config",
                        label="GitHub CLI private config snapshot directory",
                        child=None,
                    ),
                    proof_required=True,
                )
            else:
                attempt(
                    "remove-config-directory",
                    lambda: self._remove_cleanup_directory(
                        self._run_directory,
                        "config",
                        label="GitHub CLI private config snapshot directory",
                        child=self._config_snapshot_directory,
                    ),
                    proof_required=True,
                )
            if self._transport_directory is None:
                attempt(
                    "remove-transport-directory",
                    lambda: self._remove_cleanup_directory(
                        self._run_directory,
                        "transport",
                        label="GitHub API private transport directory",
                        child=None,
                    ),
                    proof_required=True,
                )
            else:
                attempt(
                    "remove-transport-directory",
                    lambda: self._remove_cleanup_directory(
                        self._run_directory,
                        "transport",
                        label="GitHub API private transport directory",
                        child=self._transport_directory,
                    ),
                    proof_required=True,
                )
            if self._executable_snapshot_directory is None:
                attempt(
                    "remove-bin-directory",
                    lambda: self._remove_cleanup_directory(
                        self._run_directory,
                        "bin",
                        label="GitHub CLI private executable snapshot directory",
                        child=None,
                    ),
                    proof_required=True,
                )
            else:
                attempt(
                    "remove-bin-directory",
                    lambda: self._remove_cleanup_directory(
                        self._run_directory,
                        "bin",
                        label="GitHub CLI private executable snapshot directory",
                        child=self._executable_snapshot_directory,
                    ),
                    proof_required=True,
                )
            if self._runtime_parent is None or not self._run_name:
                cleanup_failures.append("remove-run-directory")
                cleanup_proofs.append(False)
            else:
                run_directory_removed = attempt(
                    "remove-run-directory",
                    lambda: self._remove_cleanup_directory(
                        self._runtime_parent,
                        self._run_name,
                        label="GitHub CLI private run directory",
                        child=self._run_directory,
                    ),
                    proof_required=True,
                )

        cleanup_proven = all(cleanup_proofs)
        retained_locator = (
            None if run_directory_removed else self._retained_runtime_locator()
        )
        retained_objects = [] if cleanup_proven else self._retained_cleanup_objects()

        for managed in active_processes.values():
            process_resource_failures = _close_process_resources(
                None,
                managed,
            )
            if process_resource_failures:
                cleanup_failures.append("unresolved-process-resource-close")
        for anchor in self._provisional_cleanup_objects:
            try:
                os.close(anchor["fd"])
            except OSError:
                cleanup_failures.append("close-provisional-cleanup-object")
        self._provisional_cleanup_objects.clear()
        for bound_file in (
            self._source_hosts_file,
            self._source_global_config_file,
            self._snapshot_hosts_file,
            self._snapshot_global_config_file,
            self._snapshot_auth_header_file,
        ):
            if bound_file is not None:
                bound_file.close()
        if self._source_fd is not None:
            try:
                os.close(self._source_fd)
            except OSError:
                cleanup_failures.append("close-source-executable")
            finally:
                self._source_fd = None
        if self._snapshot_fd is not None:
            try:
                os.close(self._snapshot_fd)
            except OSError:
                cleanup_failures.append("close-executable-snapshot")
            finally:
                self._snapshot_fd = None
        if self._config_snapshot_directory is not None:
            self._config_snapshot_directory.close()
            self._config_snapshot_directory = None
        if self._source_config_directory is not None:
            self._source_config_directory.close()
            self._source_config_directory = None
        if self._executable_snapshot_directory is not None:
            self._executable_snapshot_directory.close()
            self._executable_snapshot_directory = None
        if self._transport_directory is not None:
            self._transport_directory.close()
            self._transport_directory = None
        if self._run_directory is not None:
            self._run_directory.close()
            self._run_directory = None
        if self._runtime_parent is not None:
            self._runtime_parent.close()
            self._runtime_parent = None
        if cleanup_failures or not cleanup_proven:
            cleanup_failure: dict[str, Any] = {
                "cleanup_proof": ("complete" if cleanup_proven else "inconclusive"),
                "failed_operations": sorted(set(cleanup_failures)),
            }
            if retained_locator is not None:
                cleanup_failure["retained_runtime"] = retained_locator
            if retained_objects:
                cleanup_failure["retained_objects"] = retained_objects
            if unresolved_processes:
                cleanup_failure["unresolved_processes"] = unresolved_processes
            raise _blocked(
                "collector-inconclusive",
                "GitHub CLI private snapshot policy or cleanup could not be proven",
                cleanup_failure=cleanup_failure,
            )

    def close(self) -> None:
        signal_guard = getattr(self, "_termination_signal_guard", None)
        if signal_guard is None:
            self._close_resources()
            return
        if self._termination_transaction_finished:
            return
        if self._termination_transaction_finishing:
            self._close_resources()
            return

        self._termination_transaction_finishing = True
        cleanup_error: BaseException | None = None
        finish_error: BaseException | None = None
        try:
            signal_guard.begin_cleanup()
            try:
                self._close_resources()
            except BaseException as error:
                cleanup_error = error
            try:
                signal_guard.finish()
            except BaseException as error:
                finish_error = error
            self._termination_transaction_finished = True
        finally:
            self._termination_transaction_finishing = False

        if finish_error is not None:
            if cleanup_error is not None:
                raise finish_error from cleanup_error
            raise finish_error

        supervision_error: EnforcementDoctorError | None = None
        if signal_guard.errors:
            supervision_error = _process_supervision_error(
                "github-client-lifecycle",
                "GitHub client termination-signal state could not be restored",
                unavailable=False,
            )
        deferred_signal = signal_guard.deferred_signal
        if deferred_signal is not None:
            secondary_error = cleanup_error or supervision_error
            if supervision_error is not None:
                deferred = _DeferredTerminationSignal(deferred_signal)
                if secondary_error is not None:
                    raise deferred from secondary_error
                raise deferred
            _forward_deferred_termination_signal(
                deferred_signal,
                secondary_error,
            )
        if supervision_error is not None:
            if cleanup_error is not None:
                raise supervision_error from cleanup_error
            raise supervision_error
        if cleanup_error is not None:
            raise cleanup_error

    def _close_after_termination(self, error: BaseException) -> None:
        signal_guard = getattr(self, "_termination_signal_guard", None)
        if signal_guard is None:
            return
        if (
            isinstance(error, _DeferredTerminationSignal)
            or signal_guard.deferred_signal is not None
        ):
            self.close()

    def _activate_termination_transaction(self) -> None:
        signal_guard = getattr(self, "_termination_signal_guard", None)
        if signal_guard is None or signal_guard.state == "running":
            return
        if signal_guard.state != "blocked":
            raise _process_supervision_error(
                "github-client-lifecycle",
                "GitHub client termination-signal transaction is unavailable",
                unavailable=False,
            )
        try:
            signal_guard.activate()
        except BaseException as error:
            try:
                self.close()
            except BaseException as cleanup_or_signal_error:
                raise cleanup_or_signal_error from error
            raise

    def _cleanup_noexcept(self) -> Optional[EnforcementDoctorError]:
        try:
            self.close()
        except EnforcementDoctorError as error:
            return error
        return None

    def __enter__(self) -> GitHubApiClient:
        self._activate_termination_transaction()
        return self

    def __exit__(
        self,
        exception_type: object,
        exception: object,
        traceback: object,
    ) -> bool:
        self.close()
        return False

    def _run(
        self,
        command: list[str],
        *,
        endpoint_class: str,
        stdout_limit: int,
        authentication_preflight: bool = False,
    ) -> bytes:
        self._activate_termination_transaction()
        try:
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
            try:
                self._require_deadline_remaining(self.deadline, endpoint_class)
                self._revalidate_snapshot(
                    absolute_deadline=self.deadline,
                    endpoint_class=endpoint_class,
                )
                remaining = self._require_deadline_remaining(
                    self.deadline,
                    endpoint_class,
                )
                self.calls += 1
                process_result = _bounded_subprocess(
                    command,
                    environment=dict(self._environment),
                    execution_cwd=self._execution_cwd,
                    endpoint_class=endpoint_class,
                    process_registry=self._active_processes,
                    timeout_seconds=min(float(MAX_API_SECONDS), remaining),
                    stdout_limit=stdout_limit,
                    stderr_limit=MAX_API_STDERR_BYTES,
                    termination_cleanup=self.close,
                    lifecycle_signal_guard=getattr(
                        self,
                        "_termination_signal_guard",
                        None,
                    ),
                    absolute_deadline=self.deadline,
                )
            except BaseException as error:
                self._close_after_termination(error)
                if getattr(self, "_closed", False):
                    raise
                self._revalidate_snapshot(
                    absolute_deadline=self.deadline,
                    endpoint_class=endpoint_class,
                )
                raise

            self._revalidate_snapshot(
                absolute_deadline=self.deadline,
                endpoint_class=endpoint_class,
            )
            return_code, stdout, stderr = process_result
            if return_code != 0:
                raise _api_request_error(
                    endpoint_class=endpoint_class,
                    return_code=return_code,
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
        except BaseException as error:
            self._close_after_termination(error)
            raise

    def _install_authentication_header(self, token_output: bytes) -> None:
        if self._snapshot_auth_header_file is not None:
            return
        if self._transport_directory is None:
            raise _blocked(
                "collector-unavailable",
                "GitHub API private transport directory is unavailable",
            )
        token = token_output[:-1] if token_output.endswith(b"\n") else token_output
        if (
            not token
            or b"\r" in token_output
            or b"\n" in token
            or re.fullmatch(rb"[A-Za-z0-9_.-]{1,2048}", token) is None
        ):
            raise _blocked(
                "blocked-authentication",
                "GitHub authentication token output is invalid",
                api_failure=_api_failure(
                    "authentication-preflight",
                    http_status=None,
                    failure_kind="authentication",
                ),
            )
        header_payload = b"Authorization: Bearer " + token + b"\n"

        def deadline_check() -> None:
            self._require_deadline_remaining(
                self.deadline,
                "authentication-preflight",
            )

        self._snapshot_auth_header_file = _create_private_regular_file(
            self._transport_directory,
            "authorization.headers",
            header_payload,
            cleanup_anchors=self._provisional_cleanup_objects,
            label="GitHub API private authorization header",
            mode=0o400,
            max_bytes=MAX_GH_CONFIG_BYTES,
            deadline_check=deadline_check,
        )
        self._snapshot_auth_header_file.payload = b""
        self._transport_directory.set_owner_mode(
            0o500,
            deadline_check=deadline_check,
        )
        self._revalidate_snapshot(
            absolute_deadline=self.deadline,
            endpoint_class="authentication-preflight",
        )

    def auth_preflight(self) -> dict[str, Any]:
        try:
            if self._snapshot_auth_header_file is None:
                token_output = self._run(
                    [
                        self.executable,
                        "auth",
                        "token",
                        "--hostname",
                        AUTH_HOST,
                    ],
                    endpoint_class="authentication-preflight",
                    stdout_limit=2_049,
                    authentication_preflight=True,
                )
                self._install_authentication_header(token_output)
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
        except BaseException as error:
            self._close_after_termination(error)
            raise

    def get_json(
        self,
        endpoint: str,
        parameters: Optional[dict[str, object]] = None,
    ) -> object:
        try:
            if (
                re.fullmatch(r"/[A-Za-z0-9._~/-]+", endpoint) is None
                or endpoint.startswith("//")
                or "//" in endpoint
                or "/../" in f"{endpoint}/"
                or "/./" in f"{endpoint}/"
            ):
                raise _blocked(
                    "invalid-api-endpoint",
                    "collector endpoint is not fixed",
                )
            if self._snapshot_auth_header_file is None:
                raise _blocked(
                    "blocked-authentication",
                    "GitHub API authentication preflight has not completed",
                    api_failure=_api_failure(
                        "authentication-preflight",
                        http_status=None,
                        failure_kind="authentication",
                    ),
                )
            query: list[tuple[str, str]] = []
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
                query.append((key, rendered))
            endpoint_class = _api_endpoint_class(endpoint)
            query_string = urllib.parse.urlencode(query)
            request_url = f"{API_ROOT}{endpoint}"
            if query_string:
                request_url = f"{request_url}?{query_string}"
            remaining = self._require_deadline_remaining(
                self.deadline,
                endpoint_class,
            )
            curl_binding_before = _fixed_curl_trust_binding()
            if curl_binding_before != self._curl_trust_binding:
                raise _blocked(
                    "collector-inconclusive",
                    "fixed curl transport identity or access policy changed",
                )
            header_path = (
                self._transport_directory.path / "authorization.headers"
                if self._transport_directory is not None
                else pathlib.Path()
            )
            command = [
                os.fspath(CURL_EXECUTABLE),
                "--disable",
                "--silent",
                "--show-error",
                "--request",
                "GET",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--max-redirs",
                "0",
                "--proxy",
                "",
                "--noproxy",
                "*",
                "--connect-timeout",
                str(max(1, min(MAX_API_SECONDS, int(remaining)))),
                "--max-time",
                str(max(1, min(MAX_API_SECONDS, int(remaining)))),
                "--header",
                f"@{header_path}",
                "--header",
                f"Accept: {API_ACCEPT}",
                "--header",
                f"X-GitHub-Api-Version: {API_VERSION}",
                "--write-out",
                CURL_WRITE_OUT_FORMAT,
                "--url",
                request_url,
            ]
            payload = self._run(
                command,
                endpoint_class=endpoint_class,
                stdout_limit=MAX_API_RESPONSE_BYTES + 128,
            )
            curl_binding_after = _fixed_curl_trust_binding()
            if curl_binding_after != curl_binding_before:
                raise _blocked(
                    "collector-inconclusive",
                    "fixed curl transport identity or access policy changed",
                )
            trailer = CURL_TRAILER_PATTERN.search(payload)
            if trailer is None:
                raise _blocked(
                    "api-unavailable",
                    "fixed curl transport omitted the HTTP status",
                    api_failure=_api_failure(
                        endpoint_class,
                        http_status=None,
                        failure_kind="transport-contract",
                    ),
                )
            http_status = int(trailer.group(1), 10)
            rate_remaining = trailer.group(2)
            payload = payload[: trailer.start()]
            if len(payload) > MAX_API_RESPONSE_BYTES:
                raise _blocked(
                    "api-response-too-large",
                    "GitHub API response exceeded its byte ceiling",
                    api_failure=_api_failure(
                        endpoint_class,
                        http_status=http_status,
                        failure_kind="response-too-large",
                    ),
                )
            if 300 <= http_status <= 399:
                raise _blocked(
                    "api-unavailable",
                    "GitHub API redirect was refused",
                    api_failure=_api_failure(
                        endpoint_class,
                        http_status=http_status,
                        failure_kind="redirect-refused",
                    ),
                )
            if http_status != 200:
                raise _api_http_status_error(
                    endpoint_class=endpoint_class,
                    http_status=http_status,
                    rate_limited=rate_remaining == b"0",
                )
            parsed = _parse_json_bytes(
                payload,
                label=f"GitHub API {endpoint_class}",
            )
            self._require_deadline_remaining(self.deadline, endpoint_class)
            return parsed
        except BaseException as error:
            self._close_after_termination(error)
            if (
                not isinstance(error, EnforcementDoctorError)
                or error.reason_code != "invalid-json"
            ):
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
    per_page: int = API_PER_PAGE,
) -> list[Any]:
    if type(per_page) is not int or per_page < 1 or per_page > API_PER_PAGE:
        raise _blocked(
            "invalid-api-endpoint",
            f"{label} page size is outside the collector bounds",
        )
    items: list[Any] = []
    reported_total: Optional[int] = None
    last_nonempty_page = 0
    terminal_page = 0
    for page in range(1, MAX_API_PAGES + 1):
        page_parameters = dict(parameters)
        page_parameters.update({"page": page, "per_page": per_page})
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
        if len(page_items) > per_page:
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
            "per_page": per_page,
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
        "updated_at": _normalize_rfc3339_utc(
            value.get("updated_at"),
            label="Actions variable updated timestamp",
        ),
        "value": _exact_string(
            value.get("value"),
            label="Actions variable value",
        ),
    }


def _select_cutover_input_variables(
    values: list[Any],
    *,
    expected_names: list[str],
) -> list[dict[str, str]]:
    expected = set(expected_names)
    selected: dict[str, dict[str, str]] = {}
    for value in values:
        normalized = _normalize_actions_variable(
            _exact_dict(value, label="Actions variable")
        )
        name = normalized["name"]
        if name not in expected:
            continue
        if name in selected:
            raise _blocked(
                "cutover-input-duplicate",
                "cutover input variable is duplicated in the repository snapshot",
            )
        selected[name] = normalized
    missing = [name for name in expected_names if name not in selected]
    if missing:
        raise _blocked(
            "cutover-input-missing",
            "one or more required cutover input variables are missing",
        )
    return [selected[name] for name in expected_names]


def _validate_cutover_input_variables(
    values: object,
    *,
    expected_names: list[str],
) -> list[dict[str, str]]:
    variables = _exact_list(values, label="cutover input variables")
    normalized: list[dict[str, str]] = []
    for value in variables:
        variable = _exact_dict(value, label="cutover input variable")
        _exact_keys(
            variable,
            {"name", "updated_at", "value"},
            label="cutover input variable",
        )
        normalized.append(_normalize_actions_variable(variable))
    names = [variable["name"] for variable in normalized]
    if (
        names != expected_names
        or len(names) != len(set(names))
        or len(normalized) != len(expected_names)
    ):
        raise _blocked(
            "cutover-input-set-mismatch",
            "cutover input variables differ in name, order, or uniqueness",
        )
    return normalized


def _normalize_run_attempt(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": _exact_positive_integer(
            value.get("id"),
            label="selected workflow run ID",
        ),
        "run_attempt": _exact_positive_integer(
            value.get("run_attempt"),
            label="selected workflow run attempt",
        ),
        "run_started_at": _normalize_rfc3339_utc(
            value.get("run_started_at"),
            label="selected workflow run start timestamp",
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
        "run_started_at": _normalize_rfc3339_utc(
            value.get("run_started_at"),
            label="workflow run start timestamp",
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
        "completed_at": _optional_rfc3339_utc(
            value.get("completed_at"),
            label="workflow job completion timestamp",
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
        "started_at": _normalize_rfc3339_utc(
            value.get("started_at"),
            label="workflow job start timestamp",
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
        "completed_at": _optional_rfc3339_utc(
            value.get("completed_at"),
            label="check-run completion timestamp",
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
        "started_at": _normalize_rfc3339_utc(
            value.get("started_at"),
            label="check-run start timestamp",
        ),
        "url": _exact_string(value.get("url"), label="check-run API URL"),
    }


def _normalize_check_suite(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "head_sha": _exact_sha1(
            value.get("head_sha"),
            label="check-suite head SHA",
        ),
        "id": _exact_positive_integer(
            value.get("id"),
            label="check-suite ID",
        ),
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
        selector["target_pr_number_variable"]: {
            "name": selector["target_pr_number_variable"],
            "value": str(pull_request_number),
        },
        selector["target_head_sha_variable"]: {
            "name": selector["target_head_sha_variable"],
            "value": candidate_head_sha,
        },
    }
    cutover_variables = {
        variable["name"]: variable for variable in snapshot["cutover_input_variables"]
    }
    for name, expected_variable in expected_selector_variables.items():
        selected = cutover_variables.get(name)
        if (
            selected is None
            or selected["name"] != expected_variable["name"]
            or selected["value"] != expected_variable["value"]
        ):
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
    expected_workflow_variables = {
        "CISCO_CUTOVER_EXPECTED_WORKFLOW_ID": str(expected_workflow_id),
        "CISCO_CUTOVER_EXPECTED_WORKFLOW_SHA": expected_workflow_sha,
    }
    native_workflow_variables = {
        "CISCO_CUTOVER_EXPECTED_WORKFLOW_ID": str(workflow["id"]),
        "CISCO_CUTOVER_EXPECTED_WORKFLOW_SHA": source_commit["sha"],
    }
    for name, expected_value in expected_workflow_variables.items():
        selected = cutover_variables.get(name)
        if (
            selected is None
            or selected["name"] != name
            or selected["value"] != expected_value
            or selected["value"] != native_workflow_variables[name]
        ):
            raise _blocked(
                "workflow-input-binding-mismatch",
                (
                    "administrator workflow input variable differs from "
                    "the selected native workflow identity"
                ),
            )


def _collect_snapshot(
    client: Any,
    trace: dict[str, Any],
    contract: dict[str, Any],
    *,
    phase: str,
    expected_run_attempt: int,
    expected_run_id: int,
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
    variable_values = _collect_pages(
        client,
        trace,
        phase=phase,
        label="repository Actions variables",
        endpoint=f"/repos/{target_name}/actions/variables",
        parameters={},
        item_key="variables",
        per_page=30,
    )
    cutover_input_variables = _select_cutover_input_variables(
        variable_values,
        expected_names=contract["cutover_input_variables"],
    )
    selected_run_attempt = _normalize_run_attempt(
        _get_object(
            client,
            trace,
            phase=phase,
            label="selected workflow run attempt",
            endpoint=(
                f"/repos/{target_name}/actions/runs/{expected_run_id}"
                f"/attempts/{expected_run_attempt}"
            ),
        )
    )
    if (
        selected_run_attempt["id"] != expected_run_id
        or selected_run_attempt["run_attempt"] != expected_run_attempt
    ):
        raise _blocked(
            "selected-run-attempt-mismatch",
            "exact workflow run-attempt endpoint returned another object",
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
        "cutover_input_variables": cutover_input_variables,
        "effective_rulesets": effective_rulesets,
        "organization": organization,
        "pull_request": pull_request,
        "repository": repository,
        "selected_run_attempt": selected_run_attempt,
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
    check_suite_ids: set[int] = set()
    check_run_ids: set[int] = set()
    same_name_checks_by_id: dict[int, dict[str, Any]] = {}
    for check_head_sha in sorted({candidate_head_sha, pull_request["base"]["sha"]}):
        check_suite_values = _collect_pages(
            client,
            trace,
            phase=phase,
            label=f"selected PR {check_head_sha} check suites",
            endpoint=f"/repos/{target_name}/commits/{check_head_sha}/check-suites",
            parameters={"filter": "all"},
            item_key="check_suites",
            result_cap=MAX_CHECK_SUITES,
        )
        for value in check_suite_values:
            check_suite = _normalize_check_suite(
                _exact_dict(value, label="selected PR check suite")
            )
            check_suite_id = check_suite["id"]
            if check_suite["head_sha"] != check_head_sha:
                raise _blocked(
                    "check-suite-identity-mismatch",
                    "check-suite search returned another commit",
                )
            if check_suite_id in check_suite_ids:
                raise _blocked(
                    "check-suite-identity-mismatch",
                    "same check-suite ID was repeated during collection",
                )
            check_suite_ids.add(check_suite_id)
            if len(check_suite_ids) > MAX_CHECK_SUITES:
                raise _blocked(
                    "api-search-cap-exceeded",
                    "candidate check suites exceed the complete-search cap",
                )
            check_values = _collect_pages(
                client,
                trace,
                phase=phase,
                label=f"check suite {check_suite_id} check runs",
                endpoint=f"/repos/{target_name}/check-suites/{check_suite_id}/check-runs",
                parameters={"filter": "all"},
                item_key="check_runs",
                result_cap=MAX_CHECK_RUNS,
            )
            for check_value in check_values:
                raw_check = _exact_dict(
                    check_value,
                    label="selected PR check run",
                )
                check = _normalize_check_run(raw_check)
                if (
                    check["check_suite_id"] != check_suite_id
                    or check["head_sha"] != check_head_sha
                ):
                    raise _blocked(
                        "check-run-identity-mismatch",
                        "check-run search returned another suite or commit",
                    )
                if check["id"] in check_run_ids:
                    raise _blocked(
                        "check-run-identity-mismatch",
                        "same check-run ID was repeated during collection",
                    )
                check_run_ids.add(check["id"])
                if len(check_run_ids) > MAX_CHECK_RUNS:
                    raise _blocked(
                        "api-search-cap-exceeded",
                        "candidate check runs exceed the complete-search cap",
                    )
                if (
                    check["name"] == workflow_contract["check_name"]
                    and expected_pr_link in check["pull_requests"]
                ):
                    same_name_checks_by_id[check["id"]] = check
    same_name_checks = list(same_name_checks_by_id.values())
    all_runs_by_id: dict[int, dict[str, Any]] = {}
    relevant_check_suite_ids = sorted(
        {check["check_suite_id"] for check in same_name_checks}
    )
    for check_suite_id in relevant_check_suite_ids:
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
    expected_run_attempt: int,
    expected_run_id: int,
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
    if not full_lineage:
        raise _blocked(
            "trusted-check-missing",
            "no same-name check is linked to the selected PR",
        )
    trusted: list[dict[str, Any]] = []
    for lineage in full_lineage:
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
                "same-name check is outside the pinned workflow identity",
            )
        trusted.append(lineage)
    selected_lineage = [
        lineage
        for lineage in trusted
        if lineage["run"]["id"] == expected_run_id
        and lineage["job"]["run_attempt"] == expected_run_attempt
    ]
    if not selected_lineage:
        raise _blocked(
            "selected-run-attempt-missing",
            "administrator-pinned workflow run and attempt were not found",
        )
    if len(selected_lineage) != 1:
        raise _blocked(
            "trusted-check-ambiguous",
            "administrator-pinned workflow run and attempt are ambiguous",
        )
    selected = selected_lineage[0]
    run = selected["run"]
    job = selected["job"]
    check = selected["check_run"]
    if run["run_attempt"] != expected_run_attempt:
        raise _blocked(
            "selected-run-attempt-superseded",
            "administrator-pinned attempt is not the run's current attempt",
        )
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
    selected_attempt = _exact_dict(
        snapshot["selected_run_attempt"],
        label="selected workflow run attempt",
    )
    _exact_keys(
        selected_attempt,
        {"id", "run_attempt", "run_started_at"},
        label="selected workflow run attempt",
    )
    selected_attempt = _normalize_run_attempt(selected_attempt)
    if (
        selected_attempt["id"] != expected_run_id
        or selected_attempt["run_attempt"] != expected_run_attempt
        or selected_attempt["run_started_at"] != run["run_started_at"]
    ):
        raise _blocked(
            "selected-run-attempt-mismatch",
            "exact workflow run-attempt identity or start timestamp differs",
        )
    cutover_variables = _exact_list(
        snapshot["cutover_input_variables"],
        label="cutover input variables",
    )
    latest_variable_updated_at = max(
        (
            _normalize_rfc3339_utc(
                _exact_dict(value, label="cutover input variable").get("updated_at"),
                label="cutover input variable updated timestamp",
            )
            for value in cutover_variables
        ),
        key=_rfc3339_utc_sort_key,
    )
    run_started_key = _rfc3339_utc_sort_key(selected_attempt["run_started_at"])
    latest_variable_key = _rfc3339_utc_sort_key(latest_variable_updated_at)
    if run_started_key == latest_variable_key:
        raise _blocked(
            "cutover-freshness-inconclusive",
            "selected run started at the latest cutover-input update timestamp",
        )
    if run_started_key < latest_variable_key:
        raise _blocked(
            "selected-run-predates-cutover-inputs",
            "selected run started before the latest cutover-input update",
        )
    return {
        "check_run": selected["check_run"],
        "freshness": {
            "latest_cutover_input_updated_at": latest_variable_updated_at,
            "run_started_at": selected_attempt["run_started_at"],
        },
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


def _validate_snapshot_enforcement(
    contract: dict[str, Any],
    snapshot: dict[str, Any],
    *,
    expected_run_attempt: int,
    expected_run_id: int,
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
            "cutover_input_variables",
            "effective_rulesets",
            "selected_run_attempt",
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
    _validate_cutover_input_variables(
        snapshot["cutover_input_variables"],
        expected_names=contract["cutover_input_variables"],
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
        expected_run_attempt=expected_run_attempt,
        expected_run_id=expected_run_id,
        expected_workflow_id=expected_workflow_id,
        candidate_head_sha=candidate_head_sha,
    )
    protected = {
        "cutover_input_variables": snapshot["cutover_input_variables"],
        "organization": snapshot["organization"],
        "repository": snapshot["repository"],
        "pull_request": snapshot["pull_request"],
        "selected_run_attempt": snapshot["selected_run_attempt"],
        "selected_ruleset": _ruleset_protected_fields(snapshot["selected_ruleset"]),
        "workflow_source_repository": snapshot["workflow_source_repository"],
        "workflow": snapshot["workflow"],
        "workflow_source_commit": snapshot["workflow_source_commit"],
        "same_name_lineage": trusted["same_name_lineage"],
    }
    return {
        "freshness": trusted["freshness"],
        "protected": protected,
        "trusted_check_run": trusted["check_run"],
        "trusted_job": trusted["job"],
        "trusted_run": trusted["run"],
    }


def _require_pointer_proof(contract: dict[str, Any]) -> None:
    pointer_authority = contract["pointer_authority"]
    if pointer_authority["status"] == "unavailable":
        raise _blocked(
            "pointer-proof-unavailable",
            "live private pointer authority is not configured",
        )
    raise _blocked(
        "pointer-proof-unavailable",
        "live private pointer proof has not been implemented for this authority",
    )


def validate_enforcement(
    contract: dict[str, Any],
    snapshot: dict[str, Any],
    *,
    expected_run_attempt: int,
    expected_run_id: int,
    expected_ruleset_id: int,
    expected_workflow_id: int,
    expected_workflow_sha: str,
    candidate_head_sha: str,
    pull_request_number: int,
) -> dict[str, Any]:
    loaded_contract = _load_contract(contract)
    admission = _validate_snapshot_enforcement(
        loaded_contract,
        snapshot,
        expected_run_attempt=expected_run_attempt,
        expected_run_id=expected_run_id,
        expected_ruleset_id=expected_ruleset_id,
        expected_workflow_id=expected_workflow_id,
        expected_workflow_sha=expected_workflow_sha,
        candidate_head_sha=candidate_head_sha,
        pull_request_number=pull_request_number,
    )
    _require_pointer_proof(loaded_contract)
    return admission


def _collect_and_validate_static(
    client: Any,
    contract: dict[str, Any],
    *,
    expected_run_attempt: int,
    expected_run_id: int,
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
        expected_run_attempt=expected_run_attempt,
        expected_run_id=expected_run_id,
        expected_ruleset_id=expected_ruleset_id,
        expected_workflow_id=expected_workflow_id,
        expected_workflow_sha=expected_workflow_sha,
        candidate_head_sha=candidate_head_sha,
        pull_request_number=pull_request_number,
    )
    initial_admission = _validate_snapshot_enforcement(
        contract,
        initial,
        expected_run_attempt=expected_run_attempt,
        expected_run_id=expected_run_id,
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
        expected_run_attempt=expected_run_attempt,
        expected_run_id=expected_run_id,
        expected_ruleset_id=expected_ruleset_id,
        expected_workflow_id=expected_workflow_id,
        expected_workflow_sha=expected_workflow_sha,
        candidate_head_sha=candidate_head_sha,
        pull_request_number=pull_request_number,
    )
    if initial["cutover_input_variables"] != revalidation["cutover_input_variables"]:
        raise _blocked(
            "cutover-input-drift",
            "cutover input variables changed during evidence collection",
        )
    revalidated_admission = _validate_snapshot_enforcement(
        contract,
        revalidation,
        expected_run_attempt=expected_run_attempt,
        expected_run_id=expected_run_id,
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
        "api_host": API_ORIGIN_HOST,
        "api_origin": API_ROOT,
        "api_version": API_VERSION,
        "authentication_host": AUTH_HOST,
        "authenticated_user": authenticated_user,
        "completed_at": completed_at,
        "gh_executable": {
            "environment_profile": getattr(
                client,
                "environment_profile",
                "test-double",
            ),
            "execution_source": getattr(client, "execution_source", "test-double"),
            "sha256": getattr(client, "executable_sha256", None),
        },
        "mode": "live-gh-rest",
        "object_reads": trace["object_reads"],
        "page_bounds": trace["page_bounds"],
        "schema_version": COLLECTOR_SCHEMA_VERSION,
        "started_at": started_at,
        "transport": {
            "executable": getattr(
                client,
                "transport_executable",
                os.fspath(CURL_EXECUTABLE),
            ),
            "profile": getattr(
                client,
                "transport_profile",
                "test-double",
            ),
        },
    }
    evidence = {
        "collector": collector_receipt,
        "initial": initial,
        "revalidation": revalidation,
        "schema_version": COLLECTOR_SCHEMA_VERSION,
    }
    return evidence, revalidated_admission


def collect_and_validate(
    client: Any,
    contract: dict[str, Any],
    *,
    expected_run_attempt: int,
    expected_run_id: int,
    expected_ruleset_id: int,
    expected_workflow_id: int,
    expected_workflow_sha: str,
    candidate_head_sha: str,
    pull_request_number: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    loaded_contract = _load_contract(contract)
    evidence, static_admission = _collect_and_validate_static(
        client,
        loaded_contract,
        expected_run_attempt=expected_run_attempt,
        expected_run_id=expected_run_id,
        expected_ruleset_id=expected_ruleset_id,
        expected_workflow_id=expected_workflow_id,
        expected_workflow_sha=expected_workflow_sha,
        candidate_head_sha=candidate_head_sha,
        pull_request_number=pull_request_number,
    )
    _require_pointer_proof(loaded_contract)
    return evidence, static_admission


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


def _sha256_argument(value: str) -> str:
    if SHA256_PATTERN.fullmatch(value) is None or set(value) == {"0"}:
        raise argparse.ArgumentTypeError("must be exact nonzero lowercase SHA-256")
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
        "--gh-executable",
        required=True,
        type=pathlib.Path,
    )
    parser.add_argument(
        "--expected-gh-sha256",
        required=True,
        type=_sha256_argument,
    )
    parser.add_argument(
        "--gh-config-dir",
        required=True,
        type=pathlib.Path,
    )
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
        "--expected-run-id",
        required=True,
        type=_positive_integer_argument,
    )
    parser.add_argument(
        "--expected-run-attempt",
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
    static_equivalence = None
    try:
        contract, contract_sha256 = _read_json(args.contract, label="contract")
        loaded_contract = _load_contract(contract)
        with GitHubApiClient(
            args.gh_executable,
            args.expected_gh_sha256,
            args.gh_config_dir,
        ) as client:
            evidence, admission = _collect_and_validate_static(
                client,
                loaded_contract,
                expected_run_attempt=args.expected_run_attempt,
                expected_run_id=args.expected_run_id,
                expected_ruleset_id=args.expected_ruleset_id,
                expected_workflow_id=args.expected_workflow_id,
                expected_workflow_sha=args.expected_workflow_sha,
                candidate_head_sha=args.candidate_head_sha,
                pull_request_number=args.pull_request_number,
            )
            client.revalidate_for_admission()
            evidence_sha256 = hashlib.sha256(
                _canonical_json_bytes(evidence)
            ).hexdigest()
            static_equivalence = "validated"
            _require_pointer_proof(loaded_contract)
    except EnforcementDoctorError as error:
        blocked_receipt = {
            "classification": "blocked_until_trusted",
            "contract_sha256": contract_sha256,
            "evidence_sha256": evidence_sha256,
            "operation": "cisco-cutover-enforcement-doctor",
            "reason": str(error),
            "reason_code": error.reason_code,
            "schema_version": DOCTOR_SCHEMA_VERSION,
            "static_equivalence": static_equivalence,
        }
        if error.api_failure is not None:
            blocked_receipt["api_failure"] = error.api_failure
        if error.cleanup_failure is not None:
            blocked_receipt["cleanup_failure"] = error.cleanup_failure
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
    sanitized_cutover_variables = [
        {
            "name": variable["name"],
            "updated_at": variable["updated_at"],
            "value_sha256": hashlib.sha256(
                variable["value"].encode("utf-8")
            ).hexdigest(),
        }
        for variable in revalidated_snapshot["cutover_input_variables"]
    ]
    print(
        json.dumps(
            {
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
                "cutover_freshness": admission["freshness"],
                "cutover_input_variables": sanitized_cutover_variables,
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
                "schema_version": DOCTOR_SCHEMA_VERSION,
                "static_equivalence": static_equivalence,
                "trusted_execution": {
                    "selection": {
                        "expected_run_attempt": args.expected_run_attempt,
                        "expected_run_id": args.expected_run_id,
                    },
                    "check_run": {
                        "app": trusted_check["app"],
                        "check_suite_id": trusted_check["check_suite_id"],
                        "completed_at": trusted_check["completed_at"],
                        "conclusion": trusted_check["conclusion"],
                        "details_url": trusted_check["details_url"],
                        "head_sha": trusted_check["head_sha"],
                        "html_url": trusted_check["html_url"],
                        "id": trusted_check["id"],
                        "name": trusted_check["name"],
                        "started_at": trusted_check["started_at"],
                        "status": trusted_check["status"],
                        "url": trusted_check["url"],
                    },
                    "job": {
                        "check_run_url": trusted_job["check_run_url"],
                        "completed_at": trusted_job["completed_at"],
                        "conclusion": trusted_job["conclusion"],
                        "head_sha": trusted_job["head_sha"],
                        "html_url": trusted_job["html_url"],
                        "id": trusted_job["id"],
                        "name": trusted_job["name"],
                        "run_attempt": trusted_job["run_attempt"],
                        "run_id": trusted_job["run_id"],
                        "run_url": trusted_job["run_url"],
                        "started_at": trusted_job["started_at"],
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
                        "run_started_at": trusted_run["run_started_at"],
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
