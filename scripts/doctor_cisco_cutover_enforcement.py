#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
from typing import Any

CONTRACT_SCHEMA_VERSION = 1
EVIDENCE_SCHEMA_VERSION = 1
MAX_JSON_BYTES = 512 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 16_384
MAX_JSON_CONTAINER_ITEMS = 4_096
MAX_JSON_INTEGER_DIGITS = 64
MAX_JSON_STRING_CHARS = 64 * 1024
SHA1_PATTERN = re.compile(r"[0-9a-f]{40}")


class EnforcementDoctorError(ValueError):
    def __init__(self, reason_code: str, reason: str) -> None:
        super().__init__(reason)
        self.reason_code = reason_code


def _blocked(reason_code: str, reason: str) -> EnforcementDoctorError:
    return EnforcementDoctorError(reason_code, reason)


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
        raise _blocked("unsafe-input", f"cannot safely open {label}: {error}") from error
    try:
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise _blocked("unsafe-input", f"{label} must be a regular file")
            if before.st_size > MAX_JSON_BYTES:
                raise _blocked("unsafe-input", f"{label} exceeds max bytes")
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
            after = os.fstat(fd)
        except OSError as error:
            raise _blocked(
                "unsafe-input",
                f"cannot safely read {label}: {error}",
            ) from error
    finally:
        os.close(fd)
    protected_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    protected_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    if protected_after != protected_before:
        raise _blocked("unsafe-input", f"{label} changed while it was read")
    payload = b"".join(chunks)
    if len(payload) != before.st_size:
        raise _blocked("unsafe-input", f"{label} read was incomplete")
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
    if type(parsed) is not dict:
        raise _blocked("invalid-json", f"{label} must be a JSON object")
    return parsed, hashlib.sha256(payload).hexdigest()


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


def _load_contract(contract: dict[str, Any]) -> dict[str, Any]:
    _exact_keys(
        contract,
        {
            "schema_version",
            "target_repository",
            "ruleset",
            "required_workflow",
            "disallowed_status_contexts",
            "required_collection_flags",
        },
        label="contract",
    )
    if contract["schema_version"] != CONTRACT_SCHEMA_VERSION:
        raise _blocked("invalid-contract", "contract schema version differs")
    target = _exact_dict(contract["target_repository"], label="contract target")
    _exact_keys(target, {"id", "full_name", "default_branch"}, label="contract target")
    _exact_positive_integer(target["id"], label="contract repository ID")
    _exact_string(target["full_name"], label="contract repository name")
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
            "do_not_enforce_on_create",
            "require_exact_sha",
        },
        label="contract workflow",
    )
    if workflow["repository_id"] != target["id"]:
        raise _blocked("invalid-contract", "contract workflow repository ID differs")
    if workflow["repository_full_name"] != target["full_name"]:
        raise _blocked("invalid-contract", "contract workflow repository differs")
    if workflow["ref"] != f"refs/heads/{target['default_branch']}":
        raise _blocked("invalid-contract", "contract workflow ref is not default branch")
    if workflow["require_exact_sha"] is not True:
        raise _blocked("invalid-contract", "contract must require an exact workflow SHA")
    if workflow["do_not_enforce_on_create"] is not False:
        raise _blocked("invalid-contract", "contract permits enforcement bypass on create")
    disallowed = _exact_list(
        contract["disallowed_status_contexts"],
        label="contract disallowed status contexts",
    )
    if disallowed != [workflow["check_name"]]:
        raise _blocked("invalid-contract", "contract status-context denylist differs")
    flags = _exact_list(
        contract["required_collection_flags"],
        label="contract collection flags",
    )
    if not flags or any(type(flag) is not str or not flag for flag in flags):
        raise _blocked("invalid-contract", "contract collection flags are invalid")
    return contract


def _validate_repository(
    evidence: dict[str, Any],
    *,
    target: dict[str, Any],
) -> None:
    repository = _exact_dict(evidence.get("repository"), label="repository evidence")
    _exact_keys(
        repository,
        {"id", "full_name", "default_branch", "archived", "disabled"},
        label="repository evidence",
    )
    if (
        repository["id"] != target["id"]
        or repository["full_name"] != target["full_name"]
        or repository["default_branch"] != target["default_branch"]
    ):
        raise _blocked(
            "repository-identity-mismatch",
            "repository identity does not match the contract",
        )
    if repository["archived"] is not False or repository["disabled"] is not False:
        raise _blocked("repository-unavailable", "repository is archived or disabled")


def _status_contexts(rulesets: list[Any]) -> set[str]:
    contexts: set[str] = set()
    for ruleset_value in rulesets:
        ruleset = _exact_dict(ruleset_value, label="ruleset")
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


def _validate_ruleset(
    evidence: dict[str, Any],
    *,
    contract: dict[str, Any],
    expected_ruleset_id: int,
    expected_workflow_sha: str,
) -> None:
    rulesets = _exact_list(evidence.get("rulesets"), label="rulesets evidence")
    disallowed = set(contract["disallowed_status_contexts"])
    spoofable = sorted(_status_contexts(rulesets) & disallowed)
    if spoofable:
        raise _blocked(
            "spoofable-status-rule",
            "same-name required_status_checks is not workflow identity enforcement",
        )
    selected = [
        _exact_dict(value, label="ruleset")
        for value in rulesets
        if type(value) is dict and value.get("id") == expected_ruleset_id
    ]
    if len(selected) != 1:
        raise _blocked(
            "ruleset-identity-mismatch",
            "exact administrator-pinned ruleset ID is absent or ambiguous",
        )
    ruleset = selected[0]
    expected = contract["ruleset"]
    for field in ("source_type", "source", "target"):
        if ruleset.get(field) != expected[field]:
            raise _blocked(
                "ruleset-identity-mismatch",
                f"ruleset {field} differs from the contract",
            )
    if ruleset.get("enforcement") != "active":
        raise _blocked("ruleset-not-active", "required workflow ruleset is not active")
    if ruleset.get("bypass_actors") != []:
        raise _blocked(
            "ruleset-bypass-configured",
            "required workflow ruleset has bypass actors",
        )
    if ruleset.get("conditions") != expected["conditions"]:
        raise _blocked(
            "ruleset-scope-mismatch",
            "required workflow ruleset does not target only the default branch",
        )
    rules = _exact_list(ruleset.get("rules"), label="selected ruleset rules")
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
            "required workflow repository, path, ref, or SHA differs",
        )


def _workflow_identity(
    value: dict[str, Any],
    *,
    workflow_id: int,
    workflow_contract: dict[str, Any],
    workflow_sha: str,
) -> bool:
    return (
        value.get("workflow_id") == workflow_id
        and value.get("repository_id") == workflow_contract["repository_id"]
        and value.get("workflow_path") == workflow_contract["path"]
        and value.get("workflow_ref") == workflow_contract["ref"]
        and value.get("workflow_sha") == workflow_sha
    )


def _validate_workflow_metadata(
    evidence: dict[str, Any],
    *,
    workflow_id: int,
    workflow_contract: dict[str, Any],
    workflow_sha: str,
) -> None:
    workflow = _exact_dict(evidence.get("workflow"), label="workflow metadata")
    _exact_keys(
        workflow,
        {
            "id",
            "repository_id",
            "repository_full_name",
            "path",
            "ref",
            "sha",
            "state",
        },
        label="workflow metadata",
    )
    expected = {
        "id": workflow_id,
        "repository_id": workflow_contract["repository_id"],
        "repository_full_name": workflow_contract["repository_full_name"],
        "path": workflow_contract["path"],
        "ref": workflow_contract["ref"],
        "sha": workflow_sha,
        "state": workflow_contract["state"],
    }
    if workflow != expected:
        raise _blocked(
            "workflow-identity-mismatch",
            "workflow metadata does not match the administrator-pinned identity",
        )


def _validate_candidate_evidence(
    evidence: dict[str, Any],
    *,
    candidate_head_sha: str,
    workflow_id: int,
    workflow_contract: dict[str, Any],
    workflow_sha: str,
) -> tuple[int, int]:
    candidate = _exact_dict(evidence.get("candidate"), label="candidate evidence")
    _exact_keys(
        candidate,
        {"head_sha", "trusted_workflow_run", "check_runs"},
        label="candidate evidence",
    )
    if candidate.get("head_sha") != candidate_head_sha:
        raise _blocked(
            "candidate-head-mismatch",
            "candidate evidence head differs from the frozen head",
        )
    check_runs = _exact_list(candidate.get("check_runs"), label="candidate check runs")
    check_name = workflow_contract["check_name"]
    trusted_checks: list[dict[str, Any]] = []
    for value in check_runs:
        check = _exact_dict(value, label="candidate check run")
        _exact_keys(
            check,
            {
                "id",
                "name",
                "head_sha",
                "status",
                "conclusion",
                "workflow_id",
                "repository_id",
                "workflow_path",
                "workflow_ref",
                "workflow_sha",
            },
            label="candidate check run",
        )
        if check["head_sha"] != candidate_head_sha:
            raise _blocked(
                "candidate-head-mismatch",
                "check-run evidence includes another head",
            )
        if check["name"] != check_name:
            continue
        if not _workflow_identity(
            check,
            workflow_id=workflow_id,
            workflow_contract=workflow_contract,
            workflow_sha=workflow_sha,
        ):
            raise _blocked(
                "candidate-duplicate-context",
                "same-name check was produced outside the trusted workflow identity",
            )
        trusted_checks.append(check)
    if len(trusted_checks) != 1:
        raise _blocked(
            "trusted-check-missing",
            "exactly one trusted workflow check must bind the candidate head",
        )
    trusted_check = trusted_checks[0]
    if (
        trusted_check["status"] != "completed"
        or trusted_check["conclusion"] != "success"
    ):
        raise _blocked(
            "trusted-check-failed",
            "trusted workflow check is absent, incomplete, or not successful",
        )
    run = candidate.get("trusted_workflow_run")
    if run is None:
        raise _blocked(
            "trusted-workflow-run-missing",
            "trusted required-workflow run is absent",
        )
    run = _exact_dict(run, label="trusted workflow run")
    _exact_keys(
        run,
        {
            "id",
            "run_attempt",
            "workflow_id",
            "repository_id",
            "workflow_path",
            "workflow_ref",
            "workflow_sha",
            "candidate_head_sha",
            "event",
            "status",
            "conclusion",
        },
        label="trusted workflow run",
    )
    if not _workflow_identity(
        run,
        workflow_id=workflow_id,
        workflow_contract=workflow_contract,
        workflow_sha=workflow_sha,
    ):
        raise _blocked(
            "trusted-workflow-run-mismatch",
            "trusted run identity differs from the required workflow",
        )
    if run["candidate_head_sha"] != candidate_head_sha:
        raise _blocked(
            "candidate-head-mismatch",
            "trusted run does not bind the frozen candidate head",
        )
    if run["event"] != workflow_contract["event"]:
        raise _blocked(
            "trusted-workflow-run-mismatch",
            "trusted run event differs from the contract",
        )
    if run["status"] != "completed" or run["conclusion"] != "success":
        raise _blocked(
            "trusted-workflow-run-failed",
            "trusted required-workflow run is incomplete or not successful",
        )
    return (
        _exact_positive_integer(run["id"], label="trusted workflow run ID"),
        _exact_positive_integer(trusted_check["id"], label="trusted check-run ID"),
    )


def validate_enforcement(
    contract: dict[str, Any],
    evidence: dict[str, Any],
    *,
    expected_ruleset_id: int,
    expected_workflow_id: int,
    expected_workflow_sha: str,
    candidate_head_sha: str,
) -> tuple[int, int]:
    contract = _load_contract(contract)
    _exact_keys(
        evidence,
        {
            "schema_version",
            "collection",
            "repository",
            "workflow",
            "rulesets",
            "candidate",
        },
        label="evidence",
    )
    if evidence["schema_version"] != EVIDENCE_SCHEMA_VERSION:
        raise _blocked("invalid-evidence", "evidence schema version differs")
    collection = _exact_dict(evidence["collection"], label="collection evidence")
    required_flags = contract["required_collection_flags"]
    if set(collection) != set(required_flags):
        raise _blocked("evidence-incomplete", "collection completeness fields differ")
    incomplete = [flag for flag in required_flags if collection.get(flag) is not True]
    if incomplete:
        raise _blocked(
            "evidence-incomplete",
            f"evidence collection is incomplete: {','.join(incomplete)}",
        )
    _validate_repository(evidence, target=contract["target_repository"])
    _validate_ruleset(
        evidence,
        contract=contract,
        expected_ruleset_id=expected_ruleset_id,
        expected_workflow_sha=expected_workflow_sha,
    )
    workflow_contract = contract["required_workflow"]
    _validate_workflow_metadata(
        evidence,
        workflow_id=expected_workflow_id,
        workflow_contract=workflow_contract,
        workflow_sha=expected_workflow_sha,
    )
    return _validate_candidate_evidence(
        evidence,
        candidate_head_sha=candidate_head_sha,
        workflow_id=expected_workflow_id,
        workflow_contract=workflow_contract,
        workflow_sha=expected_workflow_sha,
    )


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
            "Verify identity-bound GitHub required-workflow enforcement for "
            "the Cisco provider cutover."
        )
    )
    parser.add_argument("--contract", required=True, type=pathlib.Path)
    parser.add_argument("--evidence", required=True, type=pathlib.Path)
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
        evidence, evidence_sha256 = _read_json(args.evidence, label="evidence")
        trusted_run_id, trusted_check_run_id = validate_enforcement(
            contract,
            evidence,
            expected_ruleset_id=args.expected_ruleset_id,
            expected_workflow_id=args.expected_workflow_id,
            expected_workflow_sha=args.expected_workflow_sha,
            candidate_head_sha=args.candidate_head_sha,
        )
    except EnforcementDoctorError as error:
        print(
            json.dumps(
                {
                    "classification": "blocked_until_trusted",
                    "contract_sha256": contract_sha256,
                    "evidence_sha256": evidence_sha256,
                    "operation": "cisco-cutover-enforcement-doctor",
                    "reason": str(error),
                    "reason_code": error.reason_code,
                    "schema_version": 1,
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 1
    print(
        json.dumps(
            {
                "candidate_head_sha": args.candidate_head_sha,
                "classification": "admitted",
                "contract_sha256": contract_sha256,
                "evidence_sha256": evidence_sha256,
                "operation": "cisco-cutover-enforcement-doctor",
                "repository": contract["target_repository"],
                "ruleset_id": args.expected_ruleset_id,
                "schema_version": 1,
                "trusted_check_run_id": trusted_check_run_id,
                "trusted_workflow": {
                    "id": args.expected_workflow_id,
                    "path": contract["required_workflow"]["path"],
                    "ref": contract["required_workflow"]["ref"],
                    "repository_id": contract["required_workflow"]["repository_id"],
                    "sha": args.expected_workflow_sha,
                },
                "trusted_workflow_run_id": trusted_run_id,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
