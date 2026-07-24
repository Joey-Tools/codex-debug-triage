#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
import time
from typing import Any

CONTRACT_SCHEMA_VERSION = 3
RECEIPT_SCHEMA_VERSION = 2
DEFAULT_MAX_JSON_BYTES = 64 * 1024
MAX_RECEIPT_BYTES = 35 * 1024
JSON_READ_TIMEOUT_SECONDS = 1.0
MAX_JSON_DEPTH = 64
MAX_JSON_CONTAINERS = 1_024
MAX_JSON_NODES = 4_096
MAX_JSON_CONTAINER_ITEMS = 1_024
MAX_JSON_INTEGER_DIGITS = 64
MAX_JSON_STRING_CHARS = 32 * 1024
MAX_BLOCKED_REASON_CHARS = 1_024
SHA1_PATTERN = re.compile(r"[0-9a-f]{40}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
POSITIVE_DECIMAL_PATTERN = re.compile(r"[1-9][0-9]*")
VALIDATOR_PATH = "scripts/validate_cisco_cutover_receipt.py"
REQUIRED_EXACT_INPUTS = [
    "expected_canonical_commit",
    "expected_pull_request_number",
    "expected_private_release_commit",
    "expected_release_manifest_sha256",
    "expected_receipt_sha256",
    "expected_workflow_id",
    "expected_workflow_sha",
]
EXPECTED_CANONICAL_REPOSITORY = "Joey-Tools/codex-debug-triage"
EXPECTED_CANONICAL_REPOSITORY_ID = 1242512092
EXPECTED_DEFAULT_BRANCH = "master"
EXPECTED_PRIVATE_AGGREGATE_REPOSITORY = "Joey-Tools/codex-private-workflows"
EXPECTED_WORKFLOW_PATH = ".github/workflows/cisco-cutover-admission.yml"
EXPECTED_WORKFLOW_REF = "refs/heads/master"
EXPECTED_WORKFLOW_EVENT = "pull_request_target"
EXPECTED_WORKFLOW_CHECK_NAME = "cisco-cutover-admission"
EXPECTED_ACTIVATION = {
    "release_kind": "immutable-private-overlay",
    "atomic": True,
    "provider": {
        "source": "personal_codex/skills/cisco-build-artifacts",
        "target": "skills/cisco-build-artifacts",
    },
    "routing_policy": {
        "source": "personal_codex/AGENTS.md",
        "target": "AGENTS.md",
        "cisco_build_fetch_and_archive": "skills/cisco-build-artifacts",
        "ordinary_local_diagnosis": "base-model-no-skill-route",
    },
    "catalog": {
        "manifest": "personal_codex/private-sync-manifest.json",
        "active_target": "skills/cisco-build-artifacts",
        "removed_target": "skills/bug-triage-playbook",
    },
    "removed_link": {
        "source": "personal_codex/skills/bug-triage-playbook",
        "target": "skills/bug-triage-playbook",
        "replacement_target": "skills/cisco-build-artifacts",
        "replacement_scope": "cisco-build-fetch-and-archive-only",
    },
    "public_asset": {
        "repository": "Joey-Tools/codex-debug-triage",
        "status": "optional-source-only",
        "installed_route": False,
    },
}
EXPECTED_TRUST_GATES = [
    "private-package-validation",
    "private-overlay-verifier",
    "immutable-release-published",
    "installed-current-pointer-verified",
]
EXPECTED_BLOCKED_TARGETS = [
    "canonical-bug-triage-retirement-pr",
    "private-consumer-source-sync",
]
EXPECTED_RETIREMENT_STATE_MACHINE = {
    "phases": [
        "bootstrap-workflow-merged",
        "retirement-pr-head-frozen",
        "private-release-receipt-published",
        "repository-variables-configured",
        "organization-ruleset-activated",
        "target-workflow-observed",
        "doctor-admitted",
        "merge-readiness-revalidated",
        "retirement-pr-merged",
    ],
    "head_change_transition": "retirement-pr-head-frozen",
    "mutation_authority": "explicit-repository-admin-or-organization-owner",
    "automatic_mutation": False,
}
EXPECTED_POST_CUTOVER_DECOMMISSION = {
    "trigger": "retirement-pr-merged-at-frozen-head",
    "lease_variable": "CISCO_CUTOVER_DECOMMISSION_LEASE",
    "compare_and_swap": {
        "coordination": "create-if-absent-repository-variable-lease",
        "observations": [
            "ruleset-id-and-canonical-sha256",
            "variable-name-value-sha256-and-updated-at",
            "workflow-path-and-blob-sha",
        ],
        "unsafe-conditional-requests-supported": False,
        "revalidate-before-each-mutation": True,
    },
    "ordered_steps": [
        "acquire-and-read-back-exclusive-lease",
        "revalidate-merged-pr-head-and-doctor-receipt",
        "disable-exact-ruleset-after-content-compare",
        "prove-ruleset-is-not-effective",
        "remove-workflow-in-separate-reviewed-pr",
        "prove-workflow-absent-and-ruleset-still-inactive",
        "delete-exact-cutover-variables-after-value-digest-and-updated-at-compare",
        "delete-exact-inactive-ruleset-after-content-compare",
        "prove-rule-variables-and-workflow-are-absent",
        "delete-lease-last",
    ],
    "failure_policy": {
        "before-ruleset-inactive": "leave-workflow-and-all-variables-intact",
        "after-ruleset-inactive": "keep-ruleset-inactive-and-resume-cleanup",
        "concurrent-drift": "abort-before-next-mutation",
    },
    "automatic_mutation": False,
}


class ReceiptAdmissionError(ValueError):
    pass


def _reject_json_constant(value: str) -> None:
    raise ReceiptAdmissionError(f"non-finite JSON value is forbidden: {value}")


def _reject_json_float(value: str) -> None:
    raise ReceiptAdmissionError(f"JSON floating-point value is forbidden: {value}")


def _parse_bounded_json_integer(value: str) -> int:
    digits = value.removeprefix("-")
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise ReceiptAdmissionError(
            "JSON integer exceeds max digits: "
            f"{len(digits)} > {MAX_JSON_INTEGER_DIGITS}"
        )
    return int(value)


def _object_without_duplicates(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptAdmissionError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _check_json_structure(decoded: str, *, label: str) -> None:
    depth = 0
    containers = 0
    in_string = False
    escaped = False
    for character in decoded:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            containers += 1
            if depth > MAX_JSON_DEPTH:
                raise ReceiptAdmissionError(
                    f"{label} exceeds max JSON depth: {depth} > {MAX_JSON_DEPTH}"
                )
            if containers > MAX_JSON_CONTAINERS:
                raise ReceiptAdmissionError(
                    f"{label} exceeds max JSON containers: "
                    f"{containers} > {MAX_JSON_CONTAINERS}"
                )
        elif character in "]}":
            depth = max(0, depth - 1)


def _check_json_resources(parsed: object, *, label: str) -> None:
    nodes = 0
    pending: list[tuple[object, int]] = [(parsed, 1)]
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ReceiptAdmissionError(
                f"{label} exceeds max JSON nodes: {nodes} > {MAX_JSON_NODES}"
            )
        if type(value) is dict:
            if depth > MAX_JSON_DEPTH:
                raise ReceiptAdmissionError(
                    f"{label} exceeds max JSON depth: {depth} > {MAX_JSON_DEPTH}"
                )
            if len(value) > MAX_JSON_CONTAINER_ITEMS:
                raise ReceiptAdmissionError(
                    f"{label} object exceeds max items: "
                    f"{len(value)} > {MAX_JSON_CONTAINER_ITEMS}"
                )
            for key, item in value.items():
                if type(key) is not str:
                    raise ReceiptAdmissionError(
                        f"{label} object key must be an exact string"
                    )
                if len(key) > MAX_JSON_STRING_CHARS:
                    raise ReceiptAdmissionError(
                        f"{label} object key exceeds max characters"
                    )
                nodes += 1
                if nodes > MAX_JSON_NODES:
                    raise ReceiptAdmissionError(
                        f"{label} exceeds max JSON nodes: {nodes} > {MAX_JSON_NODES}"
                    )
                pending.append((item, depth + 1))
        elif type(value) is list:
            if depth > MAX_JSON_DEPTH:
                raise ReceiptAdmissionError(
                    f"{label} exceeds max JSON depth: {depth} > {MAX_JSON_DEPTH}"
                )
            if len(value) > MAX_JSON_CONTAINER_ITEMS:
                raise ReceiptAdmissionError(
                    f"{label} array exceeds max items: "
                    f"{len(value)} > {MAX_JSON_CONTAINER_ITEMS}"
                )
            pending.extend((item, depth + 1) for item in value)
        elif type(value) is str:
            if len(value) > MAX_JSON_STRING_CHARS:
                raise ReceiptAdmissionError(
                    f"{label} string exceeds max characters: "
                    f"{len(value)} > {MAX_JSON_STRING_CHARS}"
                )
        elif type(value) not in (int, bool, type(None)):
            raise ReceiptAdmissionError(
                f"{label} contains an unsupported JSON scalar type"
            )


def _check_read_deadline(deadline: float, *, label: str, operation: str) -> None:
    if time.monotonic() >= deadline:
        raise ReceiptAdmissionError(
            f"{label} exceeded read deadline during {operation}"
        )


def _read_exact_json(
    path: pathlib.Path,
    *,
    label: str,
    max_bytes: int,
) -> tuple[dict[str, Any], str]:
    deadline = time.monotonic() + JSON_READ_TIMEOUT_SECONDS
    missing_flags = [
        name for name in ("O_NOFOLLOW", "O_NONBLOCK") if not hasattr(os, name)
    ]
    if missing_flags:
        raise ReceiptAdmissionError(
            f"{label} safe open flags are unavailable: {','.join(missing_flags)}"
        )
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    flags |= getattr(os, "O_CLOEXEC", 0)
    _check_read_deadline(deadline, label=label, operation="open")
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise ReceiptAdmissionError(
            f"{label} could not be opened safely: {error.strerror or error}"
        ) from error
    try:
        _check_read_deadline(deadline, label=label, operation="open")
        metadata = os.fstat(fd)
        _check_read_deadline(deadline, label=label, operation="initial metadata")
        if not stat.S_ISREG(metadata.st_mode):
            raise ReceiptAdmissionError(f"{label} must be a regular file")
        if metadata.st_size > max_bytes:
            raise ReceiptAdmissionError(
                f"{label} exceeds max bytes: {metadata.st_size} > {max_bytes}"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            _check_read_deadline(deadline, label=label, operation="read")
            try:
                chunk = os.read(fd, min(16 * 1024, max_bytes + 1 - total))
            except BlockingIOError as error:
                raise ReceiptAdmissionError(
                    f"{label} could not be read without blocking"
                ) from error
            _check_read_deadline(deadline, label=label, operation="read")
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ReceiptAdmissionError(f"{label} exceeds max bytes while reading")
        final_metadata = os.fstat(fd)
        _check_read_deadline(deadline, label=label, operation="final metadata")
        if (
            final_metadata.st_dev != metadata.st_dev
            or final_metadata.st_ino != metadata.st_ino
            or final_metadata.st_size != metadata.st_size
            or total != metadata.st_size
        ):
            raise ReceiptAdmissionError(f"{label} changed while being read")
    finally:
        os.close(fd)

    raw = b"".join(chunks)
    digest = hashlib.sha256(raw).hexdigest()
    try:
        decoded = raw.decode("utf-8")
        _check_json_structure(decoded, label=label)
        parsed = json.loads(
            decoded,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_json_constant,
            parse_float=_reject_json_float,
            parse_int=_parse_bounded_json_integer,
        )
    except ReceiptAdmissionError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
        OverflowError,
    ) as error:
        raise ReceiptAdmissionError(f"{label} is not strict UTF-8 JSON") from error
    _check_json_resources(parsed, label=label)
    if type(parsed) is not dict:
        raise ReceiptAdmissionError(f"{label} root must be an object")
    return parsed, digest


def _require_exact_keys(
    value: object,
    expected: set[str],
    *,
    label: str,
) -> dict[str, Any]:
    if type(value) is not dict:
        raise ReceiptAdmissionError(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ReceiptAdmissionError(
            f"{label} keys differ: missing={missing}; extra={extra}"
        )
    return value


def _require_string(value: object, *, label: str) -> str:
    if type(value) is not str or not value:
        raise ReceiptAdmissionError(f"{label} must be a non-empty string")
    return value


def _require_exact_json(value: object, expected: object, *, label: str) -> None:
    if type(value) is not type(expected):
        raise ReceiptAdmissionError(f"{label} has the wrong exact JSON type")
    if type(expected) is dict:
        actual_object = _require_exact_keys(
            value,
            set(expected),
            label=label,
        )
        for key, expected_item in expected.items():
            _require_exact_json(
                actual_object[key],
                expected_item,
                label=f"{label}.{key}",
            )
        return
    if type(expected) is list:
        if len(value) != len(expected):
            raise ReceiptAdmissionError(f"{label} has the wrong array length")
        for index, (actual_item, expected_item) in enumerate(zip(value, expected)):
            _require_exact_json(
                actual_item,
                expected_item,
                label=f"{label}[{index}]",
            )
        return
    if value != expected:
        raise ReceiptAdmissionError(f"{label} differs from the exact expected value")


def _require_sha1(value: object, *, label: str) -> str:
    rendered = _require_string(value, label=label)
    if SHA1_PATTERN.fullmatch(rendered) is None or rendered == ("0" * 40):
        raise ReceiptAdmissionError(f"{label} must be exact lowercase 40-hex")
    return rendered


def _require_sha256(value: object, *, label: str) -> str:
    rendered = _require_string(value, label=label)
    if SHA256_PATTERN.fullmatch(rendered) is None or rendered == ("0" * 64):
        raise ReceiptAdmissionError(f"{label} must be exact lowercase 64-hex")
    return rendered


def _require_positive_decimal(value: object, *, label: str) -> int:
    rendered = _require_string(value, label=label)
    if POSITIVE_DECIMAL_PATTERN.fullmatch(rendered) is None:
        raise ReceiptAdmissionError(f"{label} must be canonical positive decimal")
    return int(rendered, 10)


def _validate_contract(contract: dict[str, Any]) -> dict[str, Any]:
    contract = _require_exact_keys(
        contract,
        {
            "schema_version",
            "canonical_repository",
            "canonical_merge_changes_installed_routing",
            "private_aggregate_repository",
            "activation",
            "trust_gates",
            "blocked_until_trusted",
            "unproved_atomicity_fallback",
            "retirement_state_machine",
            "post_cutover_decommission",
            "receipt_admission",
        },
        label="contract",
    )
    _require_exact_json(
        contract["schema_version"],
        CONTRACT_SCHEMA_VERSION,
        label="contract schema_version",
    )
    _require_exact_json(
        contract["canonical_merge_changes_installed_routing"],
        False,
        label="contract canonical_merge_changes_installed_routing",
    )
    _require_exact_json(
        contract["canonical_repository"],
        EXPECTED_CANONICAL_REPOSITORY,
        label="contract canonical_repository",
    )
    _require_exact_json(
        contract["private_aggregate_repository"],
        EXPECTED_PRIVATE_AGGREGATE_REPOSITORY,
        label="contract private_aggregate_repository",
    )
    _require_exact_json(
        contract["activation"],
        EXPECTED_ACTIVATION,
        label="contract activation",
    )
    gates = contract["trust_gates"]
    _require_exact_json(
        gates,
        EXPECTED_TRUST_GATES,
        label="contract trust_gates",
    )
    blocked = contract["blocked_until_trusted"]
    _require_exact_json(
        blocked,
        EXPECTED_BLOCKED_TARGETS,
        label="contract blocked_until_trusted",
    )
    _require_exact_json(
        contract["unproved_atomicity_fallback"],
        "retain-bug-triage-compat",
        label="contract unproved_atomicity_fallback",
    )
    _require_exact_json(
        contract["retirement_state_machine"],
        EXPECTED_RETIREMENT_STATE_MACHINE,
        label="contract retirement_state_machine",
    )
    _require_exact_json(
        contract["post_cutover_decommission"],
        EXPECTED_POST_CUTOVER_DECOMMISSION,
        label="contract post_cutover_decommission",
    )
    admission = _require_exact_keys(
        contract["receipt_admission"],
        {
            "status_without_receipt",
            "validator",
            "receipt_schema_version",
            "receipt_max_bytes",
            "producer_workflow",
            "pointer_name",
            "pointer_target_template",
            "required_exact_inputs",
        },
        label="contract receipt_admission",
    )
    expected_admission = {
        "status_without_receipt": "blocked_until_trusted",
        "validator": VALIDATOR_PATH,
        "receipt_schema_version": RECEIPT_SCHEMA_VERSION,
        "receipt_max_bytes": MAX_RECEIPT_BYTES,
        "producer_workflow": ".github/workflows/release.yml",
        "pointer_name": "current",
        "pointer_target_template": "releases/{private_release_commit}",
        "required_exact_inputs": REQUIRED_EXACT_INPUTS,
    }
    _require_exact_json(
        admission,
        expected_admission,
        label="contract receipt_admission",
    )
    return contract


def _validate_receipt(
    receipt: dict[str, Any],
    contract: dict[str, Any],
    *,
    expected_canonical_commit: str,
    expected_private_release_commit: str,
    expected_release_manifest_sha256: str,
    expected_pull_request_number: int,
    expected_workflow_id: int,
    expected_workflow_sha: str,
) -> str:
    receipt = _require_exact_keys(
        receipt,
        {
            "schema_version",
            "canonical_repository",
            "canonical_commit",
            "private_aggregate_repository",
            "private_release_commit",
            "release_manifest_sha256",
            "release_target",
            "cutover",
            "activation",
            "gates",
            "installed_pointer",
        },
        label="receipt",
    )
    _require_exact_json(
        receipt["schema_version"],
        RECEIPT_SCHEMA_VERSION,
        label="receipt schema_version",
    )
    _require_exact_json(
        receipt["canonical_repository"],
        contract["canonical_repository"],
        label="receipt canonical_repository",
    )
    _require_exact_json(
        receipt["private_aggregate_repository"],
        contract["private_aggregate_repository"],
        label="receipt private_aggregate_repository",
    )
    if (
        _require_sha1(
            receipt["canonical_commit"],
            label="receipt canonical_commit",
        )
        != expected_canonical_commit
    ):
        raise ReceiptAdmissionError("receipt canonical commit differs")
    if (
        _require_sha1(
            receipt["private_release_commit"],
            label="receipt private_release_commit",
        )
        != expected_private_release_commit
    ):
        raise ReceiptAdmissionError("receipt private release commit differs")
    if (
        _require_sha256(
            receipt["release_manifest_sha256"],
            label="receipt release_manifest_sha256",
        )
        != expected_release_manifest_sha256
    ):
        raise ReceiptAdmissionError("receipt release manifest digest differs")
    expected_target = f"releases/{expected_private_release_commit}"
    _require_exact_json(
        receipt["release_target"],
        expected_target,
        label="receipt release_target",
    )
    expected_cutover = {
        "target_repository": {
            "id": EXPECTED_CANONICAL_REPOSITORY_ID,
            "full_name": EXPECTED_CANONICAL_REPOSITORY,
            "default_branch": EXPECTED_DEFAULT_BRANCH,
        },
        "pull_request": {
            "number": expected_pull_request_number,
            "head_sha": expected_canonical_commit,
            "base_ref": EXPECTED_DEFAULT_BRANCH,
        },
        "required_workflow": {
            "id": expected_workflow_id,
            "repository_id": EXPECTED_CANONICAL_REPOSITORY_ID,
            "repository_full_name": EXPECTED_CANONICAL_REPOSITORY,
            "path": EXPECTED_WORKFLOW_PATH,
            "ref": EXPECTED_WORKFLOW_REF,
            "sha": expected_workflow_sha,
            "event": EXPECTED_WORKFLOW_EVENT,
            "check_name": EXPECTED_WORKFLOW_CHECK_NAME,
        },
    }
    _require_exact_json(
        receipt["cutover"],
        expected_cutover,
        label="receipt cutover",
    )
    _require_exact_json(
        receipt["activation"],
        contract["activation"],
        label="receipt activation",
    )

    gate_names = contract["trust_gates"]
    gates = receipt["gates"]
    if type(gates) is not list or len(gates) != len(gate_names):
        raise ReceiptAdmissionError("receipt gates do not cover the exact gate set")
    for expected_name, gate_value in zip(gate_names, gates):
        gate = _require_exact_keys(
            gate_value,
            {
                "name",
                "status",
                "private_release_commit",
                "release_manifest_sha256",
            },
            label=f"receipt gate {expected_name}",
        )
        _require_exact_json(
            gate,
            {
                "name": expected_name,
                "status": "passed",
                "private_release_commit": expected_private_release_commit,
                "release_manifest_sha256": expected_release_manifest_sha256,
            },
            label=f"receipt gate {expected_name}",
        )

    pointer = _require_exact_keys(
        receipt["installed_pointer"],
        {
            "name",
            "target",
            "resolved_release_commit",
            "release_manifest_sha256",
        },
        label="receipt installed pointer",
    )
    _require_exact_json(
        pointer,
        {
            "name": "current",
            "target": expected_target,
            "resolved_release_commit": expected_private_release_commit,
            "release_manifest_sha256": expected_release_manifest_sha256,
        },
        label="receipt installed pointer",
    )
    return expected_target


def _blocked(reason: str) -> int:
    if len(reason) > MAX_BLOCKED_REASON_CHARS:
        reason = f"{reason[: MAX_BLOCKED_REASON_CHARS - 16]}... [truncated]"
    print(
        json.dumps(
            {
                "classification": "blocked_until_trusted",
                "reason": reason,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 1


class ReceiptArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        _blocked(f"argument error: {message}")
        raise SystemExit(2)


def _parser() -> argparse.ArgumentParser:
    parser = ReceiptArgumentParser(
        description=("Admit an exact private Cisco cutover release/pointer receipt.")
    )
    parser.add_argument("--contract", required=True)
    parser.add_argument("--receipt")
    parser.add_argument("--expected-canonical-commit")
    parser.add_argument("--expected-pull-request-number")
    parser.add_argument("--expected-private-release-commit")
    parser.add_argument("--expected-release-manifest-sha256")
    parser.add_argument("--expected-receipt-sha256")
    parser.add_argument("--expected-workflow-id")
    parser.add_argument("--expected-workflow-sha")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        contract, _ = _read_exact_json(
            pathlib.Path(args.contract),
            label="contract",
            max_bytes=DEFAULT_MAX_JSON_BYTES,
        )
        contract = _validate_contract(contract)
        if args.receipt is None:
            return _blocked("trusted receipt path was not provided")

        expectations = {
            "expected_canonical_commit": args.expected_canonical_commit,
            "expected_pull_request_number": args.expected_pull_request_number,
            "expected_private_release_commit": (args.expected_private_release_commit),
            "expected_release_manifest_sha256": (args.expected_release_manifest_sha256),
            "expected_receipt_sha256": args.expected_receipt_sha256,
            "expected_workflow_id": args.expected_workflow_id,
            "expected_workflow_sha": args.expected_workflow_sha,
        }
        missing = [name for name in REQUIRED_EXACT_INPUTS if not expectations[name]]
        if missing:
            return _blocked(
                f"trusted exact expectations were not provided: {','.join(missing)}"
            )

        expected_canonical_commit = _require_sha1(
            args.expected_canonical_commit,
            label="expected canonical commit",
        )
        expected_private_release_commit = _require_sha1(
            args.expected_private_release_commit,
            label="expected private release commit",
        )
        expected_release_manifest_sha256 = _require_sha256(
            args.expected_release_manifest_sha256,
            label="expected release manifest sha256",
        )
        expected_receipt_sha256 = _require_sha256(
            args.expected_receipt_sha256,
            label="expected receipt sha256",
        )
        expected_pull_request_number = _require_positive_decimal(
            args.expected_pull_request_number,
            label="expected pull-request number",
        )
        expected_workflow_id = _require_positive_decimal(
            args.expected_workflow_id,
            label="expected workflow ID",
        )
        expected_workflow_sha = _require_sha1(
            args.expected_workflow_sha,
            label="expected workflow SHA",
        )
        receipt, receipt_sha256 = _read_exact_json(
            pathlib.Path(args.receipt),
            label="receipt",
            max_bytes=contract["receipt_admission"]["receipt_max_bytes"],
        )
        if receipt_sha256 != expected_receipt_sha256:
            raise ReceiptAdmissionError(
                "receipt bytes do not match the trusted exact digest"
            )
        pointer_target = _validate_receipt(
            receipt,
            contract,
            expected_canonical_commit=expected_canonical_commit,
            expected_private_release_commit=expected_private_release_commit,
            expected_release_manifest_sha256=(expected_release_manifest_sha256),
            expected_pull_request_number=expected_pull_request_number,
            expected_workflow_id=expected_workflow_id,
            expected_workflow_sha=expected_workflow_sha,
        )
    except (OSError, ReceiptAdmissionError) as error:
        return _blocked(str(error))

    print(
        json.dumps(
            {
                "canonical_commit": expected_canonical_commit,
                "classification": "admitted",
                "pointer_target": pointer_target,
                "private_release_commit": expected_private_release_commit,
                "pull_request_number": expected_pull_request_number,
                "receipt_sha256": receipt_sha256,
                "release_manifest_sha256": expected_release_manifest_sha256,
                "workflow_id": expected_workflow_id,
                "workflow_sha": expected_workflow_sha,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
