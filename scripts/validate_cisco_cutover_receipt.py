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


CONTRACT_SCHEMA_VERSION = 2
RECEIPT_SCHEMA_VERSION = 1
DEFAULT_MAX_JSON_BYTES = 64 * 1024
MAX_BLOCKED_REASON_CHARS = 1_024
SHA1_PATTERN = re.compile(r"[0-9a-f]{40}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
VALIDATOR_PATH = "scripts/validate_cisco_cutover_receipt.py"
REQUIRED_EXACT_INPUTS = [
    "expected_canonical_commit",
    "expected_private_release_commit",
    "expected_release_manifest_sha256",
    "expected_receipt_sha256",
]
EXPECTED_CANONICAL_REPOSITORY = "Joey-Tools/codex-debug-triage"
EXPECTED_PRIVATE_AGGREGATE_REPOSITORY = "Joey-Tools/codex-private-workflows"
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
        "remote_build_provider": "skills/cisco-build-artifacts",
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


class ReceiptAdmissionError(ValueError):
    pass


def _reject_json_constant(value: str) -> None:
    raise ReceiptAdmissionError(f"non-finite JSON value is forbidden: {value}")


def _object_without_duplicates(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReceiptAdmissionError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_exact_json(
    path: pathlib.Path,
    *,
    label: str,
    max_bytes: int,
) -> tuple[dict[str, Any], str]:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise ReceiptAdmissionError(
            f"{label} could not be opened safely: {error.strerror or error}"
        ) from error
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ReceiptAdmissionError(f"{label} must be a regular file")
        if metadata.st_size > max_bytes:
            raise ReceiptAdmissionError(
                f"{label} exceeds max bytes: {metadata.st_size} > {max_bytes}"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(16 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ReceiptAdmissionError(f"{label} exceeds max bytes while reading")
        final_metadata = os.fstat(fd)
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
        parsed = json.loads(
            decoded,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReceiptAdmissionError(f"{label} is not strict UTF-8 JSON") from error
    if not isinstance(parsed, dict):
        raise ReceiptAdmissionError(f"{label} root must be an object")
    return parsed, digest


def _require_exact_keys(
    value: object,
    expected: set[str],
    *,
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
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
    if not isinstance(value, str) or not value:
        raise ReceiptAdmissionError(f"{label} must be a non-empty string")
    return value


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
            "receipt_admission",
        },
        label="contract",
    )
    if contract["schema_version"] != CONTRACT_SCHEMA_VERSION:
        raise ReceiptAdmissionError("contract schema_version is not supported")
    if contract["canonical_merge_changes_installed_routing"] is not False:
        raise ReceiptAdmissionError(
            "contract must keep canonical merge routing inactive"
        )
    if contract["canonical_repository"] != EXPECTED_CANONICAL_REPOSITORY:
        raise ReceiptAdmissionError(
            "contract canonical repository is not the exact expected repository"
        )
    if (
        contract["private_aggregate_repository"]
        != EXPECTED_PRIVATE_AGGREGATE_REPOSITORY
    ):
        raise ReceiptAdmissionError(
            "contract private repository is not the exact expected repository"
        )
    _require_exact_keys(
        contract["activation"],
        {
            "release_kind",
            "atomic",
            "provider",
            "routing_policy",
            "catalog",
            "removed_link",
        },
        label="contract activation",
    )
    if contract["activation"] != EXPECTED_ACTIVATION:
        raise ReceiptAdmissionError(
            "contract activation is not the exact aggregate transaction"
        )
    gates = contract["trust_gates"]
    if (
        not isinstance(gates, list)
        or not gates
        or any(not isinstance(gate, str) or not gate for gate in gates)
        or len(set(gates)) != len(gates)
    ):
        raise ReceiptAdmissionError(
            "contract trust_gates must be unique non-empty strings"
        )
    if gates != EXPECTED_TRUST_GATES:
        raise ReceiptAdmissionError(
            "contract trust_gates differ from the exact required gates"
        )
    blocked = contract["blocked_until_trusted"]
    if (
        not isinstance(blocked, list)
        or not blocked
        or any(not isinstance(item, str) or not item for item in blocked)
    ):
        raise ReceiptAdmissionError(
            "contract blocked_until_trusted must be non-empty strings"
        )
    if blocked != EXPECTED_BLOCKED_TARGETS:
        raise ReceiptAdmissionError(
            "contract blocked targets differ from the exact cutover targets"
        )
    if contract["unproved_atomicity_fallback"] != "retain-bug-triage-compat":
        raise ReceiptAdmissionError(
            "contract fallback must retain bug-triage compatibility"
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
        "receipt_max_bytes": DEFAULT_MAX_JSON_BYTES,
        "producer_workflow": ".github/workflows/release.yml",
        "pointer_name": "current",
        "pointer_target_template": "releases/{private_release_commit}",
        "required_exact_inputs": REQUIRED_EXACT_INPUTS,
    }
    if admission != expected_admission:
        raise ReceiptAdmissionError(
            "contract receipt_admission does not match the validator contract"
        )
    return contract


def _validate_receipt(
    receipt: dict[str, Any],
    contract: dict[str, Any],
    *,
    expected_canonical_commit: str,
    expected_private_release_commit: str,
    expected_release_manifest_sha256: str,
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
            "activation",
            "gates",
            "installed_pointer",
        },
        label="receipt",
    )
    if receipt["schema_version"] != RECEIPT_SCHEMA_VERSION:
        raise ReceiptAdmissionError("receipt schema_version is not supported")
    if receipt["canonical_repository"] != contract["canonical_repository"]:
        raise ReceiptAdmissionError("receipt canonical repository differs")
    if (
        receipt["private_aggregate_repository"]
        != contract["private_aggregate_repository"]
    ):
        raise ReceiptAdmissionError("receipt private repository differs")
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
    if receipt["release_target"] != expected_target:
        raise ReceiptAdmissionError("receipt immutable release target differs")
    if receipt["activation"] != contract["activation"]:
        raise ReceiptAdmissionError(
            "receipt activation aggregate differs from the contract"
        )

    gate_names = contract["trust_gates"]
    gates = receipt["gates"]
    if not isinstance(gates, list) or len(gates) != len(gate_names):
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
        if gate != {
            "name": expected_name,
            "status": "passed",
            "private_release_commit": expected_private_release_commit,
            "release_manifest_sha256": expected_release_manifest_sha256,
        }:
            raise ReceiptAdmissionError(
                f"receipt gate is not exact and passed: {expected_name}"
            )

    pointer = _require_exact_keys(
        receipt["installed_pointer"],
        {
            "name",
            "target",
            "resolved_release_commit",
            "release_manifest_sha256",
        },
        label="receipt installed_pointer",
    )
    if pointer != {
        "name": "current",
        "target": expected_target,
        "resolved_release_commit": expected_private_release_commit,
        "release_manifest_sha256": expected_release_manifest_sha256,
    }:
        raise ReceiptAdmissionError(
            "receipt installed pointer does not resolve to the exact release"
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
    parser.add_argument("--expected-private-release-commit")
    parser.add_argument("--expected-release-manifest-sha256")
    parser.add_argument("--expected-receipt-sha256")
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
            "expected_private_release_commit": (args.expected_private_release_commit),
            "expected_release_manifest_sha256": (args.expected_release_manifest_sha256),
            "expected_receipt_sha256": args.expected_receipt_sha256,
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
                "receipt_sha256": receipt_sha256,
                "release_manifest_sha256": expected_release_manifest_sha256,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
