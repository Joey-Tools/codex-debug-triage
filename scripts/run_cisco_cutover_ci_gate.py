#!/usr/bin/env python3

from __future__ import annotations

import base64
import binascii
import json
import os
import pathlib
import subprocess
import sys
import tempfile

MAX_RECEIPT_BYTES = 64 * 1024
MAX_RECEIPT_BASE64_CHARS = 4 * ((MAX_RECEIPT_BYTES + 2) // 3)
REPOSITORY_ROOT = pathlib.Path(__file__).resolve().parent.parent
VALIDATOR_PATH = REPOSITORY_ROOT / "scripts/validate_cisco_cutover_receipt.py"
CONTRACT_PATH = REPOSITORY_ROOT / "tests/fixtures/cisco-build-artifacts-migration.json"
RECEIPT_ENV = "CISCO_CUTOVER_RECEIPT_BASE64"
OBSERVED_CANONICAL_ENV = "CISCO_CUTOVER_OBSERVED_CANONICAL_COMMIT"
EXPECTED_ENV = {
    "expected_canonical_commit": "CISCO_CUTOVER_EXPECTED_CANONICAL_COMMIT",
    "expected_private_release_commit": (
        "CISCO_CUTOVER_EXPECTED_PRIVATE_RELEASE_COMMIT"
    ),
    "expected_release_manifest_sha256": (
        "CISCO_CUTOVER_EXPECTED_RELEASE_MANIFEST_SHA256"
    ),
    "expected_receipt_sha256": "CISCO_CUTOVER_EXPECTED_RECEIPT_SHA256",
}
PLACEHOLDER_VALUES = frozenset(
    {
        "change-me",
        "changeme",
        "missing",
        "none",
        "placeholder",
        "todo",
        "unset",
    }
)


class GateConfigurationError(ValueError):
    pass


def _blocked(reason: str) -> int:
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


def _required_environment_value(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value.strip():
        raise GateConfigurationError(
            f"required GitHub Actions variable {name} is missing"
        )
    normalized = value.strip().lower()
    if (
        normalized in PLACEHOLDER_VALUES
        or normalized.startswith("<")
        or normalized.startswith("${{")
        or set(normalized) == {"0"}
    ):
        raise GateConfigurationError(
            f"required GitHub Actions variable {name} is a placeholder"
        )
    return value


def _decode_receipt() -> bytes:
    encoded = _required_environment_value(RECEIPT_ENV)
    if len(encoded) > MAX_RECEIPT_BASE64_CHARS:
        raise GateConfigurationError("trusted receipt Base64 exceeds max characters")
    try:
        payload = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise GateConfigurationError("trusted receipt Base64 is malformed") from error
    if not payload:
        raise GateConfigurationError("trusted receipt is empty")
    if len(payload) > MAX_RECEIPT_BYTES:
        raise GateConfigurationError("trusted receipt exceeds max bytes")
    return payload


def _write_receipt(path: pathlib.Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)


def main() -> int:
    try:
        receipt = _decode_receipt()
        expected = {
            argument: _required_environment_value(environment_name)
            for argument, environment_name in EXPECTED_ENV.items()
        }
        observed_canonical_commit = _required_environment_value(OBSERVED_CANONICAL_ENV)
    except GateConfigurationError as error:
        return _blocked(str(error))
    if observed_canonical_commit != expected["expected_canonical_commit"]:
        return _blocked(
            "trusted canonical expectation does not match the workflow candidate"
        )

    with tempfile.TemporaryDirectory(prefix="cisco-cutover-gate-") as temp_dir:
        os.chmod(temp_dir, 0o700)
        receipt_path = pathlib.Path(temp_dir) / "trusted-receipt.json"
        try:
            _write_receipt(receipt_path, receipt)
        except OSError:
            return _blocked("trusted receipt staging failed")
        command = [
            sys.executable,
            str(VALIDATOR_PATH),
            "--contract",
            str(CONTRACT_PATH),
            "--receipt",
            str(receipt_path),
            "--expected-canonical-commit",
            expected["expected_canonical_commit"],
            "--expected-private-release-commit",
            expected["expected_private_release_commit"],
            "--expected-release-manifest-sha256",
            expected["expected_release_manifest_sha256"],
            "--expected-receipt-sha256",
            expected["expected_receipt_sha256"],
        ]
        result = subprocess.run(command, check=False)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
