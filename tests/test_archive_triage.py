from __future__ import annotations

import argparse
import ast
import base64
import binascii
import ctypes
import errno
import hashlib
import importlib.util
import io
import json
import os
import shutil
import shlex
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from contextlib import (
    ExitStack,
    contextmanager,
    nullcontext,
    redirect_stderr,
    redirect_stdout,
)
from pathlib import Path
from typing import Any, Iterator
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILL_ROOT = REPO_ROOT / "skills/bug-triage-playbook"
SCRIPT_PATH = SKILL_ROOT / "scripts/archive_triage.py"
CUTOVER_VALIDATOR_PATH = REPO_ROOT / "scripts/validate_cisco_cutover_receipt.py"
CUTOVER_ENFORCEMENT_DOCTOR_PATH = (
    REPO_ROOT / "scripts/doctor_cisco_cutover_enforcement.py"
)
CUTOVER_ENFORCEMENT_CONTRACT_PATH = (
    REPO_ROOT / "docs/cisco-cutover-enforcement-contract.json"
)
CUTOVER_TRUSTED_WORKFLOW_PATH = (
    REPO_ROOT / ".github/workflows/cisco-cutover-admission.yml"
)
MIGRATION_FIXTURE_PATH = (
    REPO_ROOT / "tests/fixtures/cisco-build-artifacts-migration.json"
)
# Helper-owned synthetic-token catalog ID: access-a.
SYNTHETIC_ACCESS_TOKEN = "codex_synth_v1_access_a"
SPEC = importlib.util.spec_from_file_location("archive_triage", SCRIPT_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
ENFORCEMENT_SPEC = importlib.util.spec_from_file_location(
    "doctor_cisco_cutover_enforcement",
    CUTOVER_ENFORCEMENT_DOCTOR_PATH,
)
ENFORCEMENT_MODULE = importlib.util.module_from_spec(ENFORCEMENT_SPEC)
assert ENFORCEMENT_SPEC is not None
assert ENFORCEMENT_SPEC.loader is not None
sys.modules[ENFORCEMENT_SPEC.name] = ENFORCEMENT_MODULE
ENFORCEMENT_SPEC.loader.exec_module(ENFORCEMENT_MODULE)


class _ForwardedFixtureSignal(BaseException):
    def __init__(
        self,
        signal_number: int,
        secondary_error: BaseException | None,
    ) -> None:
        self.signal_number = signal_number
        self.secondary_error = secondary_error
        super().__init__(f"forwarded fixture signal {signal_number}")


@contextmanager
def owner_controlled_temp_root() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(
        prefix=".codex-cisco-gh-",
        dir=REPO_ROOT,
    ) as temp_dir:
        temp_root = Path(temp_dir).resolve()
        temp_root.chmod(0o700)
        yield temp_root


def _set_fixture_darwin_acl(path: Path, entry: str) -> None:
    subprocess.run(
        ["/bin/chmod", "+a", entry, str(path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )


def _clear_fixture_darwin_acl(path: Path) -> None:
    subprocess.run(
        ["/bin/chmod", "-N", str(path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )


class ArchiveTriageTests(unittest.TestCase):
    def _make_archive(self, directory: Path) -> Path:
        archive_path = directory / "run.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("logs/console.txt", "alpha\nERROR boom\ngamma\n")
            archive.writestr("logs/worker.log", "ready\ntimeout waiting\ndone\n")
            archive.writestr("metadata.json", '{"result": "failed"}\n')
        return archive_path

    def _make_forced_zip64_archive(self, directory: Path) -> Path:
        archive_path = directory / "forced-zip64.zip"
        with mock.patch.object(zipfile, "ZIP_FILECOUNT_LIMIT", 0):
            with zipfile.ZipFile(archive_path, "w", allowZip64=True) as archive:
                archive.writestr(
                    "logs/zip64.log",
                    "zip64\n",
                    compress_type=zipfile.ZIP_DEFLATED,
                )
        archive_bytes = archive_path.read_bytes()
        self.assertIn(MODULE.ZIP64_EOCD_SIGNATURE, archive_bytes)
        self.assertIn(MODULE.ZIP64_LOCATOR_SIGNATURE, archive_bytes)
        return archive_path

    def _make_local_zero_zip64_descriptor_archive(
        self,
        directory: Path,
    ) -> tuple[Path, str]:
        member_name = "logs/zip64-descriptor.log"
        raw_name = member_name.encode("utf-8")
        payload = b"zip64 descriptor\n"
        crc = binascii.crc32(payload) & MODULE.UINT32_MAX
        flags = MODULE.DATA_DESCRIPTOR_FLAG | MODULE.UTF8_FILENAME_FLAG
        local_header = struct.pack(
            "<4s5H3L2H",
            MODULE.LOCAL_FILE_HEADER_SIGNATURE,
            MODULE.ZIP64_MIN_VERSION,
            flags,
            zipfile.ZIP_STORED,
            0,
            0,
            0,
            0,
            0,
            len(raw_name),
            0,
        )
        descriptor = MODULE.DATA_DESCRIPTOR_SIGNATURE + struct.pack(
            "<LQQ",
            crc,
            len(payload),
            len(payload),
        )
        central_start = (
            len(local_header) + len(raw_name) + len(payload) + len(descriptor)
        )
        central_extra = struct.pack(
            "<HHQQ",
            MODULE.ZIP64_EXTRA_FIELD_ID,
            16,
            len(payload),
            len(payload),
        )
        central_header = bytearray(MODULE.CENTRAL_DIRECTORY_HEADER_SIZE)
        central_header[:4] = MODULE.CENTRAL_DIRECTORY_SIGNATURE
        struct.pack_into("<H", central_header, 4, MODULE.ZIP64_MIN_VERSION)
        struct.pack_into("<H", central_header, 6, MODULE.ZIP64_MIN_VERSION)
        struct.pack_into("<H", central_header, 8, flags)
        struct.pack_into("<H", central_header, 10, zipfile.ZIP_STORED)
        struct.pack_into("<L", central_header, 16, crc)
        struct.pack_into("<L", central_header, 20, MODULE.UINT32_MAX)
        struct.pack_into("<L", central_header, 24, MODULE.UINT32_MAX)
        struct.pack_into("<H", central_header, 28, len(raw_name))
        struct.pack_into("<H", central_header, 30, len(central_extra))
        central_record = bytes(central_header) + raw_name + central_extra
        eocd = struct.pack(
            "<4s4H2LH",
            MODULE.EOCD_SIGNATURE,
            0,
            0,
            1,
            1,
            len(central_record),
            central_start,
            0,
        )
        archive_path = directory / "local-zero-zip64-descriptor.zip"
        archive_path.write_bytes(
            local_header + raw_name + payload + descriptor + central_record + eocd
        )
        return archive_path, member_name

    def _make_zip64_metadata_archive(
        self,
        directory: Path,
        *,
        classic_eocd: tuple[int, int, int, int, int, int],
    ) -> Path:
        local_header = struct.pack(
            "<4s5H3L2H",
            MODULE.LOCAL_FILE_HEADER_SIGNATURE,
            20,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        central_header = bytearray(MODULE.CENTRAL_DIRECTORY_HEADER_SIZE)
        central_header[:4] = MODULE.CENTRAL_DIRECTORY_SIGNATURE
        struct.pack_into("<H", central_header, 4, 20)
        struct.pack_into("<H", central_header, 6, 20)
        central_start = len(local_header)
        zip64_eocd_offset = central_start + len(central_header)
        zip64_eocd = struct.pack(
            "<4sQ2H2L4Q",
            MODULE.ZIP64_EOCD_SIGNATURE,
            MODULE.ZIP64_EOCD_MIN_SIZE - 12,
            45,
            45,
            0,
            0,
            1,
            1,
            len(central_header),
            central_start,
        )
        locator = struct.pack(
            "<4sLQL",
            MODULE.ZIP64_LOCATOR_SIGNATURE,
            0,
            zip64_eocd_offset,
            1,
        )
        eocd = struct.pack(
            "<4s4H2LH",
            MODULE.EOCD_SIGNATURE,
            *classic_eocd,
            0,
        )
        archive_path = directory / "zip64-metadata.zip"
        archive_path.write_bytes(
            local_header + bytes(central_header) + zip64_eocd + locator + eocd
        )
        return archive_path

    def _make_dual_view_archive(self, directory: Path) -> Path:
        outer_path = directory / "outer.zip"
        with zipfile.ZipFile(outer_path, "w") as archive:
            archive.writestr("outer.txt", "outer\n")
        outer = bytearray(outer_path.read_bytes())
        outer_eocd_offset = outer.rfind(MODULE.EOCD_SIGNATURE)
        self.assertGreaterEqual(outer_eocd_offset, 0)

        inner_buffer = io.BytesIO()
        with zipfile.ZipFile(inner_buffer, "w") as archive:
            archive.writestr("inner.txt", "inner\n")
        inner = inner_buffer.getvalue()
        self.assertLessEqual(len(inner), MODULE.EOCD_MAX_COMMENT)
        struct.pack_into("<H", outer, outer_eocd_offset + 20, len(inner))
        outer_path.write_bytes(outer + inner)
        return outer_path

    def _prepend_and_rebase_archive(
        self,
        archive_path: Path,
        prefix: bytes,
        *,
        forged_zero_ordinal: int | None = None,
    ) -> None:
        data = bytearray(archive_path.read_bytes())
        eocd_offset = data.rfind(MODULE.EOCD_SIGNATURE)
        self.assertGreaterEqual(eocd_offset, 0)
        records = self._central_directory_records(data)
        for ordinal, (central_offset, _, _) in enumerate(records, start=1):
            local_header_offset = struct.unpack_from(
                "<L",
                data,
                central_offset + 42,
            )[0]
            self.assertNotEqual(local_header_offset, MODULE.UINT32_MAX)
            struct.pack_into(
                "<L",
                data,
                central_offset + 42,
                (
                    0
                    if ordinal == forged_zero_ordinal
                    else local_header_offset + len(prefix)
                ),
            )
        central_start = struct.unpack_from("<L", data, eocd_offset + 16)[0]
        if central_start != MODULE.UINT32_MAX:
            struct.pack_into(
                "<L",
                data,
                eocd_offset + 16,
                central_start + len(prefix),
            )

        locator_offset = eocd_offset - MODULE.ZIP64_LOCATOR_SIZE
        if (
            locator_offset >= 0
            and data[
                locator_offset : locator_offset + len(MODULE.ZIP64_LOCATOR_SIGNATURE)
            ]
            == MODULE.ZIP64_LOCATOR_SIGNATURE
        ):
            zip64_eocd_offset = struct.unpack_from(
                "<Q",
                data,
                locator_offset + 8,
            )[0]
            self.assertEqual(
                data[
                    zip64_eocd_offset : zip64_eocd_offset
                    + len(MODULE.ZIP64_EOCD_SIGNATURE)
                ],
                MODULE.ZIP64_EOCD_SIGNATURE,
            )
            zip64_central_start = struct.unpack_from(
                "<Q",
                data,
                zip64_eocd_offset + 48,
            )[0]
            struct.pack_into(
                "<Q",
                data,
                zip64_eocd_offset + 48,
                zip64_central_start + len(prefix),
            )
            struct.pack_into(
                "<Q",
                data,
                locator_offset + 8,
                zip64_eocd_offset + len(prefix),
            )
        archive_path.write_bytes(prefix + data)

    def _first_local_record_bytes(self, archive_path: Path) -> bytes:
        with zipfile.ZipFile(archive_path) as archive:
            infos = sorted(archive.infolist(), key=lambda info: info.header_offset)
            self.assertTrue(infos)
            record_end = infos[1].header_offset if len(infos) > 1 else archive.start_dir
            first_offset = infos[0].header_offset
        data = archive_path.read_bytes()
        self.assertEqual(first_offset, 0)
        self.assertGreater(record_end, first_offset)
        return data[first_offset:record_end]

    def _corrupt_member_payload_tail(
        self,
        archive_path: Path,
        member_name: str,
    ) -> None:
        with zipfile.ZipFile(archive_path) as archive:
            info = archive.getinfo(member_name)

        data = bytearray(archive_path.read_bytes())
        header_offset = info.header_offset
        self.assertEqual(data[header_offset : header_offset + 4], b"PK\x03\x04")
        name_length, extra_length = struct.unpack_from(
            "<HH",
            data,
            header_offset + 26,
        )
        payload_offset = header_offset + 30 + name_length + extra_length
        self.assertGreater(info.compress_size, 0)
        data[payload_offset + info.compress_size - 1] ^= 0x01
        archive_path.write_bytes(data)

    def _corrupt_member_compressed_stream(
        self,
        archive_path: Path,
        member_name: str,
        compression: int,
    ) -> None:
        with zipfile.ZipFile(archive_path) as archive:
            info = archive.getinfo(member_name)

        data = bytearray(archive_path.read_bytes())
        header_offset = info.header_offset
        name_length, extra_length = struct.unpack_from(
            "<HH",
            data,
            header_offset + 26,
        )
        payload_offset = header_offset + 30 + name_length + extra_length
        corrupt_offset = payload_offset
        if compression == zipfile.ZIP_LZMA:
            properties_length = struct.unpack_from(
                "<H",
                data,
                payload_offset + 2,
            )[0]
            corrupt_offset += 4 + properties_length
        payload_end = payload_offset + info.compress_size
        self.assertLess(corrupt_offset, payload_end)
        data[corrupt_offset:payload_end] = b"\xff" * (payload_end - corrupt_offset)
        archive_path.write_bytes(data)

    def _central_directory_records(
        self,
        data: bytes | bytearray,
    ) -> list[tuple[int, int, int]]:
        eocd_offset = data.rfind(MODULE.EOCD_SIGNATURE)
        self.assertGreaterEqual(eocd_offset, 0)
        entry_count = struct.unpack_from("<H", data, eocd_offset + 10)[0]
        cursor = struct.unpack_from("<L", data, eocd_offset + 16)[0]
        if entry_count == 0xFFFF or cursor == MODULE.UINT32_MAX:
            locator_offset = eocd_offset - MODULE.ZIP64_LOCATOR_SIZE
            self.assertEqual(
                data[
                    locator_offset : locator_offset
                    + len(MODULE.ZIP64_LOCATOR_SIGNATURE)
                ],
                MODULE.ZIP64_LOCATOR_SIGNATURE,
            )
            zip64_eocd_offset = struct.unpack_from(
                "<Q",
                data,
                locator_offset + 8,
            )[0]
            self.assertEqual(
                data[
                    zip64_eocd_offset : zip64_eocd_offset
                    + len(MODULE.ZIP64_EOCD_SIGNATURE)
                ],
                MODULE.ZIP64_EOCD_SIGNATURE,
            )
            entry_count = struct.unpack_from(
                "<Q",
                data,
                zip64_eocd_offset + 32,
            )[0]
            cursor = struct.unpack_from(
                "<Q",
                data,
                zip64_eocd_offset + 48,
            )[0]
        records = []
        for _ in range(entry_count):
            self.assertEqual(
                data[cursor : cursor + 4],
                MODULE.CENTRAL_DIRECTORY_SIGNATURE,
            )
            name_length, extra_length, comment_length = struct.unpack_from(
                "<3H",
                data,
                cursor + 28,
            )
            name_offset = cursor + MODULE.CENTRAL_DIRECTORY_HEADER_SIZE
            records.append((cursor, name_offset, name_length))
            cursor += (
                MODULE.CENTRAL_DIRECTORY_HEADER_SIZE
                + name_length
                + extra_length
                + comment_length
            )
        return records

    def _replace_member_name_byte(
        self,
        archive_path: Path,
        *,
        ordinal: int,
        byte_index: int,
        replacement: int,
    ) -> None:
        with zipfile.ZipFile(archive_path) as archive:
            info = archive.infolist()[ordinal - 1]

        data = bytearray(archive_path.read_bytes())
        local_name_length = struct.unpack_from(
            "<H",
            data,
            info.header_offset + 26,
        )[0]
        self.assertLess(byte_index, local_name_length)
        local_name_offset = info.header_offset + 30
        data[local_name_offset + byte_index] = replacement

        _, central_name_offset, central_name_length = self._central_directory_records(
            data
        )[ordinal - 1]
        self.assertEqual(central_name_length, local_name_length)
        data[central_name_offset + byte_index] = replacement
        archive_path.write_bytes(data)

    def _replace_member_raw_name(
        self,
        archive_path: Path,
        *,
        ordinal: int,
        raw_name: bytes,
        flag_bits: int,
    ) -> None:
        with zipfile.ZipFile(archive_path) as archive:
            info = archive.infolist()[ordinal - 1]

        data = bytearray(archive_path.read_bytes())
        local_name_length = struct.unpack_from(
            "<H",
            data,
            info.header_offset + 26,
        )[0]
        self.assertEqual(len(raw_name), local_name_length)
        struct.pack_into("<H", data, info.header_offset + 6, flag_bits)
        local_name_offset = info.header_offset + MODULE.LOCAL_FILE_HEADER_SIZE
        data[local_name_offset : local_name_offset + local_name_length] = raw_name

        central_offset, central_name_offset, central_name_length = (
            self._central_directory_records(data)[ordinal - 1]
        )
        self.assertEqual(central_name_length, local_name_length)
        struct.pack_into("<H", data, central_offset + 8, flag_bits)
        data[central_name_offset : central_name_offset + central_name_length] = raw_name
        archive_path.write_bytes(data)

    def _replace_declared_file_size(
        self,
        archive_path: Path,
        *,
        ordinal: int,
        file_size: int,
    ) -> None:
        with zipfile.ZipFile(archive_path) as archive:
            info = archive.infolist()[ordinal - 1]

        data = bytearray(archive_path.read_bytes())
        struct.pack_into("<L", data, info.header_offset + 22, file_size)
        central_offset = self._central_directory_records(data)[ordinal - 1][0]
        struct.pack_into("<L", data, central_offset + 24, file_size)
        archive_path.write_bytes(data)

    def _replace_member_flag_bits(
        self,
        archive_path: Path,
        *,
        ordinal: int,
        flag_bits: int,
    ) -> None:
        with zipfile.ZipFile(archive_path) as archive:
            info = archive.infolist()[ordinal - 1]

        data = bytearray(archive_path.read_bytes())
        struct.pack_into("<H", data, info.header_offset + 6, flag_bits)
        central_offset = self._central_directory_records(data)[ordinal - 1][0]
        struct.pack_into("<H", data, central_offset + 8, flag_bits)
        archive_path.write_bytes(data)

    def _replace_member_disk_start(
        self,
        archive_path: Path,
        *,
        ordinal: int,
        disk_start: int,
        use_zip64_sentinel: bool,
    ) -> None:
        data = bytearray(archive_path.read_bytes())
        central_offset = self._central_directory_records(data)[ordinal - 1][0]
        if not use_zip64_sentinel:
            struct.pack_into("<H", data, central_offset + 34, disk_start)
            archive_path.write_bytes(data)
            return

        name_length, extra_length = struct.unpack_from(
            "<HH",
            data,
            central_offset + 28,
        )
        zip64_extra = struct.pack(
            "<HHI",
            MODULE.ZIP64_EXTRA_FIELD_ID,
            4,
            disk_start,
        )
        insert_offset = (
            central_offset
            + MODULE.CENTRAL_DIRECTORY_HEADER_SIZE
            + name_length
            + extra_length
        )
        eocd_offset = data.rfind(MODULE.EOCD_SIGNATURE)
        self.assertGreaterEqual(eocd_offset, insert_offset)
        central_size = struct.unpack_from("<L", data, eocd_offset + 12)[0]

        struct.pack_into("<H", data, central_offset + 6, 45)
        struct.pack_into(
            "<H", data, central_offset + 30, extra_length + len(zip64_extra)
        )
        struct.pack_into("<H", data, central_offset + 34, 0xFFFF)
        data[insert_offset:insert_offset] = zip64_extra

        new_eocd_offset = eocd_offset + len(zip64_extra)
        struct.pack_into(
            "<L",
            data,
            new_eocd_offset + 12,
            central_size + len(zip64_extra),
        )
        archive_path.write_bytes(data)

    def _append_to_member_compressed_span(
        self,
        archive_path: Path,
        *,
        ordinal: int,
        trailing: bytes,
    ) -> None:
        with zipfile.ZipFile(archive_path) as archive:
            info = archive.infolist()[ordinal - 1]

        data = bytearray(archive_path.read_bytes())
        local_name_length, local_extra_length = struct.unpack_from(
            "<HH",
            data,
            info.header_offset + 26,
        )
        payload_start = (
            info.header_offset
            + MODULE.LOCAL_FILE_HEADER_SIZE
            + local_name_length
            + local_extra_length
        )
        payload_end = payload_start + info.compress_size
        original_eocd = data.rfind(MODULE.EOCD_SIGNATURE)
        self.assertGreaterEqual(original_eocd, 0)
        original_central_start = struct.unpack_from("<L", data, original_eocd + 16)[0]
        self.assertEqual(payload_end, original_central_start)
        data[payload_end:payload_end] = trailing

        new_eocd = original_eocd + len(trailing)
        new_central_start = original_central_start + len(trailing)
        struct.pack_into("<L", data, new_eocd + 16, new_central_start)
        struct.pack_into(
            "<L",
            data,
            info.header_offset + 18,
            info.compress_size + len(trailing),
        )
        struct.pack_into(
            "<L",
            data,
            new_central_start + 20,
            info.compress_size + len(trailing),
        )
        archive_path.write_bytes(data)

    def _parse_identity(self, rendered: str) -> dict[str, object]:
        identity = json.loads(rendered)
        self.assertEqual(
            set(identity),
            {"flag_bits", "name", "ordinal", "raw_name_b64"},
        )
        raw_name = base64.b64decode(
            identity["raw_name_b64"],
            validate=True,
        )
        encoding = (
            "utf-8" if identity["flag_bits"] & MODULE.UTF8_FILENAME_FLAG else "cp437"
        )
        self.assertEqual(raw_name.decode(encoding), identity["name"])
        return identity

    def _parse_ambiguity_identities(
        self,
        rendered: str,
    ) -> tuple[list[dict[str, object]], int]:
        lines = rendered.splitlines()
        self.assertEqual(len(lines), 1)
        prefix = "error=multiple matching members; candidates="
        self.assertTrue(lines[0].startswith(prefix), lines[0])
        candidates_text, separator, omitted_text = lines[0][len(prefix) :].rpartition(
            "; omitted="
        )
        self.assertEqual(separator, "; omitted=")
        candidates = json.loads(candidates_text)
        self.assertIsInstance(candidates, list)
        return (
            [self._parse_identity(json.dumps(candidate)) for candidate in candidates],
            int(omitted_text),
        )

    def _list_args(
        self,
        archive_path: Path,
        **overrides: object,
    ) -> argparse.Namespace:
        values: dict[str, object] = {
            "zip_path": str(archive_path),
            "match": None,
            "ignore_case": False,
            "limit": MODULE.DEFAULT_LIST_LIMIT,
            "max_archive_bytes": MODULE.DEFAULT_MAX_ARCHIVE_BYTES,
            "max_archive_members": MODULE.DEFAULT_MAX_ARCHIVE_MEMBERS,
            "max_central_directory_bytes": (MODULE.DEFAULT_MAX_CENTRAL_DIRECTORY_BYTES),
            "max_output_chars": MODULE.DEFAULT_MAX_OUTPUT_CHARS,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def _show_args(
        self,
        archive_path: Path,
        **overrides: object,
    ) -> argparse.Namespace:
        values: dict[str, object] = {
            "zip_path": str(archive_path),
            "member": "logs/console.txt",
            "regex": False,
            "all": False,
            "grep": None,
            "ignore_case": False,
            "context": 0,
            "head": 0,
            "tail": 0,
            "encoding": "utf-8",
            "line_numbers": False,
            "max_archive_bytes": MODULE.DEFAULT_MAX_ARCHIVE_BYTES,
            "max_archive_members": MODULE.DEFAULT_MAX_ARCHIVE_MEMBERS,
            "max_central_directory_bytes": (MODULE.DEFAULT_MAX_CENTRAL_DIRECTORY_BYTES),
            "max_members": MODULE.DEFAULT_MAX_MEMBERS,
            "max_member_bytes": MODULE.DEFAULT_MAX_MEMBER_BYTES,
            "max_total_member_bytes": MODULE.DEFAULT_MAX_TOTAL_MEMBER_BYTES,
            "max_member_lines": MODULE.DEFAULT_MAX_MEMBER_LINES,
            "max_input_line_chars": MODULE.DEFAULT_MAX_INPUT_LINE_CHARS,
            "max_output_lines": MODULE.DEFAULT_MAX_OUTPUT_LINES,
            "max_output_chars": MODULE.DEFAULT_MAX_OUTPUT_CHARS,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def _full_pipe_writer(
        self,
    ) -> tuple[int, int, io.TextIOWrapper, int]:
        if MODULE.fcntl is None or not hasattr(os, "O_NONBLOCK"):
            self.skipTest("fcntl O_NONBLOCK support is required")
        read_fd, write_fd = os.pipe()
        original_flags = MODULE._fcntl_get_flags(write_fd)
        MODULE._fcntl_set_flags(write_fd, original_flags | os.O_NONBLOCK)
        try:
            while True:
                os.write(write_fd, b"x" * 4096)
        except BlockingIOError:
            try:
                while True:
                    os.write(write_fd, b"x")
            except BlockingIOError:
                pass
        finally:
            MODULE._fcntl_set_flags(write_fd, original_flags)
        writer = io.TextIOWrapper(
            io.FileIO(write_fd, mode="w", closefd=False),
            encoding="utf-8",
            write_through=True,
        )
        user_flags = MODULE._fcntl_get_flags(write_fd)
        return read_fd, write_fd, writer, user_flags

    def test_zip_list_filters_case_insensitively_and_limits_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            args = self._list_args(
                archive_path,
                match="WORKER.LOG",
                ignore_case=True,
                limit=1,
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                rc = MODULE.cmd_zip_list(args)

        self.assertEqual(rc, 0)
        lines = stdout.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        fields = lines[0].split("\t", 2)
        self.assertEqual(len(fields), 3)
        identity = self._parse_identity(fields[2])
        self.assertEqual(identity["name"], "logs/worker.log")
        self.assertEqual(identity["ordinal"], 2)

    def test_zip_show_filters_with_context_and_line_numbers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            args = self._show_args(
                archive_path,
                grep="error",
                ignore_case=True,
                context=1,
                line_numbers=True,
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                rc = MODULE.cmd_zip_show(args)

        self.assertEqual(rc, 0)
        lines = stdout.getvalue().splitlines()
        self.assertEqual(
            lines[1:],
            ["1:alpha", "2:ERROR boom", "3:gamma"],
        )
        identity = self._parse_identity(lines[0][3:-3])
        self.assertEqual(identity["name"], "logs/console.txt")
        self.assertEqual(identity["ordinal"], 1)

    def test_zip_show_requires_all_for_multiple_regex_matches(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            args = self._show_args(
                archive_path,
                member=r"logs/.*",
                regex=True,
                head=1,
            )
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                rc = MODULE.cmd_zip_show(args)

        self.assertEqual(rc, 1)
        identities, omitted = self._parse_ambiguity_identities(stderr.getvalue())
        self.assertEqual(omitted, 0)
        self.assertEqual(
            [identity["name"] for identity in identities],
            ["logs/console.txt", "logs/worker.log"],
        )
        self.assertEqual(
            [identity["ordinal"] for identity in identities],
            [1, 2],
        )

    def test_zip_show_reports_missing_member(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            args = self._show_args(
                archive_path,
                member="missing.log",
            )
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                rc = MODULE.cmd_zip_show(args)

        self.assertEqual(rc, 1)
        self.assertEqual(stderr.getvalue().splitlines(), ["error=no matching members"])

    def test_zip_show_rejects_member_over_decompressed_byte_cap(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            args = self._show_args(
                archive_path,
                head=1,
                max_member_bytes=8,
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = MODULE.cmd_zip_show(args)

        self.assertEqual(rc, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("error=member exceeds max bytes", stderr.getvalue())

    def test_zip_show_truncates_total_character_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            args = self._show_args(
                archive_path,
                max_output_chars=32,
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = MODULE.cmd_zip_show(args)

        self.assertEqual(rc, 0)
        self.assertLessEqual(len(stdout.getvalue()), 32)
        self.assertIn("notice=output truncated", stderr.getvalue())

    def test_zip_show_stops_regex_selection_after_output_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "truncated-grep.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(
                    "logs/console.txt",
                    "".join(f"matching line {index}\n" for index in range(100)),
                )
            args = self._show_args(
                archive_path,
                member="logs/console.txt",
                grep="matching",
                max_output_lines=1,
            )
            searched: list[str] = []

            def bounded_search(
                _matcher: MODULE.IsolatedRegexMatcher,
                value: str,
            ) -> bool:
                searched.append(value)
                if len(searched) > 1:
                    raise AssertionError(
                        "regex selection continued after output truncation"
                    )
                return True

            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.object(
                    MODULE.IsolatedRegexMatcher,
                    "search",
                    new=bounded_search,
                ),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                rc = MODULE.cmd_zip_show(args)

        self.assertEqual(rc, 0, stderr.getvalue())
        self.assertEqual(len(searched), 1)
        self.assertEqual(len(stdout.getvalue().splitlines()), 1)
        self.assertIn('"name":"logs/console.txt"', stdout.getvalue())
        self.assertNotIn("matching line", stdout.getvalue())
        self.assertIn("notice=output truncated", stderr.getvalue())

    def test_zip_list_rejects_archive_over_member_count_cap(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            args = self._list_args(
                archive_path,
                max_archive_members=2,
            )
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                rc = MODULE.cmd_zip_list(args)

        self.assertEqual(rc, 1)
        self.assertIn("archive member count exceeds limit", stderr.getvalue())

    def test_zip_preflight_counts_entries_before_zipfile_construction(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            data = bytearray(archive_path.read_bytes())
            eocd_offset = data.rfind(MODULE.EOCD_SIGNATURE)
            self.assertGreaterEqual(eocd_offset, 0)
            struct.pack_into("<HH", data, eocd_offset + 8, 1, 1)
            archive_path.write_bytes(data)
            args = self._list_args(
                archive_path,
                max_archive_members=2,
            )
            real_zipfile = zipfile.ZipFile
            stderr = io.StringIO()
            with mock.patch.object(
                MODULE.zipfile,
                "ZipFile",
                wraps=real_zipfile,
            ) as constructor:
                with redirect_stderr(stderr):
                    rc = MODULE.cmd_zip_list(args)

        self.assertEqual(rc, 1)
        constructor.assert_not_called()
        self.assertIn("archive member count exceeds limit", stderr.getvalue())

    def test_zip_preflight_rejects_large_central_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            args = self._list_args(
                archive_path,
                max_central_directory_bytes=1,
            )
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                rc = MODULE.cmd_zip_list(args)

        self.assertEqual(rc, 1)
        self.assertIn("central directory exceeds max bytes", stderr.getvalue())

    def test_zipfile_reread_uses_snapshot_after_source_central_directory_rewrite(
        self,
    ) -> None:
        cases = (
            ("CRC", 16, "<L", lambda value: value ^ MODULE.UINT32_MAX),
            (
                "compression method",
                10,
                "<H",
                lambda value: (
                    zipfile.ZIP_DEFLATED
                    if value == zipfile.ZIP_STORED
                    else zipfile.ZIP_STORED
                ),
            ),
            ("compressed size", 20, "<L", lambda value: value + 1),
            ("uncompressed size", 24, "<L", lambda value: value + 1),
            ("local-header offset", 42, "<L", lambda value: value + 1),
        )
        for field, field_offset, field_format, replacement in cases:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp_dir:
                archive_path = self._make_archive(Path(temp_dir))
                original_size = archive_path.stat().st_size
                archive_data = archive_path.read_bytes()
                central_offset = self._central_directory_records(archive_data)[0][0]
                original_value = struct.unpack_from(
                    field_format,
                    archive_data,
                    central_offset + field_offset,
                )[0]
                replacement_value = replacement(original_value)
                real_zipfile = zipfile.ZipFile
                constructor_calls = 0

                def mutate_before_zipfile_reread(
                    file: object,
                    *args: object,
                    **kwargs: object,
                ) -> zipfile.ZipFile:
                    nonlocal constructor_calls
                    constructor_calls += 1
                    with archive_path.open("r+b") as stream:
                        stream.seek(central_offset + field_offset)
                        stream.write(struct.pack(field_format, replacement_value))
                        stream.flush()
                        os.fsync(stream.fileno())
                    return real_zipfile(file, *args, **kwargs)

                stdout = io.StringIO()
                stderr = io.StringIO()
                with mock.patch.object(
                    MODULE.zipfile,
                    "ZipFile",
                    side_effect=mutate_before_zipfile_reread,
                ):
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        rc = MODULE.cmd_zip_list(self._list_args(archive_path))

                self.assertEqual(constructor_calls, 1)
                self.assertEqual(archive_path.stat().st_size, original_size)
                self.assertEqual(rc, 0, field)
                self.assertIn("logs/console.txt", stdout.getvalue())
                self.assertEqual(stderr.getvalue(), "")

    def test_pinned_snapshot_ignores_same_size_source_rewrite_after_binding(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            with zipfile.ZipFile(archive_path) as archive:
                info = archive.infolist()[0]
            archive_data = archive_path.read_bytes()
            name_length, extra_length = struct.unpack_from(
                "<HH",
                archive_data,
                info.header_offset + 26,
            )
            data_offset = (
                info.header_offset
                + MODULE.LOCAL_FILE_HEADER_SIZE
                + name_length
                + extra_length
            )
            original_size = len(archive_data)
            with MODULE._open_pinned_archive(
                archive_path,
                MODULE.DEFAULT_MAX_ARCHIVE_BYTES,
            ) as archive_stream:
                with archive_path.open("r+b") as stream:
                    stream.seek(data_offset)
                    original = stream.read(1)
                    self.assertEqual(len(original), 1)
                    stream.seek(data_offset)
                    stream.write(bytes([original[0] ^ 0xFF]))
                    stream.flush()
                    os.fsync(stream.fileno())
                archive_stream.seek(0)
                self.assertEqual(archive_stream.read(), archive_data)
                archive_stream.validate_unchanged()
            final_size = archive_path.stat().st_size
            rewritten_data = archive_path.read_bytes()

        self.assertEqual(final_size, original_size)
        self.assertNotEqual(rewritten_data, archive_data)

    def test_snapshot_binding_rejects_same_size_source_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            original_size = archive_path.stat().st_size
            real_copy = MODULE._copy_archive_snapshot

            def copy_then_rewrite(
                source_fd: int,
                snapshot_fd: int,
                archive_size: int,
                deadline: MODULE.ArchiveCommandDeadline,
            ) -> bytes:
                digest = real_copy(
                    source_fd,
                    snapshot_fd,
                    archive_size,
                    deadline,
                )
                with archive_path.open("r+b") as stream:
                    original = stream.read(1)
                    self.assertEqual(len(original), 1)
                    stream.seek(0)
                    stream.write(bytes([original[0] ^ 0xFF]))
                    stream.flush()
                    os.fsync(stream.fileno())
                return digest

            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch.object(
                MODULE,
                "_copy_archive_snapshot",
                side_effect=copy_then_rewrite,
            ):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    rc = MODULE.cmd_zip_list(self._list_args(archive_path))
            final_size = archive_path.stat().st_size

        self.assertEqual(final_size, original_size)
        self.assertEqual(rc, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("archive changed during snapshot binding", stderr.getvalue())

    def test_source_acl_drift_before_copy_is_rejected_with_unchanged_mode(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            source_metadata = archive_path.stat()
            source_identity = (source_metadata.st_dev, source_metadata.st_ino)
            source_mode = stat.S_IMODE(source_metadata.st_mode)
            initial_policy = ("test-source-acl-v1", 32, "a" * 64)
            changed_policy = ("test-source-acl-v1", 32, "b" * 64)
            source_policies = [initial_policy, changed_policy]
            real_policy = MODULE._stable_source_access_policy_binding

            def policy_for_descriptor(fd: int) -> tuple[str, int, str]:
                current = os.fstat(fd)
                if (current.st_dev, current.st_ino) == source_identity:
                    return source_policies.pop(0)
                return real_policy(fd)

            with (
                mock.patch.object(
                    MODULE,
                    "_stable_source_access_policy_binding",
                    side_effect=policy_for_descriptor,
                ),
                mock.patch.object(MODULE, "_copy_archive_snapshot") as copied,
                self.assertRaisesRegex(
                    zipfile.BadZipFile,
                    "archive source access policy changed during snapshot binding",
                ),
            ):
                with MODULE._open_pinned_archive(
                    archive_path,
                    MODULE.DEFAULT_MAX_ARCHIVE_BYTES,
                ):
                    self.fail("source ACL drift was accepted")

            copied.assert_not_called()
            self.assertEqual(source_policies, [])
            self.assertEqual(stat.S_IMODE(archive_path.stat().st_mode), source_mode)

    def test_source_acl_drift_after_copy_is_rejected_before_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            source_metadata = archive_path.stat()
            source_identity = (source_metadata.st_dev, source_metadata.st_ino)
            initial_policy = ("test-source-acl-v1", 32, "a" * 64)
            changed_policy = ("test-source-acl-v1", 32, "b" * 64)
            source_policies = [
                initial_policy,
                initial_policy,
                changed_policy,
            ]
            real_policy = MODULE._stable_source_access_policy_binding
            real_copy = MODULE._copy_archive_snapshot

            def policy_for_descriptor(fd: int) -> tuple[str, int, str]:
                current = os.fstat(fd)
                if (current.st_dev, current.st_ino) == source_identity:
                    return source_policies.pop(0)
                return real_policy(fd)

            with (
                mock.patch.object(
                    MODULE,
                    "_stable_source_access_policy_binding",
                    side_effect=policy_for_descriptor,
                ),
                mock.patch.object(
                    MODULE,
                    "_copy_archive_snapshot",
                    wraps=real_copy,
                ) as copied,
                mock.patch.object(MODULE, "_digest_archive_fd") as digested,
                self.assertRaisesRegex(
                    zipfile.BadZipFile,
                    "archive source access policy changed during snapshot binding",
                ),
            ):
                with MODULE._open_pinned_archive(
                    archive_path,
                    MODULE.DEFAULT_MAX_ARCHIVE_BYTES,
                ):
                    self.fail("post-copy source ACL drift was accepted")

            copied.assert_called_once()
            digested.assert_not_called()
            self.assertEqual(source_policies, [])

    def test_source_acl_drift_after_final_digest_is_rejected_with_unchanged_mode(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            source_metadata = archive_path.stat()
            source_identity = (source_metadata.st_dev, source_metadata.st_ino)
            source_mode = stat.S_IMODE(source_metadata.st_mode)
            initial_policy = ("test-source-acl-v1", 32, "a" * 64)
            changed_policy = ("test-source-acl-v1", 32, "b" * 64)
            source_policies = [
                initial_policy,
                initial_policy,
                initial_policy,
                changed_policy,
            ]
            real_policy = MODULE._stable_source_access_policy_binding
            real_copy = MODULE._copy_archive_snapshot

            def policy_for_descriptor(fd: int) -> tuple[str, int, str]:
                current = os.fstat(fd)
                if (current.st_dev, current.st_ino) == source_identity:
                    return source_policies.pop(0)
                return real_policy(fd)

            with (
                mock.patch.object(
                    MODULE,
                    "_stable_source_access_policy_binding",
                    side_effect=policy_for_descriptor,
                ),
                mock.patch.object(
                    MODULE,
                    "_copy_archive_snapshot",
                    wraps=real_copy,
                ) as copied,
                self.assertRaisesRegex(
                    zipfile.BadZipFile,
                    "archive source access policy changed during snapshot binding",
                ),
            ):
                with MODULE._open_pinned_archive(
                    archive_path,
                    MODULE.DEFAULT_MAX_ARCHIVE_BYTES,
                ):
                    self.fail("source ACL drift was accepted")

            copied.assert_called_once()
            self.assertEqual(source_policies, [])
            self.assertEqual(stat.S_IMODE(archive_path.stat().st_mode), source_mode)

    def test_snapshot_ignores_ambient_tmpdir_and_is_unlinked_before_copy(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            archive_path = self._make_archive(root)
            ambient_tmpdir = root / "ambient-tmp"
            ambient_tmpdir.mkdir(mode=0o700)
            real_copy = MODULE._copy_archive_snapshot
            observed: dict[str, int] = {}

            def inspect_snapshot_before_copy(
                source_fd: int,
                snapshot_fd: int,
                archive_size: int,
                deadline: MODULE.ArchiveCommandDeadline,
            ) -> bytes:
                metadata = os.fstat(snapshot_fd)
                observed["links"] = metadata.st_nlink
                observed["mode"] = stat.S_IMODE(metadata.st_mode)
                return real_copy(
                    source_fd,
                    snapshot_fd,
                    archive_size,
                    deadline,
                )

            with (
                mock.patch.dict(
                    os.environ,
                    {"TMPDIR": str(ambient_tmpdir)},
                    clear=False,
                ),
                mock.patch.object(
                    MODULE,
                    "_copy_archive_snapshot",
                    side_effect=inspect_snapshot_before_copy,
                ),
                MODULE._open_pinned_archive(
                    archive_path,
                    MODULE.DEFAULT_MAX_ARCHIVE_BYTES,
                ) as archive_stream,
            ):
                archive_stream.seek(0)
                self.assertEqual(archive_stream.read(4), b"PK\x03\x04")

            self.assertEqual(list(ambient_tmpdir.iterdir()), [])
            self.assertEqual(observed, {"links": 0, "mode": 0o600})

    def test_snapshot_acl_is_validated_before_first_archive_byte_is_written(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            real_policy = MODULE._stable_snapshot_access_policy_binding

            def reject_regular_file(fd: int) -> tuple[str, int, str]:
                metadata = os.fstat(fd)
                if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 0:
                    raise OSError(errno.EACCES, "injected snapshot ACL grant")
                return real_policy(fd)

            with (
                mock.patch.object(
                    MODULE,
                    "_stable_snapshot_access_policy_binding",
                    side_effect=reject_regular_file,
                ),
                mock.patch.object(
                    MODULE,
                    "_copy_archive_snapshot",
                ) as copied,
                self.assertRaisesRegex(
                    OSError,
                    "injected snapshot ACL grant",
                ),
            ):
                with MODULE._open_pinned_archive(
                    archive_path,
                    MODULE.DEFAULT_MAX_ARCHIVE_BYTES,
                ):
                    self.fail("unsafe snapshot was published")

            copied.assert_not_called()

    def test_linux_acl_profile_binds_raw_named_acl_under_the_same_mask(
        self,
    ) -> None:
        def access_acl(named_user_permissions: int) -> bytes:
            undefined_id = 0xFFFFFFFF
            return b"".join(
                (
                    struct.pack("<I", 0x0002),
                    struct.pack("<HHI", 0x0001, 0o6, undefined_id),
                    struct.pack("<HHI", 0x0002, named_user_permissions, 1000),
                    struct.pack("<HHI", 0x0004, 0, undefined_id),
                    struct.pack("<HHI", 0x0010, 0o4, undefined_id),
                    struct.pack("<HHI", 0x0020, 0, undefined_id),
                )
            )

        first_acl = access_acl(0o4)
        second_acl = access_acl(0)
        self.assertEqual(len(first_acl), len(second_acl))
        payloads = iter((first_acl, second_acl))

        def copy_acl(
            fd: int,
            name: bytes,
            destination: object,
            capacity: int,
        ) -> int:
            self.assertEqual(fd, 17)
            self.assertEqual(name, MODULE.LINUX_POSIX_ACL_XATTR_NAME)
            payload = next(payloads)
            self.assertGreaterEqual(capacity, len(payload))
            ctypes.memmove(destination, payload, len(payload))
            return len(payload)

        runtime = object.__new__(MODULE._LinuxSnapshotAclRuntime)
        runtime._libc = mock.Mock()
        runtime._libc.fgetxattr.side_effect = copy_acl

        first_binding = runtime.binding(17)
        second_binding = runtime.binding(17)

        self.assertEqual(
            first_binding,
            (
                MODULE.LINUX_SNAPSHOT_ACL_PROFILE,
                len(first_acl),
                hashlib.sha256(first_acl).hexdigest(),
            ),
        )
        self.assertEqual(second_binding[1], len(second_acl))
        self.assertNotEqual(first_binding, second_binding)

    def test_linux_acl_query_distinguishes_absent_unsupported_and_unreadable(
        self,
    ) -> None:
        runtime = object.__new__(MODULE._LinuxSnapshotAclRuntime)
        runtime._libc = mock.Mock()

        def fail_with(error_number: int) -> object:
            def fail(
                _fd: int,
                _name: bytes,
                _destination: object,
                _capacity: int,
            ) -> int:
                ctypes.set_errno(error_number)
                return -1

            return fail

        runtime._libc.fgetxattr.side_effect = fail_with(errno.ENODATA)
        self.assertEqual(
            runtime.binding(17),
            (
                MODULE.LINUX_SNAPSHOT_ACL_PROFILE,
                0,
                "no-posix-access-acl",
            ),
        )

        cases = (
            (
                getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
                "is unsupported",
            ),
            (errno.EACCES, "query failed"),
        )
        for error_number, message in cases:
            with self.subTest(error_number=error_number):
                runtime._libc.fgetxattr.side_effect = fail_with(error_number)
                with self.assertRaisesRegex(OSError, message) as raised:
                    runtime.binding(17)
                self.assertEqual(raised.exception.errno, error_number)

        runtime._libc.fgetxattr.side_effect = fail_with(errno.ERANGE)
        with self.assertRaisesRegex(OSError, "byte ceiling") as overflow:
            runtime.binding(17)
        self.assertEqual(overflow.exception.errno, errno.EOVERFLOW)

    def test_access_policy_query_failure_is_distinct_from_binding_drift(
        self,
    ) -> None:
        with mock.patch.object(
            MODULE,
            "_source_access_policy_binding",
            side_effect=OSError(errno.EACCES, "injected unreadable ACL"),
        ):
            with self.assertRaisesRegex(
                OSError,
                "injected unreadable ACL",
            ) as unreadable:
                MODULE._stable_source_access_policy_binding(17)
        self.assertEqual(unreadable.exception.errno, errno.EACCES)

        with mock.patch.object(
            MODULE,
            "_source_access_policy_binding",
            side_effect=(
                ("test-source-acl-v1", 32, "a" * 64),
                ("test-source-acl-v1", 32, "b" * 64),
            ),
        ):
            with self.assertRaisesRegex(
                OSError,
                "access policy changed during inspection",
            ) as drift:
                MODULE._stable_source_access_policy_binding(17)
        self.assertEqual(drift.exception.errno, errno.EAGAIN)

    def test_source_acl_query_errors_abort_before_snapshot_creation(self) -> None:
        cases = (
            (errno.ENOTSUP, "injected unsupported ACL"),
            (errno.EACCES, "injected unreadable ACL"),
        )
        for error_number, message in cases:
            with self.subTest(error_number=error_number):
                with tempfile.TemporaryDirectory() as temp_dir:
                    archive_path = self._make_archive(Path(temp_dir))
                    with (
                        mock.patch.object(
                            MODULE,
                            "_stable_source_access_policy_binding",
                            side_effect=OSError(error_number, message),
                        ),
                        mock.patch.object(
                            MODULE,
                            "_create_private_archive_snapshot",
                        ) as created,
                        self.assertRaisesRegex(OSError, message) as raised,
                    ):
                        with MODULE._open_pinned_archive(
                            archive_path,
                            MODULE.DEFAULT_MAX_ARCHIVE_BYTES,
                        ):
                            self.fail("unavailable source ACL was accepted")

                    self.assertEqual(raised.exception.errno, error_number)
                    created.assert_not_called()

    @unittest.skipUnless(
        sys.platform == "darwin",
        "requires Darwin inherited extended ACLs",
    )
    def test_snapshot_rejects_inherited_allow_acl_before_copy(self) -> None:
        with owner_controlled_temp_root() as temp_root:
            archive_path = self._make_archive(temp_root)
            _set_fixture_darwin_acl(
                temp_root,
                "everyone allow read,file_inherit,directory_inherit",
            )
            try:
                with (
                    mock.patch.object(
                        MODULE,
                        "ARCHIVE_SNAPSHOT_PARENT",
                        temp_root,
                    ),
                    mock.patch.object(
                        MODULE,
                        "_copy_archive_snapshot",
                    ) as copied,
                    self.assertRaisesRegex(
                        OSError,
                        "Darwin extended ACL grants are not allowed",
                    ),
                ):
                    with MODULE._open_pinned_archive(
                        archive_path,
                        MODULE.DEFAULT_MAX_ARCHIVE_BYTES,
                    ):
                        self.fail("inherited snapshot grant was accepted")
                copied.assert_not_called()
            finally:
                _clear_fixture_darwin_acl(temp_root)

    @unittest.skipUnless(
        sys.platform == "darwin",
        "requires Darwin extended ACLs",
    )
    def test_source_darwin_acl_drift_after_copy_is_rejected(self) -> None:
        with owner_controlled_temp_root() as temp_root:
            archive_path = self._make_archive(temp_root)
            real_copy = MODULE._copy_archive_snapshot
            acl_set = False

            def copy_then_change_acl(
                source_fd: int,
                snapshot_fd: int,
                archive_size: int,
                deadline: MODULE.ArchiveCommandDeadline,
            ) -> bytes:
                nonlocal acl_set
                digest = real_copy(
                    source_fd,
                    snapshot_fd,
                    archive_size,
                    deadline,
                )
                _set_fixture_darwin_acl(
                    archive_path,
                    "everyone deny readextattr",
                )
                acl_set = True
                return digest

            try:
                with (
                    mock.patch.object(
                        MODULE,
                        "_copy_archive_snapshot",
                        side_effect=copy_then_change_acl,
                    ),
                    self.assertRaisesRegex(
                        zipfile.BadZipFile,
                        "archive source access policy changed during snapshot binding",
                    ),
                ):
                    with MODULE._open_pinned_archive(
                        archive_path,
                        MODULE.DEFAULT_MAX_ARCHIVE_BYTES,
                    ):
                        self.fail("Darwin source ACL drift was accepted")
            finally:
                if acl_set:
                    _clear_fixture_darwin_acl(archive_path)

    @unittest.skipUnless(
        sys.platform == "darwin",
        "requires Darwin extended ACLs",
    )
    def test_source_darwin_stable_extended_allow_acl_is_bound_not_rejected(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            archive_path = self._make_archive(temp_root)
            _set_fixture_darwin_acl(
                archive_path,
                "everyone allow readextattr",
            )
            try:
                with MODULE._open_pinned_archive(
                    archive_path,
                    MODULE.DEFAULT_MAX_ARCHIVE_BYTES,
                ) as archive_stream:
                    archive_stream.seek(0)
                    self.assertEqual(archive_stream.read(4), b"PK\x03\x04")
            finally:
                _clear_fixture_darwin_acl(archive_path)

    def test_final_validation_allows_timestamp_only_churn(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            original_validate = MODULE.PinnedArchiveReader.validate_unchanged

            def touch_then_validate(
                archive_stream: MODULE.PinnedArchiveReader,
            ) -> None:
                current = archive_path.stat()
                os.utime(
                    archive_path,
                    ns=(current.st_atime_ns, current.st_mtime_ns + 1_000_000),
                )
                original_validate(archive_stream)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch.object(
                MODULE.PinnedArchiveReader,
                "validate_unchanged",
                autospec=True,
                side_effect=touch_then_validate,
            ):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    rc = MODULE.cmd_zip_list(self._list_args(archive_path))

        self.assertEqual(rc, 0)
        self.assertNotEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")

    def test_zip_preflight_rejects_eocd_signature_in_comment(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            data = bytearray(archive_path.read_bytes())
            eocd_offset = data.rfind(MODULE.EOCD_SIGNATURE)
            self.assertGreaterEqual(eocd_offset, 0)
            comment = b"prefix" + MODULE.EOCD_SIGNATURE + b"suffix"
            struct.pack_into("<H", data, eocd_offset + 20, len(comment))
            archive_path.write_bytes(data + comment)
            args = self._list_args(archive_path)
            real_zipfile = zipfile.ZipFile
            stderr = io.StringIO()
            with mock.patch.object(
                MODULE.zipfile,
                "ZipFile",
                wraps=real_zipfile,
            ) as constructor:
                with redirect_stderr(stderr):
                    rc = MODULE.cmd_zip_list(args)

        self.assertEqual(rc, 1)
        constructor.assert_not_called()
        self.assertIn(
            "ambiguous end-of-central-directory signature",
            stderr.getvalue(),
        )

    def test_zip_preflight_rejects_nested_dual_view_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_dual_view_archive(Path(temp_dir))
            with zipfile.ZipFile(archive_path) as archive:
                self.assertEqual(archive.namelist(), ["inner.txt"])

            outer_bytes = archive_path.read_bytes()
            outer_eocd_offset = outer_bytes.find(MODULE.EOCD_SIGNATURE)
            inner_eocd_offset = outer_bytes.rfind(MODULE.EOCD_SIGNATURE)
            self.assertGreater(inner_eocd_offset, outer_eocd_offset)
            outer_comment_length = struct.unpack_from(
                "<H",
                outer_bytes,
                outer_eocd_offset + 20,
            )[0]
            inner_comment_length = struct.unpack_from(
                "<H",
                outer_bytes,
                inner_eocd_offset + 20,
            )[0]
            self.assertEqual(
                outer_eocd_offset + MODULE.EOCD_MIN_SIZE + outer_comment_length,
                len(outer_bytes),
            )
            self.assertEqual(
                inner_eocd_offset + MODULE.EOCD_MIN_SIZE + inner_comment_length,
                len(outer_bytes),
            )

            real_zipfile = zipfile.ZipFile
            stderr = io.StringIO()
            with mock.patch.object(
                MODULE.zipfile,
                "ZipFile",
                wraps=real_zipfile,
            ) as constructor:
                with redirect_stderr(stderr):
                    rc = MODULE.cmd_zip_list(self._list_args(archive_path))

        self.assertEqual(rc, 1)
        constructor.assert_not_called()
        self.assertIn(
            "ambiguous end-of-central-directory signature",
            stderr.getvalue(),
        )

    def test_zip_preflight_does_not_cap_unverified_eocd_signatures(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "many-signatures.zip"
            invalid_candidate = MODULE.EOCD_SIGNATURE + (b"\0" * 18)
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(
                    "many-signatures.bin",
                    invalid_candidate * 2_048,
                    compress_type=zipfile.ZIP_STORED,
                )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = MODULE.cmd_zip_list(self._list_args(archive_path))

        self.assertEqual(rc, 0, stderr.getvalue())
        self.assertIn("many-signatures.bin", stdout.getvalue())

    def test_unprefixed_single_eocd_candidate_variants_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            ordinary_path = self._make_archive(directory)
            zip64_path = self._make_forced_zip64_archive(directory)

            cases = {
                "ordinary": ordinary_path,
                "zip64": zip64_path,
            }
            for label, archive_path in cases.items():
                with self.subTest(case=label):
                    stderr = io.StringIO()
                    with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                        rc = MODULE.cmd_zip_list(self._list_args(archive_path))
                    self.assertEqual(rc, 0, stderr.getvalue())

    def test_prefixed_ordinary_archive_is_rejected_before_zipfile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            archive_path = self._make_archive(directory)
            prefixed_path = directory / "prefixed.zip"
            prefixed_path.write_bytes(
                b"self-extracting-prefix" + archive_path.read_bytes()
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            real_zipfile = zipfile.ZipFile
            with mock.patch.object(
                MODULE.zipfile,
                "ZipFile",
                wraps=real_zipfile,
            ) as constructor:
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    rc = MODULE.cmd_zip_list(self._list_args(prefixed_path))

        self.assertEqual(rc, 1)
        constructor.assert_not_called()
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn(
            "concatenated or prefixed ZIP archives are unsupported",
            stderr.getvalue(),
        )

    def test_prefixed_archive_with_rebased_offsets_is_rejected_before_zipfile(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            archive_path = self._make_archive(directory)
            self._prepend_and_rebase_archive(
                archive_path,
                b"polyglot-prefix",
            )
            with zipfile.ZipFile(archive_path) as archive:
                self.assertEqual(
                    archive.namelist(),
                    [
                        "logs/console.txt",
                        "logs/worker.log",
                        "metadata.json",
                    ],
                )

            stdout = io.StringIO()
            stderr = io.StringIO()
            real_zipfile = zipfile.ZipFile
            with mock.patch.object(
                MODULE.zipfile,
                "ZipFile",
                wraps=real_zipfile,
            ) as constructor:
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    rc = MODULE.cmd_zip_list(self._list_args(archive_path))

        self.assertEqual(rc, 1)
        constructor.assert_not_called()
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn(
            "concatenated or prefixed ZIP archives are unsupported",
            stderr.getvalue(),
        )

    def test_prefixed_classic_archive_cannot_forge_unused_offset_zero(
        self,
    ) -> None:
        selected_name = "logs/selected.log"
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "forged-classic.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("logs/unused.log", "unused\n")
                archive.writestr(selected_name, "selected\n")
            self._prepend_and_rebase_archive(
                archive_path,
                b"not-a-local-record",
                forged_zero_ordinal=1,
            )
            with zipfile.ZipFile(archive_path) as archive:
                self.assertEqual(archive.read(selected_name), b"selected\n")

            stdout = io.StringIO()
            stderr = io.StringIO()
            real_zipfile = zipfile.ZipFile
            with mock.patch.object(
                MODULE.zipfile,
                "ZipFile",
                wraps=real_zipfile,
            ) as constructor:
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    rc = MODULE.cmd_zip_show(
                        self._show_args(
                            archive_path,
                            member=selected_name,
                        )
                    )

        self.assertEqual(rc, 1)
        constructor.assert_not_called()
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn(
            "first local record has an invalid local-file-header signature",
            stderr.getvalue(),
        )

    def test_prefixed_classic_archive_rejects_copied_valid_local_record(
        self,
    ) -> None:
        selected_name = "logs/selected.log"
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "copied-prefix-classic.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("logs/unused.log", "unused\n")
                archive.writestr(selected_name, "selected\n")
            valid_prefix = self._first_local_record_bytes(archive_path)
            self._prepend_and_rebase_archive(
                archive_path,
                valid_prefix,
                forged_zero_ordinal=1,
            )
            with zipfile.ZipFile(archive_path) as archive:
                self.assertEqual(archive.read(selected_name), b"selected\n")

            stdout = io.StringIO()
            stderr = io.StringIO()
            real_zipfile = zipfile.ZipFile
            with mock.patch.object(
                MODULE.zipfile,
                "ZipFile",
                wraps=real_zipfile,
            ) as constructor:
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    rc = MODULE.cmd_zip_show(
                        self._show_args(
                            archive_path,
                            member=selected_name,
                        )
                    )

        self.assertEqual(rc, 1)
        constructor.assert_not_called()
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn(
            "unexplained bytes between local records",
            stderr.getvalue(),
        )

    def test_prefixed_empty_archive_with_rebased_offset_is_rejected_before_zipfile(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "empty.zip"
            with zipfile.ZipFile(archive_path, "w"):
                pass
            self._prepend_and_rebase_archive(
                archive_path,
                b"polyglot-prefix",
            )
            with zipfile.ZipFile(archive_path) as archive:
                self.assertEqual(archive.namelist(), [])

            stdout = io.StringIO()
            stderr = io.StringIO()
            real_zipfile = zipfile.ZipFile
            with mock.patch.object(
                MODULE.zipfile,
                "ZipFile",
                wraps=real_zipfile,
            ) as constructor:
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    rc = MODULE.cmd_zip_list(self._list_args(archive_path))

        self.assertEqual(rc, 1)
        constructor.assert_not_called()
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn(
            "concatenated or prefixed empty ZIP archives are unsupported",
            stderr.getvalue(),
        )

    def test_zip64_preflight_accepts_classic_eocd_sentinels(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_zip64_metadata_archive(
                Path(temp_dir),
                classic_eocd=(
                    0xFFFF,
                    0xFFFF,
                    0xFFFF,
                    0xFFFF,
                    0xFFFFFFFF,
                    0xFFFFFFFF,
                ),
            )
            with MODULE._open_pinned_archive(
                archive_path,
                MODULE.DEFAULT_MAX_ARCHIVE_BYTES,
            ) as archive_stream:
                MODULE._preflight_central_directory(
                    archive_stream,
                    max_archive_members=MODULE.DEFAULT_MAX_ARCHIVE_MEMBERS,
                    max_central_directory_bytes=(
                        MODULE.DEFAULT_MAX_CENTRAL_DIRECTORY_BYTES
                    ),
                )

    def test_zip64_preflight_accepts_equal_classic_eocd_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_zip64_metadata_archive(
                Path(temp_dir),
                classic_eocd=(
                    0,
                    0,
                    1,
                    1,
                    MODULE.CENTRAL_DIRECTORY_HEADER_SIZE,
                    MODULE.LOCAL_FILE_HEADER_SIZE,
                ),
            )
            with MODULE._open_pinned_archive(
                archive_path,
                MODULE.DEFAULT_MAX_ARCHIVE_BYTES,
            ) as archive_stream:
                MODULE._preflight_central_directory(
                    archive_stream,
                    max_archive_members=MODULE.DEFAULT_MAX_ARCHIVE_MEMBERS,
                    max_central_directory_bytes=(
                        MODULE.DEFAULT_MAX_CENTRAL_DIRECTORY_BYTES
                    ),
                )

    def test_zip64_preflight_rejects_conflicting_classic_eocd_values(self) -> None:
        cases = {
            "disk-number": (
                1,
                0,
                1,
                1,
                MODULE.CENTRAL_DIRECTORY_HEADER_SIZE,
                MODULE.LOCAL_FILE_HEADER_SIZE,
            ),
            "central-directory-disk": (
                0,
                1,
                1,
                1,
                MODULE.CENTRAL_DIRECTORY_HEADER_SIZE,
                MODULE.LOCAL_FILE_HEADER_SIZE,
            ),
            "entries-on-disk": (
                0,
                0,
                2,
                1,
                MODULE.CENTRAL_DIRECTORY_HEADER_SIZE,
                MODULE.LOCAL_FILE_HEADER_SIZE,
            ),
            "total-entries": (
                0,
                0,
                1,
                2,
                MODULE.CENTRAL_DIRECTORY_HEADER_SIZE,
                MODULE.LOCAL_FILE_HEADER_SIZE,
            ),
            "central-directory-size": (
                0,
                0,
                1,
                1,
                MODULE.CENTRAL_DIRECTORY_HEADER_SIZE - 1,
                MODULE.LOCAL_FILE_HEADER_SIZE,
            ),
            "central-directory-offset": (
                0,
                0,
                1,
                1,
                MODULE.CENTRAL_DIRECTORY_HEADER_SIZE,
                MODULE.LOCAL_FILE_HEADER_SIZE + 1,
            ),
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            for field, classic_eocd in cases.items():
                with self.subTest(field=field):
                    archive_path = self._make_zip64_metadata_archive(
                        Path(temp_dir),
                        classic_eocd=classic_eocd,
                    )
                    with MODULE._open_pinned_archive(
                        archive_path,
                        MODULE.DEFAULT_MAX_ARCHIVE_BYTES,
                    ) as archive_stream:
                        with self.assertRaisesRegex(
                            zipfile.BadZipFile,
                            f"field={field}",
                        ):
                            MODULE._preflight_central_directory(
                                archive_stream,
                                max_archive_members=(
                                    MODULE.DEFAULT_MAX_ARCHIVE_MEMBERS
                                ),
                                max_central_directory_bytes=(
                                    MODULE.DEFAULT_MAX_CENTRAL_DIRECTORY_BYTES
                                ),
                            )

    def test_unprefixed_forced_zip64_archive_is_accepted_for_extraction(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_forced_zip64_archive(Path(temp_dir))
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = MODULE.cmd_zip_show(
                    self._show_args(
                        archive_path,
                        member="logs/zip64.log",
                    )
                )

        self.assertEqual(rc, 0, stderr.getvalue())
        self.assertIn("zip64", stdout.getvalue())

    def test_prefixed_forced_zip64_archive_is_rejected_before_zipfile(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            archive_path = self._make_forced_zip64_archive(directory)
            prefixed_path = directory / "prefixed-zip64.zip"
            prefixed_path.write_bytes(
                b"prefixed-container-data" + archive_path.read_bytes()
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            real_zipfile = zipfile.ZipFile
            with mock.patch.object(
                MODULE.zipfile,
                "ZipFile",
                wraps=real_zipfile,
            ) as constructor:
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    rc = MODULE.cmd_zip_show(
                        self._show_args(
                            prefixed_path,
                            member="logs/zip64.log",
                        )
                    )

        self.assertEqual(rc, 1)
        constructor.assert_not_called()
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn(
            "concatenated or prefixed ZIP64 archives are unsupported",
            stderr.getvalue(),
        )

    def test_prefixed_zip64_archive_cannot_forge_unused_offset_zero(
        self,
    ) -> None:
        selected_name = "logs/selected-zip64.log"
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "forged-zip64.zip"
            with mock.patch.object(zipfile, "ZIP_FILECOUNT_LIMIT", 0):
                with zipfile.ZipFile(
                    archive_path,
                    "w",
                    allowZip64=True,
                ) as archive:
                    archive.writestr("logs/unused-zip64.log", "unused\n")
                    archive.writestr(selected_name, "selected\n")
            self._prepend_and_rebase_archive(
                archive_path,
                b"not-a-local-record",
                forged_zero_ordinal=1,
            )
            with zipfile.ZipFile(archive_path) as archive:
                self.assertEqual(archive.read(selected_name), b"selected\n")

            stdout = io.StringIO()
            stderr = io.StringIO()
            real_zipfile = zipfile.ZipFile
            with mock.patch.object(
                MODULE.zipfile,
                "ZipFile",
                wraps=real_zipfile,
            ) as constructor:
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    rc = MODULE.cmd_zip_show(
                        self._show_args(
                            archive_path,
                            member=selected_name,
                        )
                    )

        self.assertEqual(rc, 1)
        constructor.assert_not_called()
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn(
            "first local record has an invalid local-file-header signature",
            stderr.getvalue(),
        )

    def test_prefixed_zip64_archive_rejects_copied_valid_local_record(
        self,
    ) -> None:
        selected_name = "logs/selected-zip64.log"
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "copied-prefix-zip64.zip"
            with mock.patch.object(zipfile, "ZIP_FILECOUNT_LIMIT", 0):
                with zipfile.ZipFile(
                    archive_path,
                    "w",
                    allowZip64=True,
                ) as archive:
                    archive.writestr("logs/unused-zip64.log", "unused\n")
                    archive.writestr(selected_name, "selected\n")
            valid_prefix = self._first_local_record_bytes(archive_path)
            self._prepend_and_rebase_archive(
                archive_path,
                valid_prefix,
                forged_zero_ordinal=1,
            )
            with zipfile.ZipFile(archive_path) as archive:
                self.assertEqual(archive.read(selected_name), b"selected\n")

            stdout = io.StringIO()
            stderr = io.StringIO()
            real_zipfile = zipfile.ZipFile
            with mock.patch.object(
                MODULE.zipfile,
                "ZipFile",
                wraps=real_zipfile,
            ) as constructor:
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    rc = MODULE.cmd_zip_show(
                        self._show_args(
                            archive_path,
                            member=selected_name,
                        )
                    )

        self.assertEqual(rc, 1)
        constructor.assert_not_called()
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn(
            "unexplained bytes between local records",
            stderr.getvalue(),
        )

    def test_zip64_rejects_tampered_locator_offsets(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_forced_zip64_archive(Path(temp_dir))
            original = archive_path.read_bytes()
            locator_offset = original.rfind(MODULE.ZIP64_LOCATOR_SIGNATURE)
            self.assertGreaterEqual(locator_offset, 0)
            logical_zip64_offset = struct.unpack_from(
                "<Q",
                original,
                locator_offset + 8,
            )[0]
            physical_zip64_offset = locator_offset - MODULE.ZIP64_EOCD_MIN_SIZE
            cases = {
                "before-physical": logical_zip64_offset - 1,
                "beyond-physical": physical_zip64_offset + 1,
            }
            self.assertEqual(logical_zip64_offset, physical_zip64_offset)
            self.assertGreater(logical_zip64_offset, 0)
            for label, tampered_offset in cases.items():
                with self.subTest(case=label):
                    data = bytearray(original)
                    struct.pack_into(
                        "<Q",
                        data,
                        locator_offset + 8,
                        tampered_offset,
                    )
                    candidate = Path(temp_dir) / f"{label}.zip"
                    candidate.write_bytes(data)
                    stderr = io.StringIO()
                    with redirect_stderr(stderr):
                        rc = MODULE.cmd_zip_list(self._list_args(candidate))

                    self.assertEqual(rc, 1)
                    self.assertIn("ZIP64", stderr.getvalue())

    def test_unsupported_general_purpose_flags_are_rejected_before_zipfile(
        self,
    ) -> None:
        unsupported_bits = [
            1 << bit_index
            for bit_index in range(16)
            if not (1 << bit_index) & MODULE.SUPPORTED_GENERAL_PURPOSE_FLAGS
        ]
        self.assertIn(0x0020, unsupported_bits)
        self.assertIn(0x0040, unsupported_bits)
        self.assertEqual(len(unsupported_bits), 14)

        for flag_bits in unsupported_bits:
            with self.subTest(flag_bits=f"0x{flag_bits:04x}"):
                with tempfile.TemporaryDirectory() as temp_dir:
                    archive_path = Path(temp_dir) / "flags.zip"
                    with self.assertWarns(UserWarning):
                        with zipfile.ZipFile(archive_path, "w") as archive:
                            archive.writestr("logs/member.log", "first\n")
                            archive.writestr("logs/member.log", "second\n")
                    self._replace_member_flag_bits(
                        archive_path,
                        ordinal=2,
                        flag_bits=flag_bits,
                    )
                    stdout = io.StringIO()
                    stderr = io.StringIO()
                    with mock.patch.object(
                        MODULE,
                        "BoundedMemberReader",
                        wraps=MODULE.BoundedMemberReader,
                    ) as reader:
                        with redirect_stdout(stdout), redirect_stderr(stderr):
                            rc = MODULE.cmd_zip_show(
                                self._show_args(
                                    archive_path,
                                    member="logs/member.log",
                                    all=True,
                                )
                            )

                self.assertEqual(rc, 1)
                reader.assert_not_called()
                self.assertEqual(stdout.getvalue(), "")
                self.assertIn(
                    "unsupported ZIP general-purpose flag bits",
                    stderr.getvalue(),
                )

    def test_deflate_standard_compression_option_flag_combinations_are_allowed(
        self,
    ) -> None:
        self.assertEqual(MODULE.DEFLATE_OPTION_FLAGS, 0x0006)
        for flag_bits in (0x0000, 0x0002, 0x0004, 0x0006):
            with self.subTest(flag_bits=f"0x{flag_bits:04x}"):
                with tempfile.TemporaryDirectory() as temp_dir:
                    archive_path = Path(temp_dir) / "deflate-options.zip"
                    with zipfile.ZipFile(archive_path, "w") as archive:
                        archive.writestr(
                            "logs/member.log",
                            "deflate-option\n",
                            compress_type=zipfile.ZIP_DEFLATED,
                        )
                    self._replace_member_flag_bits(
                        archive_path,
                        ordinal=1,
                        flag_bits=flag_bits,
                    )
                    stdout = io.StringIO()
                    stderr = io.StringIO()
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        rc = MODULE.cmd_zip_show(
                            self._show_args(
                                archive_path,
                                member="logs/member.log",
                            )
                        )

                self.assertEqual(rc, 0, stderr.getvalue())
                self.assertEqual(stderr.getvalue(), "")
                self.assertIn("deflate-option", stdout.getvalue())

    def test_deflate_options_do_not_allow_encryption_or_dangerous_flags(
        self,
    ) -> None:
        dangerous_bits = {
            "encryption": 0x0001,
            "patched-data": 0x0020,
            "strong-encryption": 0x0040,
            "masked-header": 0x2000,
        }
        for label, dangerous_bit in dangerous_bits.items():
            with self.subTest(flag=label):
                with tempfile.TemporaryDirectory() as temp_dir:
                    archive_path = Path(temp_dir) / f"{label}.zip"
                    with zipfile.ZipFile(archive_path, "w") as archive:
                        archive.writestr(
                            "logs/member.log",
                            "blocked\n",
                            compress_type=zipfile.ZIP_DEFLATED,
                        )
                    self._replace_member_flag_bits(
                        archive_path,
                        ordinal=1,
                        flag_bits=MODULE.DEFLATE_OPTION_FLAGS | dangerous_bit,
                    )
                    stdout = io.StringIO()
                    stderr = io.StringIO()
                    with mock.patch.object(
                        MODULE,
                        "BoundedMemberReader",
                        wraps=MODULE.BoundedMemberReader,
                    ) as reader:
                        with redirect_stdout(stdout), redirect_stderr(stderr):
                            rc = MODULE.cmd_zip_show(
                                self._show_args(
                                    archive_path,
                                    member="logs/member.log",
                                )
                            )

                self.assertEqual(rc, 1)
                reader.assert_not_called()
                self.assertEqual(stdout.getvalue(), "")
                self.assertIn(
                    "unsupported ZIP general-purpose flag bits",
                    stderr.getvalue(),
                )

    def test_nonzero_member_disk_start_is_rejected_before_zipfile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            self._replace_member_disk_start(
                archive_path,
                ordinal=1,
                disk_start=1,
                use_zip64_sentinel=False,
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            real_zipfile = zipfile.ZipFile
            with mock.patch.object(
                MODULE.zipfile,
                "ZipFile",
                wraps=real_zipfile,
            ) as constructor:
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    rc = MODULE.cmd_zip_list(self._list_args(archive_path))

        self.assertEqual(rc, 1)
        constructor.assert_not_called()
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("disk-start=1", stderr.getvalue())

    def test_zip64_member_disk_start_sentinel_is_resolved(self) -> None:
        for disk_start, expected_rc in ((0, 0), (1, 1)):
            with self.subTest(disk_start=disk_start):
                with tempfile.TemporaryDirectory() as temp_dir:
                    archive_path = Path(temp_dir) / "member-disk-start.zip"
                    with zipfile.ZipFile(archive_path, "w") as archive:
                        archive.writestr("logs/member.log", "member\n")
                    self._replace_member_disk_start(
                        archive_path,
                        ordinal=1,
                        disk_start=disk_start,
                        use_zip64_sentinel=True,
                    )
                    stdout = io.StringIO()
                    stderr = io.StringIO()
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        rc = MODULE.cmd_zip_list(self._list_args(archive_path))

                self.assertEqual(rc, expected_rc, stderr.getvalue())
                if expected_rc == 0:
                    self.assertIn("logs/member.log", stdout.getvalue())
                else:
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertIn("disk-start=1", stderr.getvalue())

    def test_python39_static_compatibility_has_no_strict_zip(self) -> None:
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        tree = ast.parse(
            source,
            filename=str(SCRIPT_PATH),
            feature_version=9,
        )
        strict_zip_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "zip"
            and any(keyword.arg == "strict" for keyword in node.keywords)
        ]
        self.assertEqual(strict_zip_calls, [])

    def test_zip_list_rejects_archive_over_file_byte_cap(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            args = self._list_args(archive_path, max_archive_bytes=1)
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                rc = MODULE.cmd_zip_list(args)

        self.assertEqual(rc, 1)
        self.assertIn("archive file exceeds max bytes", stderr.getvalue())

    def test_zip_show_uses_one_pinned_archive_open(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            args = self._show_args(archive_path, head=1)
            real_open = os.open
            with mock.patch.object(
                MODULE.os,
                "open",
                wraps=real_open,
            ) as open_call:
                with redirect_stdout(io.StringIO()):
                    rc = MODULE.cmd_zip_show(args)

        self.assertEqual(rc, 0)
        source_open_calls = [
            call
            for call in open_call.call_args_list
            if call.args and call.args[0] == archive_path
        ]
        self.assertEqual(len(source_open_calls), 1)

    def test_archive_growth_during_snapshot_binding_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            real_copy = MODULE._copy_archive_snapshot

            def copy_then_grow(
                source_fd: int,
                snapshot_fd: int,
                archive_size: int,
                deadline: MODULE.ArchiveCommandDeadline,
            ) -> bytes:
                digest = real_copy(
                    source_fd,
                    snapshot_fd,
                    archive_size,
                    deadline,
                )
                with archive_path.open("ab") as stream:
                    stream.write(b"concurrent-growth")
                    stream.flush()
                    os.fsync(stream.fileno())
                return digest

            stdout = io.StringIO()
            stderr = io.StringIO()
            real_zipfile = zipfile.ZipFile
            with mock.patch.object(
                MODULE,
                "_copy_archive_snapshot",
                side_effect=copy_then_grow,
            ):
                with mock.patch.object(
                    MODULE.zipfile,
                    "ZipFile",
                    wraps=real_zipfile,
                ) as constructor:
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        rc = MODULE.cmd_zip_list(self._list_args(archive_path))

        self.assertEqual(rc, 1)
        constructor.assert_not_called()
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn(
            "archive changed during snapshot binding",
            stderr.getvalue(),
        )

    def test_pinned_archive_reader_enforces_initial_eof(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            archive_size = archive_path.stat().st_size
            with MODULE._open_pinned_archive(
                archive_path,
                MODULE.DEFAULT_MAX_ARCHIVE_BYTES,
            ) as archive_stream:
                with self.assertRaisesRegex(
                    zipfile.BadZipFile,
                    "seek exceeds the initially accepted size",
                ):
                    archive_stream.seek(archive_size + 1)
                archive_stream.seek(archive_size)
                self.assertEqual(archive_stream.read(1), b"")

    def test_zip_show_escapes_terminal_control_characters(self) -> None:
        unsafe_line = "before\x1b]0;owned\x07after\x08X\u009b31mred\u202e"
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "terminal-controls.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(
                    "logs/control.log",
                    unsafe_line + "\n",
                )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = MODULE.cmd_zip_show(
                    self._show_args(
                        archive_path,
                        member="logs/control.log",
                    )
                )

        self.assertEqual(rc, 0, stderr.getvalue())
        rendered = stdout.getvalue()
        for unsafe_character in ("\x1b", "\x07", "\x08", "\u009b", "\u202e"):
            self.assertNotIn(unsafe_character, rendered)
        self.assertIn(
            "before\\x1b]0;owned\\x07after\\x08X\\x9b31mred\\u202e",
            rendered,
        )

    def test_regex_entrypoints_terminate_catastrophic_backtracking(self) -> None:
        catastrophic_pattern = r"(a+)+$"
        hostile_name = ("a" * 400) + "!"
        hostile_line = ("a" * 20_000) + "!\n"
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "regex-deadline.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(hostile_name, "name\n")
                archive.writestr("logs/hostile.log", hostile_line)

            cases = {
                "zip-list-match": self._list_args(
                    archive_path,
                    match=catastrophic_pattern,
                ),
                "member-regex": self._show_args(
                    archive_path,
                    member=catastrophic_pattern,
                    regex=True,
                ),
                "grep": self._show_args(
                    archive_path,
                    member="logs/hostile.log",
                    grep=catastrophic_pattern,
                ),
            }
            for label, args in cases.items():
                with self.subTest(entrypoint=label):
                    stdout = io.StringIO()
                    stderr = io.StringIO()
                    started = time.monotonic()
                    with mock.patch.object(
                        MODULE,
                        "DEFAULT_REGEX_MATCH_TIMEOUT_SECONDS",
                        0.05,
                    ):
                        with mock.patch.object(
                            MODULE,
                            "DEFAULT_REGEX_AGGREGATE_TIMEOUT_SECONDS",
                            2.0,
                        ):
                            with redirect_stdout(stdout), redirect_stderr(stderr):
                                if label == "zip-list-match":
                                    rc = MODULE.cmd_zip_list(args)
                                else:
                                    rc = MODULE.cmd_zip_show(args)
                    elapsed = time.monotonic() - started

                    self.assertEqual(rc, 1)
                    self.assertLess(elapsed, 2.0)
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertIn(
                        "regular expression per-match deadline exceeded",
                        stderr.getvalue(),
                    )

    def test_regex_budget_starts_after_archive_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            cases = (
                (
                    "zip-list",
                    self._list_args(archive_path, match="console"),
                    MODULE.cmd_zip_list,
                ),
                (
                    "zip-show",
                    self._show_args(
                        archive_path,
                        member=r"logs/console\.txt",
                        regex=True,
                        grep="line",
                    ),
                    MODULE.cmd_zip_show,
                ),
            )
            real_preflight = MODULE._preflight_central_directory
            real_budget = MODULE.RegexMatchBudget

            for label, args, command in cases:
                with self.subTest(command=label):
                    preflight_complete = False

                    def complete_preflight(
                        *preflight_args: object,
                        **preflight_kwargs: object,
                    ) -> MODULE.CentralDirectoryLayout:
                        nonlocal preflight_complete
                        result = real_preflight(
                            *preflight_args,
                            **preflight_kwargs,
                        )
                        preflight_complete = True
                        return result

                    def create_budget() -> MODULE.RegexMatchBudget:
                        self.assertTrue(
                            preflight_complete,
                            "regex aggregate budget started before archive preflight",
                        )
                        return real_budget()

                    stdout = io.StringIO()
                    stderr = io.StringIO()
                    with (
                        mock.patch.object(
                            MODULE,
                            "_preflight_central_directory",
                            side_effect=complete_preflight,
                        ),
                        mock.patch.object(
                            MODULE,
                            "RegexMatchBudget",
                            side_effect=create_budget,
                        ),
                        redirect_stdout(stdout),
                        redirect_stderr(stderr),
                    ):
                        rc = command(args)

                    self.assertEqual(rc, 0, stderr.getvalue())

    def test_regex_timeout_reaps_worker(self) -> None:
        budget = MODULE.RegexMatchBudget()
        process = None
        with MODULE.IsolatedRegexMatcher(
            r"(a+)+$",
            ignore_case=False,
            budget=budget,
        ) as matcher:
            process = matcher._process
            self.assertIsNotNone(process)
            with mock.patch.object(
                MODULE,
                "DEFAULT_REGEX_MATCH_TIMEOUT_SECONDS",
                0.05,
            ):
                with self.assertRaisesRegex(
                    MODULE.ArtifactLimitError,
                    "per-match deadline exceeded",
                ):
                    matcher.search(("a" * 20_000) + "!")

        assert process is not None
        self.assertIsNotNone(process.poll())

    @unittest.skipUnless(
        os.name == "posix"
        and hasattr(os, "killpg")
        and all(
            hasattr(signal, name)
            for name in (
                "SIGALRM",
                "ITIMER_REAL",
                "setitimer",
                "pthread_sigmask",
                "sigpending",
                "SIG_BLOCK",
                "SIG_SETMASK",
            )
        ),
        "deadline teardown transaction requires POSIX signal timers",
    )
    def test_command_deadline_during_regex_teardown_reaps_worker_group(
        self,
    ) -> None:
        real_popen = subprocess.Popen
        deadline = MODULE.ArchiveCommandDeadline()
        matcher = MODULE.IsolatedRegexMatcher(
            "safe",
            ignore_case=False,
            budget=MODULE.RegexMatchBudget(),
            command_deadline=deadline,
        )
        process = None
        worker_pgid = None
        initial_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())

        def isolated_worker_popen(
            *args: object,
            **kwargs: object,
        ) -> subprocess.Popen[bytes]:
            isolated_kwargs = dict(kwargs)
            isolated_kwargs["start_new_session"] = True
            return real_popen(*args, **isolated_kwargs)

        try:
            with mock.patch.object(
                MODULE.subprocess,
                "Popen",
                side_effect=isolated_worker_popen,
            ):
                matcher.__enter__()
            process = matcher._process
            self.assertIsNotNone(process)
            assert process is not None
            worker_pgid = os.getpgid(process.pid)
            self.assertEqual(worker_pgid, process.pid)

            deadline.arm()
            self.assertTrue(matcher.search("safe"))
            real_terminate = process.terminate

            def terminate_after_alarm_is_pending() -> None:
                current_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
                self.assertIn(signal.SIGALRM, current_mask)
                deadline.deadline = time.monotonic() + 0.01
                signal.setitimer(
                    signal.ITIMER_REAL,
                    0.01,
                    MODULE.ARCHIVE_DEADLINE_RETRY_SECONDS,
                )
                pending_deadline = time.monotonic() + 1.0
                while (
                    signal.SIGALRM not in signal.sigpending()
                    and time.monotonic() < pending_deadline
                ):
                    time.sleep(0.005)
                self.assertIn(signal.SIGALRM, signal.sigpending())
                real_terminate()

            with mock.patch.object(
                process,
                "terminate",
                side_effect=terminate_after_alarm_is_pending,
            ):
                with self.assertRaises(MODULE.ArtifactLimitError) as deadline_error:
                    matcher.close()
            self.assertIs(
                type(deadline_error.exception),
                MODULE.ArtifactLimitError,
            )
            self.assertEqual(
                str(deadline_error.exception),
                "archive command deadline exceeded",
            )
            self.assertIsNone(matcher._process)
            self.assertIsNotNone(process.poll())
        finally:
            try:
                signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
                deadline.close()
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, initial_mask)
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)

        assert worker_pgid is not None
        with self.assertRaises(ProcessLookupError):
            os.killpg(worker_pgid, 0)

    @unittest.skipUnless(
        os.name == "posix"
        and hasattr(os, "killpg")
        and all(
            hasattr(signal, name)
            for name in (
                "SIGALRM",
                "ITIMER_REAL",
                "setitimer",
                "pthread_sigmask",
                "sigpending",
                "SIG_BLOCK",
                "SIG_SETMASK",
            )
        ),
        "deadline teardown handshake requires POSIX signal timers",
    )
    def test_regex_cleanup_handshake_preserves_true_original_signal_mask(
        self,
    ) -> None:
        real_popen = subprocess.Popen
        real_sigmask = signal.pthread_sigmask
        deadline = MODULE.ArchiveCommandDeadline()
        matcher = MODULE.IsolatedRegexMatcher(
            "safe",
            ignore_case=False,
            budget=MODULE.RegexMatchBudget(),
            command_deadline=deadline,
        )
        process = None
        worker_pgid = None
        captured_error = None
        transition_attempts = 0
        support_checks = 0
        mask_events: list[tuple[str, set[signal.Signals]]] = []
        initial_mask = real_sigmask(signal.SIG_BLOCK, set())
        real_transition = deadline._transition_regex_cleanup
        real_require_signal_support = deadline._require_signal_support

        def isolated_worker_popen(
            *args: object,
            **kwargs: object,
        ) -> subprocess.Popen[bytes]:
            isolated_kwargs = dict(kwargs)
            isolated_kwargs["start_new_session"] = True
            return real_popen(*args, **isolated_kwargs)

        def interrupt_first_transition(
            expected_state: str,
            next_state: str,
        ) -> None:
            nonlocal transition_attempts
            if (
                expected_state == MODULE.REGEX_CLEANUP_IDLE
                and next_state == MODULE.REGEX_CLEANUP_DEFERRING
            ):
                transition_attempts += 1
                if transition_attempts == 1:
                    deadline._raise_timeout(signal.SIGALRM, None)
            real_transition(expected_state, next_state)

        def interrupt_support_check() -> None:
            nonlocal support_checks
            support_checks += 1
            self.assertEqual(
                deadline._regex_cleanup_state,
                MODULE.REGEX_CLEANUP_DEFERRING,
            )
            deadline._raise_timeout(signal.SIGALRM, None)
            real_require_signal_support()

        def interrupt_first_mask(
            operation: int,
            signals: set[signal.Signals],
        ) -> set[signal.Signals]:
            requested_mask = set(signals)
            if operation == signal.SIG_BLOCK:
                self.assertEqual(
                    deadline._regex_cleanup_state,
                    MODULE.REGEX_CLEANUP_DEFERRING,
                )
                previous_mask = real_sigmask(operation, signals)
                mask_events.append(("block-return", set(previous_mask)))
                current_mask = real_sigmask(signal.SIG_BLOCK, set())
                self.assertIn(signal.SIGALRM, current_mask)
                deadline._raise_timeout(signal.SIGALRM, None)
                return previous_mask
            self.assertEqual(operation, signal.SIG_SETMASK)
            self.assertEqual(
                deadline._regex_cleanup_state,
                MODULE.REGEX_CLEANUP_RESTORING,
            )
            mask_events.append(("restore-request", requested_mask))
            return real_sigmask(operation, signals)

        try:
            deadline.arm()
            with mock.patch.object(
                MODULE.subprocess,
                "Popen",
                side_effect=isolated_worker_popen,
            ):
                matcher.__enter__()
            process = matcher._process
            self.assertIsNotNone(process)
            assert process is not None
            worker_pgid = os.getpgid(process.pid)
            self.assertEqual(worker_pgid, process.pid)
            self.assertTrue(matcher.search("safe"))

            with (
                mock.patch.object(
                    deadline,
                    "_transition_regex_cleanup",
                    side_effect=interrupt_first_transition,
                ),
                mock.patch.object(
                    deadline,
                    "_require_signal_support",
                    side_effect=interrupt_support_check,
                ),
                mock.patch.object(
                    MODULE.signal,
                    "pthread_sigmask",
                    side_effect=interrupt_first_mask,
                ),
            ):
                with self.assertRaises(MODULE.ArtifactLimitError) as error:
                    matcher.close()
                captured_error = error.exception
        finally:
            try:
                real_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
                deadline.close()
            finally:
                real_sigmask(signal.SIG_SETMASK, initial_mask)
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)

        self.assertIsNotNone(captured_error)
        assert captured_error is not None
        self.assertIs(type(captured_error), MODULE.ArtifactLimitError)
        self.assertEqual(
            str(captured_error),
            "archive command deadline exceeded",
        )
        self.assertEqual(transition_attempts, 2)
        self.assertEqual(support_checks, 1)
        self.assertEqual(
            mask_events,
            [
                ("block-return", set(initial_mask)),
                ("restore-request", set(initial_mask)),
            ],
        )
        self.assertEqual(
            real_sigmask(signal.SIG_BLOCK, set()),
            initial_mask,
        )
        self.assertEqual(
            deadline._regex_cleanup_state,
            MODULE.REGEX_CLEANUP_IDLE,
        )
        self.assertIsNone(matcher._process)
        assert process is not None
        self.assertIsNotNone(process.poll())
        assert worker_pgid is not None
        with self.assertRaises(ProcessLookupError):
            os.killpg(worker_pgid, 0)

    def test_regex_cleanup_initial_mask_failure_retains_diagnostic_fence(
        self,
    ) -> None:
        deadline = MODULE.ArchiveCommandDeadline()
        deadline._armed = True
        deadline._diagnostic_timer_safe = True
        mask_error = OSError(errno.EIO, "injected initial mask failure")
        cleanup = mock.Mock()

        with (
            mock.patch.object(deadline, "_require_signal_support"),
            mock.patch.object(
                MODULE.signal,
                "pthread_sigmask",
                side_effect=mask_error,
            ),
            self.assertRaises(OSError) as raised,
        ):
            deadline.run_regex_worker_cleanup(cleanup)

        self.assertIs(raised.exception, mask_error)
        cleanup.assert_not_called()
        self.assertEqual(
            deadline._regex_cleanup_state,
            MODULE.REGEX_CLEANUP_FENCED,
        )
        self.assertFalse(deadline.timer_backed_diagnostics_safe())

        with (
            mock.patch.object(
                MODULE,
                "_publish_terminal_line_without_timer",
                return_value=False,
            ) as publisher,
            redirect_stderr(io.StringIO()),
        ):
            MODULE._emit_error(raised.exception, deadline=deadline)
        publisher.assert_called_once()

    def test_regex_cleanup_restore_failure_preserves_primary_and_fences(
        self,
    ) -> None:
        deadline = MODULE.ArchiveCommandDeadline()
        deadline._armed = True
        deadline._diagnostic_timer_safe = True
        cleanup_error = RuntimeError("injected cleanup failure")
        restore_error = OSError(errno.EIO, "injected mask restore failure")
        mask_calls = 0

        def change_mask(
            _operation: int,
            _signals: object,
        ) -> set[signal.Signals]:
            nonlocal mask_calls
            mask_calls += 1
            if mask_calls == 2:
                raise restore_error
            return set()

        def fail_cleanup() -> None:
            raise cleanup_error

        with (
            mock.patch.object(deadline, "_require_signal_support"),
            mock.patch.object(
                MODULE.signal,
                "pthread_sigmask",
                side_effect=change_mask,
            ),
            self.assertRaises(RuntimeError) as raised,
        ):
            deadline.run_regex_worker_cleanup(fail_cleanup)

        self.assertIs(raised.exception, cleanup_error)
        self.assertIs(raised.exception.__cause__, restore_error)
        self.assertEqual(
            deadline._regex_cleanup_state,
            MODULE.REGEX_CLEANUP_FENCED,
        )
        self.assertFalse(deadline.timer_backed_diagnostics_safe())

        with (
            mock.patch.object(
                MODULE,
                "_publish_terminal_line_without_timer",
                return_value=False,
            ) as publisher,
            redirect_stderr(io.StringIO()),
        ):
            MODULE._emit_error(raised.exception, deadline=deadline)
        publisher.assert_called_once()

    def test_regex_cleanup_restored_mask_returns_to_idle(self) -> None:
        deadline = MODULE.ArchiveCommandDeadline()
        deadline._armed = True
        deadline._diagnostic_timer_safe = True
        mask_operations: list[int] = []
        cleanup = mock.Mock()

        def change_mask(
            operation: int,
            _signals: object,
        ) -> set[signal.Signals]:
            mask_operations.append(operation)
            return set()

        with (
            mock.patch.object(deadline, "_require_signal_support"),
            mock.patch.object(
                MODULE.signal,
                "pthread_sigmask",
                side_effect=change_mask,
            ),
        ):
            deadline.run_regex_worker_cleanup(cleanup)

        cleanup.assert_called_once_with()
        self.assertEqual(
            mask_operations,
            [signal.SIG_BLOCK, signal.SIG_SETMASK],
        )
        self.assertEqual(
            deadline._regex_cleanup_state,
            MODULE.REGEX_CLEANUP_IDLE,
        )
        self.assertTrue(deadline.timer_backed_diagnostics_safe())

    @unittest.skipUnless(
        os.name == "posix"
        and all(
            hasattr(signal, name)
            for name in (
                "SIGALRM",
                "ITIMER_REAL",
                "setitimer",
                "pthread_sigmask",
                "SIG_BLOCK",
                "SIG_SETMASK",
            )
        ),
        "regex spawn publication requires POSIX signal timers",
    )
    def test_regex_spawn_defers_deadline_at_popen_return_boundary(self) -> None:
        real_popen = subprocess.Popen
        deadline = MODULE.ArchiveCommandDeadline()
        matcher = MODULE.IsolatedRegexMatcher(
            "safe",
            ignore_case=False,
            budget=MODULE.RegexMatchBudget(),
            command_deadline=deadline,
        )
        process = None
        initial_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())

        def interrupt_after_popen_returns(
            *args: object,
            **kwargs: object,
        ) -> subprocess.Popen[bytes]:
            nonlocal process
            process = real_popen(*args, **kwargs)
            self.assertIsNone(matcher._process)
            self.assertEqual(
                deadline._regex_spawn_state,
                MODULE.REGEX_SPAWN_MASKED,
            )
            os.kill(os.getpid(), signal.SIGALRM)
            self.assertIn(signal.SIGALRM, signal.sigpending())
            return process

        try:
            deadline.arm()
            with mock.patch.object(
                MODULE.subprocess,
                "Popen",
                side_effect=interrupt_after_popen_returns,
            ):
                with self.assertRaises(MODULE.ArtifactLimitError) as raised:
                    with MODULE.contextlib.ExitStack() as workers:
                        deadline.enter_regex_worker(workers, matcher)
            self.assertEqual(
                str(raised.exception),
                "archive command deadline exceeded",
            )
            self.assertIsNot(raised.exception.__context__, raised.exception)
            self.assertIsNone(matcher._process)
            assert process is not None
            self.assertIsNotNone(process.poll())
            self.assertEqual(
                signal.pthread_sigmask(signal.SIG_BLOCK, set()),
                initial_mask,
            )
            self.assertEqual(
                deadline._regex_spawn_state,
                MODULE.REGEX_SPAWN_IDLE,
            )
        finally:
            try:
                signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
                deadline.close()
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, initial_mask)
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)

    @unittest.skipUnless(
        os.name == "posix"
        and all(
            hasattr(signal, name)
            for name in (
                "SIGALRM",
                "ITIMER_REAL",
                "setitimer",
                "pthread_sigmask",
                "SIG_BLOCK",
                "SIG_SETMASK",
            )
        ),
        "regex spawn handshake requires POSIX signal timers",
    )
    def test_regex_spawn_handshake_preserves_true_original_signal_mask(
        self,
    ) -> None:
        real_sigmask = signal.pthread_sigmask
        deadline = MODULE.ArchiveCommandDeadline()
        matcher = MODULE.IsolatedRegexMatcher(
            "safe",
            ignore_case=False,
            budget=MODULE.RegexMatchBudget(),
            command_deadline=deadline,
        )
        process = None
        support_checks = 0
        spawn_mask_calls = 0
        initial_mask = real_sigmask(signal.SIG_BLOCK, set())
        real_require_signal_support = deadline._require_signal_support

        def interrupt_support_check() -> None:
            nonlocal support_checks
            if deadline._regex_spawn_state == MODULE.REGEX_SPAWN_DEFERRING:
                support_checks += 1
                deadline._raise_timeout(signal.SIGALRM, None)
            real_require_signal_support()

        def interrupt_first_spawn_mask(
            operation: int,
            signals: set[signal.Signals],
        ) -> set[signal.Signals]:
            nonlocal spawn_mask_calls
            previous_mask = real_sigmask(operation, signals)
            if (
                operation == signal.SIG_BLOCK
                and deadline._regex_spawn_state == MODULE.REGEX_SPAWN_DEFERRING
            ):
                spawn_mask_calls += 1
                deadline._raise_timeout(signal.SIGALRM, None)
            return previous_mask

        try:
            deadline.arm()
            with (
                mock.patch.object(
                    deadline,
                    "_require_signal_support",
                    side_effect=interrupt_support_check,
                ),
                mock.patch.object(
                    MODULE.signal,
                    "pthread_sigmask",
                    side_effect=interrupt_first_spawn_mask,
                ),
                self.assertRaises(MODULE.ArtifactLimitError) as raised,
            ):
                with MODULE.contextlib.ExitStack() as workers:
                    deadline.enter_regex_worker(workers, matcher)
            process = matcher._process
            self.assertIsNone(process)
            self.assertEqual(
                str(raised.exception),
                "archive command deadline exceeded",
            )
        finally:
            try:
                real_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
                deadline.close()
            finally:
                real_sigmask(signal.SIG_SETMASK, initial_mask)
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)

        self.assertEqual(support_checks, 1)
        self.assertEqual(spawn_mask_calls, 1)
        self.assertEqual(
            real_sigmask(signal.SIG_BLOCK, set()),
            initial_mask,
        )
        self.assertEqual(
            deadline._regex_spawn_state,
            MODULE.REGEX_SPAWN_IDLE,
        )

    def test_regex_spawn_cleanup_failure_retains_signal_fence(self) -> None:
        deadline = MODULE.ArchiveCommandDeadline()
        matcher = MODULE.IsolatedRegexMatcher(
            "safe",
            ignore_case=False,
            budget=MODULE.RegexMatchBudget(),
            command_deadline=deadline,
        )
        process = mock.Mock()
        process.pid = 4242
        process.stdin = mock.Mock()
        process.stdout = mock.Mock()
        process.poll.return_value = None
        cleanup_error = MODULE.RegexWorkerCleanupError(
            process,
            cleanup_stage="kill-wait",
            process_group_id=4242,
        )
        mask_operations: list[int] = []

        def change_mask(
            operation: int,
            _signals: object,
        ) -> set[signal.Signals]:
            mask_operations.append(operation)
            if operation == signal.SIG_SETMASK:
                self.fail("an unproven worker must retain the signal fence")
            return set()

        with (
            mock.patch.object(deadline, "_require_signal_support"),
            mock.patch.object(
                MODULE.signal,
                "pthread_sigmask",
                side_effect=change_mask,
            ),
            mock.patch.object(
                MODULE.subprocess,
                "Popen",
                return_value=process,
            ),
            mock.patch.object(MODULE.os, "set_blocking"),
            mock.patch.object(
                matcher,
                "_request",
                side_effect=RuntimeError("injected worker setup failure"),
            ),
            mock.patch.object(
                matcher,
                "_terminate_worker",
                side_effect=cleanup_error,
            ) as cleanup,
            self.assertRaises(MODULE.RegexWorkerCleanupError) as raised,
        ):
            with MODULE.contextlib.ExitStack() as workers:
                deadline.enter_regex_worker(workers, matcher)

        self.assertIs(raised.exception, cleanup_error)
        self.assertIsInstance(raised.exception.__cause__, RuntimeError)
        self.assertIs(matcher._process, process)
        self.assertEqual(
            deadline._regex_spawn_state,
            MODULE.REGEX_SPAWN_FENCED,
        )
        self.assertEqual(mask_operations, [signal.SIG_BLOCK])
        cleanup.assert_called_once_with()

    @unittest.skipUnless(
        os.name == "posix"
        and MODULE.fcntl is not None
        and hasattr(os, "O_NONBLOCK")
        and hasattr(signal, "pthread_sigmask"),
        "timerless fenced diagnostics require POSIX fcntl and signal masks",
    )
    def test_regex_spawn_recovery_failure_bounds_full_pipe_diagnostic(
        self,
    ) -> None:
        launcher = "\n".join(
            (
                "import contextlib",
                "import importlib.util",
                "import os",
                "import pathlib",
                "import signal",
                "import sys",
                "from unittest import mock",
                "path = pathlib.Path(sys.argv[1])",
                (
                    "spec = importlib.util.spec_from_file_location("
                    "'archive_triage_fenced_diagnostic_test', path)"
                ),
                "module = importlib.util.module_from_spec(spec)",
                "sys.modules[spec.name] = module",
                "spec.loader.exec_module(module)",
                "fd = sys.stderr.fileno()",
                "original_flags = module._fcntl_get_flags(fd)",
                ("module._fcntl_set_flags(fd, original_flags | os.O_NONBLOCK)"),
                "try:",
                "    while True:",
                "        os.write(fd, b'x' * 4096)",
                "except BlockingIOError:",
                "    pass",
                "finally:",
                "    module._fcntl_set_flags(fd, original_flags)",
                "deadline = module.ArchiveCommandDeadline()",
                "deadline._armed = True",
                "deadline._diagnostic_timer_safe = True",
                "matcher = module.IsolatedRegexMatcher(",
                "    'safe',",
                "    ignore_case=False,",
                "    budget=module.RegexMatchBudget(),",
                "    command_deadline=deadline,",
                ")",
                "process = mock.Mock()",
                "process.pid = 4242",
                "process.stdin = mock.Mock()",
                "process.stdout = mock.Mock()",
                "process.poll.return_value = None",
                "cleanup_error = module.RegexWorkerCleanupError(",
                "    process,",
                "    cleanup_stage='kill-wait',",
                "    process_group_id=4242,",
                ")",
                "def change_mask(operation, _signals):",
                "    if operation == signal.SIG_SETMASK:",
                (
                    "        raise AssertionError("
                    "'unproven worker restored SIGALRM mask')"
                ),
                "    return set()",
                "patches = (",
                "    mock.patch.object(deadline, '_require_signal_support'),",
                (
                    "    mock.patch.object("
                    "module.signal, 'pthread_sigmask', side_effect=change_mask),"
                ),
                (
                    "    mock.patch.object("
                    "module.subprocess, 'Popen', return_value=process),"
                ),
                "    mock.patch.object(module.os, 'set_blocking'),",
                (
                    "    mock.patch.object("
                    "matcher, '_request', "
                    "side_effect=RuntimeError('injected setup failure')),"
                ),
                (
                    "    mock.patch.object("
                    "matcher, '_terminate_worker', side_effect=cleanup_error),"
                ),
                ")",
                "with contextlib.ExitStack() as patch_stack:",
                "    for patcher in patches:",
                "        patch_stack.enter_context(patcher)",
                "    try:",
                "        with module.contextlib.ExitStack() as workers:",
                "            deadline.enter_regex_worker(workers, matcher)",
                "    except module.RegexWorkerCleanupError as error:",
                "        captured_error = error",
                "    else:",
                (
                    "        raise AssertionError("
                    "'worker recovery failure was not raised')"
                ),
                ("assert deadline._regex_spawn_state == module.REGEX_SPAWN_FENCED"),
                "module._emit_error(captured_error, deadline=deadline)",
                "assert not deadline.timer_backed_diagnostics_safe()",
                (
                    "assert bool(module._fcntl_get_flags(fd) & os.O_NONBLOCK) "
                    "== bool(original_flags & os.O_NONBLOCK)"
                ),
            )
        )
        started = time.monotonic()
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                launcher,
                str(SCRIPT_PATH),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=2)
            self.fail("fenced diagnostic blocked on a full stderr pipe")
        stdout, stderr = process.communicate(timeout=2)
        elapsed = time.monotonic() - started

        self.assertEqual(
            process.returncode,
            0,
            stderr[-512:].decode("utf-8", errors="replace"),
        )
        self.assertEqual(stdout, b"")
        self.assertLess(elapsed, 1.0)

    @unittest.skipUnless(
        os.name == "posix"
        and MODULE.fcntl is not None
        and hasattr(os, "O_NONBLOCK")
        and hasattr(signal, "pthread_sigmask"),
        "timerless fenced diagnostics require POSIX fcntl and signal masks",
    )
    def test_regex_cleanup_restore_failure_bounds_full_pipe_diagnostic(
        self,
    ) -> None:
        launcher = "\n".join(
            (
                "import importlib.util",
                "import os",
                "import pathlib",
                "import signal",
                "import sys",
                "from unittest import mock",
                "path = pathlib.Path(sys.argv[1])",
                (
                    "spec = importlib.util.spec_from_file_location("
                    "'archive_triage_cleanup_fence_test', path)"
                ),
                "module = importlib.util.module_from_spec(spec)",
                "sys.modules[spec.name] = module",
                "spec.loader.exec_module(module)",
                "fd = sys.stderr.fileno()",
                "original_flags = module._fcntl_get_flags(fd)",
                "real_sigmask = signal.pthread_sigmask",
                "original_mask = real_sigmask(signal.SIG_BLOCK, set())",
                "module._fcntl_set_flags(fd, original_flags | os.O_NONBLOCK)",
                "try:",
                "    while True:",
                "        os.write(fd, b'x' * 4096)",
                "except BlockingIOError:",
                "    pass",
                "finally:",
                "    module._fcntl_set_flags(fd, original_flags)",
                "deadline = module.ArchiveCommandDeadline()",
                "deadline._armed = True",
                "deadline._diagnostic_timer_safe = True",
                "cleanup_error = RuntimeError('injected cleanup failure')",
                "restore_error = OSError('injected mask restore failure')",
                "def cleanup():",
                "    raise cleanup_error",
                "def change_mask(operation, signals):",
                "    if operation == signal.SIG_BLOCK:",
                "        return real_sigmask(operation, signals)",
                "    raise restore_error",
                "try:",
                "    with (",
                ("        mock.patch.object(deadline, '_require_signal_support'),"),
                (
                    "        mock.patch.object("
                    "module.signal, 'pthread_sigmask', "
                    "side_effect=change_mask),"
                ),
                "    ):",
                "        try:",
                "            deadline.run_regex_worker_cleanup(cleanup)",
                "        except RuntimeError as error:",
                "            captured_error = error",
                "        else:",
                ("            raise AssertionError('cleanup failure was not raised')"),
                "    assert captured_error is cleanup_error",
                "    assert captured_error.__cause__ is restore_error",
                (
                    "    assert deadline._regex_cleanup_state "
                    "== module.REGEX_CLEANUP_FENCED"
                ),
                "    assert not deadline.timer_backed_diagnostics_safe()",
                "    module._emit_error(captured_error, deadline=deadline)",
                (
                    "    assert bool(module._fcntl_get_flags(fd) "
                    "& os.O_NONBLOCK) "
                    "== bool(original_flags & os.O_NONBLOCK)"
                ),
                "finally:",
                "    real_sigmask(signal.SIG_SETMASK, original_mask)",
            )
        )
        started = time.monotonic()
        process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                launcher,
                str(SCRIPT_PATH),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=2)
            self.fail("fenced cleanup diagnostic blocked on a full stderr pipe")
        stdout, stderr = process.communicate(timeout=2)
        elapsed = time.monotonic() - started

        self.assertEqual(
            process.returncode,
            0,
            stderr[-512:].decode("utf-8", errors="replace"),
        )
        self.assertEqual(stdout, b"")
        self.assertLess(elapsed, 1.0)

    @unittest.skipUnless(
        os.name == "posix"
        and hasattr(os, "killpg")
        and all(
            hasattr(signal, name)
            for name in (
                "SIGALRM",
                "ITIMER_REAL",
                "setitimer",
                "pthread_sigmask",
                "SIG_BLOCK",
                "SIG_SETMASK",
            )
        ),
        "live cleanup recovery evidence requires POSIX signal timers",
    )
    def test_regex_cleanup_setup_failure_retains_live_worker_recovery(
        self,
    ) -> None:
        real_popen = subprocess.Popen
        deadline = MODULE.ArchiveCommandDeadline()
        matcher = MODULE.IsolatedRegexMatcher(
            "safe",
            ignore_case=False,
            budget=MODULE.RegexMatchBudget(),
            command_deadline=deadline,
        )
        process = None
        worker_pgid = None
        cleanup_error = None
        initial_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())

        def isolated_worker_popen(
            *args: object,
            **kwargs: object,
        ) -> subprocess.Popen[bytes]:
            isolated_kwargs = dict(kwargs)
            isolated_kwargs["start_new_session"] = True
            return real_popen(*args, **isolated_kwargs)

        try:
            deadline.arm()
            with mock.patch.object(
                MODULE.subprocess,
                "Popen",
                side_effect=isolated_worker_popen,
            ):
                matcher.__enter__()
            process = matcher._process
            self.assertIsNotNone(process)
            assert process is not None
            worker_pgid = os.getpgid(process.pid)
            self.assertEqual(worker_pgid, process.pid)
            self.assertTrue(matcher.search("safe"))

            with mock.patch.object(
                deadline,
                "_require_signal_support",
                side_effect=OSError(
                    errno.EIO,
                    "injected cleanup support failure",
                ),
            ):
                with self.assertRaises(MODULE.RegexWorkerCleanupError) as raised:
                    matcher.close()
                cleanup_error = raised.exception

            self.assertIs(matcher._process, process)
            self.assertIs(cleanup_error.process, process)
            self.assertEqual(cleanup_error.pid, process.pid)
            self.assertEqual(cleanup_error.process_group_id, worker_pgid)
            self.assertEqual(cleanup_error.cleanup_stage, "signal-mask")
            self.assertEqual(
                cleanup_error.recovery["process_handle"],
                "retained",
            )
            self.assertEqual(
                cleanup_error.recovery["reap_status"],
                "unproven",
            )
            self.assertIsNone(process.poll())
            os.killpg(worker_pgid, 0)
            self.assertEqual(
                signal.pthread_sigmask(signal.SIG_BLOCK, set()),
                initial_mask,
            )
            self.assertEqual(
                deadline._regex_cleanup_state,
                MODULE.REGEX_CLEANUP_IDLE,
            )
        finally:
            try:
                signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
                deadline.close()
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, initial_mask)
                matcher._command_deadline = None
                try:
                    matcher.close()
                except MODULE.RegexWorkerCleanupError:
                    if process is not None and process.poll() is None:
                        process.kill()
                        process.wait(timeout=2)

        self.assertIsNotNone(cleanup_error)
        assert process is not None
        self.assertIsNotNone(process.poll())
        assert worker_pgid is not None
        with self.assertRaises(ProcessLookupError):
            os.killpg(worker_pgid, 0)

    def test_regex_cleanup_failure_retains_authoritative_process_handle(
        self,
    ) -> None:
        matcher = MODULE.IsolatedRegexMatcher(
            "safe",
            ignore_case=False,
            budget=MODULE.RegexMatchBudget(),
        )
        process = mock.Mock()
        process.pid = 4242
        process.poll.return_value = None
        process.wait.side_effect = (
            subprocess.TimeoutExpired("regex-worker", 0.5),
            subprocess.TimeoutExpired("regex-worker", 0.5),
        )
        process.stdin = mock.Mock()
        process.stdout = mock.Mock()
        matcher._process = process

        with mock.patch.object(
            MODULE.os,
            "getpgid",
            return_value=4343,
            create=True,
        ):
            with self.assertRaises(MODULE.RegexWorkerCleanupError) as cleanup_error:
                matcher.close()

        error = cleanup_error.exception
        self.assertIs(matcher._process, process)
        self.assertIs(error.process, process)
        self.assertEqual(error.pid, 4242)
        self.assertEqual(error.process_group_id, 4343)
        self.assertEqual(error.cleanup_stage, "final-poll")
        self.assertEqual(error.recovery["reap_status"], "unproven")
        self.assertEqual(error.recovery["process_handle"], "retained")
        self.assertEqual(matcher._cleanup_recovery, error.recovery)
        process.terminate.assert_called_once_with()
        process.kill.assert_called_once_with()
        self.assertEqual(process.wait.call_count, 2)
        process.stdin.close.assert_called_once_with()
        process.stdout.close.assert_called_once_with()

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "killpg"),
        "process-group containment requires POSIX",
    )
    def test_external_group_termination_stops_catastrophic_regex_worker(
        self,
    ) -> None:
        launcher = "\n".join(
            (
                "import importlib.util",
                "import os",
                "import pathlib",
                "import sys",
                "path = pathlib.Path(sys.argv[1])",
                "metadata_path = pathlib.Path(sys.argv[2])",
                (
                    "spec = importlib.util.spec_from_file_location("
                    "'archive_triage_group_test', path)"
                ),
                "module = importlib.util.module_from_spec(spec)",
                "sys.modules[spec.name] = module",
                "spec.loader.exec_module(module)",
                "module.DEFAULT_REGEX_MATCH_TIMEOUT_SECONDS = 30.0",
                "module.DEFAULT_REGEX_AGGREGATE_TIMEOUT_SECONDS = 30.0",
                "real_popen = module.subprocess.Popen",
                "def tracking_popen(*args, **kwargs):",
                "    process = real_popen(*args, **kwargs)",
                "    command = args[0] if args else kwargs.get('args', ())",
                "    if module.REGEX_WORKER_ARG in command:",
                (
                    "        metadata_path.write_text("
                    "f'{process.pid} {os.getpgid(process.pid)}\\n')"
                ),
                "    return process",
                "module.subprocess.Popen = tracking_popen",
                "sys.argv = [str(path), *sys.argv[3:]]",
                "raise SystemExit(module.main())",
            )
        )

        class DarwinProcBsdInfo(ctypes.Structure):
            _fields_ = [
                ("pbi_flags", ctypes.c_uint32),
                ("pbi_status", ctypes.c_uint32),
                ("pbi_xstatus", ctypes.c_uint32),
                ("pbi_pid", ctypes.c_uint32),
                ("pbi_ppid", ctypes.c_uint32),
                ("pbi_uid", ctypes.c_uint32),
                ("pbi_gid", ctypes.c_uint32),
                ("pbi_ruid", ctypes.c_uint32),
                ("pbi_rgid", ctypes.c_uint32),
                ("pbi_svuid", ctypes.c_uint32),
                ("pbi_svgid", ctypes.c_uint32),
                ("rfu_1", ctypes.c_uint32),
                ("pbi_comm", ctypes.c_char * 16),
                ("pbi_name", ctypes.c_char * 32),
                ("pbi_nfiles", ctypes.c_uint32),
                ("pbi_pgid", ctypes.c_uint32),
                ("pbi_pjobc", ctypes.c_uint32),
                ("e_tdev", ctypes.c_uint32),
                ("e_tpgid", ctypes.c_uint32),
                ("pbi_nice", ctypes.c_int32),
                ("pbi_start_tvsec", ctypes.c_uint64),
                ("pbi_start_tvusec", ctypes.c_uint64),
            ]

        darwin_proc_pidinfo = None
        darwin_proc_pid_bsd_info = 3
        darwin_process_zombie = 5
        if sys.platform == "darwin":
            libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            darwin_proc_pidinfo = libproc.proc_pidinfo
            darwin_proc_pidinfo.argtypes = [
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_uint64,
                ctypes.c_void_p,
                ctypes.c_int,
            ]
            darwin_proc_pidinfo.restype = ctypes.c_int
            self.assertEqual(ctypes.sizeof(DarwinProcBsdInfo), 136)

        def process_state(pid: int) -> str | None:
            if sys.platform.startswith("linux"):
                try:
                    status_payload = Path(f"/proc/{pid}/stat").read_text(
                        encoding="ascii"
                    )
                except FileNotFoundError:
                    return None
                command_end = status_payload.rfind(")")
                self.assertGreaterEqual(command_end, 0)
                return status_payload[command_end + 2]
            if sys.platform == "darwin":
                assert darwin_proc_pidinfo is not None
                info = DarwinProcBsdInfo()
                ctypes.set_errno(0)
                bytes_read = darwin_proc_pidinfo(
                    pid,
                    darwin_proc_pid_bsd_info,
                    0,
                    ctypes.byref(info),
                    ctypes.sizeof(info),
                )
                if bytes_read == 0:
                    error_number = ctypes.get_errno()
                    if error_number not in (0, errno.ESRCH):
                        raise OSError(
                            error_number,
                            "proc_pidinfo process-state inspection failed",
                        )
                    return None
                self.assertEqual(bytes_read, ctypes.sizeof(info))
                return "Z" if info.pbi_status == darwin_process_zombie else "R"
            self.skipTest("process-state inspection requires Linux or Darwin")

        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "external-group-kill.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(("a" * 400) + "!", "hostile\n")

            for termination_signal in (signal.SIGTERM, signal.SIGKILL):
                with self.subTest(signal=termination_signal.name):
                    metadata_path = (
                        Path(temp_dir) / f"worker-{termination_signal.name.lower()}.txt"
                    )
                    process = subprocess.Popen(
                        [
                            sys.executable,
                            "-c",
                            launcher,
                            str(SCRIPT_PATH),
                            str(metadata_path),
                            "zip-list",
                            str(archive_path),
                            "--match",
                            r"(a+)+$",
                        ],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        close_fds=True,
                        start_new_session=True,
                    )
                    helper_pgid = process.pid
                    worker_pid = None
                    worker_pgid = None
                    try:
                        discovery_deadline = time.monotonic() + 2.0
                        while time.monotonic() < discovery_deadline:
                            if metadata_path.is_file():
                                fields = metadata_path.read_text(
                                    encoding="utf-8"
                                ).split()
                                if len(fields) == 2:
                                    worker_pid, worker_pgid = map(int, fields)
                                    break
                            if process.poll() is not None:
                                break
                            time.sleep(0.01)

                        self.assertIsNotNone(
                            worker_pid,
                            "catastrophic regex worker did not start",
                        )
                        assert worker_pid is not None
                        assert worker_pgid is not None
                        self.assertEqual(worker_pgid, helper_pgid)
                        self.assertNotIn(process_state(worker_pid), (None, "Z"))
                        time.sleep(0.05)
                        self.assertIsNone(process.poll())

                        os.killpg(helper_pgid, termination_signal)
                        process.wait(timeout=2)

                        stop_deadline = time.monotonic() + 2.0
                        worker_state = process_state(worker_pid)
                        while (
                            worker_state not in (None, "Z")
                            and time.monotonic() < stop_deadline
                        ):
                            time.sleep(0.01)
                            worker_state = process_state(worker_pid)
                        self.assertIn(worker_state, (None, "Z"))
                    finally:
                        if process.poll() is None:
                            os.killpg(helper_pgid, signal.SIGKILL)
                            process.wait(timeout=2)

    def test_regex_worker_crash_is_a_bounded_failure(self) -> None:
        budget = MODULE.RegexMatchBudget()
        process = None
        with MODULE.IsolatedRegexMatcher(
            "safe",
            ignore_case=False,
            budget=budget,
        ) as matcher:
            process = matcher._process
            self.assertIsNotNone(process)
            assert process is not None
            process.kill()
            process.wait(1.0)
            with self.assertRaisesRegex(
                RuntimeError,
                "worker is unavailable",
            ):
                matcher.search("safe")

        assert process is not None
        self.assertIsNotNone(process.poll())

    def test_regex_workers_share_and_enforce_aggregate_deadline(self) -> None:
        budget = MODULE.RegexMatchBudget()
        processes = []
        real_popen = subprocess.Popen

        def tracking_popen(
            *args: object,
            **kwargs: object,
        ) -> subprocess.Popen[bytes]:
            process = real_popen(*args, **kwargs)
            processes.append(process)
            return process

        with mock.patch.object(
            MODULE.subprocess,
            "Popen",
            side_effect=tracking_popen,
        ):
            with MODULE.IsolatedRegexMatcher(
                "first",
                ignore_case=False,
                budget=budget,
            ) as first_matcher:
                self.assertTrue(first_matcher.search("first"))
                budget.deadline = time.monotonic() - 1.0
                with self.assertRaisesRegex(
                    MODULE.ArtifactLimitError,
                    "aggregate deadline exceeded",
                ):
                    with MODULE.IsolatedRegexMatcher(
                        "second",
                        ignore_case=False,
                        budget=budget,
                    ):
                        self.fail("expired matcher unexpectedly started")

        self.assertEqual(len(processes), 2)
        self.assertTrue(all(process.poll() is not None for process in processes))

    def test_zip_show_rejects_member_over_line_cap_without_partial_output(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            args = self._show_args(archive_path, max_member_lines=2)
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = MODULE.cmd_zip_show(args)

        self.assertEqual(rc, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("member line count exceeds limit", stderr.getvalue())

    def test_zip_show_rejects_aggregate_member_bytes_without_partial_output(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            args = self._show_args(
                archive_path,
                member=r"logs/.*",
                regex=True,
                all=True,
                max_output_chars=24,
                max_total_member_bytes=30,
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = MODULE.cmd_zip_show(args)

        self.assertEqual(rc, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("aggregate max bytes", stderr.getvalue())

    def test_zip_show_head_drain_detects_tail_crc_corruption(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "corrupt-tail.zip"
            content = "first\n" + ("filler line\n" * 20_000)
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("logs/large.log", content)
            self._corrupt_member_payload_tail(
                archive_path,
                "logs/large.log",
            )
            args = self._show_args(
                archive_path,
                member="logs/large.log",
                head=1,
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = MODULE.cmd_zip_show(args)

        self.assertEqual(rc, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("Bad CRC-32", stderr.getvalue())

    def test_zip_show_rejects_trailing_deflate_data(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "deflate-trailing.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(
                    "logs/deflate.log",
                    "first\n" + ("line\n" * 100),
                    compress_type=zipfile.ZIP_DEFLATED,
                )
            self._append_to_member_compressed_span(
                archive_path,
                ordinal=1,
                trailing=b"\0",
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = MODULE.cmd_zip_show(
                    self._show_args(
                        archive_path,
                        member="logs/deflate.log",
                        head=1,
                    )
                )

        self.assertEqual(rc, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("trailing compressed data", stderr.getvalue())

    def test_zip_show_validates_data_descriptor_before_output(self) -> None:
        class NonSeekableBuffer(io.BytesIO):
            def seekable(self) -> bool:
                return False

            def seek(self, *args: object, **kwargs: object) -> int:
                raise OSError("stream is not seekable")

        archive_buffer = NonSeekableBuffer()
        member_name = "logs/déscriptor.log"
        with zipfile.ZipFile(archive_buffer, "w") as archive:
            archive.writestr(
                member_name,
                "descriptor\n",
                compress_type=zipfile.ZIP_DEFLATED,
            )
        with zipfile.ZipFile(io.BytesIO(archive_buffer.getvalue())) as archive:
            self.assertEqual(
                archive.getinfo(member_name).flag_bits,
                MODULE.SUPPORTED_GENERAL_PURPOSE_FLAGS,
            )

        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "descriptor.zip"
            archive_path.write_bytes(archive_buffer.getvalue())
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = MODULE.cmd_zip_show(
                    self._show_args(
                        archive_path,
                        member=member_name,
                    )
                )

        self.assertEqual(rc, 0, stderr.getvalue())
        self.assertIn("descriptor", stdout.getvalue())

    def test_zip_show_accepts_local_zero_zip64_data_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path, member_name = self._make_local_zero_zip64_descriptor_archive(
                Path(temp_dir)
            )
            with zipfile.ZipFile(archive_path) as archive:
                info = archive.getinfo(member_name)
                self.assertEqual(info.extract_version, MODULE.ZIP64_MIN_VERSION)
                self.assertEqual(info.file_size, len(b"zip64 descriptor\n"))
                self.assertEqual(info.compress_size, len(b"zip64 descriptor\n"))

            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = MODULE.cmd_zip_show(
                    self._show_args(
                        archive_path,
                        member=member_name,
                    )
                )

        self.assertEqual(rc, 0, stderr.getvalue())
        self.assertIn("zip64 descriptor", stdout.getvalue())

    def test_member_payload_cannot_overlap_next_local_record(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "overlap.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("logs/one.log", b"one\n")
                archive.writestr("logs/two.log", b"two\n")
            with zipfile.ZipFile(archive_path) as archive:
                first = archive.infolist()[0]

            data = bytearray(archive_path.read_bytes())
            central_offset = self._central_directory_records(data)[0][0]
            forged_size = first.compress_size + 1
            struct.pack_into("<L", data, first.header_offset + 18, forged_size)
            struct.pack_into("<L", data, first.header_offset + 22, forged_size)
            struct.pack_into("<L", data, central_offset + 20, forged_size)
            struct.pack_into("<L", data, central_offset + 24, forged_size)
            archive_path.write_bytes(data)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = MODULE.cmd_zip_show(
                    self._show_args(
                        archive_path,
                        member="logs/one.log",
                    )
                )

        self.assertEqual(rc, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("member payload exceeds the local-data region", stderr.getvalue())

    def test_actual_byte_cap_limits_each_reader_request(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "read-limit.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("logs/large.log", b"A" * (1024 * 1024))
            self._replace_declared_file_size(
                archive_path,
                ordinal=1,
                file_size=1,
            )

            read_limits = []
            real_read_stored = MODULE.BoundedMemberReader._read_stored

            def tracking_read_stored(
                reader: MODULE.BoundedMemberReader,
                max_bytes: int,
            ) -> bytes:
                read_limits.append(max_bytes)
                return real_read_stored(reader, max_bytes)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch.object(
                MODULE.BoundedMemberReader,
                "_read_stored",
                new=tracking_read_stored,
            ):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    rc = MODULE.cmd_zip_show(
                        self._show_args(
                            archive_path,
                            member="logs/large.log",
                            max_member_bytes=1,
                        )
                    )

        self.assertEqual(rc, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertTrue(read_limits)
        self.assertLessEqual(max(read_limits), 2)
        self.assertIn("member exceeds max bytes", stderr.getvalue())

    def test_zip_show_all_drains_later_member_after_output_truncation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "corrupt-later.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(
                    "logs/one.log",
                    "first\n" + ("one\n" * 100),
                )
                archive.writestr(
                    "logs/two.log",
                    "second\n" + ("two\n" * 20_000),
                )
            self._corrupt_member_payload_tail(
                archive_path,
                "logs/two.log",
            )
            args = self._show_args(
                archive_path,
                member=r"logs/.*",
                regex=True,
                all=True,
                head=1,
                max_output_chars=28,
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = MODULE.cmd_zip_show(args)

        self.assertEqual(rc, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn('"name":"logs/two.log"', stderr.getvalue())
        self.assertIn("Bad CRC-32", stderr.getvalue())

    def test_malformed_compressed_later_member_is_bounded_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "deflate.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(
                    "logs/first.log",
                    "first\n" + ("one\n" * 100),
                    compress_type=zipfile.ZIP_STORED,
                )
                archive.writestr(
                    "logs/broken.log",
                    "second\n" + ("two\n" * 20_000),
                    compress_type=zipfile.ZIP_DEFLATED,
                )
            self._corrupt_member_compressed_stream(
                archive_path,
                "logs/broken.log",
                zipfile.ZIP_DEFLATED,
            )
            args = self._show_args(
                archive_path,
                member=r"logs/.*",
                regex=True,
                all=True,
                head=1,
                max_output_chars=1,
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = MODULE.cmd_zip_show(args)

        self.assertEqual(rc, 1)
        self.assertEqual(stdout.getvalue(), "")
        error_text = stderr.getvalue()
        self.assertEqual(len(error_text.splitlines()), 1)
        self.assertLessEqual(
            len(error_text),
            MODULE.DEFAULT_MAX_OUTPUT_CHARS,
        )
        self.assertNotIn("Traceback", error_text)
        self.assertIn('"ordinal":2', error_text)
        self.assertIn("type=zlib.error", error_text)
        self.assertIn("invalid deflate stream", error_text)

    def test_forged_small_file_size_is_detected_for_supported_methods(
        self,
    ) -> None:
        for label, compression in (
            ("stored", zipfile.ZIP_STORED),
            ("deflate", zipfile.ZIP_DEFLATED),
        ):
            with self.subTest(compression=label):
                with tempfile.TemporaryDirectory() as temp_dir:
                    archive_path = Path(temp_dir) / f"{label}.zip"
                    with zipfile.ZipFile(archive_path, "w") as archive:
                        archive.writestr(
                            "logs/expanded.log",
                            (b"A" * 1023 + b"\n") * 256,
                            compress_type=compression,
                        )
                    self._replace_declared_file_size(
                        archive_path,
                        ordinal=1,
                        file_size=1,
                    )
                    stdout = io.StringIO()
                    stderr = io.StringIO()
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        rc = MODULE.cmd_zip_show(
                            self._show_args(
                                archive_path,
                                member="logs/expanded.log",
                                head=1,
                            )
                        )

                self.assertEqual(rc, 1)
                self.assertEqual(stdout.getvalue(), "")
                self.assertIn(
                    "decompressed member size differs from central directory",
                    stderr.getvalue(),
                )

    def test_lzma_and_bzip2_are_rejected_before_decompression(
        self,
    ) -> None:
        for label, compression in (
            ("lzma", zipfile.ZIP_LZMA),
            ("bzip2", zipfile.ZIP_BZIP2),
        ):
            with self.subTest(compression=label):
                with tempfile.TemporaryDirectory() as temp_dir:
                    archive_path = Path(temp_dir) / f"{label}.zip"
                    with zipfile.ZipFile(archive_path, "w") as archive:
                        archive.writestr(
                            "logs/expanded.log",
                            b"A\n" * (512 * 1024),
                            compress_type=compression,
                        )
                    self._replace_declared_file_size(
                        archive_path,
                        ordinal=1,
                        file_size=1,
                    )
                    stdout = io.StringIO()
                    stderr = io.StringIO()
                    with mock.patch.object(
                        MODULE,
                        "BoundedMemberReader",
                        wraps=MODULE.BoundedMemberReader,
                    ) as reader:
                        with redirect_stdout(stdout), redirect_stderr(stderr):
                            rc = MODULE.cmd_zip_show(
                                self._show_args(
                                    archive_path,
                                    member="logs/expanded.log",
                                    head=1,
                                )
                            )

                self.assertEqual(rc, 1)
                reader.assert_not_called()
                self.assertEqual(stdout.getvalue(), "")
                self.assertIn(
                    "compression method is unsupported for bounded extraction",
                    stderr.getvalue(),
                )

    def test_unmatched_boundary_member_identity_is_not_rendered(self) -> None:
        cp437_raw_name = b"\x01" * MODULE.DEFAULT_MAX_RAW_MEMBER_NAME_BYTES
        placeholder = "A" * len(cp437_raw_name)
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "cp437-name.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(placeholder, "unrelated\n")
                archive.writestr("logs/selected.log", "selected\n")
            self._replace_member_raw_name(
                archive_path,
                ordinal=1,
                raw_name=cp437_raw_name,
                flag_bits=0,
            )

            list_stdout = io.StringIO()
            list_stderr = io.StringIO()
            show_stdout = io.StringIO()
            show_stderr = io.StringIO()
            real_render = MODULE._render_member_identity

            def reject_unmatched_render(
                identity: MODULE.CentralDirectoryIdentity,
            ) -> str:
                if identity.ordinal == 1:
                    raise AssertionError("unmatched member identity was rendered")
                return real_render(identity)

            with mock.patch.object(
                MODULE,
                "_render_member_identity",
                side_effect=reject_unmatched_render,
            ):
                with redirect_stdout(list_stdout), redirect_stderr(list_stderr):
                    list_rc = MODULE.cmd_zip_list(
                        self._list_args(
                            archive_path,
                            match="selected.log",
                        )
                    )
                with redirect_stdout(show_stdout), redirect_stderr(show_stderr):
                    show_rc = MODULE.cmd_zip_show(
                        self._show_args(
                            archive_path,
                            member="logs/selected.log",
                        )
                    )

        self.assertEqual(list_rc, 0, list_stderr.getvalue())
        self.assertNotIn('"ordinal":1', list_stdout.getvalue())
        self.assertIn('"ordinal":2', list_stdout.getvalue())
        self.assertEqual(show_rc, 0, show_stderr.getvalue())
        self.assertIn("selected", show_stdout.getvalue())

    def test_identity_bound_covers_utf8_and_cp437_raw_name_limit(self) -> None:
        utf8_name = "é" * (MODULE.DEFAULT_MAX_RAW_MEMBER_NAME_BYTES // 2)
        cp437_raw_name = b"\x01" * MODULE.DEFAULT_MAX_RAW_MEMBER_NAME_BYTES
        placeholder = "A" * len(cp437_raw_name)
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "identity-limits.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(utf8_name, "utf8\n")
                archive.writestr(placeholder, "cp437\n")
            self._replace_member_raw_name(
                archive_path,
                ordinal=2,
                raw_name=cp437_raw_name,
                flag_bits=0,
            )

            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = MODULE.cmd_zip_list(self._list_args(archive_path))

        self.assertEqual(rc, 0, stderr.getvalue())
        identities = [
            self._parse_identity(line.split("\t", 2)[2])
            for line in stdout.getvalue().splitlines()
        ]
        self.assertEqual(len(identities), 2)
        self.assertEqual(
            len(base64.b64decode(identities[0]["raw_name_b64"])),
            MODULE.DEFAULT_MAX_RAW_MEMBER_NAME_BYTES,
        )
        self.assertEqual(
            len(base64.b64decode(identities[1]["raw_name_b64"])),
            MODULE.DEFAULT_MAX_RAW_MEMBER_NAME_BYTES,
        )
        for line in stdout.getvalue().splitlines():
            rendered = line.split("\t", 2)[2]
            self.assertLessEqual(
                len(rendered),
                MODULE.DEFAULT_MAX_MEMBER_IDENTITY_CHARS,
            )

    def test_zipfile_member_error_detail_is_bounded_and_single_line(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            oversized_detail = ("raw-name-fragment" * 10_000) + "\nINJECTED"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch.object(
                MODULE,
                "_member_payload_layout",
                side_effect=zipfile.BadZipFile(oversized_detail),
            ):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    rc = MODULE.cmd_zip_show(self._show_args(archive_path, head=1))

        self.assertEqual(rc, 1)
        self.assertEqual(stdout.getvalue(), "")
        error_text = stderr.getvalue()
        self.assertEqual(len(error_text.splitlines()), 1)
        self.assertLessEqual(
            len(error_text),
            MODULE.DEFAULT_MAX_MEMBER_IDENTITY_CHARS
            + MODULE.DEFAULT_MAX_ERROR_DETAIL_CHARS,
        )
        self.assertNotIn("raw-name-fragment", error_text)
        self.assertNotIn("INJECTED", error_text)
        self.assertIn("diagnostic omitted", error_text)

    def test_duplicate_physical_members_have_distinct_identities(
        self,
    ) -> None:
        duplicate_name = "logs/duplicate.log"
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "duplicates.zip"
            with self.assertWarns(UserWarning):
                with zipfile.ZipFile(archive_path, "w") as archive:
                    archive.writestr(duplicate_name, "first\n")
                    archive.writestr(duplicate_name, "second\n")

            list_stdout = io.StringIO()
            with redirect_stdout(list_stdout):
                list_rc = MODULE.cmd_zip_list(self._list_args(archive_path))

            ambiguous_stderr = io.StringIO()
            with redirect_stderr(ambiguous_stderr):
                ambiguous_rc = MODULE.cmd_zip_show(
                    self._show_args(
                        archive_path,
                        member=duplicate_name,
                        head=1,
                    )
                )

            opened_infos = []
            real_layout = MODULE._member_payload_layout

            def tracking_layout(
                archive_stream: io.BufferedReader,
                member: MODULE.ArchiveMember,
                *,
                central_start: int,
            ) -> MODULE.MemberPayloadLayout:
                opened_infos.append(member.info)
                return real_layout(
                    archive_stream,
                    member,
                    central_start=central_start,
                )

            show_stdout = io.StringIO()
            with mock.patch.object(
                MODULE,
                "_member_payload_layout",
                side_effect=tracking_layout,
            ):
                with redirect_stdout(show_stdout):
                    show_rc = MODULE.cmd_zip_show(
                        self._show_args(
                            archive_path,
                            member=duplicate_name,
                            all=True,
                            head=1,
                        )
                    )

        self.assertEqual(list_rc, 0)
        list_identities = [
            self._parse_identity(line.split("\t", 2)[2])
            for line in list_stdout.getvalue().splitlines()
        ]
        self.assertEqual(
            [identity["ordinal"] for identity in list_identities],
            [1, 2],
        )
        self.assertEqual(
            [identity["name"] for identity in list_identities],
            [duplicate_name, duplicate_name],
        )
        self.assertEqual(
            list_identities[0]["raw_name_b64"],
            list_identities[1]["raw_name_b64"],
        )

        self.assertEqual(ambiguous_rc, 1)
        ambiguity_identities, omitted = self._parse_ambiguity_identities(
            ambiguous_stderr.getvalue()
        )
        self.assertEqual(omitted, 0)
        self.assertEqual(
            [identity["ordinal"] for identity in ambiguity_identities],
            [1, 2],
        )

        self.assertEqual(show_rc, 0)
        show_lines = show_stdout.getvalue().splitlines()
        self.assertEqual(show_lines[1], "first")
        self.assertEqual(show_lines[4], "second")
        heading_identities = [
            self._parse_identity(line[3:-3])
            for line in show_lines
            if line.startswith("== ")
        ]
        self.assertEqual(
            [identity["ordinal"] for identity in heading_identities],
            [1, 2],
        )
        self.assertEqual(len(opened_infos), 2)
        self.assertIsInstance(opened_infos[0], zipfile.ZipInfo)
        self.assertIsInstance(opened_infos[1], zipfile.ZipInfo)
        self.assertIsNot(opened_infos[0], opened_infos[1])

    def test_nul_bearing_central_name_is_rejected_before_zipfile(
        self,
    ) -> None:
        original_name = "logs/nulXname.log"
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "nul-name.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(original_name, "content\n")
            self._replace_member_name_byte(
                archive_path,
                ordinal=1,
                byte_index=original_name.index("X"),
                replacement=0,
            )

            stdout = io.StringIO()
            stderr = io.StringIO()
            real_zipfile = zipfile.ZipFile
            with mock.patch.object(
                MODULE.zipfile,
                "ZipFile",
                wraps=real_zipfile,
            ) as constructor:
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    rc = MODULE.cmd_zip_list(self._list_args(archive_path))

        self.assertEqual(rc, 1)
        constructor.assert_not_called()
        self.assertEqual(stdout.getvalue(), "")
        error_text = stderr.getvalue()
        self.assertEqual(len(error_text.splitlines()), 1)
        self.assertLessEqual(
            len(error_text),
            MODULE.DEFAULT_MAX_OUTPUT_CHARS,
        )
        self.assertIn("name contains a NUL byte: ordinal=1", error_text)
        self.assertNotIn("\0", error_text)

    def test_member_names_are_reversible_and_single_line_everywhere(
        self,
    ) -> None:
        names = [
            "logs/line\nbreak.txt",
            r"logs/line\nbreak.txt",
            "logs/tab\tcr\rreturn\x1b\\tail.txt",
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "names.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                for name in names:
                    archive.writestr(name, "ok\n")

            list_args = self._list_args(archive_path)
            list_stdout = io.StringIO()
            with redirect_stdout(list_stdout):
                list_rc = MODULE.cmd_zip_list(list_args)

            ambiguous_args = self._show_args(
                archive_path,
                member=r"^logs/",
                regex=True,
                head=1,
            )
            ambiguous_stderr = io.StringIO()
            with redirect_stderr(ambiguous_stderr):
                ambiguous_rc = MODULE.cmd_zip_show(ambiguous_args)

            show_args = self._show_args(
                archive_path,
                member=r"^logs/",
                regex=True,
                all=True,
                head=1,
                max_output_lines=12,
                max_output_chars=512,
            )
            show_stdout = io.StringIO()
            with redirect_stdout(show_stdout):
                show_rc = MODULE.cmd_zip_show(show_args)

            tiny_args = self._list_args(
                archive_path,
                max_output_chars=20,
            )
            tiny_stdout = io.StringIO()
            tiny_stderr = io.StringIO()
            with redirect_stdout(tiny_stdout), redirect_stderr(tiny_stderr):
                tiny_rc = MODULE.cmd_zip_list(tiny_args)

        self.assertEqual(list_rc, 0)
        list_lines = list_stdout.getvalue().splitlines()
        self.assertEqual(len(list_lines), len(names))
        self.assertLessEqual(
            len(list_stdout.getvalue()),
            list_args.max_output_chars,
        )
        listed_names = []
        for line in list_lines:
            fields = line.split("\t", 2)
            self.assertEqual(len(fields), 3)
            listed_names.append(self._parse_identity(fields[2])["name"])
        self.assertEqual(listed_names, names)

        self.assertEqual(ambiguous_rc, 1)
        ambiguity_lines = ambiguous_stderr.getvalue().splitlines()
        self.assertEqual(len(ambiguity_lines), 1)
        self.assertLessEqual(
            len(ambiguous_stderr.getvalue()), MODULE.HARD_MAX_ERROR_CHARS
        )
        ambiguity_identities, omitted = self._parse_ambiguity_identities(
            ambiguous_stderr.getvalue()
        )
        self.assertEqual(omitted, 0)
        ambiguous_names = [identity["name"] for identity in ambiguity_identities]
        self.assertEqual(ambiguous_names, names)

        self.assertEqual(show_rc, 0)
        show_lines = show_stdout.getvalue().splitlines()
        self.assertLessEqual(len(show_lines), show_args.max_output_lines)
        self.assertLessEqual(
            len(show_stdout.getvalue()),
            show_args.max_output_chars,
        )
        heading_names = [
            self._parse_identity(line[3:-3])["name"]
            for line in show_lines
            if line.startswith("== ")
        ]
        self.assertEqual(heading_names, names)
        self.assertEqual(len(set(heading_names)), len(names))

        for rendered_line in list_lines + ambiguity_lines + show_lines:
            self.assertNotIn("\r", rendered_line)
            self.assertNotIn("\x1b", rendered_line)

        self.assertEqual(tiny_rc, 0)
        self.assertEqual(tiny_stdout.getvalue(), "")
        self.assertIn("notice=output truncated", tiny_stderr.getvalue())

    def test_member_name_in_error_uses_canonical_escape(self) -> None:
        directory_name = "logs/control\n\t\x1b\\/"
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "directory-name.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(directory_name, b"")
            args = self._show_args(
                archive_path,
                member=directory_name,
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                rc = MODULE.cmd_zip_show(args)

        self.assertEqual(rc, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(len(stderr.getvalue().splitlines()), 1)
        rendered_identity = (
            stderr.getvalue()
            .rstrip()
            .split(
                "member=",
                1,
            )[1]
        )
        identity = self._parse_identity(rendered_identity)
        self.assertEqual(identity["name"], directory_name)
        self.assertEqual(identity["ordinal"], 1)

    def test_long_nul_suffix_fails_without_partial_or_unbounded_output(
        self,
    ) -> None:
        long_name = f"logs/X{'x' * 600}.log"
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "long-name.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("logs/first.log", "first\n")
                archive.writestr(long_name, "second\n")
            self._replace_member_name_byte(
                archive_path,
                ordinal=2,
                byte_index=long_name.index("X"),
                replacement=0,
            )

            list_stdout = io.StringIO()
            list_stderr = io.StringIO()
            with redirect_stdout(list_stdout), redirect_stderr(list_stderr):
                list_rc = MODULE.cmd_zip_list(self._list_args(archive_path))

            show_stdout = io.StringIO()
            show_stderr = io.StringIO()
            with redirect_stdout(show_stdout), redirect_stderr(show_stderr):
                show_rc = MODULE.cmd_zip_show(
                    self._show_args(
                        archive_path,
                        member=r"^logs/",
                        regex=True,
                        all=True,
                    )
                )

        self.assertEqual(list_rc, 1)
        self.assertEqual(show_rc, 1)
        self.assertEqual(list_stdout.getvalue(), "")
        self.assertEqual(show_stdout.getvalue(), "")
        for error_text in (list_stderr.getvalue(), show_stderr.getvalue()):
            self.assertEqual(len(error_text.splitlines()), 1)
            self.assertLessEqual(
                len(error_text),
                MODULE.DEFAULT_MAX_OUTPUT_CHARS,
            )
            self.assertIn(
                "central-directory member raw name exceeds max bytes",
                error_text,
            )
            self.assertNotIn("x" * 80, error_text)

    def test_parser_rejects_negative_window(self) -> None:
        parser = MODULE.build_parser()
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                parser.parse_args(
                    ["zip-show", "run.zip", "console.txt", "--head", "-1"]
                )

        self.assertEqual(raised.exception.code, 2)

    def test_parser_rejects_every_budget_above_immutable_hard_max(self) -> None:
        parser = MODULE.build_parser()
        cases = {
            "list-limit": (
                ["zip-list", "run.zip", "--limit"],
                MODULE.HARD_MAX_LIST_LIMIT,
            ),
            "list-archive-bytes": (
                ["zip-list", "run.zip", "--max-archive-bytes"],
                MODULE.HARD_MAX_ARCHIVE_BYTES,
            ),
            "list-archive-members": (
                ["zip-list", "run.zip", "--max-archive-members"],
                MODULE.HARD_MAX_ARCHIVE_MEMBERS,
            ),
            "list-central-directory": (
                ["zip-list", "run.zip", "--max-central-directory-bytes"],
                MODULE.HARD_MAX_CENTRAL_DIRECTORY_BYTES,
            ),
            "list-output-chars": (
                ["zip-list", "run.zip", "--max-output-chars"],
                MODULE.HARD_MAX_OUTPUT_CHARS,
            ),
            "show-archive-bytes": (
                ["zip-show", "run.zip", "console.txt", "--max-archive-bytes"],
                MODULE.HARD_MAX_ARCHIVE_BYTES,
            ),
            "show-archive-members": (
                ["zip-show", "run.zip", "console.txt", "--max-archive-members"],
                MODULE.HARD_MAX_ARCHIVE_MEMBERS,
            ),
            "show-central-directory": (
                [
                    "zip-show",
                    "run.zip",
                    "console.txt",
                    "--max-central-directory-bytes",
                ],
                MODULE.HARD_MAX_CENTRAL_DIRECTORY_BYTES,
            ),
            "show-members": (
                ["zip-show", "run.zip", "console.txt", "--max-members"],
                MODULE.HARD_MAX_MEMBERS,
            ),
            "show-member-bytes": (
                ["zip-show", "run.zip", "console.txt", "--max-member-bytes"],
                MODULE.HARD_MAX_MEMBER_BYTES,
            ),
            "show-total-member-bytes": (
                [
                    "zip-show",
                    "run.zip",
                    "console.txt",
                    "--max-total-member-bytes",
                ],
                MODULE.HARD_MAX_TOTAL_MEMBER_BYTES,
            ),
            "show-member-lines": (
                ["zip-show", "run.zip", "console.txt", "--max-member-lines"],
                MODULE.HARD_MAX_MEMBER_LINES,
            ),
            "show-input-line-chars": (
                [
                    "zip-show",
                    "run.zip",
                    "console.txt",
                    "--max-input-line-chars",
                ],
                MODULE.HARD_MAX_INPUT_LINE_CHARS,
            ),
            "show-output-lines": (
                ["zip-show", "run.zip", "console.txt", "--max-output-lines"],
                MODULE.HARD_MAX_OUTPUT_LINES,
            ),
            "show-output-chars": (
                ["zip-show", "run.zip", "console.txt", "--max-output-chars"],
                MODULE.HARD_MAX_OUTPUT_CHARS,
            ),
        }
        for label, (argv, hard_max) in cases.items():
            with self.subTest(option=label), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    parser.parse_args([*argv, str(hard_max + 1)])
                self.assertEqual(raised.exception.code, 2)

    def test_direct_entrypoints_reject_every_budget_above_hard_max(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            list_cases = {
                "limit": MODULE.HARD_MAX_LIST_LIMIT,
                "max_archive_bytes": MODULE.HARD_MAX_ARCHIVE_BYTES,
                "max_archive_members": MODULE.HARD_MAX_ARCHIVE_MEMBERS,
                "max_central_directory_bytes": (
                    MODULE.HARD_MAX_CENTRAL_DIRECTORY_BYTES
                ),
                "max_output_chars": MODULE.HARD_MAX_OUTPUT_CHARS,
            }
            show_cases = {
                "max_archive_bytes": MODULE.HARD_MAX_ARCHIVE_BYTES,
                "max_archive_members": MODULE.HARD_MAX_ARCHIVE_MEMBERS,
                "max_central_directory_bytes": (
                    MODULE.HARD_MAX_CENTRAL_DIRECTORY_BYTES
                ),
                "max_members": MODULE.HARD_MAX_MEMBERS,
                "max_member_bytes": MODULE.HARD_MAX_MEMBER_BYTES,
                "max_total_member_bytes": MODULE.HARD_MAX_TOTAL_MEMBER_BYTES,
                "max_member_lines": MODULE.HARD_MAX_MEMBER_LINES,
                "max_input_line_chars": MODULE.HARD_MAX_INPUT_LINE_CHARS,
                "max_output_lines": MODULE.HARD_MAX_OUTPUT_LINES,
                "max_output_chars": MODULE.HARD_MAX_OUTPUT_CHARS,
            }

            for option_name, hard_max in list_cases.items():
                with self.subTest(command="zip-list", option=option_name):
                    stdout = io.StringIO()
                    stderr = io.StringIO()
                    args = self._list_args(
                        archive_path,
                        **{option_name: hard_max + 1},
                    )
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        rc = MODULE.cmd_zip_list(args)
                    self.assertEqual(rc, 1)
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertIn("immutable hard max", stderr.getvalue())

            for option_name, hard_max in show_cases.items():
                with self.subTest(command="zip-show", option=option_name):
                    stdout = io.StringIO()
                    stderr = io.StringIO()
                    args = self._show_args(
                        archive_path,
                        **{option_name: hard_max + 1},
                    )
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        rc = MODULE.cmd_zip_show(args)
                    self.assertEqual(rc, 1)
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertIn("immutable hard max", stderr.getvalue())

    def test_member_validation_drain_obeys_command_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            args = self._show_args(archive_path, head=1)
            stdout = io.StringIO()
            stderr = io.StringIO()
            original_check = MODULE.PinnedArchiveReader.check_deadline

            def fail_drain(
                stream: MODULE.PinnedArchiveReader,
                phase: str,
            ) -> None:
                if phase == "member validation drain":
                    raise MODULE.ArtifactLimitError(
                        "archive command deadline exceeded during member "
                        "validation drain"
                    )
                original_check(stream, phase)

            with mock.patch.object(
                MODULE.PinnedArchiveReader,
                "check_deadline",
                fail_drain,
            ):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    rc = MODULE.cmd_zip_show(args)

        self.assertEqual(rc, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn(
            "archive command deadline exceeded during member validation drain",
            stderr.getvalue(),
        )

    def test_archive_command_timeout_is_immutable(self) -> None:
        with self.assertRaisesRegex(
            MODULE.ArtifactLimitError,
            "immutable hard max",
        ):
            MODULE.ArchiveCommandDeadline(
                MODULE.HARD_MAX_ARCHIVE_COMMAND_TIMEOUT_SECONDS + 1.0
            )

    def test_archive_command_timer_wiring_interrupts_python_sleep(self) -> None:
        deadline = MODULE.ArchiveCommandDeadline(0.05)
        started = time.monotonic()
        try:
            deadline.arm()
            with self.assertRaisesRegex(
                MODULE.ArtifactLimitError,
                "archive command deadline exceeded",
            ):
                time.sleep(1.0)
        finally:
            deadline.close()

        self.assertLess(time.monotonic() - started, 0.5)

    def test_deadline_state_never_trusts_stale_armed_or_closing_flags(
        self,
    ) -> None:
        deadline = MODULE.ArchiveCommandDeadline()
        deadline._armed = True
        deadline._diagnostic_timer_safe = True

        deadline._closing = True
        self.assertFalse(deadline.timer_backed_diagnostics_safe())

        deadline._closing = False
        deadline._armed = False
        self.assertFalse(deadline.timer_backed_diagnostics_safe())

        deadline._armed = True
        deadline._diagnostic_timer_safe = False
        self.assertFalse(deadline.timer_backed_diagnostics_safe())

        deadline._diagnostic_timer_safe = True
        deadline._regex_cleanup_state = MODULE.REGEX_CLEANUP_MASKED
        self.assertFalse(deadline.timer_backed_diagnostics_safe())

        deadline._regex_cleanup_state = MODULE.REGEX_CLEANUP_IDLE
        deadline._regex_spawn_state = MODULE.REGEX_SPAWN_FENCED
        self.assertFalse(deadline.timer_backed_diagnostics_safe())

    def test_deadline_cleanup_failures_disable_timer_backed_diagnostics(
        self,
    ) -> None:
        failure_cases = (
            "setitimer",
            "drain",
            "handler",
            "mask",
        )
        for failure_case in failure_cases:
            with self.subTest(failure=failure_case):
                deadline = MODULE.ArchiveCommandDeadline()
                deadline._armed = True
                deadline._diagnostic_timer_safe = True
                deadline._previous_handler = signal.SIG_DFL

                def setitimer(
                    _which: int,
                    _seconds: float,
                ) -> None:
                    if failure_case == "setitimer":
                        raise OSError(errno.EIO, "injected setitimer failure")

                def drain() -> None:
                    if failure_case == "drain":
                        raise OSError(errno.EIO, "injected drain failure")

                def install_handler(
                    _signal_number: int,
                    _handler: object,
                ) -> None:
                    if failure_case == "handler":
                        raise OSError(errno.EIO, "injected handler failure")

                mask_calls = 0

                def change_mask(
                    _operation: int,
                    _signals: object,
                ) -> set[signal.Signals]:
                    nonlocal mask_calls
                    mask_calls += 1
                    if failure_case == "mask" and mask_calls == 2:
                        raise OSError(errno.EIO, "injected mask restore failure")
                    return set()

                with (
                    mock.patch.object(
                        deadline,
                        "_require_signal_support",
                    ),
                    mock.patch.object(
                        deadline,
                        "_drain_pending_alarm",
                        side_effect=drain,
                    ),
                    mock.patch.object(
                        MODULE.signal,
                        "setitimer",
                        side_effect=setitimer,
                    ),
                    mock.patch.object(
                        MODULE.signal,
                        "signal",
                        side_effect=install_handler,
                    ),
                    mock.patch.object(
                        MODULE.signal,
                        "pthread_sigmask",
                        side_effect=change_mask,
                    ),
                    self.assertRaises(OSError),
                ):
                    deadline.close()

                self.assertTrue(deadline._closing)
                self.assertFalse(deadline.timer_backed_diagnostics_safe())

    def test_deadline_arm_mask_restore_failure_never_enables_diagnostics(
        self,
    ) -> None:
        deadline = MODULE.ArchiveCommandDeadline()
        mask_calls = 0

        def change_mask(
            _operation: int,
            _signals: object,
        ) -> set[signal.Signals]:
            nonlocal mask_calls
            mask_calls += 1
            if mask_calls == 2:
                raise OSError(errno.EIO, "injected mask restore failure")
            return set()

        with (
            mock.patch.object(deadline, "_require_signal_support"),
            mock.patch.object(MODULE.signal, "sigpending", return_value=set()),
            mock.patch.object(
                MODULE.signal,
                "getitimer",
                return_value=(0.0, 0.0),
            ),
            mock.patch.object(
                MODULE.signal,
                "getsignal",
                return_value=signal.SIG_DFL,
            ),
            mock.patch.object(MODULE.signal, "signal"),
            mock.patch.object(MODULE.signal, "setitimer"),
            mock.patch.object(
                MODULE.signal,
                "pthread_sigmask",
                side_effect=change_mask,
            ),
            self.assertRaisesRegex(OSError, "mask restore"),
        ):
            deadline.arm()

        self.assertTrue(deadline._armed)
        self.assertFalse(deadline.timer_backed_diagnostics_safe())

    @unittest.skipUnless(
        all(
            hasattr(signal, name)
            for name in (
                "SIGALRM",
                "pthread_sigmask",
                "SIG_BLOCK",
                "SIG_SETMASK",
            )
        ),
        "POSIX signal masks are required",
    )
    def test_archive_command_rejects_blocked_sigalrm_before_archive_open(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            previous_mask = signal.pthread_sigmask(
                signal.SIG_BLOCK,
                {signal.SIGALRM},
            )
            try:
                stderr = io.StringIO()
                with mock.patch.object(MODULE, "_open_pinned_archive") as opener:
                    with redirect_stderr(stderr):
                        rc = MODULE.cmd_zip_list(self._list_args(archive_path))
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

        self.assertEqual(rc, 1)
        opener.assert_not_called()
        self.assertEqual(len(stderr.getvalue().splitlines()), 1)
        self.assertIn("refuses to arm while SIGALRM is blocked", stderr.getvalue())

    @unittest.skipUnless(
        hasattr(signal, "pthread_sigmask") and hasattr(signal, "SIGALRM"),
        "POSIX signal masks are required",
    )
    def test_blocked_sigalrm_error_does_not_block_on_full_stderr_pipe(
        self,
    ) -> None:
        read_fd, write_fd, writer, original_flags = self._full_pipe_writer()
        previous_mask = signal.pthread_sigmask(
            signal.SIG_BLOCK,
            {signal.SIGALRM},
        )
        started = time.monotonic()
        try:
            with redirect_stderr(writer):
                rc = MODULE.cmd_zip_list(self._list_args(Path("unused.zip")))
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            writer.close()
            final_flags = MODULE._fcntl_get_flags(write_fd)
            os.close(write_fd)
            os.close(read_fd)

        self.assertEqual(rc, 1)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertEqual(final_flags, original_flags)

    @unittest.skipUnless(
        all(
            hasattr(signal, name)
            for name in (
                "SIGALRM",
                "pthread_sigmask",
                "sigpending",
                "SIG_BLOCK",
                "SIG_SETMASK",
            )
        ),
        "POSIX pending-signal controls are required",
    )
    def test_pending_sigalrm_error_does_not_block_on_full_stderr_pipe(
        self,
    ) -> None:
        read_fd, write_fd, writer, original_flags = self._full_pipe_writer()
        started = time.monotonic()
        try:
            with (
                mock.patch.object(
                    MODULE.signal,
                    "sigpending",
                    return_value={signal.SIGALRM},
                ),
                redirect_stderr(writer),
            ):
                rc = MODULE.cmd_zip_list(self._list_args(Path("unused.zip")))
        finally:
            writer.close()
            final_flags = MODULE._fcntl_get_flags(write_fd)
            os.close(write_fd)
            os.close(read_fd)

        self.assertEqual(rc, 1)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertEqual(final_flags, original_flags)

    @unittest.skipUnless(
        hasattr(signal, "setitimer") and hasattr(signal, "SIGALRM"),
        "POSIX interval timers are required",
    )
    def test_existing_timer_error_does_not_block_on_full_stderr_pipe(
        self,
    ) -> None:
        previous_timer = signal.getitimer(signal.ITIMER_REAL)
        if previous_timer != (0.0, 0.0):
            self.skipTest("the test runner already owns ITIMER_REAL")
        if hasattr(
            signal, "pthread_sigmask"
        ) and signal.SIGALRM in signal.pthread_sigmask(signal.SIG_BLOCK, set()):
            self.skipTest("the test runner already blocks SIGALRM")
        previous_handler = signal.getsignal(signal.SIGALRM)
        read_fd, write_fd, writer, original_flags = self._full_pipe_writer()
        signal.signal(signal.SIGALRM, lambda _signum, _frame: None)
        signal.setitimer(signal.ITIMER_REAL, 2.0)
        started = time.monotonic()
        try:
            with redirect_stderr(writer):
                rc = MODULE.cmd_zip_list(self._list_args(Path("unused.zip")))
            remaining_timer = signal.getitimer(signal.ITIMER_REAL)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            signal.signal(signal.SIGALRM, previous_handler)
            writer.close()
            final_flags = MODULE._fcntl_get_flags(write_fd)
            os.close(write_fd)
            os.close(read_fd)

        self.assertEqual(rc, 1)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertGreater(remaining_timer[0], 1.0)
        self.assertEqual(final_flags, original_flags)

    def test_argparse_error_does_not_block_on_full_stderr_pipe(self) -> None:
        read_fd, write_fd, writer, original_flags = self._full_pipe_writer()
        parser = MODULE.build_parser()
        started = time.monotonic()
        try:
            with (
                redirect_stderr(writer),
                self.assertRaises(SystemExit) as raised,
            ):
                parser.parse_args(["not-a-command"])
        finally:
            writer.close()
            final_flags = MODULE._fcntl_get_flags(write_fd)
            os.close(write_fd)
            os.close(read_fd)

        self.assertEqual(raised.exception.code, 2)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertEqual(final_flags, original_flags)

    def test_deadline_transition_failures_use_timerless_full_pipe_output(
        self,
    ) -> None:
        failure_cases = (
            ("arm-setitimer", True),
            ("close-setitimer", False),
            ("close-drain", False),
            ("close-handler", False),
            ("close-mask", False),
        )

        for failure_label, fail_on_arm in failure_cases:
            with self.subTest(failure=failure_label):

                class FailingDeadline:
                    def __init__(self) -> None:
                        self._armed = False
                        self._closing = False
                        self._diagnostic_timer_safe = False

                    def arm(self) -> None:
                        self._armed = True
                        self._diagnostic_timer_safe = True
                        if fail_on_arm:
                            raise OSError(errno.EIO, f"injected {failure_label}")

                    def close(self) -> None:
                        self._diagnostic_timer_safe = False
                        self._closing = True
                        if not fail_on_arm:
                            raise OSError(errno.EIO, f"injected {failure_label}")

                    def timer_backed_diagnostics_safe(self) -> bool:
                        return (
                            self._diagnostic_timer_safe
                            and self._armed
                            and not self._closing
                        )

                read_fd, write_fd, writer, original_flags = self._full_pipe_writer()
                started = time.monotonic()
                try:
                    with (
                        mock.patch.object(
                            MODULE,
                            "ArchiveCommandDeadline",
                            FailingDeadline,
                        ),
                        redirect_stderr(writer),
                    ):
                        rc = MODULE._run_archive_command(lambda _deadline: None)
                finally:
                    writer.close()
                    final_flags = MODULE._fcntl_get_flags(write_fd)
                    os.close(write_fd)
                    os.close(read_fd)

                self.assertEqual(rc, 1)
                self.assertLess(time.monotonic() - started, 0.5)
                self.assertEqual(final_flags, original_flags)

    def test_deadline_cleanup_failure_does_not_write_to_character_device(
        self,
    ) -> None:
        class FailingCloseDeadline:
            def __init__(self) -> None:
                self._armed = False
                self._closing = False
                self._diagnostic_timer_safe = False

            def arm(self) -> None:
                self._armed = True
                self._diagnostic_timer_safe = True

            def close(self) -> None:
                self._diagnostic_timer_safe = False
                self._closing = True
                raise OSError(errno.EIO, "injected close failure")

            def timer_backed_diagnostics_safe(self) -> bool:
                return self._diagnostic_timer_safe and self._armed and not self._closing

        with (
            open(os.devnull, "w", encoding="utf-8") as stream,
            mock.patch.object(
                MODULE,
                "ArchiveCommandDeadline",
                FailingCloseDeadline,
            ),
            mock.patch.object(MODULE.os, "write") as writer,
            redirect_stderr(stream),
        ):
            started = time.monotonic()
            rc = MODULE._run_archive_command(lambda _deadline: None)
            elapsed = time.monotonic() - started

        self.assertEqual(rc, 1)
        self.assertLess(elapsed, 0.5)
        writer.assert_not_called()

    def test_timerless_publisher_restores_flags_before_selector_close_failure(
        self,
    ) -> None:
        read_fd, write_fd, writer, original_flags = self._full_pipe_writer()
        selector = mock.Mock()
        selector.select.return_value = []
        selector.close.side_effect = OSError(errno.EIO, "injected close failure")
        try:
            with (
                mock.patch.object(
                    MODULE.selectors,
                    "DefaultSelector",
                    return_value=selector,
                ),
                self.assertRaisesRegex(OSError, "injected close failure"),
            ):
                MODULE._publish_terminal_line_without_timer(
                    "error=injected\n",
                    writer,
                )
        finally:
            writer.close()
            final_flags = MODULE._fcntl_get_flags(write_fd)
            os.close(write_fd)
            os.close(read_fd)

        self.assertEqual(final_flags, original_flags)
        selector.register.assert_called_once()
        selector.close.assert_called_once()

    def test_timerless_publisher_bounds_fcntl_get_interrupt_retries(self) -> None:
        read_fd, write_fd, writer, original_flags = self._full_pipe_writer()
        started = time.monotonic()
        try:
            with (
                mock.patch.object(
                    MODULE.fcntl,
                    "fcntl",
                    side_effect=InterruptedError("injected interruption"),
                ),
                self.assertRaises(OSError) as raised,
            ):
                MODULE._publish_terminal_line_without_timer(
                    "error=injected\n",
                    writer,
                )
        finally:
            writer.close()
            final_flags = MODULE._fcntl_get_flags(write_fd)
            os.close(write_fd)
            os.close(read_fd)

        self.assertEqual(raised.exception.errno, errno.ETIMEDOUT)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertEqual(final_flags, original_flags)

    def test_timerless_publisher_bounds_fcntl_set_interrupt_retries(self) -> None:
        read_fd, write_fd, writer, original_flags = self._full_pipe_writer()
        real_fcntl = MODULE.fcntl.fcntl

        def interrupt_nonblocking_set(
            fd: int,
            operation: int,
            argument: int = 0,
        ) -> int:
            if operation == MODULE.fcntl.F_SETFL and argument & os.O_NONBLOCK:
                raise InterruptedError("injected interruption")
            if operation == MODULE.fcntl.F_GETFL:
                return int(real_fcntl(fd, operation))
            return int(real_fcntl(fd, operation, argument))

        started = time.monotonic()
        try:
            with (
                mock.patch.object(
                    MODULE.fcntl,
                    "fcntl",
                    side_effect=interrupt_nonblocking_set,
                ),
                self.assertRaises(OSError) as raised,
            ):
                MODULE._publish_terminal_line_without_timer(
                    "error=injected\n",
                    writer,
                )
        finally:
            writer.close()
            final_flags = MODULE._fcntl_get_flags(write_fd)
            os.close(write_fd)
            os.close(read_fd)

        self.assertEqual(raised.exception.errno, errno.ETIMEDOUT)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertEqual(final_flags, original_flags)

    def test_timerless_publisher_retries_restore_fcntl_interruptions(self) -> None:
        read_fd, write_fd, writer, original_flags = self._full_pipe_writer()
        real_fcntl = MODULE.fcntl.fcntl
        state = {
            "nonblocking_set": False,
            "restore_get_interruptions": 3,
            "restore_set_interruptions": 3,
        }

        def interrupt_restore(
            fd: int,
            operation: int,
            argument: int = 0,
        ) -> int:
            if operation == MODULE.fcntl.F_GETFL:
                if state["nonblocking_set"] and state["restore_get_interruptions"] > 0:
                    state["restore_get_interruptions"] -= 1
                    raise InterruptedError("injected restore get interruption")
                return int(real_fcntl(fd, operation))
            if argument & os.O_NONBLOCK:
                result = int(real_fcntl(fd, operation, argument))
                state["nonblocking_set"] = True
                return result
            if state["nonblocking_set"] and state["restore_set_interruptions"] > 0:
                state["restore_set_interruptions"] -= 1
                raise InterruptedError("injected restore set interruption")
            result = int(real_fcntl(fd, operation, argument))
            state["nonblocking_set"] = False
            return result

        try:
            with mock.patch.object(
                MODULE.fcntl,
                "fcntl",
                side_effect=interrupt_restore,
            ):
                published = MODULE._publish_terminal_line_without_timer(
                    "error=injected\n",
                    writer,
                )
        finally:
            writer.close()
            final_flags = MODULE._fcntl_get_flags(write_fd)
            os.close(write_fd)
            os.close(read_fd)

        self.assertFalse(published)
        self.assertEqual(state["restore_get_interruptions"], 0)
        self.assertEqual(state["restore_set_interruptions"], 0)
        self.assertFalse(state["nonblocking_set"])
        self.assertEqual(final_flags, original_flags)

    def test_timerless_publisher_rejects_non_tty_character_device(self) -> None:
        with (
            open(os.devnull, "w", encoding="utf-8") as stream,
            mock.patch.object(MODULE.os, "write") as writer,
        ):
            published = MODULE._publish_terminal_line_without_timer(
                "error=injected\n",
                stream,
            )

        self.assertFalse(published)
        writer.assert_not_called()

    @unittest.skipUnless(
        all(
            hasattr(signal, name)
            for name in (
                "SIGALRM",
                "ITIMER_REAL",
                "pthread_sigmask",
                "sigpending",
                "SIG_BLOCK",
                "SIG_SETMASK",
            )
        ),
        "POSIX pending-signal controls are required",
    )
    def test_archive_command_close_drains_alarm_before_restoring_old_handler(
        self,
    ) -> None:
        previous_handler = signal.getsignal(signal.SIGALRM)
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        if signal.SIGALRM in original_mask:
            self.skipTest("SIGALRM was already blocked by the test runner")

        old_handler_calls: list[int] = []

        def old_handler(signum: int, _frame: object) -> None:
            old_handler_calls.append(signum)

        deadline = MODULE.ArchiveCommandDeadline(0.03)
        blocked_mask: set[signal.Signals] | None = None
        try:
            signal.signal(signal.SIGALRM, old_handler)
            deadline.arm()
            blocked_mask = signal.pthread_sigmask(
                signal.SIG_BLOCK,
                {signal.SIGALRM},
            )
            time.sleep(0.08)
            self.assertIn(signal.SIGALRM, signal.sigpending())

            deadline.close()
            self.assertNotIn(signal.SIGALRM, signal.sigpending())
            self.assertIs(signal.getsignal(signal.SIGALRM), old_handler)
            signal.pthread_sigmask(signal.SIG_SETMASK, blocked_mask)
            blocked_mask = None
            time.sleep(0.02)
            self.assertEqual(old_handler_calls, [])
        finally:
            if deadline._armed:
                deadline.close()
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            if blocked_mask is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, blocked_mask)
            signal.signal(signal.SIGALRM, previous_handler)
            signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)

    def test_blocking_success_output_flush_stays_under_command_deadline(
        self,
    ) -> None:
        class BlockingFlush(io.StringIO):
            def flush(self) -> None:
                time.sleep(1.0)

        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            deadline = MODULE.ArchiveCommandDeadline(0.05)
            stdout = BlockingFlush()
            stderr = io.StringIO()
            started = time.monotonic()
            with mock.patch.object(
                MODULE,
                "ArchiveCommandDeadline",
                return_value=deadline,
            ):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    rc = MODULE.cmd_zip_list(self._list_args(archive_path))
            elapsed = time.monotonic() - started

        self.assertEqual(rc, 1)
        self.assertLess(elapsed, 0.5)
        self.assertEqual(len(stderr.getvalue().splitlines()), 1)
        self.assertIn("archive command deadline exceeded", stderr.getvalue())

    def test_blocking_error_output_is_not_retried_outside_command_deadline(
        self,
    ) -> None:
        class BlockingErrorStream(io.StringIO):
            def write(self, value: str) -> int:
                time.sleep(1.0)
                return super().write(value)

        deadline = MODULE.ArchiveCommandDeadline(0.05)
        stderr = BlockingErrorStream()
        started = time.monotonic()
        with mock.patch.object(
            MODULE,
            "ArchiveCommandDeadline",
            return_value=deadline,
        ):
            with mock.patch.object(
                MODULE,
                "_validate_list_args",
                side_effect=ValueError("controlled failure"),
            ):
                with redirect_stderr(stderr):
                    rc = MODULE.cmd_zip_list(self._list_args(Path("unused.zip")))
        elapsed = time.monotonic() - started

        self.assertEqual(rc, 1)
        self.assertLess(elapsed, 0.5)
        self.assertEqual(stderr.getvalue(), "")

    def test_runtime_error_is_single_line_terminal_safe_and_hard_capped(
        self,
    ) -> None:
        oversized_error = Exception(f"unsafe\nterminal\x1b{('detail' * 10_000)}")
        stderr = io.StringIO()
        with mock.patch.object(
            MODULE,
            "_validate_list_args",
            side_effect=oversized_error,
        ):
            with redirect_stderr(stderr):
                rc = MODULE.cmd_zip_list(self._list_args(Path("unused.zip")))

        self.assertEqual(rc, 1)
        self.assertEqual(len(stderr.getvalue().splitlines()), 1)
        self.assertLessEqual(len(stderr.getvalue()), MODULE.HARD_MAX_ERROR_CHARS)
        self.assertIn(r"\x0a", stderr.getvalue())
        self.assertIn(r"\x1b", stderr.getvalue())
        self.assertIn(MODULE.TRUNCATION_MARKER, stderr.getvalue())

    def test_direct_encoding_rejects_control_characters_before_archive_open(
        self,
    ) -> None:
        args = self._show_args(
            Path("unused.zip"),
            encoding="utf-8\n\x1b",
        )
        stderr = io.StringIO()
        with mock.patch.object(MODULE, "_open_pinned_archive") as opener:
            with redirect_stderr(stderr):
                rc = MODULE.cmd_zip_show(args)

        self.assertEqual(rc, 1)
        opener.assert_not_called()
        self.assertEqual(len(stderr.getvalue().splitlines()), 1)
        self.assertIn(
            "encoding name contains unsupported characters",
            stderr.getvalue(),
        )

    def test_cli_encoding_length_error_is_single_line_and_hard_capped(
        self,
    ) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "zip-show",
                "unused.zip",
                "console.txt",
                "--encoding",
                "x" * (MODULE.HARD_MAX_ENCODING_NAME_CHARS + 1),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(len(result.stderr.splitlines()), 1)
        self.assertLessEqual(len(result.stderr), MODULE.HARD_MAX_ERROR_CHARS)
        self.assertIn("encoding name exceeds immutable hard max", result.stderr)

    def test_regex_entrypoints_report_invalid_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            cases = {
                "zip-list-match": self._list_args(
                    archive_path,
                    match="[",
                ),
                "member-regex": self._show_args(
                    archive_path,
                    member="[",
                    regex=True,
                ),
                "grep": self._show_args(
                    archive_path,
                    grep="[",
                ),
            }
            for label, args in cases.items():
                with self.subTest(entrypoint=label):
                    stdout = io.StringIO()
                    stderr = io.StringIO()
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        if label == "zip-list-match":
                            rc = MODULE.cmd_zip_list(args)
                        else:
                            rc = MODULE.cmd_zip_show(args)

                    self.assertEqual(rc, 1)
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertIn(
                        "error=unterminated character set",
                        stderr.getvalue(),
                    )

    def test_command_line_zip_list_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "zip-list",
                    str(archive_path),
                    "--match",
                    "console",
                    "--limit",
                    "1",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        fields = result.stdout.rstrip().split("\t", 2)
        self.assertEqual(len(fields), 3)
        identity = self._parse_identity(fields[2])
        self.assertEqual(identity["name"], "logs/console.txt")


class BugTriageDocumentationTests(unittest.TestCase):
    _pull_request_number = 7
    _canonical_commit = "1" * 40
    _base_sha = "9" * 40
    _private_release_commit = "2" * 40
    _release_manifest_sha256 = "3" * 64
    _workflow_source_commit = "4" * 40
    _ruleset_id = 97531
    _workflow_id = 86420
    _installation_scope_id = "fixture-installation-scope"
    _pointer_generation = 17
    _pointer_observed_at = "2026-07-24T12:00:00Z"
    _pointer_expires_at = "2099-07-24T13:00:00Z"
    _trusted_gate_environment_names = (
        "EVENT_REPOSITORY",
        "PR_BASE_REF",
        "PR_BASE_SHA",
        "PR_HEAD_REPOSITORY",
        "PR_HEAD_SHA",
        "PR_NUMBER",
        "SELECTED_TARGET_HEAD_SHA",
        "SELECTED_TARGET_BASE_SHA",
        "SELECTED_TARGET_PR_NUMBER",
        "CISCO_CUTOVER_TARGET_BASE_SHA",
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
    _selector_environment_names = (
        "EVENT_REPOSITORY",
        "PR_BASE_REF",
        "PR_BASE_SHA",
        "PR_HEAD_REPOSITORY",
        "PR_HEAD_SHA",
        "PR_NUMBER",
        "CISCO_CUTOVER_TARGET_HEAD_SHA",
        "CISCO_CUTOVER_TARGET_BASE_SHA",
        "CISCO_CUTOVER_TARGET_PR_NUMBER",
        "GITHUB_OUTPUT",
    )

    @staticmethod
    def _expected_base_change_enforcement() -> dict[str, object]:
        return {
            "status": "unavailable",
            "reason": "ruleset-workflow-default-activities-exclude-edited",
            "event": "pull_request_target",
            "required_activity": "edited",
            "ruleset_dispatch_activities": [
                "opened",
                "synchronize",
                "reopened",
            ],
        }

    @classmethod
    def _expected_admission_blockers(
        cls,
        *,
        pointer_available: bool = False,
    ) -> list[dict[str, object]]:
        blockers = [
            {
                "name": "base-change-enforcement",
                "priority": 1,
                **cls._expected_base_change_enforcement(),
            }
        ]
        if not pointer_available:
            blockers.append(
                {
                    "authority_reason": "private-live-authority-not-configured",
                    "name": "pointer-proof",
                    "priority": 2,
                    "reason": "pointer-proof-unavailable",
                    "status": "unavailable",
                }
            )
        return blockers

    def test_generated_project_journal_index_is_ignored_exactly(self) -> None:
        ignore_lines = (
            (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        )
        generated_index = "/docs/project_journal/INDEX.md"
        self.assertEqual(ignore_lines.count(generated_index), 1)
        self.assertNotIn("docs/project_journal/", ignore_lines)
        self.assertIn(
            "docs/project_journal/INDEX.md",
            (REPO_ROOT / "docs/PROJECT_STATE.md").read_text(encoding="utf-8"),
        )

    def _pointer_state_sha256(
        self,
        *,
        generation: int | None = None,
        installation_scope_id: str | None = None,
        target: str | None = None,
    ) -> str:
        selected_generation = generation or self._pointer_generation
        selected_scope = installation_scope_id or self._installation_scope_id
        selected_target = target or f"releases/{self._private_release_commit}"
        state = {
            "generation": selected_generation,
            "installation_scope_id": selected_scope,
            "name": "current",
            "release_manifest_sha256": self._release_manifest_sha256,
            "resolved_release_commit": self._private_release_commit,
            "target": selected_target,
        }
        canonical_state = b"cisco-installed-pointer-state-v1\0" + json.dumps(
            state,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(canonical_state).hexdigest()

    def _matching_cutover_receipt(
        self,
        fixture: dict[str, object],
    ) -> dict[str, object]:
        release_target = f"releases/{self._private_release_commit}"
        return {
            "schema_version": 3,
            "canonical_repository": fixture["canonical_repository"],
            "canonical_commit": self._canonical_commit,
            "private_aggregate_repository": fixture["private_aggregate_repository"],
            "private_release_commit": self._private_release_commit,
            "release_manifest_sha256": self._release_manifest_sha256,
            "release_target": release_target,
            "cutover": {
                "target_repository": {
                    "id": 1242512092,
                    "full_name": fixture["canonical_repository"],
                    "default_branch": "master",
                },
                "pull_request": {
                    "number": self._pull_request_number,
                    "head_sha": self._canonical_commit,
                    "base_ref": "master",
                    "base_sha": self._base_sha,
                },
                "required_workflow": {
                    "id": self._workflow_id,
                    "repository_id": 1242512092,
                    "repository_full_name": fixture["canonical_repository"],
                    "path": ".github/workflows/cisco-cutover-admission.yml",
                    "ref": "refs/heads/master",
                    "sha": self._workflow_source_commit,
                    "event": "pull_request_target",
                    "check_name": "cisco-cutover-admission",
                },
            },
            "activation": fixture["activation"],
            "gates": [
                {
                    "name": name,
                    "status": "passed",
                    "private_release_commit": self._private_release_commit,
                    "release_manifest_sha256": self._release_manifest_sha256,
                }
                for name in fixture["trust_gates"]
            ],
            "installed_pointer": {
                "name": "current",
                "target": release_target,
                "resolved_release_commit": self._private_release_commit,
                "release_manifest_sha256": self._release_manifest_sha256,
                "installation_scope_id": self._installation_scope_id,
                "generation": self._pointer_generation,
                "state_sha256": self._pointer_state_sha256(),
                "observed_at": self._pointer_observed_at,
                "expires_at": self._pointer_expires_at,
                "live_authority": {
                    "repository_id": 223344,
                    "repository_full_name": fixture["private_aggregate_repository"],
                    "workflow_id": 334455,
                    "workflow_path": ".github/workflows/release.yml",
                    "workflow_ref": "refs/heads/master",
                    "workflow_sha": "5" * 40,
                    "run_id": 445566,
                    "run_attempt": 1,
                    "provider": {
                        "id": 15368,
                        "slug": "github-actions",
                    },
                    "proof_artifact_id": 556677,
                    "proof_artifact_sha256": "6" * 64,
                },
                "merge_lease": {
                    "lease_id": "fixture-merge-lease",
                    "status": "active",
                    "target_repository_id": 1242512092,
                    "pull_request_number": self._pull_request_number,
                    "pull_request_head_sha": self._canonical_commit,
                    "pull_request_base_sha": self._base_sha,
                    "installation_scope_id": self._installation_scope_id,
                    "pointer_generation": self._pointer_generation,
                    "acquired_at": self._pointer_observed_at,
                    "expires_at": self._pointer_expires_at,
                },
            },
        }

    def _write_cutover_receipt(
        self,
        path: Path,
        receipt: dict[str, object],
    ) -> str:
        payload = (
            json.dumps(
                receipt,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        path.write_bytes(payload)
        return hashlib.sha256(payload).hexdigest()

    def _run_cutover_validator(
        self,
        *,
        contract_path: Path = MIGRATION_FIXTURE_PATH,
        receipt_path: Path | None = None,
        receipt_sha256: str | None = None,
        expected_installation_scope_id: str | None = None,
        expected_base_sha: str | None = None,
        include_expected_base_sha: bool = True,
        expected_pointer_generation: int | None = None,
        expected_pointer_state_sha256: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            sys.executable,
            str(CUTOVER_VALIDATOR_PATH),
            "--contract",
            str(contract_path),
        ]
        if receipt_path is not None:
            command.extend(
                [
                    "--receipt",
                    str(receipt_path),
                    "--expected-canonical-commit",
                    self._canonical_commit,
                    "--expected-pull-request-number",
                    str(self._pull_request_number),
                    "--expected-private-release-commit",
                    self._private_release_commit,
                    "--expected-release-manifest-sha256",
                    self._release_manifest_sha256,
                    "--expected-receipt-sha256",
                    receipt_sha256 or ("0" * 64),
                    "--expected-workflow-id",
                    str(self._workflow_id),
                    "--expected-workflow-sha",
                    self._workflow_source_commit,
                    "--expected-installation-scope-id",
                    (expected_installation_scope_id or self._installation_scope_id),
                    "--expected-pointer-generation",
                    str(expected_pointer_generation or self._pointer_generation),
                    "--expected-pointer-state-sha256",
                    (expected_pointer_state_sha256 or self._pointer_state_sha256()),
                ]
            )
            if include_expected_base_sha:
                canonical_index = command.index("--expected-canonical-commit")
                command[canonical_index + 2 : canonical_index + 2] = [
                    "--expected-base-sha",
                    expected_base_sha or self._base_sha,
                ]
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )

    def _trusted_workflow_program(self) -> str:
        workflow = CUTOVER_TRUSTED_WORKFLOW_PATH.read_text(encoding="utf-8")
        start_marker = "          python3 - <<'ADMISSION_PY'\n"
        end_marker = "\n          ADMISSION_PY\n"
        self.assertEqual(workflow.count(start_marker), 1)
        self.assertEqual(workflow.count(end_marker), 1)
        embedded = workflow.split(start_marker, 1)[1].split(end_marker, 1)[0]
        lines = embedded.splitlines()
        self.assertTrue(lines)
        self.assertTrue(
            all(not line or line.startswith("          ") for line in lines)
        )
        return "\n".join(line[10:] if line else "" for line in lines)

    def _selector_workflow_program(self) -> str:
        workflow = CUTOVER_TRUSTED_WORKFLOW_PATH.read_text(encoding="utf-8")
        start_marker = "          python3 - <<'SELECTOR_PY'\n"
        end_marker = "\n          SELECTOR_PY\n"
        self.assertEqual(workflow.count(start_marker), 1)
        self.assertEqual(workflow.count(end_marker), 1)
        embedded = workflow.split(start_marker, 1)[1].split(end_marker, 1)[0]
        lines = embedded.splitlines()
        self.assertTrue(lines)
        self.assertTrue(
            all(not line or line.startswith("          ") for line in lines)
        )
        return "\n".join(line[10:] if line else "" for line in lines)

    def _trusted_workflow_environment(
        self,
        *,
        receipt_payload: bytes,
        receipt_sha256: str | None = None,
        overrides: dict[str, str] | None = None,
    ) -> dict[str, str]:
        environment = os.environ.copy()
        for name in self._trusted_gate_environment_names:
            environment.pop(name, None)
        environment.update(
            {
                "GITHUB_REPOSITORY": "Joey-Tools/codex-debug-triage",
                "EVENT_REPOSITORY": "Joey-Tools/codex-debug-triage",
                "PR_BASE_REF": "master",
                "PR_BASE_SHA": self._base_sha,
                "PR_HEAD_REPOSITORY": "Joey-Tools/codex-debug-triage",
                "PR_HEAD_SHA": self._canonical_commit,
                "PR_NUMBER": str(self._pull_request_number),
                "SELECTED_TARGET_HEAD_SHA": self._canonical_commit,
                "SELECTED_TARGET_BASE_SHA": self._base_sha,
                "SELECTED_TARGET_PR_NUMBER": str(self._pull_request_number),
                "CISCO_CUTOVER_TARGET_BASE_SHA": self._base_sha,
                "CISCO_CUTOVER_RECEIPT_BASE64": base64.b64encode(
                    receipt_payload
                ).decode("ascii"),
                "CISCO_CUTOVER_EXPECTED_CANONICAL_COMMIT": self._canonical_commit,
                "CISCO_CUTOVER_EXPECTED_PRIVATE_RELEASE_COMMIT": (
                    self._private_release_commit
                ),
                "CISCO_CUTOVER_EXPECTED_RELEASE_MANIFEST_SHA256": (
                    self._release_manifest_sha256
                ),
                "CISCO_CUTOVER_EXPECTED_RECEIPT_SHA256": (
                    receipt_sha256 or hashlib.sha256(receipt_payload).hexdigest()
                ),
                "CISCO_CUTOVER_EXPECTED_WORKFLOW_ID": str(self._workflow_id),
                "CISCO_CUTOVER_EXPECTED_WORKFLOW_SHA": (self._workflow_source_commit),
                "CISCO_CUTOVER_EXPECTED_INSTALLATION_SCOPE_ID": (
                    self._installation_scope_id
                ),
                "CISCO_CUTOVER_EXPECTED_POINTER_GENERATION": str(
                    self._pointer_generation
                ),
                "CISCO_CUTOVER_EXPECTED_POINTER_STATE_SHA256": (
                    self._pointer_state_sha256()
                ),
            }
        )
        if overrides:
            environment.update(overrides)
        return environment

    def _selector_workflow_environment(
        self,
        *,
        output_path: Path,
        current_pr_number: int | None = None,
        current_head_sha: str | None = None,
        current_base_sha: str | None = None,
        target_pr_number: int | None = None,
        target_head_sha: str | None = None,
        target_base_sha: str | None = None,
        overrides: dict[str, str] | None = None,
    ) -> dict[str, str]:
        environment = os.environ.copy()
        for name in self._selector_environment_names:
            environment.pop(name, None)
        environment.update(
            {
                "GITHUB_REPOSITORY": "Joey-Tools/codex-debug-triage",
                "EVENT_REPOSITORY": "Joey-Tools/codex-debug-triage",
                "PR_BASE_REF": "master",
                "PR_BASE_SHA": current_base_sha or self._base_sha,
                "PR_HEAD_REPOSITORY": "Joey-Tools/codex-debug-triage",
                "PR_HEAD_SHA": current_head_sha or self._canonical_commit,
                "PR_NUMBER": str(current_pr_number or self._pull_request_number),
                "CISCO_CUTOVER_TARGET_HEAD_SHA": (
                    target_head_sha or self._canonical_commit
                ),
                "CISCO_CUTOVER_TARGET_BASE_SHA": (target_base_sha or self._base_sha),
                "CISCO_CUTOVER_TARGET_PR_NUMBER": str(
                    target_pr_number or self._pull_request_number
                ),
                "GITHUB_OUTPUT": str(output_path),
            }
        )
        if overrides:
            environment.update(overrides)
        return environment

    def _run_trusted_workflow_program(
        self,
        *,
        environment: dict[str, str],
        cwd: Path,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-c", self._trusted_workflow_program()],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            env=environment,
            cwd=cwd,
        )

    def _run_selector_workflow_program(
        self,
        *,
        environment: dict[str, str],
        cwd: Path,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-c", self._selector_workflow_program()],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            env=environment,
            cwd=cwd,
        )

    def _matching_enforcement_evidence(self) -> dict[str, object]:
        contract = json.loads(
            CUTOVER_ENFORCEMENT_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        organization = contract["source_organization"]
        repository = contract["target_repository"]
        workflow = contract["required_workflow"]
        repository_api = f"https://api.github.com/repos/{repository['full_name']}"
        pull_request = {
            "base": {
                "ref": repository["default_branch"],
                "repository": {
                    "full_name": repository["full_name"],
                    "id": repository["id"],
                },
                "sha": self._base_sha,
            },
            "head": {
                "repository": {
                    "full_name": repository["full_name"],
                    "id": repository["id"],
                },
                "sha": self._canonical_commit,
            },
            "html_url": (f"https://github.com/{repository['full_name']}/pull/7"),
            "id": 7007,
            "merged": False,
            "number": 7,
            "state": "open",
            "url": f"{repository_api}/pulls/7",
        }
        pull_request_link = {
            "base": {
                "ref": repository["default_branch"],
                "repository_id": repository["id"],
                "sha": self._base_sha,
            },
            "head": {
                "repository_id": repository["id"],
                "sha": self._canonical_commit,
            },
            "id": 7007,
            "number": 7,
            "url": f"{repository_api}/pulls/7",
        }
        ruleset = {
            "id": self._ruleset_id,
            "name": "Cisco cutover required workflow",
            "source_type": contract["ruleset"]["source_type"],
            "source": contract["ruleset"]["source"],
            "target": contract["ruleset"]["target"],
            "enforcement": contract["ruleset"]["enforcement"],
            "bypass_actors": contract["ruleset"]["bypass_actors"],
            "conditions": contract["ruleset"]["conditions"],
            "rules": [
                {"type": "deletion"},
                {"type": "non_fast_forward"},
                {
                    "type": "workflows",
                    "parameters": {
                        "do_not_enforce_on_create": workflow[
                            "do_not_enforce_on_create"
                        ],
                        "workflows": [
                            {
                                "repository_id": workflow["repository_id"],
                                "path": workflow["path"],
                                "ref": workflow["ref"],
                                "sha": self._workflow_source_commit,
                            }
                        ],
                    },
                },
            ],
        }
        base_sha = pull_request["base"]["sha"]
        run_url = f"{repository_api}/actions/runs/10101"
        check_url = f"{repository_api}/check-runs/20202"
        run_node_id = "WFR_kwDOFixture10101"
        workflow_file_node_id = "WFRF_kwDOFixture10101"
        run_started_at = "2026-07-24T12:05:00Z"
        completed_at = "2026-07-24T12:06:00Z"
        run = {
            "check_suite_id": 30303,
            "check_suite_url": f"{repository_api}/check-suites/30303",
            "conclusion": "success",
            "event": workflow["event"],
            "head_repository": {
                "full_name": repository["full_name"],
                "id": repository["id"],
            },
            "head_sha": base_sha,
            "html_url": (
                f"https://github.com/{repository['full_name']}/actions/runs/10101"
            ),
            "id": 10101,
            "node_id": run_node_id,
            "jobs_url": f"{run_url}/jobs",
            "path": f"{workflow['path']}@master",
            "pull_requests": [self._copy_json(pull_request_link)],
            "repository": {
                "full_name": repository["full_name"],
                "id": repository["id"],
            },
            "run_attempt": 1,
            "run_started_at": run_started_at,
            "status": "completed",
            "url": run_url,
            "workflow_id": self._workflow_id,
            "workflow_url": (
                "https://api.github.com/repos/"
                f"{workflow['repository_full_name']}/actions/workflows/"
                f"{self._workflow_id}"
            ),
        }
        job = {
            "check_run_url": check_url,
            "conclusion": "success",
            "head_sha": base_sha,
            "html_url": (
                f"https://github.com/{repository['full_name']}"
                "/actions/runs/10101/job/20202"
            ),
            "id": 20202,
            "name": workflow["check_name"],
            "run_attempt": 1,
            "run_id": 10101,
            "run_url": run_url,
            "started_at": run_started_at,
            "completed_at": completed_at,
            "status": "completed",
            "url": f"{repository_api}/actions/jobs/20202",
            "workflow_name": "Cisco cutover admission",
        }
        check_run = {
            "app": workflow["provider"],
            "check_suite_id": 30303,
            "conclusion": "success",
            "details_url": job["html_url"],
            "head_sha": base_sha,
            "html_url": job["html_url"],
            "id": 20202,
            "name": workflow["check_name"],
            "pull_requests": [self._copy_json(pull_request_link)],
            "started_at": run_started_at,
            "completed_at": completed_at,
            "status": "completed",
            "url": check_url,
        }
        cutover_values = {
            "CISCO_CUTOVER_TARGET_PR_NUMBER": str(self._pull_request_number),
            "CISCO_CUTOVER_TARGET_HEAD_SHA": self._canonical_commit,
            "CISCO_CUTOVER_TARGET_BASE_SHA": self._base_sha,
            "CISCO_CUTOVER_RECEIPT_BASE64": "Zml4dHVyZS1yZWNlaXB0",
            "CISCO_CUTOVER_EXPECTED_CANONICAL_COMMIT": self._canonical_commit,
            "CISCO_CUTOVER_EXPECTED_PRIVATE_RELEASE_COMMIT": (
                self._private_release_commit
            ),
            "CISCO_CUTOVER_EXPECTED_RELEASE_MANIFEST_SHA256": (
                self._release_manifest_sha256
            ),
            "CISCO_CUTOVER_EXPECTED_RECEIPT_SHA256": "7" * 64,
            "CISCO_CUTOVER_EXPECTED_WORKFLOW_ID": str(self._workflow_id),
            "CISCO_CUTOVER_EXPECTED_WORKFLOW_SHA": self._workflow_source_commit,
            "CISCO_CUTOVER_EXPECTED_INSTALLATION_SCOPE_ID": (
                self._installation_scope_id
            ),
            "CISCO_CUTOVER_EXPECTED_POINTER_GENERATION": str(self._pointer_generation),
            "CISCO_CUTOVER_EXPECTED_POINTER_STATE_SHA256": (
                self._pointer_state_sha256()
            ),
        }
        cutover_variables = [
            {
                "name": name,
                "updated_at": "2026-07-24T12:00:00Z",
                "value": cutover_values[name],
            }
            for name in contract["cutover_input_variables"]
        ]
        return {
            "organization": organization,
            "repository": {
                "archived": False,
                "default_branch": repository["default_branch"],
                "disabled": False,
                "full_name": repository["full_name"],
                "id": repository["id"],
                "owner": {
                    "id": organization["id"],
                    "login": organization["login"],
                    "type": "Organization",
                },
            },
            "pull_request": pull_request,
            "cutover_input_variables": cutover_variables,
            "effective_rulesets": [self._copy_json(ruleset)],
            "selected_ruleset": ruleset,
            "workflow_source_repository": {
                "archived": False,
                "default_branch": "master",
                "disabled": False,
                "full_name": workflow["repository_full_name"],
                "id": workflow["repository_id"],
                "owner": {
                    "id": organization["id"],
                    "login": organization["login"],
                    "type": "Organization",
                },
            },
            "workflow": {
                "html_url": (
                    "https://github.com/"
                    f"{workflow['repository_full_name']}/actions/workflows/"
                    f"{workflow['path'].rsplit('/', 1)[-1]}"
                ),
                "id": self._workflow_id,
                "path": workflow["path"],
                "state": workflow["state"],
                "url": (
                    "https://api.github.com/repos/"
                    f"{workflow['repository_full_name']}/actions/workflows/"
                    f"{self._workflow_id}"
                ),
            },
            "workflow_source_commit": {
                "html_url": (
                    "https://github.com/"
                    f"{workflow['repository_full_name']}/commit/"
                    f"{self._workflow_source_commit}"
                ),
                "sha": self._workflow_source_commit,
                "url": (
                    "https://api.github.com/repos/"
                    f"{workflow['repository_full_name']}/commits/"
                    f"{self._workflow_source_commit}"
                ),
            },
            "workflow_run_definition": {
                "file": {
                    "id": workflow_file_node_id,
                    "path": workflow["path"],
                    "repository_file_url": (
                        "https://github.com/"
                        f"{workflow['repository_full_name']}/blob/"
                        f"{self._workflow_source_commit}/{workflow['path']}"
                    ),
                    "repository_name": workflow["repository_full_name"],
                },
                "run": {
                    "database_id": 10101,
                    "event": workflow["event"],
                    "id": run_node_id,
                    "run_attempt": 1,
                },
            },
            "workflow_runs": [run],
            "selected_run_attempt": {
                "id": 10101,
                "run_attempt": 1,
                "run_started_at": run_started_at,
            },
            "jobs": [job],
            "check_runs": [check_run],
        }

    @staticmethod
    def _api_pr_link(link: dict[str, object]) -> dict[str, object]:
        return {
            "base": {
                "ref": link["base"]["ref"],
                "repo": {
                    "id": link["base"]["repository_id"],
                },
                "sha": link["base"]["sha"],
            },
            "head": {
                "repo": {
                    "id": link["head"]["repository_id"],
                },
                "sha": link["head"]["sha"],
            },
            "id": link["id"],
            "number": link["number"],
            "url": link["url"],
        }

    def _matching_live_api_client(self) -> object:
        evidence = self._matching_enforcement_evidence()
        contract = json.loads(
            CUTOVER_ENFORCEMENT_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        repository = contract["target_repository"]
        workflow = contract["required_workflow"]
        target_name = repository["full_name"]
        workflow_name = workflow["repository_full_name"]
        pull_request = self._copy_json(evidence["pull_request"])
        pull_request["base"]["repo"] = pull_request["base"].pop("repository")
        pull_request["head"]["repo"] = pull_request["head"].pop("repository")
        run = self._copy_json(evidence["workflow_runs"][0])
        run["pull_requests"] = [
            self._api_pr_link(link) for link in run["pull_requests"]
        ]
        job = self._copy_json(evidence["jobs"][0])
        del job["run_attempt"]
        check_run = self._copy_json(evidence["check_runs"][0])
        check_run["check_suite"] = {
            "id": check_run.pop("check_suite_id"),
        }
        check_run["pull_requests"] = [
            self._api_pr_link(link) for link in check_run["pull_requests"]
        ]
        check_suite = {
            "head_sha": check_run["head_sha"],
            "id": check_run["check_suite"]["id"],
        }
        cutover_variables = self._copy_json(
            {"values": evidence["cutover_input_variables"]}
        )["values"]
        selected_run_attempt = self._copy_json(evidence["selected_run_attempt"])
        normalized_definition = evidence["workflow_run_definition"]
        workflow_run_definition = {
            "data": {
                "node": {
                    "__typename": "WorkflowRun",
                    "databaseId": normalized_definition["run"]["database_id"],
                    "event": normalized_definition["run"]["event"],
                    "file": {
                        "id": normalized_definition["file"]["id"],
                        "path": normalized_definition["file"]["path"],
                        "repositoryFileUrl": normalized_definition["file"][
                            "repository_file_url"
                        ],
                        "repositoryName": normalized_definition["file"][
                            "repository_name"
                        ],
                    },
                    "id": normalized_definition["run"]["id"],
                    "runAttempt": normalized_definition["run"]["run_attempt"],
                }
            }
        }
        ruleset_summaries = [
            {
                field: ruleset[field]
                for field in (
                    "enforcement",
                    "id",
                    "name",
                    "source",
                    "source_type",
                    "target",
                )
            }
            for ruleset in evidence["effective_rulesets"]
        ]

        class FixtureApiClient:
            def __init__(
                self,
                *,
                objects: dict[str, object],
                collections: dict[str, dict[str, object]],
                workflow_run_definition: dict[str, object],
            ) -> None:
                self.objects = objects
                self.collections = collections
                self.workflow_run_definition = workflow_run_definition
                self.auth_calls = 0
                self.calls: list[tuple[str, dict[str, object]]] = []
                self.executable_sha256 = "a" * 64
                self.execution_source = "owner-private-snapshot"
                self.environment_profile = "minimal-snapshotted-config-v2"

            def auth_preflight(self) -> dict[str, object]:
                self.auth_calls += 1
                return {
                    "id": 4242,
                    "login": "fixture-admin",
                }

            def __enter__(self) -> object:
                return self

            def __exit__(
                self,
                exception_type: object,
                exception: object,
                traceback: object,
            ) -> bool:
                return False

            def revalidate_for_admission(self) -> None:
                return None

            def get_json(
                self,
                endpoint: str,
                parameters: dict[str, object] | None = None,
            ) -> object:
                query = dict(parameters or {})
                self.calls.append((endpoint, query))
                if endpoint in self.objects:
                    return json.loads(json.dumps(self.objects[endpoint]))
                collection = self.collections[endpoint]
                page = int(query["page"])
                pages = collection["pages"]
                page_items = pages[page - 1] if page <= len(pages) else []
                item_key = collection["item_key"]
                copied_items = json.loads(json.dumps(page_items))
                if item_key is None:
                    return copied_items
                total_count = sum(len(items) for items in pages)
                return {
                    "total_count": total_count,
                    item_key: copied_items,
                }

            def get_workflow_run_definition(self, node_id: str) -> object:
                self.calls.append(("/graphql", {"id": node_id}))
                return json.loads(json.dumps(self.workflow_run_definition))

        objects = {
            f"/orgs/{contract['source_organization']['login']}": evidence[
                "organization"
            ],
            f"/repos/{target_name}": evidence["repository"],
            f"/repos/{target_name}/pulls/7": pull_request,
            (
                f"/repos/{target_name}/actions/runs/10101/attempts/1"
            ): selected_run_attempt,
            (
                f"/orgs/{contract['source_organization']['login']}/rulesets/"
                f"{self._ruleset_id}"
            ): evidence["selected_ruleset"],
            f"/repos/{workflow_name}": evidence["workflow_source_repository"],
            (f"/repos/{workflow_name}/actions/workflows/{self._workflow_id}"): evidence[
                "workflow"
            ],
            (
                f"/repos/{workflow_name}/commits/{self._workflow_source_commit}"
            ): evidence["workflow_source_commit"],
        }
        collections = {
            f"/repos/{target_name}/actions/variables": {
                "item_key": "variables",
                "pages": [cutover_variables],
            },
            f"/repos/{target_name}/rulesets": {
                "item_key": None,
                "pages": [ruleset_summaries],
            },
            f"/repos/{target_name}/actions/runs": {
                "item_key": "workflow_runs",
                "pages": [[run]],
            },
            f"/repos/{target_name}/commits/{pull_request['base']['sha']}/check-suites": {
                "item_key": "check_suites",
                "pages": [[check_suite]],
            },
            f"/repos/{target_name}/commits/{self._canonical_commit}/check-suites": {
                "item_key": "check_suites",
                "pages": [[]],
            },
            f"/repos/{target_name}/check-suites/{check_suite['id']}/check-runs": {
                "item_key": "check_runs",
                "pages": [[check_run]],
            },
            (f"/repos/{target_name}/actions/runs/10101/attempts/1/jobs"): {
                "item_key": "jobs",
                "pages": [[job]],
            },
        }
        return FixtureApiClient(
            objects=objects,
            collections=collections,
            workflow_run_definition=workflow_run_definition,
        )

    def _collect_live_snapshot(self, client: object) -> dict[str, object]:
        contract = json.loads(
            CUTOVER_ENFORCEMENT_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        return ENFORCEMENT_MODULE._collect_snapshot(
            client,
            {"object_reads": [], "page_bounds": []},
            contract,
            phase="test",
            expected_run_attempt=1,
            expected_run_id=10101,
            expected_ruleset_id=self._ruleset_id,
            expected_workflow_id=self._workflow_id,
            expected_workflow_sha=self._workflow_source_commit,
            expected_base_sha=self._base_sha,
            candidate_head_sha=self._canonical_commit,
            pull_request_number=7,
        )

    def _run_enforcement_doctor(
        self,
        evidence: dict[str, object],
        *,
        expected_run_attempt: int = 1,
        expected_run_id: int = 10101,
        expected_ruleset_id: int | None = None,
        expected_workflow_id: int | None = None,
        expected_workflow_sha: str | None = None,
        expected_base_sha: str | None = None,
        candidate_head_sha: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        contract_payload = CUTOVER_ENFORCEMENT_CONTRACT_PATH.read_bytes()
        contract = json.loads(contract_payload)
        ruleset_id = expected_ruleset_id or self._ruleset_id
        workflow_id = expected_workflow_id or self._workflow_id
        workflow_sha = expected_workflow_sha or self._workflow_source_commit
        base_sha = expected_base_sha or self._base_sha
        head_sha = candidate_head_sha or self._canonical_commit
        try:
            admission = ENFORCEMENT_MODULE.validate_enforcement(
                contract,
                evidence,
                expected_run_attempt=expected_run_attempt,
                expected_run_id=expected_run_id,
                expected_ruleset_id=ruleset_id,
                expected_workflow_id=workflow_id,
                expected_workflow_sha=workflow_sha,
                expected_base_sha=base_sha,
                candidate_head_sha=head_sha,
                pull_request_number=7,
            )
        except ENFORCEMENT_MODULE.EnforcementDoctorError as error:
            outcome = {
                "classification": "blocked_until_trusted",
                "reason": str(error),
                "reason_code": error.reason_code,
            }
            if error.blockers is not None:
                outcome["blockers"] = error.blockers
            return subprocess.CompletedProcess(
                args=[],
                returncode=1,
                stdout=json.dumps(outcome),
                stderr="",
            )
        outcome = {
            "candidate_head_sha": head_sha,
            "classification": "admitted",
            "contract_sha256": hashlib.sha256(contract_payload).hexdigest(),
            "evidence_sha256": hashlib.sha256(
                json.dumps(
                    evidence,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest(),
            "ruleset_id": ruleset_id,
            "trusted_check_run_id": admission["trusted_check_run"]["id"],
            "trusted_workflow": {
                "id": workflow_id,
                "path": contract["required_workflow"]["path"],
                "ref": contract["required_workflow"]["ref"],
                "repository_id": contract["required_workflow"]["repository_id"],
                "sha": workflow_sha,
            },
            "trusted_workflow_run_id": admission["trusted_run"]["id"],
        }
        return subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(outcome),
            stderr="",
        )

    def _validate_static_enforcement(
        self,
        evidence: dict[str, object],
        *,
        contract: dict[str, object] | None = None,
        expected_run_attempt: int = 1,
        expected_run_id: int = 10101,
        expected_ruleset_id: int | None = None,
        expected_workflow_id: int | None = None,
        expected_workflow_sha: str | None = None,
        expected_base_sha: str | None = None,
        candidate_head_sha: str | None = None,
    ) -> dict[str, object]:
        selected_contract = contract or json.loads(
            CUTOVER_ENFORCEMENT_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        return ENFORCEMENT_MODULE._validate_snapshot_enforcement(
            selected_contract,
            evidence,
            expected_run_attempt=expected_run_attempt,
            expected_run_id=expected_run_id,
            expected_ruleset_id=expected_ruleset_id or self._ruleset_id,
            expected_workflow_id=expected_workflow_id or self._workflow_id,
            expected_workflow_sha=(
                expected_workflow_sha or self._workflow_source_commit
            ),
            expected_base_sha=expected_base_sha or self._base_sha,
            candidate_head_sha=candidate_head_sha or self._canonical_commit,
            pull_request_number=7,
        )

    @staticmethod
    def _copy_json(value: dict[str, object]) -> dict[str, object]:
        return json.loads(json.dumps(value))

    @staticmethod
    def _make_private_gh_config(
        temp_root: Path,
        *,
        config_payload: str | None = None,
        hosts_payload: str | None = None,
    ) -> tuple[Path, Path]:
        resolved_root = temp_root.resolve()
        config_dir = resolved_root / "gh-config"
        config_dir.mkdir(mode=0o700)
        config_dir.chmod(0o700)
        hosts_path = config_dir / "hosts.yml"
        hosts_path.write_text(
            hosts_payload
            or (
                "github.com:\n"
                "    git_protocol: https\n"
                "    users:\n"
                "        fixture-admin:\n"
                f"            oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                "    user: fixture-admin\n"
                f"    oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
            ),
            encoding="utf-8",
        )
        hosts_path.chmod(0o600)
        config_path = config_dir / "config.yml"
        config_path.write_text(
            config_payload
            or (
                "version: 1\ngit_protocol: https\nprompt: disabled\nhttp_unix_socket:\n"
            ),
            encoding="utf-8",
        )
        config_path.chmod(0o600)
        return config_dir, resolved_root / "fixed-gh-runtime"

    @staticmethod
    def _prime_github_api_transport(client: object) -> None:
        client._install_authentication_header(
            f"{SYNTHETIC_ACCESS_TOKEN}\n".encode("ascii")
        )

    @staticmethod
    def _curl_response(
        body: bytes,
        status: int = 200,
        *,
        rate_remaining: str = "",
    ) -> bytes:
        trailer = (f"\nCISCO_STATUS={status}\nCISCO_RATE={rate_remaining}\n").encode(
            "ascii"
        )
        return body + trailer

    @staticmethod
    def _set_darwin_acl(path: Path, entry: str) -> None:
        _set_fixture_darwin_acl(path, entry)

    @staticmethod
    def _clear_darwin_acl(path: Path) -> None:
        _clear_fixture_darwin_acl(path)

    @staticmethod
    def _cutover_variable(
        evidence: dict[str, object],
        name: str,
    ) -> dict[str, object]:
        matches = [
            value
            for value in evidence["cutover_input_variables"]
            if value["name"] == name
        ]
        if len(matches) != 1:
            raise AssertionError(f"expected one cutover variable: {name}")
        return matches[0]

    def test_bootstrap_retains_legacy_jenkins_entrypoint(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn("jenkins_artifact_probe.py", skill)
        self.assertIn("scripts/archive_triage.py", skill)
        self.assertIn("references/local-artifact-recipes.md", skill)
        self.assertTrue(
            (SKILL_ROOT / "references/jenkins-artifact-recipes.md").is_file()
        )
        self.assertTrue((SKILL_ROOT / "scripts/jenkins_artifact_probe.py").is_file())
        self.assertTrue((REPO_ROOT / "tests/test_jenkins_artifact_probe.py").is_file())
        self.assertIn("retains the existing Jenkins", readme)

    def test_local_archive_helper_has_no_remote_auth_contract(self) -> None:
        local_files = [
            SKILL_ROOT / "references/local-artifact-recipes.md",
            SKILL_ROOT / "scripts/archive_triage.py",
        ]
        local_text = "\n".join(path.read_text(encoding="utf-8") for path in local_files)

        self.assertNotIn("JENKINS_ARTIFACT_USER", local_text)
        self.assertNotIn("JENKINS_ARTIFACT_TOKEN", local_text)
        self.assertNotIn("--auth-profile", local_text)
        self.assertNotIn("probe-url", local_text)
        self.assertNotIn("fetch-url", local_text)
        self.assertNotIn("urllib.request", local_text)

    def test_cutover_receipt_validator_has_no_network_or_credentials(
        self,
    ) -> None:
        source = CUTOVER_VALIDATOR_PATH.read_text(encoding="utf-8")

        for forbidden in (
            "urllib",
            "import requests",
            "from requests",
            "http.client",
            "socket",
            "JENKINS_ARTIFACT_USER",
            "JENKINS_ARTIFACT_TOKEN",
            "--auth-profile",
            "fetch-url",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_local_recipe_budgets_artifact_reads(self) -> None:
        recipe = (SKILL_ROOT / "references/local-artifact-recipes.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("Start with bounded metadata and candidate names", recipe)
        self.assertIn(
            'find "$artifact_dir" -type f -print | head -n 80',
            recipe,
        )
        self.assertNotIn(
            'find "$artifact_dir" -type f -print | sed -n',
            recipe,
        )
        self.assertIn(
            "sed -n '420,470p;471q' \"$artifact_dir/run.log\"",
            recipe,
        )
        self.assertNotIn(
            "sed -n '420,470p' \"$artifact_dir/run.log\"",
            recipe,
        )
        self.assertIn("Use filenames and counts first", recipe)
        self.assertIn("scripts/archive_triage.py", recipe)
        self.assertIn("does not fetch URLs", recipe)
        self.assertIn("or handle credentials", recipe)
        self.assertIn("reject archive files above 256 MiB", recipe)
        self.assertIn("and 100,000 lines", recipe)
        self.assertIn("immutable hard ceilings", recipe)
        self.assertIn("30-second in-process `ITIMER_REAL` budget", recipe)
        self.assertIn("best-effort interruption mechanism", recipe)
        self.assertIn("cannot guarantee interruption of NFS, FUSE", recipe)
        self.assertIn("external wall-clock supervisor", recipe)
        self.assertIn("inherits the helper's process group", recipe)
        self.assertIn("must never call `setsid`", recipe)
        self.assertIn("apply TERM/KILL to that", recipe)
        self.assertIn("masks `SIGALRM` across TERM/KILL/reap", recipe)
        self.assertIn("retryable cleanup-state handshake", recipe)
        self.assertIn("exactly one blocking mask call", recipe)
        self.assertIn("timer\nremains armed", recipe)
        self.assertIn("cleanup retains the authoritative", recipe)
        self.assertIn(
            "process handle plus the observed PID/process-group",
            recipe,
        )
        self.assertIn("validation drain", recipe)
        self.assertIn("temporarily enables `O_NONBLOCK`", recipe)
        self.assertIn("FIFO, socket, or terminal descriptor", recipe)
        self.assertIn("monotonic 100-millisecond poll budget", recipe)
        self.assertIn("descriptor blocking state", recipe)
        self.assertIn("owner-private, descriptor-only temporary snapshot", recipe)
        self.assertIn("does not consult ambient `TMPDIR`", recipe)
        self.assertIn("unique `0700` root plus a `0600` regular file", recipe)
        self.assertIn("before writing the first archive byte", recipe)
        self.assertIn("rejects every extended allow", recipe)
        self.assertIn("leaving a zero-link descriptor", recipe)
        self.assertIn("complete SHA-256 content", recipe)
        self.assertIn("same-inode/same-size rewrites", recipe)
        self.assertIn("Before constructing Python `ZipInfo` objects", recipe)
        self.assertIn("binds each central record to\none matching local record", recipe)
        self.assertIn("without gaps or unreferenced\nrecords", recipe)
        self.assertIn("local and central ZIP64\nextra/version/size", recipe)
        self.assertIn("accepts only stored and DEFLATE members", recipe)
        self.assertIn("The four DEFLATE option", recipe)
        self.assertIn("`0x0000`, `0x0002`, `0x0004`, and `0x0006`", recipe)
        self.assertIn("stored\nmembers still reject", recipe)
        self.assertIn("rejects those\nmethods before opening a decompressor", recipe)
        self.assertIn("absence of trailing compressed data", recipe)

    def test_documented_member_regex_matches_literal_log_suffix(self) -> None:
        recipe = (SKILL_ROOT / "references/local-artifact-recipes.md").read_text(
            encoding="utf-8"
        )
        pattern_line = next(
            line for line in recipe.splitlines() if line.strip().startswith("'error.*")
        )
        documented_pattern = shlex.split(pattern_line.removesuffix(" \\"))[0]
        self.assertEqual(documented_pattern, r"error.*\.log")

        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = Path(temp_dir) / "recipe-regex.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("logs/error-build.log", "target\n")
                archive.writestr("logs/error-buildXlog", "nonmatch\n")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT_PATH),
                    "zip-show",
                    str(archive_path),
                    documented_pattern,
                    "--regex",
                    "--head",
                    "1",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"name":"logs/error-build.log"', result.stdout)
        self.assertNotIn("error-buildXlog", result.stdout)
        self.assertIn("target", result.stdout)
        self.assertNotIn("nonmatch", result.stdout)

    def test_private_migration_contract_is_explicit(self) -> None:
        migration = (REPO_ROOT / "docs/cisco-build-artifacts-migration.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("probe-url <url>", migration)
        self.assertIn("show-url <url>", migration)
        self.assertIn("fetch-url <url>", migration)
        self.assertIn("exact HTTPS host allowlists", migration)
        self.assertIn("every redirect target", migration)
        self.assertIn("Strip\n  `Authorization`", migration)
        self.assertIn("Stream response bodies in fixed-size chunks", migration)
        self.assertIn("`HARD_MAX_*` constants", migration)
        self.assertIn("no-replace atomic primitive", migration)
        self.assertIn("Hold the parent\n   `dirfd`", migration)
        self.assertIn("initial exact origin before reading", migration)
        self.assertIn("re-walk from the\n   held trusted-root", migration)
        self.assertIn("published / durability-unverified", migration)
        self.assertIn("source history only", migration)
        self.assertIn("One candidate immutable private-overlay release", migration)
        self.assertIn("same release", migration)
        self.assertIn("Keep both the canonical bug-triage retirement PR", migration)
        self.assertIn("retain a compatible\n`bug-triage-playbook` route", migration)
        self.assertIn("Do not copy private fixtures", migration)
        self.assertIn("stores no fabricated completion\nreceipt", migration)
        self.assertIn("classification=blocked_until_trusted", migration)
        self.assertIn("exact SHA-256 of the receipt bytes", migration)
        self.assertIn(
            "immediately rejects anything other than a regular file", migration
        )
        self.assertIn("limits integers to 64 digits", migration)
        self.assertIn("require exact JSON scalar and container types", migration)
        self.assertIn(
            "independent trusted source, not copied from the receipt",
            migration,
        )
        self.assertIn(
            "Protected-Base Admission And Exact Unblocking Inputs",
            migration,
        )
        self.assertIn("performs no checkout", migration)
        self.assertIn("executes no candidate script", migration)
        self.assertIn(
            "cannot protect the pull request that first introduces it",
            migration,
        )
        self.assertIn("minimum\nordinary PR-merge state machine", migration)
        self.assertIn("restores the Jenkins entrypoint", migration)
        self.assertIn("is not an enforcement identity", migration)
        self.assertIn(
            "`source_type=Organization` and `type=workflows`",
            migration,
        )
        self.assertIn("A branch ref without the exact `sha` is mutable", migration)
        self.assertIn("candidate-authored duplicate cannot compensate", migration)
        self.assertIn("accepts no `--evidence`", migration)
        self.assertIn("explicit empty terminal page", migration)
        self.assertIn("The live preflight is read-only", migration)
        self.assertIn("source workflow repository", migration)
        self.assertIn("timestamps alone", migration)
        self.assertIn("active credential lacks `admin:org`", migration)
        self.assertIn("no OAuth scope or\nlive ruleset was changed", migration)
        self.assertIn("cannot install a base-owned workflow", migration)
        self.assertIn("doctor_cisco_cutover_enforcement.py", migration)
        self.assertIn("cisco-cutover-selector", migration)
        self.assertIn("classification=not_applicable", migration)
        self.assertIn("Post-Cutover Decommission Transaction", migration)
        self.assertIn("create-if-absent repository-variable lease", migration)
        self.assertIn("does not document conditional `If-Match`", migration)
        self.assertIn("--expected-run-id", migration)
        self.assertIn("--expected-run-attempt", migration)
        self.assertIn("--expected-base-sha", migration)
        self.assertIn("CISCO_CUTOVER_TARGET_BASE_SHA", migration)
        self.assertIn("base-only retarget", migration)
        self.assertIn(
            "schema-6 doctor output reserves exact admitted fields", migration
        )
        self.assertIn(
            "ruleset-workflow-default-activities-exclude-edited",
            migration,
        )
        self.assertIn("--gh-executable", migration)
        self.assertIn("--expected-gh-sha256", migration)
        self.assertIn("--gh-config-dir", migration)
        self.assertIn("private `bin` directory", migration)
        self.assertIn("ignores ambient `HOME` and `TMPDIR`", migration)
        self.assertIn("non-ABA execution binding", migration)
        self.assertIn(
            "source `hosts.yml` parser admits only the simple `github.com`",
            migration,
        )
        self.assertIn("transport overrides are rejected", migration)
        self.assertIn("returns `collector-inconclusive`", migration)
        self.assertIn("A later attempt supersedes an older", migration)
        self.assertIn("blocked-permission", migration)
        self.assertIn("http_status=403", migration)

    def test_documented_retirement_state_machine_has_satisfiable_order(
        self,
    ) -> None:
        migration = (REPO_ROOT / "docs/cisco-build-artifacts-migration.md").read_text(
            encoding="utf-8"
        )
        checkpoints = (
            "Separately review and merge a compatibility/bootstrap PR",
            "create the separate\n   retirement PR",
            "producer-authored schema-3 receipt",
            "configures all three selector variables",
            "creates or updates the active,\n   bypass-free organization",
            "Configure and independently validate the live pointer authority",
            "trigger a new target evaluation",
            "Run the live read-only doctor against that exact retirement PR/head",
            "Immediately before merge, revalidate",
            "may an authorized maintainer merge the retirement PR",
        )
        positions = [migration.index(checkpoint) for checkpoint in checkpoints]

        self.assertEqual(positions, sorted(positions))
        self.assertIn(
            "No merge, rerun, variable write, ruleset\n"
            "   write, or release publication is an automatic action",
            migration,
        )

    def test_trusted_cutover_workflow_has_no_candidate_execution_path(
        self,
    ) -> None:
        workflow = CUTOVER_TRUSTED_WORKFLOW_PATH.read_text(encoding="utf-8")
        regular_ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(
            encoding="utf-8"
        )
        program = self._trusted_workflow_program()
        compile(program, str(CUTOVER_TRUSTED_WORKFLOW_PATH), "exec")

        self.assertIn("pull_request_target:", workflow)
        self.assertIn("branches:\n      - master", workflow)
        event_source = workflow.split("pull_request_target:\n", 1)[1].split(
            "\npermissions:",
            1,
        )[0]
        self.assertIn("      - edited\n", event_source)
        self.assertIn("name: cisco-cutover-admission", workflow)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn(
            "EVENT_REPOSITORY: ${{ github.event.repository.full_name }}",
            workflow,
        )
        self.assertIn(
            "PR_HEAD_SHA: ${{ github.event.pull_request.head.sha }}",
            workflow,
        )
        self.assertIn("name: cisco-cutover-selector", workflow)
        self.assertIn("name: cisco-cutover-neutral", workflow)
        self.assertIn(
            "if: needs.cisco-cutover-selector.outputs.applicable == 'true'",
            workflow,
        )
        self.assertIn(
            "if: needs.cisco-cutover-selector.outputs.applicable == 'false'",
            workflow,
        )
        self.assertIn('"target_evidence_consumed":false', workflow)
        neutral_job = workflow.split("\n  cisco-cutover-neutral:\n", 1)[1]
        self.assertNotIn("env:", neutral_job)
        self.assertNotIn("${{ vars.", neutral_job)
        self.assertNotIn("CISCO_CUTOVER_RECEIPT", neutral_job)
        for forbidden in (
            "actions/checkout",
            "uses:",
            "download-artifact",
            "run_cisco_cutover_ci_gate.py",
            "validate_cisco_cutover_receipt.py",
            "secrets.",
            "github.event.pull_request.body",
            "github.event.pull_request.title",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, workflow)
        for name in self._trusted_gate_environment_names:
            with self.subTest(environment=name):
                if name.startswith("CISCO_CUTOVER_"):
                    self.assertIn(f"{name}: ${{{{ vars.{name} }}}}", workflow)
                self.assertIn(name, program)
        self.assertNotIn("CISCO_CUTOVER_", regular_ci)
        self.assertIn("tests.test_jenkins_artifact_probe", regular_ci)
        self.assertIn("doctor_cisco_cutover_enforcement.py", regular_ci)

    def test_ci_exercises_linux_transport_and_real_darwin_acl_integration(
        self,
    ) -> None:
        workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn('          - "3.9"', workflow)
        self.assertIn('          - "3.x"', workflow)
        self.assertIn("runs-on: ubuntu-latest", workflow)
        self.assertIn(
            "test_enforcement_gh_linux_host_fixed_curl_policy_is_enforced",
            workflow,
        )
        self.assertIn("darwin-acl-integration:", workflow)
        self.assertIn("runs-on: macos-latest", workflow)
        self.assertNotIn("continue-on-error:", workflow)
        for test_name in (
            "test_snapshot_rejects_inherited_allow_acl_before_copy",
            "test_source_darwin_acl_drift_after_copy_is_rejected",
            "test_source_darwin_stable_extended_allow_acl_is_bound_not_rejected",
            "test_enforcement_darwin_acl_ctypes_abi_constants_and_iteration",
            "test_enforcement_gh_acl_allows_only_noninherited_deny_entries",
            "test_enforcement_gh_acl_rejects_inherited_source_token_read_grant",
            "test_enforcement_gh_acl_drift_discards_command_output",
            "test_enforcement_gh_acl_restrictive_deny_churn_is_benign",
            "test_enforcement_gh_acl_drift_is_revalidated_after_spawn_failure",
        ):
            with self.subTest(test=test_name):
                self.assertIn(test_name, workflow)

    def test_private_child_creation_removes_directory_after_fchmod_failure(
        self,
    ) -> None:
        with owner_controlled_temp_root() as parent_path:
            parent = ENFORCEMENT_MODULE._BoundDirectory(
                parent_path,
                label="test runtime parent",
            )
            try:
                with mock.patch.object(
                    ENFORCEMENT_MODULE.os,
                    "fchmod",
                    side_effect=PermissionError("injected fchmod failure"),
                ):
                    with self.assertRaises(
                        ENFORCEMENT_MODULE.EnforcementDoctorError
                    ) as raised:
                        ENFORCEMENT_MODULE._create_private_child_directory(
                            parent,
                            "candidate",
                            label="test run directory",
                        )
                self.assertEqual(
                    raised.exception.reason_code,
                    "collector-unavailable",
                )
                self.assertFalse((parent_path / "candidate").exists())
                parent.revalidate()
            finally:
                parent.close()

    def test_private_child_creation_does_not_remove_replacement(self) -> None:
        with owner_controlled_temp_root() as parent_path:
            parent = ENFORCEMENT_MODULE._BoundDirectory(
                parent_path,
                label="test runtime parent",
            )
            original_fchmod = ENFORCEMENT_MODULE.os.fchmod

            def replace_before_failure(fd: int, mode: int) -> None:
                original_fchmod(fd, mode)
                os.rename(
                    parent_path / "candidate",
                    parent_path / "retained-original",
                )
                (parent_path / "candidate").mkdir(mode=0o700)
                raise PermissionError("injected post-replacement failure")

            try:
                with mock.patch.object(
                    ENFORCEMENT_MODULE.os,
                    "fchmod",
                    side_effect=replace_before_failure,
                ):
                    with self.assertRaises(
                        ENFORCEMENT_MODULE.EnforcementDoctorError
                    ) as raised:
                        ENFORCEMENT_MODULE._create_private_child_directory(
                            parent,
                            "candidate",
                            label="test run directory",
                        )
                self.assertEqual(
                    raised.exception.reason_code,
                    "collector-inconclusive",
                )
                cleanup = raised.exception.cleanup_failure
                self.assertEqual(cleanup["cleanup_proof"], "inconclusive")
                self.assertEqual(
                    cleanup["failed_operations"],
                    ["remove-created-directory"],
                )
                self.assertEqual(len(cleanup["retained_objects"]), 1)
                locator = cleanup["retained_objects"][0]
                retained_original = (parent_path / "retained-original").stat()
                self.assertEqual(locator["device"], retained_original.st_dev)
                self.assertEqual(locator["inode"], retained_original.st_ino)
                self.assertEqual(locator["path_binding"], "unverified")
                self.assertEqual(
                    locator["last_known_path"],
                    str(parent_path / "candidate"),
                )
                self.assertTrue((parent_path / "candidate").is_dir())
                self.assertTrue((parent_path / "retained-original").is_dir())
            finally:
                parent.close()

    def test_private_child_creation_rejects_replacement_during_rebind(
        self,
    ) -> None:
        with owner_controlled_temp_root() as parent_path:
            parent = ENFORCEMENT_MODULE._BoundDirectory(
                parent_path,
                label="test runtime parent",
            )
            original_bound_directory = ENFORCEMENT_MODULE._BoundDirectory

            def replace_before_rebind(
                path: Path,
                **kwargs: Any,
            ) -> object:
                os.rename(
                    parent_path / "candidate",
                    parent_path / "retained-original",
                )
                (parent_path / "candidate").mkdir(mode=0o700)
                return original_bound_directory(path, **kwargs)

            try:
                with mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "_BoundDirectory",
                    side_effect=replace_before_rebind,
                ):
                    with self.assertRaises(
                        ENFORCEMENT_MODULE.EnforcementDoctorError
                    ) as raised:
                        ENFORCEMENT_MODULE._create_private_child_directory(
                            parent,
                            "candidate",
                            label="test run directory",
                        )
                self.assertEqual(
                    raised.exception.reason_code,
                    "collector-inconclusive",
                )
                self.assertIn(
                    "cleanup could not be proven",
                    str(raised.exception),
                )
                self.assertTrue((parent_path / "candidate").is_dir())
                self.assertTrue((parent_path / "retained-original").is_dir())
                parent.revalidate()
            finally:
                parent.close()

    def test_private_file_creation_rejects_replacement_during_rebind(
        self,
    ) -> None:
        payload = b"safe-token\n"
        with owner_controlled_temp_root() as parent_path:
            parent = ENFORCEMENT_MODULE._BoundDirectory(
                parent_path,
                label="test runtime parent",
            )
            original_bound_file = ENFORCEMENT_MODULE._BoundRegularFile
            cleanup_anchors: list[dict[str, Any]] = []

            def replace_before_rebind(
                bound_parent: object,
                name: str,
                **kwargs: Any,
            ) -> object:
                os.rename(
                    parent_path / name,
                    parent_path / "retained-original",
                )
                replacement = parent_path / name
                replacement.write_bytes(payload)
                replacement.chmod(0o600)
                return original_bound_file(bound_parent, name, **kwargs)

            try:
                with mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "_BoundRegularFile",
                    side_effect=replace_before_rebind,
                ):
                    with self.assertRaises(
                        ENFORCEMENT_MODULE.EnforcementDoctorError
                    ) as raised:
                        ENFORCEMENT_MODULE._create_private_regular_file(
                            parent,
                            "candidate",
                            payload,
                            cleanup_anchors=cleanup_anchors,
                            label="test private file",
                            mode=0o600,
                            max_bytes=1024,
                        )
                self.assertEqual(
                    raised.exception.reason_code,
                    "collector-inconclusive",
                )
                self.assertIn(
                    "object identity or content changed",
                    str(raised.exception),
                )
                self.assertEqual(len(cleanup_anchors), 1)
                retained = (parent_path / "retained-original").stat()
                anchor_status = os.fstat(cleanup_anchors[0]["fd"])
                self.assertEqual(
                    (anchor_status.st_dev, anchor_status.st_ino),
                    (retained.st_dev, retained.st_ino),
                )
                self.assertEqual((parent_path / "candidate").read_bytes(), payload)
                parent.revalidate()
            finally:
                for anchor in cleanup_anchors:
                    os.close(anchor["fd"])
                parent.close()

    def test_private_file_creation_rejects_content_mutation_during_rebind(
        self,
    ) -> None:
        payload = b"safe-token\n"
        mutated_payload = b"evil-token\n"
        self.assertEqual(len(payload), len(mutated_payload))
        with owner_controlled_temp_root() as parent_path:
            parent = ENFORCEMENT_MODULE._BoundDirectory(
                parent_path,
                label="test runtime parent",
            )
            original_bound_file = ENFORCEMENT_MODULE._BoundRegularFile
            cleanup_anchors: list[dict[str, Any]] = []

            def mutate_before_rebind(
                bound_parent: object,
                name: str,
                **kwargs: Any,
            ) -> object:
                candidate = parent_path / name
                candidate.write_bytes(mutated_payload)
                candidate.chmod(0o600)
                return original_bound_file(bound_parent, name, **kwargs)

            try:
                with mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "_BoundRegularFile",
                    side_effect=mutate_before_rebind,
                ):
                    with self.assertRaises(
                        ENFORCEMENT_MODULE.EnforcementDoctorError
                    ) as raised:
                        ENFORCEMENT_MODULE._create_private_regular_file(
                            parent,
                            "candidate",
                            payload,
                            cleanup_anchors=cleanup_anchors,
                            label="test private file",
                            mode=0o600,
                            max_bytes=1024,
                        )
                self.assertEqual(
                    raised.exception.reason_code,
                    "collector-inconclusive",
                )
                self.assertIn(
                    "object identity or content changed",
                    str(raised.exception),
                )
                self.assertEqual(len(cleanup_anchors), 1)
                anchor_status = os.fstat(cleanup_anchors[0]["fd"])
                candidate_status = (parent_path / "candidate").stat()
                self.assertEqual(
                    (anchor_status.st_dev, anchor_status.st_ino),
                    (candidate_status.st_dev, candidate_status.st_ino),
                )
                self.assertEqual(
                    (parent_path / "candidate").read_bytes(),
                    mutated_payload,
                )
                parent.revalidate()
            finally:
                for anchor in cleanup_anchors:
                    os.close(anchor["fd"])
                parent.close()

    def test_trusted_cutover_selector_routes_target_and_non_target_prs(
        self,
    ) -> None:
        scenarios = (
            (
                "target",
                self._pull_request_number,
                self._canonical_commit,
                "target",
                "true",
            ),
            (
                "concurrent-pr",
                self._pull_request_number + 1,
                "8" * 40,
                "not_applicable",
                "false",
            ),
            (
                "future-pr-after-merge",
                self._pull_request_number + 2,
                "7" * 40,
                "not_applicable",
                "false",
            ),
            (
                "concurrent-fork-pr",
                self._pull_request_number + 3,
                "6" * 40,
                "not_applicable",
                "false",
            ),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            for (
                label,
                current_pr,
                current_head,
                classification,
                applicable,
            ) in scenarios:
                with self.subTest(route=label):
                    output_path = temp_root / f"{label}.output"
                    environment = self._selector_workflow_environment(
                        output_path=output_path,
                        current_pr_number=current_pr,
                        current_head_sha=current_head,
                    )
                    if label == "concurrent-fork-pr":
                        environment["PR_HEAD_REPOSITORY"] = "contributor/fork"
                    result = self._run_selector_workflow_program(
                        environment=environment,
                        cwd=temp_root,
                    )

                    self.assertEqual(
                        result.returncode, 0, result.stdout + result.stderr
                    )
                    outcome = json.loads(result.stdout)
                    self.assertEqual(outcome["classification"], classification)
                    self.assertEqual(outcome["target_base_sha"], self._base_sha)
                    output = output_path.read_text(encoding="utf-8")
                    self.assertIn(f"applicable={applicable}\n", output)
                    self.assertIn(f"target-base-sha={self._base_sha}\n", output)

    def test_trusted_cutover_selector_blocks_target_head_change(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            environment = self._selector_workflow_environment(
                output_path=temp_root / "selector.output",
                current_head_sha="8" * 40,
            )
            result = self._run_selector_workflow_program(
                environment=environment,
                cwd=temp_root,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertIn("head changed", outcome["reason"])

    def test_trusted_cutover_selector_blocks_target_base_change(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            environment = self._selector_workflow_environment(
                output_path=temp_root / "selector.output",
                current_base_sha="8" * 40,
            )
            result = self._run_selector_workflow_program(
                environment=environment,
                cwd=temp_root,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertIn("base changed", outcome["reason"])

    def test_trusted_cutover_selector_is_neutral_when_unconfigured(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            output_path = temp_root / "selector.output"
            environment = self._selector_workflow_environment(
                output_path=output_path,
            )
            environment.pop("CISCO_CUTOVER_TARGET_PR_NUMBER")
            environment.pop("CISCO_CUTOVER_TARGET_HEAD_SHA")
            environment.pop("CISCO_CUTOVER_TARGET_BASE_SHA")
            result = self._run_selector_workflow_program(
                environment=environment,
                cwd=temp_root,
            )
            output = output_path.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "not_applicable")
        self.assertIsNone(outcome["target_pr_number"])
        self.assertIsNone(outcome["target_head_sha"])
        self.assertIsNone(outcome["target_base_sha"])
        self.assertEqual(
            output,
            (
                "applicable=false\n"
                "target-base-sha=\n"
                "target-head-sha=\n"
                "target-pr-number=\n"
            ),
        )

    def test_trusted_cutover_selector_blocks_partial_configuration(self) -> None:
        for missing_name in (
            "CISCO_CUTOVER_TARGET_PR_NUMBER",
            "CISCO_CUTOVER_TARGET_HEAD_SHA",
            "CISCO_CUTOVER_TARGET_BASE_SHA",
        ):
            with self.subTest(missing=missing_name):
                with tempfile.TemporaryDirectory() as temp_dir:
                    temp_root = Path(temp_dir)
                    environment = self._selector_workflow_environment(
                        output_path=temp_root / "selector.output",
                    )
                    environment.pop(missing_name)
                    result = self._run_selector_workflow_program(
                        environment=environment,
                        cwd=temp_root,
                    )

                self.assertEqual(result.returncode, 1, result.stderr)
                outcome = json.loads(result.stdout)
                self.assertEqual(
                    outcome["classification"],
                    "blocked_until_trusted",
                )
                self.assertIn(
                    "must be configured together",
                    outcome["reason"],
                )

    def test_trusted_cutover_selector_blocks_target_fork(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            environment = self._selector_workflow_environment(
                output_path=temp_root / "selector.output",
            )
            environment["PR_HEAD_REPOSITORY"] = "contributor/fork"
            result = self._run_selector_workflow_program(
                environment=environment,
                cwd=temp_root,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertIn("head repository differs", outcome["reason"])

    def test_enforcement_contract_binds_required_workflow_identity(self) -> None:
        contract = json.loads(
            CUTOVER_ENFORCEMENT_CONTRACT_PATH.read_text(encoding="utf-8")
        )

        self.assertEqual(contract["schema_version"], 4)
        self.assertEqual(
            contract["source_organization"],
            {
                "id": 283943935,
                "login": "Joey-Tools",
            },
        )
        self.assertEqual(
            contract["target_repository"],
            {
                "id": 1242512092,
                "full_name": "Joey-Tools/codex-debug-triage",
                "default_branch": "master",
            },
        )
        self.assertEqual(contract["ruleset"]["source_type"], "Organization")
        self.assertEqual(contract["ruleset"]["source"], "Joey-Tools")
        self.assertEqual(contract["ruleset"]["enforcement"], "active")
        self.assertEqual(contract["ruleset"]["bypass_actors"], [])
        self.assertEqual(
            contract["ruleset"]["conditions"],
            {
                "repository_id": {
                    "repository_ids": [1242512092],
                },
                "ref_name": {
                    "include": ["~DEFAULT_BRANCH"],
                    "exclude": [],
                },
            },
        )
        workflow = contract["required_workflow"]
        self.assertEqual(workflow["repository_id"], 1242512092)
        self.assertEqual(
            workflow["path"],
            ".github/workflows/cisco-cutover-admission.yml",
        )
        self.assertEqual(workflow["ref"], "refs/heads/master")
        self.assertTrue(workflow["require_exact_sha"])
        self.assertFalse(workflow["do_not_enforce_on_create"])
        self.assertEqual(
            workflow["provider"],
            {
                "id": 15368,
                "slug": "github-actions",
            },
        )
        self.assertEqual(
            contract["disallowed_status_contexts"],
            ["cisco-cutover-admission"],
        )
        self.assertEqual(
            contract["applicability_selector"],
            {
                "target_pr_number_variable": "CISCO_CUTOVER_TARGET_PR_NUMBER",
                "target_head_sha_variable": "CISCO_CUTOVER_TARGET_HEAD_SHA",
                "target_base_sha_variable": "CISCO_CUTOVER_TARGET_BASE_SHA",
                "selector_job_name": "cisco-cutover-selector",
                "target_job_name": "cisco-cutover-admission",
                "neutral_job_name": "cisco-cutover-neutral",
                "non_target_classification": "not_applicable",
            },
        )
        self.assertEqual(
            contract["cutover_input_variables"],
            [
                "CISCO_CUTOVER_TARGET_PR_NUMBER",
                "CISCO_CUTOVER_TARGET_HEAD_SHA",
                "CISCO_CUTOVER_TARGET_BASE_SHA",
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
            ],
        )
        self.assertEqual(
            contract["pointer_authority"],
            {
                "status": "unavailable",
                "reason": "private-live-authority-not-configured",
            },
        )
        self.assertEqual(
            contract["base_change_enforcement"],
            self._expected_base_change_enforcement(),
        )

    def test_enforcement_contract_rejects_base_change_precondition_drift(
        self,
    ) -> None:
        cases = {
            "available": lambda precondition: precondition.update(
                {"status": "available"}
            ),
            "edited-dispatched": lambda precondition: precondition[
                "ruleset_dispatch_activities"
            ].append("edited"),
        }
        for label, mutate in cases.items():
            with self.subTest(case=label):
                contract = json.loads(
                    CUTOVER_ENFORCEMENT_CONTRACT_PATH.read_text(encoding="utf-8")
                )
                mutate(contract["base_change_enforcement"])

                with self.assertRaises(
                    ENFORCEMENT_MODULE.EnforcementDoctorError
                ) as raised:
                    ENFORCEMENT_MODULE._load_contract(contract)

                self.assertEqual(raised.exception.reason_code, "invalid-contract")
                self.assertIn("base-change enforcement", str(raised.exception))

    def test_trusted_cutover_workflow_cannot_green_without_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            environment = os.environ.copy()
            for name in self._trusted_gate_environment_names:
                environment.pop(name, None)
            environment["GITHUB_REPOSITORY"] = "Joey-Tools/codex-debug-triage"
            result = self._run_trusted_workflow_program(
                environment=environment,
                cwd=Path(temp_dir),
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stderr, "")
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertIn("is missing", outcome["reason"])

    def test_trusted_cutover_workflow_rejects_identity_and_binding_drift(
        self,
    ) -> None:
        fixture = json.loads(MIGRATION_FIXTURE_PATH.read_text(encoding="utf-8"))
        receipt = self._matching_cutover_receipt(fixture)
        receipt_payload = (
            json.dumps(
                receipt,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        cases = {
            "runner-repository": {
                "GITHUB_REPOSITORY": "attacker/example",
            },
            "event-repository": {
                "EVENT_REPOSITORY": "attacker/example",
            },
            "head-repository": {
                "PR_HEAD_REPOSITORY": "attacker/example",
            },
            "base-ref": {
                "PR_BASE_REF": "attacker-base",
            },
            "base-sha": {
                "PR_BASE_SHA": "8" * 40,
            },
            "head-sha": {
                "PR_HEAD_SHA": "4" * 40,
            },
            "pull-request-number": {
                "PR_NUMBER": str(self._pull_request_number + 1),
            },
            "selector-head": {
                "SELECTED_TARGET_HEAD_SHA": "4" * 40,
            },
            "selector-base": {
                "SELECTED_TARGET_BASE_SHA": "8" * 40,
            },
            "selector-pr": {
                "SELECTED_TARGET_PR_NUMBER": str(self._pull_request_number + 1),
            },
            "expected-canonical": {
                "CISCO_CUTOVER_EXPECTED_CANONICAL_COMMIT": "4" * 40,
            },
            "expected-base": {
                "CISCO_CUTOVER_TARGET_BASE_SHA": "8" * 40,
            },
            "receipt-digest": {
                "CISCO_CUTOVER_EXPECTED_RECEIPT_SHA256": "4" * 64,
            },
            "workflow-id": {
                "CISCO_CUTOVER_EXPECTED_WORKFLOW_ID": str(self._workflow_id + 1),
            },
            "workflow-sha": {
                "CISCO_CUTOVER_EXPECTED_WORKFLOW_SHA": "5" * 40,
            },
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            for label, overrides in cases.items():
                with self.subTest(drift=label):
                    environment = self._trusted_workflow_environment(
                        receipt_payload=receipt_payload,
                        overrides=overrides,
                    )
                    result = self._run_trusted_workflow_program(
                        environment=environment,
                        cwd=Path(temp_dir),
                    )

                    self.assertEqual(result.returncode, 1, result.stderr)
                    outcome = json.loads(result.stdout)
                    self.assertEqual(
                        outcome["classification"],
                        "blocked_until_trusted",
                    )

    def test_trusted_cutover_workflow_rejects_pointer_and_lease_drift(
        self,
    ) -> None:
        fixture = json.loads(MIGRATION_FIXTURE_PATH.read_text(encoding="utf-8"))
        cases = {
            "scope": (
                lambda pointer: pointer.update(
                    {"installation_scope_id": "other-installation-scope"}
                ),
                "installation scope differs",
            ),
            "state": (
                lambda pointer: pointer.update({"state_sha256": "7" * 64}),
                "state digest differs",
            ),
            "authority": (
                lambda pointer: pointer["live_authority"].update(
                    {"repository_full_name": "attacker/private-workflows"}
                ),
                "authority repository differs",
            ),
            "lease-status": (
                lambda pointer: pointer["merge_lease"].update({"status": "released"}),
                "merge lease is not active",
            ),
            "lease-head": (
                lambda pointer: pointer["merge_lease"].update(
                    {"pull_request_head_sha": "8" * 40}
                ),
                "merge lease head differs",
            ),
            "lease-base": (
                lambda pointer: pointer["merge_lease"].update(
                    {"pull_request_base_sha": "8" * 40}
                ),
                "merge lease base differs",
            ),
            "lease-generation": (
                lambda pointer: pointer["merge_lease"].update(
                    {"pointer_generation": self._pointer_generation + 1}
                ),
                "merge lease generation differs",
            ),
            "expired": (
                lambda pointer: (
                    pointer.update(
                        {
                            "observed_at": "2000-01-01T00:00:00Z",
                            "expires_at": "2000-01-02T00:00:00Z",
                        }
                    ),
                    pointer["merge_lease"].update(
                        {"acquired_at": "2000-01-01T00:00:00Z"}
                    ),
                ),
                "pointer proof has expired",
            ),
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            for label, (mutate, expected_reason) in cases.items():
                with self.subTest(pointer_drift=label):
                    receipt = self._matching_cutover_receipt(fixture)
                    mutate(receipt["installed_pointer"])
                    receipt_payload = (
                        json.dumps(
                            receipt,
                            ensure_ascii=True,
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                        + "\n"
                    ).encode("utf-8")
                    result = self._run_trusted_workflow_program(
                        environment=self._trusted_workflow_environment(
                            receipt_payload=receipt_payload,
                        ),
                        cwd=temp_root,
                    )

                    self.assertEqual(result.returncode, 1, result.stdout)
                    outcome = json.loads(result.stdout)
                    self.assertEqual(
                        outcome["classification"],
                        "blocked_until_trusted",
                    )
                    self.assertIn(expected_reason, outcome["reason"])

    def test_trusted_cutover_workflow_rejects_stale_receipt_after_base_retarget(
        self,
    ) -> None:
        fixture = json.loads(MIGRATION_FIXTURE_PATH.read_text(encoding="utf-8"))
        stale_receipt = self._matching_cutover_receipt(fixture)
        receipt_payload = (
            json.dumps(
                stale_receipt,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        new_base_sha = "8" * 40
        environment = self._trusted_workflow_environment(
            receipt_payload=receipt_payload,
            overrides={
                "PR_BASE_SHA": new_base_sha,
                "SELECTED_TARGET_BASE_SHA": new_base_sha,
                "CISCO_CUTOVER_TARGET_BASE_SHA": new_base_sha,
            },
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            result = self._run_trusted_workflow_program(
                environment=environment,
                cwd=Path(temp_dir),
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertIn("receipt cutover contract differs", outcome["reason"])
        self.assertNotEqual(outcome.get("static_equivalence"), "validated")

    def test_trusted_cutover_workflow_ignores_malicious_candidate_files(
        self,
    ) -> None:
        fixture = json.loads(MIGRATION_FIXTURE_PATH.read_text(encoding="utf-8"))
        receipt = self._matching_cutover_receipt(fixture)
        receipt_payload = (
            json.dumps(
                receipt,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            trusted_cwd = temp_root / "trusted-runner"
            candidate = temp_root / "candidate"
            trusted_cwd.mkdir()
            (candidate / ".github/workflows").mkdir(parents=True)
            (candidate / "scripts").mkdir()
            (candidate / "tests").mkdir()
            marker = temp_root / "candidate-executed"
            malicious = (
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed')\n"
                "raise SystemExit(0)\n"
            )
            (candidate / ".github/workflows/cisco-cutover-admission.yml").write_text(
                "name: attacker\non: pull_request_target\njobs: {}\n",
                encoding="utf-8",
            )
            (candidate / "scripts/validate_cisco_cutover_receipt.py").write_text(
                malicious, encoding="utf-8"
            )
            (candidate / "tests/test_archive_triage.py").write_text(
                malicious,
                encoding="utf-8",
            )
            environment = self._trusted_workflow_environment(
                receipt_payload=receipt_payload,
                overrides={"GITHUB_WORKSPACE": str(candidate)},
            )
            result = self._run_trusted_workflow_program(
                environment=environment,
                cwd=trusted_cwd,
            )
            candidate_executed = marker.exists()

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertFalse(candidate_executed)
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertEqual(
            outcome["reason"],
            "admission-preconditions-unavailable",
        )
        self.assertEqual(
            outcome["blockers"],
            self._expected_admission_blockers(),
        )
        self.assertEqual(outcome["static_equivalence"], "validated")
        self.assertEqual(outcome["expected_base_sha"], self._base_sha)
        self.assertEqual(
            outcome["provider_observed_base_sha"],
            self._base_sha,
        )
        self.assertEqual(
            outcome["receipt_sha256"],
            hashlib.sha256(receipt_payload).hexdigest(),
        )

    def test_trusted_cutover_workflow_rejects_placeholder_expectations(
        self,
    ) -> None:
        for placeholder in ("placeholder", "<unset>", "0" * 40):
            with self.subTest(placeholder=placeholder):
                environment = self._trusted_workflow_environment(
                    receipt_payload=b"{}\n",
                    overrides={"CISCO_CUTOVER_EXPECTED_CANONICAL_COMMIT": placeholder},
                )
                with tempfile.TemporaryDirectory() as temp_dir:
                    result = self._run_trusted_workflow_program(
                        environment=environment,
                        cwd=Path(temp_dir),
                    )

                self.assertEqual(result.returncode, 1, result.stderr)
                outcome = json.loads(result.stdout)
                self.assertEqual(
                    outcome["classification"],
                    "blocked_until_trusted",
                )
                self.assertIn("is a placeholder", outcome["reason"])

    def test_trusted_cutover_workflow_rejects_untrusted_base_expectations(
        self,
    ) -> None:
        cases = {
            "missing": None,
            "malformed": "A" * 40,
            "placeholder": "placeholder",
            "all-zero": "0" * 40,
        }
        for label, value in cases.items():
            with self.subTest(case=label):
                environment = self._trusted_workflow_environment(
                    receipt_payload=b"{}\n",
                )
                if value is None:
                    environment.pop("CISCO_CUTOVER_TARGET_BASE_SHA")
                else:
                    environment["CISCO_CUTOVER_TARGET_BASE_SHA"] = value
                with tempfile.TemporaryDirectory() as temp_dir:
                    result = self._run_trusted_workflow_program(
                        environment=environment,
                        cwd=Path(temp_dir),
                    )

                self.assertEqual(result.returncode, 1, result.stderr)
                outcome = json.loads(result.stdout)
                self.assertEqual(
                    outcome["classification"],
                    "blocked_until_trusted",
                )
                self.assertRegex(
                    outcome["reason"],
                    r"(is missing|is a placeholder|must be exact lowercase hex)",
                )

    def test_enforcement_doctor_blocks_on_unavailable_admission_preconditions(
        self,
    ) -> None:
        result = self._run_enforcement_doctor(self._matching_enforcement_evidence())

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(result.stderr, "")
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertEqual(
            outcome["reason_code"],
            "admission-preconditions-unavailable",
        )
        self.assertEqual(
            outcome["blockers"],
            self._expected_admission_blockers(),
        )

    def test_enforcement_live_collector_exhausts_pages_and_binds_lineage(
        self,
    ) -> None:
        contract = json.loads(
            CUTOVER_ENFORCEMENT_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        client = self._matching_live_api_client()

        receipt, admission = ENFORCEMENT_MODULE._collect_and_validate_static(
            client,
            contract,
            expected_run_attempt=1,
            expected_run_id=10101,
            expected_ruleset_id=self._ruleset_id,
            expected_workflow_id=self._workflow_id,
            expected_workflow_sha=self._workflow_source_commit,
            expected_base_sha=self._base_sha,
            candidate_head_sha=self._canonical_commit,
            pull_request_number=7,
        )

        self.assertEqual(receipt["schema_version"], 4)
        self.assertEqual(
            receipt["collector"]["mode"],
            "live-github-rest-graphql",
        )
        self.assertEqual(
            receipt["collector"]["gh_executable"],
            {
                "environment_profile": "minimal-snapshotted-config-v2",
                "execution_source": "owner-private-snapshot",
                "sha256": "a" * 64,
            },
        )
        self.assertEqual(client.auth_calls, 1)
        self.assertNotIn("collection", receipt["initial"])
        self.assertEqual(admission["trusted_run"]["id"], 10101)
        self.assertEqual(admission["trusted_job"]["id"], 20202)
        self.assertEqual(admission["trusted_check_run"]["id"], 20202)
        ruleset_bounds = [
            bound
            for bound in receipt["collector"]["page_bounds"]
            if bound["label"] == "effective repository rulesets"
        ]
        self.assertEqual(len(ruleset_bounds), 2)
        self.assertEqual(
            {bound["phase"] for bound in ruleset_bounds},
            {"initial", "revalidation"},
        )
        self.assertTrue(
            all(bound["terminal_empty_page"] == 2 for bound in ruleset_bounds)
        )
        self.assertTrue(all(bound["item_count"] == 1 for bound in ruleset_bounds))
        suite_bounds = [
            bound
            for bound in receipt["collector"]["page_bounds"]
            if bound["label"].startswith("selected PR ")
            and bound["label"].endswith(" check suites")
        ]
        self.assertEqual(len(suite_bounds), 4)
        self.assertEqual(
            {bound["endpoint"] for bound in suite_bounds},
            {
                (
                    "/repos/Joey-Tools/codex-debug-triage/commits/"
                    f"{self._canonical_commit}/check-suites"
                ),
                (
                    "/repos/Joey-Tools/codex-debug-triage/commits/"
                    f"{'9' * 40}/check-suites"
                ),
            },
        )
        self.assertTrue(
            all(bound["parameters"] == {"filter": "all"} for bound in suite_bounds)
        )
        check_run_bounds = [
            bound
            for bound in receipt["collector"]["page_bounds"]
            if bound["label"] == "check suite 30303 check runs"
        ]
        self.assertEqual(len(check_run_bounds), 2)
        self.assertTrue(
            all(bound["terminal_empty_page"] == 2 for bound in check_run_bounds)
        )
        self.assertTrue(
            all(bound["parameters"] == {"filter": "all"} for bound in check_run_bounds)
        )

    def test_enforcement_live_collector_requests_all_check_suites(
        self,
    ) -> None:
        client = self._matching_live_api_client()
        target_name = "Joey-Tools/codex-debug-triage"
        base_sha = "9" * 40
        suite_endpoint = f"/repos/{target_name}/commits/{base_sha}/check-suites"
        older_suite = self._copy_json(client.collections[suite_endpoint]["pages"][0][0])
        latest_suite = {
            "head_sha": base_sha,
            "id": 40_404,
        }
        client.collections[suite_endpoint]["pages"] = [
            [latest_suite, older_suite],
        ]
        client.collections[
            f"/repos/{target_name}/check-suites/{latest_suite['id']}/check-runs"
        ] = {
            "item_key": "check_runs",
            "pages": [[]],
        }
        original_get_json = client.get_json

        def filter_sensitive_get_json(
            endpoint: str,
            parameters: dict[str, object] | None = None,
        ) -> object:
            query = dict(parameters or {})
            if endpoint == suite_endpoint and query.get("filter", "latest") != "all":
                page_items = [latest_suite] if query["page"] == 1 else []
                return {
                    "total_count": 1,
                    "check_suites": self._copy_json(page_items),
                }
            return original_get_json(endpoint, parameters)

        client.get_json = filter_sensitive_get_json
        default_page = client.get_json(
            suite_endpoint,
            {"page": 1, "per_page": ENFORCEMENT_MODULE.API_PER_PAGE},
        )
        self.assertEqual(
            [suite["id"] for suite in default_page["check_suites"]],
            [latest_suite["id"]],
        )

        snapshot = self._collect_live_snapshot(client)

        self.assertEqual([check["id"] for check in snapshot["check_runs"]], [20202])
        suite_calls = [
            query
            for endpoint, query in client.calls
            if endpoint.endswith("/check-suites")
        ]
        self.assertTrue(suite_calls)
        self.assertTrue(all(query["filter"] == "all" for query in suite_calls))
        check_run_calls = [
            query
            for endpoint, query in client.calls
            if "/check-suites/" in endpoint and endpoint.endswith("/check-runs")
        ]
        self.assertTrue(check_run_calls)
        self.assertTrue(all(query["filter"] == "all" for query in check_run_calls))

    def test_enforcement_live_collector_reads_more_than_one_thousand_suites(
        self,
    ) -> None:
        client = self._matching_live_api_client()
        base_sha = "9" * 40
        target_name = "Joey-Tools/codex-debug-triage"
        suite_endpoint = f"/repos/{target_name}/commits/{base_sha}/check-suites"
        original_suite = self._copy_json(
            client.collections[suite_endpoint]["pages"][0][0]
        )
        suites = [original_suite]
        for offset in range(1, 1_001):
            suite_id = 40_000 + offset
            suites.append({"head_sha": base_sha, "id": suite_id})
            client.collections[
                f"/repos/{target_name}/check-suites/{suite_id}/check-runs"
            ] = {
                "item_key": "check_runs",
                "pages": [[]],
            }
        client.collections[suite_endpoint]["pages"] = [
            suites[index : index + ENFORCEMENT_MODULE.API_PER_PAGE]
            for index in range(0, len(suites), ENFORCEMENT_MODULE.API_PER_PAGE)
        ]

        snapshot = self._collect_live_snapshot(client)

        self.assertEqual(len(suites), 1_001)
        self.assertEqual([check["id"] for check in snapshot["check_runs"]], [20202])
        requested_suite_pages = [
            query["page"]
            for endpoint, query in client.calls
            if endpoint == suite_endpoint
        ]
        self.assertEqual(requested_suite_pages, list(range(1, 13)))

    def test_enforcement_live_collector_rejects_duplicate_suite_and_run_ids(
        self,
    ) -> None:
        target_name = "Joey-Tools/codex-debug-triage"
        base_sha = "9" * 40
        suite_endpoint = f"/repos/{target_name}/commits/{base_sha}/check-suites"
        cases = ("suite", "check-run")
        for duplicate_kind in cases:
            with self.subTest(duplicate=duplicate_kind):
                client = self._matching_live_api_client()
                original_suite = self._copy_json(
                    client.collections[suite_endpoint]["pages"][0][0]
                )
                if duplicate_kind == "suite":
                    client.collections[suite_endpoint]["pages"].append(
                        [self._copy_json(original_suite)]
                    )
                    expected_reason = "check-suite-identity-mismatch"
                else:
                    duplicate_suite_id = 40_404
                    client.collections[suite_endpoint]["pages"][0].append(
                        {
                            "head_sha": base_sha,
                            "id": duplicate_suite_id,
                        }
                    )
                    original_check = self._copy_json(
                        client.collections[
                            f"/repos/{target_name}/check-suites/"
                            f"{original_suite['id']}/check-runs"
                        ]["pages"][0][0]
                    )
                    original_check["check_suite"]["id"] = duplicate_suite_id
                    client.collections[
                        f"/repos/{target_name}/check-suites/"
                        f"{duplicate_suite_id}/check-runs"
                    ] = {
                        "item_key": "check_runs",
                        "pages": [[original_check]],
                    }
                    expected_reason = "check-run-identity-mismatch"

                with self.assertRaises(
                    ENFORCEMENT_MODULE.EnforcementDoctorError
                ) as raised:
                    self._collect_live_snapshot(client)

                self.assertEqual(raised.exception.reason_code, expected_reason)

    def test_enforcement_check_suite_collection_fails_closed_on_capacity(
        self,
    ) -> None:
        client = self._matching_live_api_client()
        target_name = "Joey-Tools/codex-debug-triage"
        suite_endpoint = f"/repos/{target_name}/commits/{'9' * 40}/check-suites"
        client.collections[suite_endpoint]["pages"][0].append(
            {"head_sha": "9" * 40, "id": 40_404}
        )

        with (
            mock.patch.object(ENFORCEMENT_MODULE, "MAX_CHECK_SUITES", 1),
            self.assertRaises(ENFORCEMENT_MODULE.EnforcementDoctorError) as raised,
        ):
            self._collect_live_snapshot(client)

        self.assertEqual(raised.exception.reason_code, "api-search-cap-exceeded")

    def test_enforcement_check_suite_collection_fails_closed_on_page_exhaustion(
        self,
    ) -> None:
        client = self._matching_live_api_client()
        endpoint = (
            f"/repos/Joey-Tools/codex-debug-triage/commits/{'9' * 40}/check-suites"
        )

        with (
            mock.patch.object(ENFORCEMENT_MODULE, "MAX_API_PAGES", 1),
            self.assertRaises(ENFORCEMENT_MODULE.EnforcementDoctorError) as raised,
        ):
            ENFORCEMENT_MODULE._collect_pages(
                client,
                {"object_reads": [], "page_bounds": []},
                phase="test",
                label="selected PR check suites",
                endpoint=endpoint,
                parameters={},
                item_key="check_suites",
                result_cap=ENFORCEMENT_MODULE.MAX_CHECK_SUITES,
            )

        self.assertEqual(raised.exception.reason_code, "api-pagination-incomplete")

    def test_enforcement_check_suite_collection_rejects_partial_total(
        self,
    ) -> None:
        client = self._matching_live_api_client()
        endpoint = (
            f"/repos/Joey-Tools/codex-debug-triage/commits/{'9' * 40}/check-suites"
        )
        original_get_json = client.get_json

        def partial_get_json(
            selected_endpoint: str,
            parameters: dict[str, object] | None = None,
        ) -> object:
            result = original_get_json(selected_endpoint, parameters)
            if (
                selected_endpoint == endpoint
                and int((parameters or {}).get("page", 0)) == 1
            ):
                result["total_count"] += 1
            return result

        client.get_json = partial_get_json
        with self.assertRaises(ENFORCEMENT_MODULE.EnforcementDoctorError) as raised:
            ENFORCEMENT_MODULE._collect_pages(
                client,
                {"object_reads": [], "page_bounds": []},
                phase="test",
                label="selected PR check suites",
                endpoint=endpoint,
                parameters={},
                item_key="check_suites",
                result_cap=ENFORCEMENT_MODULE.MAX_CHECK_SUITES,
            )

        self.assertEqual(raised.exception.reason_code, "api-pagination-incomplete")

    def test_enforcement_live_collector_reads_hidden_later_page(
        self,
    ) -> None:
        contract = json.loads(
            CUTOVER_ENFORCEMENT_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        client = self._matching_live_api_client()
        target_name = contract["target_repository"]["full_name"]
        hidden_ruleset = self._copy_json(
            self._matching_enforcement_evidence()["selected_ruleset"]
        )
        hidden_ruleset["id"] = self._ruleset_id + 1
        hidden_ruleset["name"] = "Hidden same-name status rule"
        hidden_ruleset["rules"] = [
            {
                "type": "required_status_checks",
                "parameters": {
                    "required_status_checks": [
                        {
                            "context": "cisco-cutover-admission",
                            "integration_id": 15368,
                        }
                    ],
                },
            }
        ]
        client.collections[f"/repos/{target_name}/rulesets"]["pages"].append(
            [hidden_ruleset]
        )
        client.objects[
            (
                f"/orgs/{contract['source_organization']['login']}/rulesets/"
                f"{hidden_ruleset['id']}"
            )
        ] = hidden_ruleset

        with self.assertRaisesRegex(
            ENFORCEMENT_MODULE.EnforcementDoctorError,
            "same-name required_status_checks",
        ) as raised:
            ENFORCEMENT_MODULE.collect_and_validate(
                client,
                contract,
                expected_run_attempt=1,
                expected_run_id=10101,
                expected_ruleset_id=self._ruleset_id,
                expected_workflow_id=self._workflow_id,
                expected_workflow_sha=self._workflow_source_commit,
                expected_base_sha=self._base_sha,
                candidate_head_sha=self._canonical_commit,
                pull_request_number=7,
            )

        self.assertEqual(raised.exception.reason_code, "spoofable-status-rule")
        requested_ruleset_pages = [
            query["page"]
            for endpoint, query in client.calls
            if endpoint == f"/repos/{target_name}/rulesets"
        ]
        self.assertEqual(requested_ruleset_pages, [1, 2, 3])

    def test_enforcement_live_collector_rejects_head_change_on_revalidation(
        self,
    ) -> None:
        contract = json.loads(
            CUTOVER_ENFORCEMENT_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        client = self._matching_live_api_client()
        pull_endpoint = "/repos/Joey-Tools/codex-debug-triage/pulls/7"
        original_get_json = client.get_json
        pull_reads = 0

        def raced_get_json(
            endpoint: str,
            parameters: dict[str, object] | None = None,
        ) -> object:
            nonlocal pull_reads
            result = original_get_json(endpoint, parameters)
            if endpoint == pull_endpoint:
                pull_reads += 1
                if pull_reads == 2:
                    result["head"]["sha"] = "8" * 40
            return result

        client.get_json = raced_get_json

        with self.assertRaises(ENFORCEMENT_MODULE.EnforcementDoctorError) as raised:
            ENFORCEMENT_MODULE.collect_and_validate(
                client,
                contract,
                expected_run_attempt=1,
                expected_run_id=10101,
                expected_ruleset_id=self._ruleset_id,
                expected_workflow_id=self._workflow_id,
                expected_workflow_sha=self._workflow_source_commit,
                expected_base_sha=self._base_sha,
                candidate_head_sha=self._canonical_commit,
                pull_request_number=7,
            )

        self.assertEqual(
            raised.exception.reason_code,
            "pull-request-identity-mismatch",
        )
        self.assertEqual(pull_reads, 2)

    def test_enforcement_live_collector_rejects_base_change_on_revalidation(
        self,
    ) -> None:
        contract = json.loads(
            CUTOVER_ENFORCEMENT_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        client = self._matching_live_api_client()
        pull_endpoint = "/repos/Joey-Tools/codex-debug-triage/pulls/7"
        original_get_json = client.get_json
        pull_reads = 0

        def raced_get_json(
            endpoint: str,
            parameters: dict[str, object] | None = None,
        ) -> object:
            nonlocal pull_reads
            result = original_get_json(endpoint, parameters)
            if endpoint == pull_endpoint:
                pull_reads += 1
                if pull_reads == 2:
                    result["base"]["sha"] = "8" * 40
            return result

        client.get_json = raced_get_json

        with self.assertRaises(ENFORCEMENT_MODULE.EnforcementDoctorError) as raised:
            ENFORCEMENT_MODULE.collect_and_validate(
                client,
                contract,
                expected_run_attempt=1,
                expected_run_id=10101,
                expected_ruleset_id=self._ruleset_id,
                expected_workflow_id=self._workflow_id,
                expected_workflow_sha=self._workflow_source_commit,
                expected_base_sha=self._base_sha,
                candidate_head_sha=self._canonical_commit,
                pull_request_number=7,
            )

        self.assertEqual(
            raised.exception.reason_code,
            "pull-request-identity-mismatch",
        )
        self.assertEqual(pull_reads, 2)

    def test_enforcement_live_collector_ignores_timestamp_only_churn(
        self,
    ) -> None:
        contract = json.loads(
            CUTOVER_ENFORCEMENT_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        client = self._matching_live_api_client()
        original_get_json = client.get_json
        read_count = 0

        def timestamped_get_json(
            endpoint: str,
            parameters: dict[str, object] | None = None,
        ) -> object:
            nonlocal read_count
            read_count += 1
            result = original_get_json(endpoint, parameters)
            if type(result) is dict:
                result["updated_at"] = f"2026-07-24T00:00:{read_count % 60:02d}Z"
            return result

        client.get_json = timestamped_get_json

        _, admission = ENFORCEMENT_MODULE._collect_and_validate_static(
            client,
            contract,
            expected_run_attempt=1,
            expected_run_id=10101,
            expected_ruleset_id=self._ruleset_id,
            expected_workflow_id=self._workflow_id,
            expected_workflow_sha=self._workflow_source_commit,
            expected_base_sha=self._base_sha,
            candidate_head_sha=self._canonical_commit,
            pull_request_number=7,
        )

        self.assertEqual(admission["trusted_run"]["id"], 10101)

    def test_enforcement_live_collector_fully_paginates_cutover_variables(
        self,
    ) -> None:
        contract = json.loads(
            CUTOVER_ENFORCEMENT_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        client = self._matching_live_api_client()
        variable_endpoint = "/repos/Joey-Tools/codex-debug-triage/actions/variables"
        variables = client.collections[variable_endpoint]["pages"][0]
        client.collections[variable_endpoint]["pages"] = [
            variables[:5],
            variables[5:],
        ]

        receipt, _ = ENFORCEMENT_MODULE._collect_and_validate_static(
            client,
            contract,
            expected_run_attempt=1,
            expected_run_id=10101,
            expected_ruleset_id=self._ruleset_id,
            expected_workflow_id=self._workflow_id,
            expected_workflow_sha=self._workflow_source_commit,
            expected_base_sha=self._base_sha,
            candidate_head_sha=self._canonical_commit,
            pull_request_number=7,
        )

        bounds = [
            value
            for value in receipt["collector"]["page_bounds"]
            if value["label"] == "repository Actions variables"
        ]
        self.assertEqual(len(bounds), 2)
        self.assertEqual(
            {value["phase"] for value in bounds},
            {"initial", "revalidation"},
        )
        self.assertTrue(all(value["item_count"] == 13 for value in bounds))
        self.assertTrue(all(value["terminal_empty_page"] == 3 for value in bounds))
        self.assertTrue(all(value["per_page"] == 30 for value in bounds))
        variable_calls = [
            parameters
            for endpoint, parameters in client.calls
            if endpoint == variable_endpoint
        ]
        self.assertEqual(
            [parameters["page"] for parameters in variable_calls],
            [1, 2, 3, 1, 2, 3],
        )
        self.assertTrue(
            all(parameters["per_page"] == 30 for parameters in variable_calls)
        )

    def test_enforcement_live_collector_rejects_missing_or_duplicate_variables(
        self,
    ) -> None:
        contract = json.loads(
            CUTOVER_ENFORCEMENT_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        variable_endpoint = "/repos/Joey-Tools/codex-debug-triage/actions/variables"
        cases = (
            ("missing", "cutover-input-missing"),
            ("duplicate", "cutover-input-duplicate"),
        )
        for label, reason_code in cases:
            with self.subTest(variable_set=label):
                client = self._matching_live_api_client()
                variables = client.collections[variable_endpoint]["pages"][0]
                if label == "missing":
                    client.collections[variable_endpoint]["pages"] = [variables[:-1]]
                else:
                    client.collections[variable_endpoint]["pages"] = [
                        variables,
                        [self._copy_json(variables[0])],
                    ]

                with self.assertRaises(
                    ENFORCEMENT_MODULE.EnforcementDoctorError
                ) as raised:
                    ENFORCEMENT_MODULE.collect_and_validate(
                        client,
                        contract,
                        expected_run_attempt=1,
                        expected_run_id=10101,
                        expected_ruleset_id=self._ruleset_id,
                        expected_workflow_id=self._workflow_id,
                        expected_workflow_sha=self._workflow_source_commit,
                        expected_base_sha=self._base_sha,
                        candidate_head_sha=self._canonical_commit,
                        pull_request_number=7,
                    )

                self.assertEqual(raised.exception.reason_code, reason_code)

    def test_enforcement_live_collector_detects_cutover_input_timestamp_drift(
        self,
    ) -> None:
        contract = json.loads(
            CUTOVER_ENFORCEMENT_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        client = self._matching_live_api_client()
        variable_endpoint = "/repos/Joey-Tools/codex-debug-triage/actions/variables"
        original_get_json = client.get_json
        first_page_reads = 0

        def drifting_get_json(
            endpoint: str,
            parameters: dict[str, object] | None = None,
        ) -> object:
            nonlocal first_page_reads
            result = original_get_json(endpoint, parameters)
            if (
                endpoint == variable_endpoint
                and int((parameters or {}).get("page", 0)) == 1
            ):
                first_page_reads += 1
                if first_page_reads == 2:
                    result["variables"][0]["updated_at"] = "2026-07-24T12:00:01Z"
            return result

        client.get_json = drifting_get_json
        with self.assertRaises(ENFORCEMENT_MODULE.EnforcementDoctorError) as raised:
            ENFORCEMENT_MODULE.collect_and_validate(
                client,
                contract,
                expected_run_attempt=1,
                expected_run_id=10101,
                expected_ruleset_id=self._ruleset_id,
                expected_workflow_id=self._workflow_id,
                expected_workflow_sha=self._workflow_source_commit,
                expected_base_sha=self._base_sha,
                candidate_head_sha=self._canonical_commit,
                pull_request_number=7,
            )

        self.assertEqual(first_page_reads, 2)
        self.assertEqual(raised.exception.reason_code, "cutover-input-drift")

    def test_enforcement_live_collector_detects_cutover_input_value_drift(
        self,
    ) -> None:
        contract = json.loads(
            CUTOVER_ENFORCEMENT_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        client = self._matching_live_api_client()
        variable_endpoint = "/repos/Joey-Tools/codex-debug-triage/actions/variables"
        original_get_json = client.get_json
        first_page_reads = 0

        def drifting_get_json(
            endpoint: str,
            parameters: dict[str, object] | None = None,
        ) -> object:
            nonlocal first_page_reads
            result = original_get_json(endpoint, parameters)
            if (
                endpoint == variable_endpoint
                and int((parameters or {}).get("page", 0)) == 1
            ):
                first_page_reads += 1
                if first_page_reads == 2:
                    selected = next(
                        value
                        for value in result["variables"]
                        if value["name"] == "CISCO_CUTOVER_RECEIPT_BASE64"
                    )
                    selected["value"] = "ZHJpZnRlZC1yZWNlaXB0"
            return result

        client.get_json = drifting_get_json
        with self.assertRaises(ENFORCEMENT_MODULE.EnforcementDoctorError) as raised:
            ENFORCEMENT_MODULE.collect_and_validate(
                client,
                contract,
                expected_run_attempt=1,
                expected_run_id=10101,
                expected_ruleset_id=self._ruleset_id,
                expected_workflow_id=self._workflow_id,
                expected_workflow_sha=self._workflow_source_commit,
                expected_base_sha=self._base_sha,
                candidate_head_sha=self._canonical_commit,
                pull_request_number=7,
            )

        self.assertEqual(first_page_reads, 2)
        self.assertEqual(raised.exception.reason_code, "cutover-input-drift")

    def test_enforcement_live_collector_binds_exact_attempt_endpoint(
        self,
    ) -> None:
        contract = json.loads(
            CUTOVER_ENFORCEMENT_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        client = self._matching_live_api_client()
        attempt_endpoint = (
            "/repos/Joey-Tools/codex-debug-triage/actions/runs/10101/attempts/1"
        )
        client.objects[attempt_endpoint]["run_attempt"] = 2

        with self.assertRaises(ENFORCEMENT_MODULE.EnforcementDoctorError) as raised:
            ENFORCEMENT_MODULE.collect_and_validate(
                client,
                contract,
                expected_run_attempt=1,
                expected_run_id=10101,
                expected_ruleset_id=self._ruleset_id,
                expected_workflow_id=self._workflow_id,
                expected_workflow_sha=self._workflow_source_commit,
                expected_base_sha=self._base_sha,
                candidate_head_sha=self._canonical_commit,
                pull_request_number=7,
            )

        self.assertEqual(
            raised.exception.reason_code,
            "selected-run-attempt-mismatch",
        )

    def test_enforcement_run_must_be_strictly_newer_than_every_cutover_input(
        self,
    ) -> None:
        contract = json.loads(
            CUTOVER_ENFORCEMENT_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        for variable_name in contract["cutover_input_variables"]:
            with self.subTest(variable=variable_name):
                evidence = self._matching_enforcement_evidence()
                self._cutover_variable(
                    evidence,
                    variable_name,
                )["updated_at"] = "2026-07-24T12:05:01Z"
                result = self._run_enforcement_doctor(evidence)

                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertEqual(
                    json.loads(result.stdout)["reason_code"],
                    "selected-run-predates-cutover-inputs",
                )

        evidence = self._matching_enforcement_evidence()
        self._cutover_variable(
            evidence,
            "CISCO_CUTOVER_EXPECTED_POINTER_GENERATION",
        )["updated_at"] = "2026-07-24T12:05:00Z"
        result = self._run_enforcement_doctor(evidence)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertEqual(
            json.loads(result.stdout)["reason_code"],
            "cutover-freshness-inconclusive",
        )

    def test_enforcement_older_selected_run_is_not_rescued_by_newer_success(
        self,
    ) -> None:
        evidence = self._matching_enforcement_evidence()
        for variable in evidence["cutover_input_variables"]:
            variable["updated_at"] = "2026-07-24T12:07:00Z"
        original_run = evidence["workflow_runs"][0]
        original_job = evidence["jobs"][0]
        original_check = evidence["check_runs"][0]
        newer_run = self._copy_json(original_run)
        newer_run_url = (
            "https://api.github.com/repos/Joey-Tools/"
            "codex-debug-triage/actions/runs/10102"
        )
        newer_run.update(
            {
                "check_suite_id": 30304,
                "check_suite_url": (
                    "https://api.github.com/repos/Joey-Tools/"
                    "codex-debug-triage/check-suites/30304"
                ),
                "html_url": (
                    "https://github.com/Joey-Tools/codex-debug-triage/"
                    "actions/runs/10102"
                ),
                "id": 10102,
                "jobs_url": f"{newer_run_url}/jobs",
                "run_started_at": "2026-07-24T12:10:00Z",
                "url": newer_run_url,
            }
        )
        newer_check_url = (
            "https://api.github.com/repos/Joey-Tools/"
            "codex-debug-triage/check-runs/20204"
        )
        newer_job = self._copy_json(original_job)
        newer_job.update(
            {
                "check_run_url": newer_check_url,
                "completed_at": "2026-07-24T12:11:00Z",
                "html_url": (
                    "https://github.com/Joey-Tools/codex-debug-triage/"
                    "actions/runs/10102/job/20204"
                ),
                "id": 20204,
                "run_id": 10102,
                "run_url": newer_run_url,
                "started_at": "2026-07-24T12:10:00Z",
                "url": (
                    "https://api.github.com/repos/Joey-Tools/"
                    "codex-debug-triage/actions/jobs/20204"
                ),
            }
        )
        newer_check = self._copy_json(original_check)
        newer_check.update(
            {
                "check_suite_id": 30304,
                "completed_at": "2026-07-24T12:11:00Z",
                "details_url": newer_job["html_url"],
                "html_url": newer_job["html_url"],
                "id": 20204,
                "started_at": "2026-07-24T12:10:00Z",
                "url": newer_check_url,
            }
        )
        evidence["workflow_runs"].append(newer_run)
        evidence["jobs"].append(newer_job)
        evidence["check_runs"].append(newer_check)

        result = self._run_enforcement_doctor(
            evidence,
            expected_run_id=10101,
            expected_run_attempt=1,
        )

        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertEqual(
            json.loads(result.stdout)["reason_code"],
            "selected-run-predates-cutover-inputs",
        )

    def test_enforcement_doctor_cli_has_no_untrusted_evidence_input(
        self,
    ) -> None:
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                ENFORCEMENT_MODULE.build_parser().parse_args(
                    [
                        "--contract",
                        str(CUTOVER_ENFORCEMENT_CONTRACT_PATH),
                        "--evidence",
                        "caller.json",
                        "--pull-request-number",
                        "7",
                        "--expected-ruleset-id",
                        str(self._ruleset_id),
                        "--expected-run-id",
                        "10101",
                        "--expected-run-attempt",
                        "1",
                        "--expected-workflow-id",
                        str(self._workflow_id),
                        "--expected-workflow-sha",
                        self._workflow_source_commit,
                        "--expected-base-sha",
                        self._base_sha,
                        "--candidate-head-sha",
                        self._canonical_commit,
                    ]
                )

        self.assertEqual(raised.exception.code, 2)

    def test_enforcement_doctor_requires_pinned_gh_arguments(self) -> None:
        required_arguments = (
            "--gh-executable",
            "--expected-gh-sha256",
            "--gh-config-dir",
        )
        base_arguments = [
            "--contract",
            str(CUTOVER_ENFORCEMENT_CONTRACT_PATH),
            "--gh-executable",
            "/usr/bin/true",
            "--expected-gh-sha256",
            "a" * 64,
            "--gh-config-dir",
            tempfile.gettempdir(),
            "--pull-request-number",
            "7",
            "--expected-ruleset-id",
            str(self._ruleset_id),
            "--expected-run-id",
            "10101",
            "--expected-run-attempt",
            "1",
            "--expected-workflow-id",
            str(self._workflow_id),
            "--expected-workflow-sha",
            self._workflow_source_commit,
            "--expected-base-sha",
            self._base_sha,
            "--candidate-head-sha",
            self._canonical_commit,
        ]
        for argument in required_arguments:
            with self.subTest(required=argument):
                index = base_arguments.index(argument)
                incomplete = base_arguments[:index] + base_arguments[index + 2 :]
                with redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        ENFORCEMENT_MODULE.build_parser().parse_args(incomplete)
                self.assertEqual(raised.exception.code, 2)

    def test_enforcement_doctor_requires_exact_pinned_base_sha(self) -> None:
        base_arguments = [
            "--contract",
            str(CUTOVER_ENFORCEMENT_CONTRACT_PATH),
            "--gh-executable",
            "/usr/bin/true",
            "--expected-gh-sha256",
            "a" * 64,
            "--gh-config-dir",
            tempfile.gettempdir(),
            "--pull-request-number",
            "7",
            "--expected-ruleset-id",
            str(self._ruleset_id),
            "--expected-run-id",
            "10101",
            "--expected-run-attempt",
            "1",
            "--expected-workflow-id",
            str(self._workflow_id),
            "--expected-workflow-sha",
            self._workflow_source_commit,
            "--expected-base-sha",
            self._base_sha,
            "--candidate-head-sha",
            self._canonical_commit,
        ]
        base_index = base_arguments.index("--expected-base-sha")
        cases = {
            "missing": base_arguments[:base_index] + base_arguments[base_index + 2 :],
            "malformed": (
                base_arguments[: base_index + 1]
                + ["A" * 40]
                + base_arguments[base_index + 2 :]
            ),
            "placeholder": (
                base_arguments[: base_index + 1]
                + ["placeholder"]
                + base_arguments[base_index + 2 :]
            ),
            "all-zero": (
                base_arguments[: base_index + 1]
                + ["0" * 40]
                + base_arguments[base_index + 2 :]
            ),
        }
        for label, arguments in cases.items():
            with self.subTest(case=label):
                with redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        ENFORCEMENT_MODULE.build_parser().parse_args(arguments)
                self.assertEqual(raised.exception.code, 2)

    def test_enforcement_acl_contract_is_descriptor_bound_and_platform_explicit(
        self,
    ) -> None:
        source = CUTOVER_ENFORCEMENT_DOCTOR_PATH.read_text(encoding="utf-8")
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        migration = (REPO_ROOT / "docs/cisco-build-artifacts-migration.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'DARWIN_LIBSYSTEM_PATH = "/usr/lib/libSystem.B.dylib"',
            source,
        )
        self.assertIn("acl_get_fd_np", source)
        self.assertIn("acl_copy_ext", source)
        self.assertIn("DARWIN_ACL_EXTENDED_ALLOW", source)
        self.assertIn('LINUX_ACL_PROFILE = "linux-posix-mode-mask-v1"', source)
        self.assertNotIn("ls -lde", source)
        self.assertIn("/usr/lib/libSystem.B.dylib", readme)
        self.assertIn("linux-posix-mode-mask-v1", migration)
        self.assertIn(
            "checked before any executable or token bytes are written",
            " ".join(migration.split()),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "object"
            path.write_bytes(b"fixture")
            descriptor = os.open(path, os.O_RDONLY)
            try:
                with mock.patch.object(
                    ENFORCEMENT_MODULE.sys,
                    "platform",
                    "linux",
                ):
                    with mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "_DarwinAclRuntime",
                        side_effect=AssertionError("Darwin runtime must not load"),
                    ):
                        binding = ENFORCEMENT_MODULE._stable_fd_access_policy_binding(
                            descriptor
                        )
            finally:
                os.close(descriptor)
        self.assertEqual(
            binding,
            ("linux-posix-mode-mask-v1", 0, "mode-bits-authoritative"),
        )

    @unittest.skipUnless(
        sys.platform == "darwin",
        "requires Darwin extended ACLs",
    )
    def test_enforcement_darwin_acl_ctypes_abi_constants_and_iteration(
        self,
    ) -> None:
        self.assertEqual(ENFORCEMENT_MODULE.DARWIN_ACL_TYPE_EXTENDED, 0x100)
        self.assertEqual(ENFORCEMENT_MODULE.DARWIN_ACL_EXTENDED_ALLOW, 1)
        self.assertEqual(ENFORCEMENT_MODULE.DARWIN_ACL_EXTENDED_DENY, 2)
        self.assertEqual(ENFORCEMENT_MODULE.DARWIN_ACL_FIRST_ENTRY, 0)
        self.assertEqual(ENFORCEMENT_MODULE.DARWIN_ACL_NEXT_ENTRY, -1)
        self.assertEqual(
            ENFORCEMENT_MODULE.DARWIN_ACL_INHERITANCE_FLAGS,
            (0x10, 0x20, 0x40, 0x80, 0x100),
        )

        runtime = ENFORCEMENT_MODULE._DarwinAclRuntime()
        self.assertEqual(
            runtime._libc.acl_get_fd_np.argtypes,
            [ctypes.c_int, ctypes.c_int],
        )
        self.assertIs(runtime._libc.acl_get_fd_np.restype, ctypes.c_void_p)
        self.assertEqual(
            runtime._libc.acl_get_entry.argtypes,
            [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)],
        )
        self.assertIs(runtime._libc.acl_get_entry.restype, ctypes.c_int)
        self.assertEqual(
            runtime._libc.acl_copy_ext.argtypes,
            [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ssize_t],
        )
        self.assertIs(runtime._libc.acl_copy_ext.restype, ctypes.c_ssize_t)

        with owner_controlled_temp_root() as temp_root:
            acl_path = temp_root / "deny-only"
            acl_path.write_bytes(b"fixture")
            acl_path.chmod(0o600)
            self._set_darwin_acl(acl_path, "everyone deny readextattr")
            descriptor = os.open(acl_path, os.O_RDONLY)
            try:
                binding = runtime.binding(descriptor)
            finally:
                os.close(descriptor)
                self._clear_darwin_acl(acl_path)

        self.assertEqual(
            binding,
            (
                "darwin-fd-no-extended-grants-v1",
                0,
                "no-extended-grants-or-inheritance",
            ),
        )

    def test_enforcement_darwin_acl_only_enoent_proves_absence(self) -> None:
        runtime = object.__new__(ENFORCEMENT_MODULE._DarwinAclRuntime)
        runtime._libc = mock.Mock()

        def missing_acl(error_number: int) -> object:
            def query(_fd: int, _acl_type: int) -> None:
                ctypes.set_errno(error_number)
                return None

            return query

        runtime._libc.acl_get_fd_np.side_effect = missing_acl(errno.ENOENT)
        self.assertEqual(
            runtime.binding(17),
            (
                "darwin-fd-no-extended-grants-v1",
                0,
                "no-extended-grants-or-inheritance",
            ),
        )

        for error_number in (errno.ENOTSUP, errno.EACCES):
            with self.subTest(error_number=error_number):
                runtime._libc.acl_get_fd_np.side_effect = missing_acl(error_number)
                with self.assertRaises(OSError) as raised:
                    runtime.binding(17)
                self.assertEqual(raised.exception.errno, error_number)

    @unittest.skipUnless(
        sys.platform == "darwin",
        "requires Darwin extended ACLs",
    )
    def test_enforcement_gh_acl_allows_only_noninherited_deny_entries(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            self._set_darwin_acl(temp_root, "everyone deny readextattr")
            try:
                with ENFORCEMENT_MODULE.GitHubApiClient(
                    trusted_gh,
                    hashlib.sha256(trusted_payload).hexdigest(),
                    config_dir,
                    runtime_parent=runtime_parent,
                ):
                    pass
            finally:
                self._clear_darwin_acl(temp_root)

            self._set_darwin_acl(
                temp_root,
                "everyone allow list,search,add_file,delete_child",
            )
            try:
                with self.assertRaises(
                    ENFORCEMENT_MODULE.EnforcementDoctorError
                ) as raised:
                    ENFORCEMENT_MODULE.GitHubApiClient(
                        trusted_gh,
                        hashlib.sha256(trusted_payload).hexdigest(),
                        config_dir,
                        runtime_parent=runtime_parent,
                    )
            finally:
                self._clear_darwin_acl(temp_root)
        self.assertEqual(raised.exception.reason_code, "collector-unavailable")

    @unittest.skipUnless(
        sys.platform == "darwin",
        "requires Darwin extended ACL inheritance",
    )
    def test_enforcement_gh_acl_rejects_inherited_source_token_read_grant(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir = temp_root / "gh-config"
            config_dir.mkdir(mode=0o700)
            self._set_darwin_acl(
                config_dir,
                "everyone allow read,file_inherit,directory_inherit",
            )
            hosts_path = config_dir / "hosts.yml"
            hosts_path.write_text(
                (
                    "github.com:\n"
                    "    git_protocol: https\n"
                    "    users:\n"
                    "        fixture-admin:\n"
                    f"            oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                    "    user: fixture-admin\n"
                    f"    oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                ),
                encoding="utf-8",
            )
            hosts_path.chmod(0o600)
            config_path = config_dir / "config.yml"
            config_path.write_text("version: 1\n", encoding="utf-8")
            config_path.chmod(0o600)
            self._clear_darwin_acl(config_dir)

            with mock.patch.object(
                ENFORCEMENT_MODULE,
                "_bounded_subprocess",
            ) as spawned:
                with self.assertRaises(
                    ENFORCEMENT_MODULE.EnforcementDoctorError
                ) as raised:
                    ENFORCEMENT_MODULE.GitHubApiClient(
                        trusted_gh,
                        hashlib.sha256(trusted_payload).hexdigest(),
                        config_dir,
                        runtime_parent=temp_root / "fixed-gh-runtime",
                    )
            spawned.assert_not_called()
        self.assertEqual(raised.exception.reason_code, "collector-unavailable")

    def test_enforcement_gh_pin_uses_exact_digest_and_minimal_environment(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = (
                b'#!/bin/sh\nprintf \'%s\\n\' \'{"id":1,"login":"fixture"}\'\n'
            )
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            expected_digest = hashlib.sha256(trusted_payload).hexdigest()
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            malicious_dir = temp_root / "malicious-path"
            malicious_dir.mkdir()
            malicious_gh = malicious_dir / "gh"
            malicious_gh.write_bytes(b"#!/bin/sh\nexit 99\n")
            malicious_gh.chmod(0o700)
            observed: dict[str, object] = {}

            def fixed_result(
                command: list[str],
                **kwargs: object,
            ) -> tuple[int, bytes, bytes]:
                observed["command"] = command
                observed["environment"] = kwargs["environment"]
                return (
                    0,
                    self._curl_response(b'{"id":1,"login":"fixture"}'),
                    b"",
                )

            ambient = {
                "PATH": str(malicious_dir),
                "HOME": "/ambient-home",
                "GH_TOKEN": "ambient-gh-token",
                "GH_HOST": "attacker.invalid",
                "HTTPS_PROXY": "https://proxy.invalid",
                "SSL_CERT_FILE": "/ambient-ca.pem",
                "DYLD_INSERT_LIBRARIES": "/ambient.dylib",
                "LD_PRELOAD": "/ambient.so",
                "TMPDIR": str(malicious_dir),
            }
            with mock.patch.dict(os.environ, ambient, clear=False):
                expected_default_runtime = Path(
                    ENFORCEMENT_MODULE.pwd.getpwuid(os.geteuid()).pw_dir
                ).joinpath(*ENFORCEMENT_MODULE.GH_RUNTIME_COMPONENTS)
                self.assertEqual(
                    ENFORCEMENT_MODULE._default_gh_runtime_parent(),
                    expected_default_runtime,
                )
                with ENFORCEMENT_MODULE.GitHubApiClient(
                    trusted_gh,
                    expected_digest,
                    config_dir,
                    runtime_parent=runtime_parent,
                ) as client:
                    with mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "_bounded_subprocess",
                        side_effect=fixed_result,
                    ):
                        response = client.get_json("/user")

                    self.assertEqual(response["login"], "fixture")
                    self.assertEqual(
                        observed["command"][0],
                        str(ENFORCEMENT_MODULE.CURL_EXECUTABLE),
                    )
                    self.assertEqual(observed["command"][1], "--disable")
                    self.assertNotEqual(observed["command"][0], str(malicious_gh))
                    self.assertFalse(
                        Path(observed["command"][0]).is_relative_to(malicious_dir)
                    )
                    self.assertNotIn("--location", observed["command"])
                    self.assertNotIn("--location-trusted", observed["command"])
                    self.assertEqual(
                        observed["command"][observed["command"].index("--url") + 1],
                        "https://api.github.com/user",
                    )
                    self.assertNotIn(
                        SYNTHETIC_ACCESS_TOKEN,
                        "\0".join(observed["command"]),
                    )
                    snapshot_config_dir = Path(observed["environment"]["GH_CONFIG_DIR"])
                    self.assertNotEqual(snapshot_config_dir, config_dir)
                    self.assertEqual(
                        snapshot_config_dir.parent,
                        Path(client.executable).parent.parent,
                    )
                    self.assertEqual(
                        observed["environment"],
                        {
                            "GH_CONFIG_DIR": str(snapshot_config_dir),
                            "GH_NO_UPDATE_NOTIFIER": "1",
                            "GH_PROMPT_DISABLED": "1",
                            "LC_ALL": "C",
                            "PATH": ENFORCEMENT_MODULE.GH_TRUSTED_SYSTEM_PATH,
                        },
                    )
                    self.assertEqual(client.executable_sha256, expected_digest)
                    self.assertEqual(
                        client.execution_source,
                        "owner-private-snapshot",
                    )
                    self.assertEqual(
                        client.environment_profile,
                        "minimal-snapshotted-auth-v4",
                    )
                    self.assertEqual(
                        client.transport_profile,
                        "fixed-curl-no-redirect-v1",
                    )

                    def attempt_execution_window_replacement(
                        command: list[str],
                        **kwargs: object,
                    ) -> tuple[int, bytes, bytes]:
                        try:
                            if os.geteuid() == 0:
                                raise PermissionError(
                                    errno.EACCES,
                                    "root test process bypasses directory DAC",
                                )
                            client._snapshot_path.rename(
                                client._snapshot_path.with_name("gh.replaced")
                            )
                        except PermissionError:
                            observed["execution_window_replacement_blocked"] = True
                        return 0, f"{SYNTHETIC_ACCESS_TOKEN}\n".encode("ascii"), b""

                    with mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "_bounded_subprocess",
                        side_effect=attempt_execution_window_replacement,
                    ):
                        token_output = client._run(
                            [
                                client.executable,
                                "auth",
                                "token",
                                "--hostname",
                                ENFORCEMENT_MODULE.AUTH_HOST,
                            ],
                            endpoint_class="authentication-preflight",
                            stdout_limit=2_049,
                            authentication_preflight=True,
                        )
                    self.assertTrue(observed["execution_window_replacement_blocked"])
                    self.assertEqual(
                        token_output,
                        f"{SYNTHETIC_ACCESS_TOKEN}\n".encode("ascii"),
                    )

    def test_enforcement_auth_uses_fixed_keychain_helper_path(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_helper_dir = temp_root / "trusted-system-bin"
            malicious_helper_dir = temp_root / "ambient-bin"
            trusted_helper_dir.mkdir(mode=0o700)
            malicious_helper_dir.mkdir(mode=0o700)
            trusted_marker = temp_root / "trusted-security.marker"
            malicious_marker = temp_root / "malicious-security.marker"

            trusted_security = trusted_helper_dir / "security"
            trusted_security.write_text(
                "#!/bin/sh\n"
                'if [ "$1" != "find-generic-password" ]; then exit 97; fi\n'
                f"printf '%s\\n' trusted > {shlex.quote(str(trusted_marker))}\n"
                f"printf '%s\\n' {shlex.quote(SYNTHETIC_ACCESS_TOKEN)}\n",
                encoding="utf-8",
            )
            trusted_security.chmod(0o700)
            malicious_security = malicious_helper_dir / "security"
            malicious_security.write_text(
                "#!/bin/sh\n"
                f"printf '%s\\n' malicious > {shlex.quote(str(malicious_marker))}\n"
                "exit 99\n",
                encoding="utf-8",
            )
            malicious_security.chmod(0o700)

            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = (
                b"#!/bin/sh\nexec security find-generic-password -w github.com\n"
            )
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(
                temp_root,
                hosts_payload=(
                    "github.com:\n"
                    "    git_protocol: https\n"
                    "    users:\n"
                    "        fixture-admin:\n"
                    "    user: fixture-admin\n"
                ),
            )

            with mock.patch.object(
                ENFORCEMENT_MODULE,
                "GH_TRUSTED_SYSTEM_PATH",
                str(trusted_helper_dir),
            ):
                with mock.patch.dict(
                    os.environ,
                    {"PATH": str(malicious_helper_dir)},
                    clear=False,
                ):
                    with ENFORCEMENT_MODULE.GitHubApiClient(
                        trusted_gh,
                        hashlib.sha256(trusted_payload).hexdigest(),
                        config_dir,
                        runtime_parent=runtime_parent,
                    ) as client:
                        self.assertIsNone(client._snapshot_auth_header_file)
                        with mock.patch.object(
                            client,
                            "get_json",
                            return_value={"id": 4242, "login": "fixture-admin"},
                        ) as get_json:
                            authenticated_user = client.auth_preflight()
                        get_json.assert_called_once_with("/user")

            self.assertEqual(
                authenticated_user,
                {"id": 4242, "login": "fixture-admin"},
            )
            self.assertTrue(trusted_marker.is_file())
            self.assertFalse(malicious_marker.exists())

    def test_enforcement_graphql_workflow_definition_query_is_fixed(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            observed: dict[str, object] = {}
            node_id = "WFR_kwDOFixture10101"

            def graphql_result(
                command: list[str],
                **kwargs: object,
            ) -> tuple[int, bytes, bytes]:
                observed["command"] = command
                observed["environment"] = kwargs["environment"]
                payload = {
                    "data": {
                        "node": {
                            "__typename": "WorkflowRun",
                            "databaseId": 10101,
                            "event": "pull_request_target",
                            "file": {
                                "id": "WFRF_kwDOFixture10101",
                                "path": ".github/workflows/admission.yml",
                                "repositoryFileUrl": (
                                    "https://github.com/example/repo/blob/"
                                    f"{'4' * 40}/.github/workflows/admission.yml"
                                ),
                                "repositoryName": "example/repo",
                            },
                            "id": node_id,
                            "runAttempt": 1,
                        }
                    }
                }
                return 0, self._curl_response(json.dumps(payload).encode()), b""

            with ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            ) as client:
                with mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "_bounded_subprocess",
                    side_effect=graphql_result,
                ):
                    response = client.get_workflow_run_definition(node_id)

            self.assertEqual(response["data"]["node"]["id"], node_id)
            command = observed["command"]
            self.assertEqual(command[command.index("--request") + 1], "POST")
            self.assertEqual(
                command[command.index("--url") + 1],
                "https://api.github.com/graphql",
            )
            request = json.loads(command[command.index("--data-binary") + 1])
            self.assertEqual(request["variables"], {"id": node_id})
            self.assertEqual(
                request["query"],
                ENFORCEMENT_MODULE.GRAPHQL_WORKFLOW_RUN_DEFINITION_QUERY,
            )
            self.assertEqual(
                observed["environment"]["PATH"],
                ENFORCEMENT_MODULE.GH_TRUSTED_SYSTEM_PATH,
            )

    def test_enforcement_gh_pin_rejects_same_object_snapshot_rewrite(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            changed_payload = b"#!/bin/sh\nexit 9\n"
            self.assertEqual(len(changed_payload), len(trusted_payload))
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            real_sha256_fd_bounded = ENFORCEMENT_MODULE._sha256_fd_bounded
            exercised = False

            def rewrite_snapshot_before_readback(
                fd: int,
                *,
                deadline_check: object = None,
            ) -> tuple[str, int]:
                nonlocal exercised
                self.assertFalse(exercised)
                snapshot_path = ENFORCEMENT_MODULE._verified_descriptor_path(fd)
                self.assertIsNotNone(snapshot_path)
                assert snapshot_path is not None
                before = os.fstat(fd)
                self.assertEqual(stat.S_IMODE(before.st_mode), 0o500)
                snapshot_path.chmod(0o700)
                try:
                    with snapshot_path.open("r+b") as snapshot_file:
                        snapshot_file.write(changed_payload)
                        snapshot_file.flush()
                        os.fsync(snapshot_file.fileno())
                finally:
                    snapshot_path.chmod(0o500)
                after = os.fstat(fd)
                self.assertEqual(
                    (after.st_dev, after.st_ino),
                    (before.st_dev, before.st_ino),
                )
                self.assertEqual(after.st_size, before.st_size)
                self.assertEqual(stat.S_IMODE(after.st_mode), 0o500)
                exercised = True
                return real_sha256_fd_bounded(
                    fd,
                    deadline_check=deadline_check,
                )

            with (
                mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "_sha256_fd_bounded",
                    side_effect=rewrite_snapshot_before_readback,
                ),
                mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "_bounded_subprocess",
                ) as spawned,
                self.assertRaises(ENFORCEMENT_MODULE.EnforcementDoctorError) as raised,
            ):
                ENFORCEMENT_MODULE.GitHubApiClient(
                    trusted_gh,
                    hashlib.sha256(trusted_payload).hexdigest(),
                    config_dir,
                    runtime_parent=runtime_parent,
                )

            self.assertTrue(exercised)
            self.assertEqual(raised.exception.reason_code, "collector-unavailable")
            self.assertEqual(list(runtime_parent.glob("run-*")), [])
            spawned.assert_not_called()

    def test_enforcement_initialization_deadline_precedes_default_path_read(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            observed: dict[str, object] = {}

            def select_runtime_parent(
                *,
                deadline_check: object,
            ) -> Path:
                observed["deadline"] = deadline_check
                deadline_check()
                return runtime_parent

            with mock.patch.object(
                ENFORCEMENT_MODULE,
                "_default_gh_runtime_parent",
                side_effect=select_runtime_parent,
            ):
                with ENFORCEMENT_MODULE.GitHubApiClient(
                    trusted_gh,
                    hashlib.sha256(trusted_payload).hexdigest(),
                    config_dir,
                ) as client:
                    self.assertLess(time.monotonic(), client.deadline)

            self.assertTrue(callable(observed["deadline"]))
            self.assertEqual(list(runtime_parent.glob("run-*")), [])

    def test_enforcement_initialization_stalls_honor_deadline_and_cleanup(
        self,
    ) -> None:
        for phase in (
            "config-read",
            "executable-copy",
            "executable-fsync",
            "executable-reopen",
        ):
            with self.subTest(phase=phase), owner_controlled_temp_root() as temp_root:
                trusted_gh = temp_root / "trusted-gh"
                trusted_payload = b"#!/bin/sh\nexit 0\n"
                trusted_gh.write_bytes(trusted_payload)
                trusted_gh.chmod(0o700)
                config_dir, runtime_parent = self._make_private_gh_config(temp_root)
                real_monotonic = time.monotonic
                expired = False
                exercised = False

                def controlled_monotonic() -> float:
                    offset = (
                        ENFORCEMENT_MODULE.MAX_COLLECTION_SECONDS + 1.0
                        if expired
                        else 0.0
                    )
                    return real_monotonic() + offset

                with ExitStack() as stack:
                    stack.enter_context(
                        mock.patch.object(
                            ENFORCEMENT_MODULE.time,
                            "monotonic",
                            side_effect=controlled_monotonic,
                        )
                    )
                    if phase == "config-read":
                        real_read = ENFORCEMENT_MODULE._read_fd_payload_bounded

                        def stall_config_read(
                            fd: int,
                            *,
                            label: str,
                            limit: int,
                            deadline_check: object = None,
                        ) -> bytes:
                            nonlocal expired, exercised
                            if label == "GitHub CLI source hosts.yml" and not exercised:
                                self.assertIsNotNone(deadline_check)
                                exercised = True
                                expired = True
                                deadline_check()
                            return real_read(
                                fd,
                                label=label,
                                limit=limit,
                                deadline_check=deadline_check,
                            )

                        stack.enter_context(
                            mock.patch.object(
                                ENFORCEMENT_MODULE,
                                "_read_fd_payload_bounded",
                                side_effect=stall_config_read,
                            )
                        )
                    elif phase == "executable-copy":
                        real_write = ENFORCEMENT_MODULE._write_all

                        def stall_executable_copy(
                            fd: int,
                            payload: bytes,
                            *,
                            deadline_check: object = None,
                        ) -> None:
                            nonlocal expired, exercised
                            real_write(
                                fd,
                                payload,
                                deadline_check=deadline_check,
                            )
                            if payload == trusted_payload and not exercised:
                                self.assertIsNotNone(deadline_check)
                                exercised = True
                                expired = True
                                deadline_check()

                        stack.enter_context(
                            mock.patch.object(
                                ENFORCEMENT_MODULE,
                                "_write_all",
                                side_effect=stall_executable_copy,
                            )
                        )
                    elif phase == "executable-fsync":
                        real_fsync = os.fsync

                        def stall_executable_fsync(fd: int) -> None:
                            nonlocal expired, exercised
                            real_fsync(fd)
                            if (
                                stat.S_IMODE(os.fstat(fd).st_mode) == 0o500
                                and not exercised
                            ):
                                exercised = True
                                expired = True

                        stack.enter_context(
                            mock.patch.object(
                                ENFORCEMENT_MODULE.os,
                                "fsync",
                                side_effect=stall_executable_fsync,
                            )
                        )
                    else:
                        real_open = os.open

                        def stall_executable_reopen(
                            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                            flags: int,
                            mode: int = 0o777,
                            *,
                            dir_fd: int | None = None,
                        ) -> int:
                            nonlocal expired, exercised
                            fd = real_open(
                                path,
                                flags,
                                mode,
                                dir_fd=dir_fd,
                            )
                            if (
                                path == "gh"
                                and flags & os.O_ACCMODE == os.O_RDONLY
                                and not exercised
                            ):
                                exercised = True
                                expired = True
                            return fd

                        stack.enter_context(
                            mock.patch.object(
                                ENFORCEMENT_MODULE.os,
                                "open",
                                side_effect=stall_executable_reopen,
                            )
                        )
                    with self.assertRaises(
                        ENFORCEMENT_MODULE.EnforcementDoctorError
                    ) as raised:
                        ENFORCEMENT_MODULE.GitHubApiClient(
                            trusted_gh,
                            hashlib.sha256(trusted_payload).hexdigest(),
                            config_dir,
                            runtime_parent=runtime_parent,
                        )

                self.assertTrue(exercised)
                self.assertEqual(raised.exception.reason_code, "api-timeout")
                self.assertEqual(
                    raised.exception.api_failure,
                    {
                        "endpoint_class": "collector-initialization",
                        "failure_kind": "timeout",
                        "http_status": None,
                    },
                )
                self.assertEqual(list(runtime_parent.glob("run-*")), [])

    def test_enforcement_subprocess_registers_before_deadline_initialization(
        self,
    ) -> None:
        process = mock.Mock()
        process.pid = 4242
        process.stdout = mock.Mock()
        process.stderr = mock.Mock()
        process_registry: dict[int, object] = {}

        with (
            mock.patch.object(
                ENFORCEMENT_MODULE.subprocess,
                "Popen",
                return_value=process,
            ),
            mock.patch.object(
                ENFORCEMENT_MODULE.time,
                "monotonic",
                side_effect=OSError(
                    errno.EIO,
                    "injected deadline initialization failure",
                ),
            ),
            mock.patch.object(
                ENFORCEMENT_MODULE,
                "_terminate_drain_reap",
                return_value=[],
            ) as cleanup,
            self.assertRaises(ENFORCEMENT_MODULE.EnforcementDoctorError) as raised,
        ):
            ENFORCEMENT_MODULE._bounded_subprocess(
                ["/fixed/gh", "api", "/user"],
                environment={},
                execution_cwd=tempfile.gettempdir(),
                endpoint_class="authenticated-user",
                process_registry=process_registry,
                timeout_seconds=1,
                stdout_limit=1024,
                stderr_limit=1024,
            )

        cleanup.assert_called_once()
        managed = cleanup.call_args.args[0]
        self.assertIs(managed.process, process)
        self.assertEqual(process_registry, {})
        self.assertEqual(raised.exception.reason_code, "collector-inconclusive")
        self.assertEqual(
            raised.exception.api_failure,
            {
                "endpoint_class": "authenticated-user",
                "failure_kind": "process-io",
                "http_status": None,
            },
        )
        process.stdout.close.assert_called_once()
        process.stderr.close.assert_called_once()

    @unittest.skipUnless(
        os.name == "posix"
        and all(
            hasattr(signal, name)
            for name in (
                "SIGINT",
                "pthread_sigmask",
                "sigpending",
                "sigwait",
                "SIG_BLOCK",
                "SIG_SETMASK",
            )
        ),
        "collector spawn publication requires POSIX signal controls",
    )
    def test_enforcement_subprocess_defers_signal_before_registry_publication(
        self,
    ) -> None:
        process = mock.Mock()
        process.pid = 4242
        process.stdout = mock.Mock()
        process.stderr = mock.Mock()
        process_registry: dict[int, object] = {}
        events: list[str] = []
        original_handler = signal.getsignal(signal.SIGINT)
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        original_managed_process = ENFORCEMENT_MODULE._ManagedProcess
        if signal.SIGINT in original_mask:
            self.skipTest("the test runner already blocks SIGINT")

        def interrupt_before_publication(*_args: object, **_kwargs: object) -> object:
            self.assertEqual(process_registry, {})
            events.append("popen-return")
            os.kill(os.getpid(), signal.SIGINT)
            self.assertIn(signal.SIGINT, signal.sigpending())
            return process

        def construct_managed_process(spawned_process: object) -> object:
            self.assertEqual(process_registry, {})
            self.assertIn(signal.SIGINT, signal.sigpending())
            events.append("managed-construction")
            return original_managed_process(spawned_process)

        def terminate_child(_managed: object) -> list[str]:
            events.append("child-cleanup")
            return []

        def cleanup_credentials() -> None:
            self.assertEqual(process_registry, {})
            events.append("credential-cleanup")

        try:
            signal.signal(signal.SIGINT, signal.default_int_handler)
            with (
                mock.patch.object(
                    ENFORCEMENT_MODULE.subprocess,
                    "Popen",
                    side_effect=interrupt_before_publication,
                ),
                mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "_ManagedProcess",
                    side_effect=construct_managed_process,
                ),
                mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "_terminate_drain_reap",
                    side_effect=terminate_child,
                ) as cleanup,
                self.assertRaises(KeyboardInterrupt),
            ):
                ENFORCEMENT_MODULE._bounded_subprocess(
                    ["/fixed/gh", "api", "/user"],
                    environment={},
                    execution_cwd=tempfile.gettempdir(),
                    endpoint_class="authenticated-user",
                    process_registry=process_registry,
                    timeout_seconds=1,
                    stdout_limit=1024,
                    stderr_limit=1024,
                    termination_cleanup=cleanup_credentials,
                )
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
            signal.signal(signal.SIGINT, original_handler)

        cleanup.assert_called_once()
        self.assertEqual(
            events,
            [
                "popen-return",
                "managed-construction",
                "child-cleanup",
                "credential-cleanup",
            ],
        )
        self.assertEqual(process_registry, {})
        process.stdout.close.assert_called_once_with()
        process.stderr.close.assert_called_once_with()

    def test_enforcement_forwarded_signal_keeps_cleanup_error_secondary(
        self,
    ) -> None:
        cleanup_error = ENFORCEMENT_MODULE.EnforcementDoctorError(
            "collector-inconclusive",
            "injected credential cleanup failure",
        )
        with (
            mock.patch.object(
                ENFORCEMENT_MODULE.os,
                "kill",
                side_effect=KeyboardInterrupt,
            ),
            self.assertRaises(KeyboardInterrupt) as raised,
        ):
            ENFORCEMENT_MODULE._forward_deferred_termination_signal(
                signal.SIGINT,
                cleanup_error,
            )

        self.assertIs(raised.exception.__cause__, cleanup_error)

    @unittest.skipUnless(
        os.name == "posix"
        and all(
            hasattr(signal, name)
            for name in (
                "SIGINT",
                "pthread_sigmask",
                "sigpending",
                "sigwait",
                "SIG_BLOCK",
                "SIG_SETMASK",
            )
        ),
        "collector registry publication requires POSIX signal controls",
    )
    def test_enforcement_client_cleans_snapshot_after_published_signal(
        self,
    ) -> None:
        original_handler = signal.getsignal(signal.SIGINT)
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        if signal.SIGINT in original_mask:
            self.skipTest("the test runner already blocks SIGINT")
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            client = ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            )
            run_path = client._run_directory.path
            process = mock.Mock()
            process.pid = 4242
            process.stdout = mock.Mock()
            process.stderr = mock.Mock()
            original_publish = client._termination_signal_guard.publish

            def interrupt_after_publication(managed: object) -> None:
                original_publish(managed)
                published = client._active_processes.get(process.pid)
                self.assertIsNotNone(published)
                self.assertIs(published.process, process)
                os.kill(os.getpid(), signal.SIGINT)

            try:
                signal.signal(signal.SIGINT, signal.default_int_handler)
                with (
                    mock.patch.object(
                        ENFORCEMENT_MODULE.subprocess,
                        "Popen",
                        return_value=process,
                    ),
                    mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "_terminate_drain_reap",
                        return_value=[],
                    ) as cleanup,
                    mock.patch.object(
                        client._termination_signal_guard,
                        "publish",
                        side_effect=interrupt_after_publication,
                    ),
                    self.assertRaises(KeyboardInterrupt),
                ):
                    client.get_json("/user")
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)
                signal.signal(signal.SIGINT, original_handler)
                if not client._closed:
                    client.close()

        cleanup.assert_called_once()
        self.assertTrue(client._closed)
        self.assertEqual(client._active_processes, {})
        self.assertFalse(run_path.exists())
        process.stdout.close.assert_called_once_with()
        process.stderr.close.assert_called_once_with()

    @unittest.skipUnless(
        os.name == "posix"
        and all(
            hasattr(signal, name)
            for name in (
                "SIGHUP",
                "SIGQUIT",
                "SIGTERM",
                "pthread_sigmask",
                "sigpending",
                "sigwait",
                "SIG_BLOCK",
                "SIG_SETMASK",
            )
        ),
        "client lifecycle transaction requires POSIX signal controls",
    )
    def test_enforcement_client_lifecycle_covers_initialization_phases(
        self,
    ) -> None:
        phases = (
            "_snapshot_configuration",
            "_pin_executable",
            "_revalidate_snapshot",
        )
        termination_signals = (
            signal.SIGHUP,
            signal.SIGQUIT,
            signal.SIGTERM,
        )
        for phase in phases:
            for signal_number in termination_signals:
                with self.subTest(phase=phase, signal=signal_number):
                    with owner_controlled_temp_root() as temp_root:
                        trusted_gh = temp_root / "trusted-gh"
                        trusted_payload = b"#!/bin/sh\nexit 0\n"
                        trusted_gh.write_bytes(trusted_payload)
                        trusted_gh.chmod(0o700)
                        config_dir, runtime_parent = self._make_private_gh_config(
                            temp_root,
                            hosts_payload=(
                                "github.com:\n"
                                "    git_protocol: https\n"
                                "    users:\n"
                                "        fixture-admin:\n"
                                f"            oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                                "    user: fixture-admin\n"
                                f"    oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                            ),
                        )
                        original_phase = getattr(
                            ENFORCEMENT_MODULE.GitHubApiClient,
                            phase,
                        )
                        injected = False

                        def inject_signal(
                            client: object,
                            *args: object,
                            **kwargs: object,
                        ) -> object:
                            nonlocal injected
                            result = original_phase(client, *args, **kwargs)
                            if not injected:
                                injected = True
                                client._termination_signal_guard._handle_signal(
                                    signal_number,
                                    None,
                                )
                            return result

                        def forward_signal(
                            forwarded: int,
                            secondary_error: BaseException | None,
                        ) -> None:
                            raise _ForwardedFixtureSignal(
                                forwarded,
                                secondary_error,
                            )

                        with (
                            mock.patch.object(
                                ENFORCEMENT_MODULE.GitHubApiClient,
                                phase,
                                autospec=True,
                                side_effect=inject_signal,
                            ),
                            mock.patch.object(
                                ENFORCEMENT_MODULE,
                                "_forward_deferred_termination_signal",
                                side_effect=forward_signal,
                            ),
                            self.assertRaises(_ForwardedFixtureSignal) as raised,
                        ):
                            ENFORCEMENT_MODULE.GitHubApiClient(
                                trusted_gh,
                                hashlib.sha256(trusted_payload).hexdigest(),
                                config_dir,
                                runtime_parent=runtime_parent,
                            )

                        self.assertTrue(injected)
                        self.assertEqual(
                            raised.exception.signal_number,
                            signal_number,
                        )
                        self.assertIsNone(raised.exception.secondary_error)
                        self.assertEqual(
                            list(runtime_parent.glob("run-*")),
                            [],
                        )

    @unittest.skipUnless(
        os.name == "posix"
        and all(
            hasattr(signal, name)
            for name in (
                "SIGTERM",
                "pthread_sigmask",
                "sigpending",
                "sigwait",
                "SIG_BLOCK",
                "SIG_SETMASK",
            )
        ),
        "client lifecycle transaction requires POSIX signal controls",
    )
    def test_enforcement_client_lifecycle_covers_request_gaps_and_parsing(
        self,
    ) -> None:
        for phase in (
            "request-gap",
            "endpoint-validation",
            "run-call-limit",
            "json-parse",
            "snapshot-revalidation",
            "transport-postvalidation",
            "trailer-parse",
        ):
            with self.subTest(phase=phase):
                with owner_controlled_temp_root() as temp_root:
                    trusted_gh = temp_root / "trusted-gh"
                    trusted_payload = b"#!/bin/sh\nexit 0\n"
                    trusted_gh.write_bytes(trusted_payload)
                    trusted_gh.chmod(0o700)
                    config_dir, runtime_parent = self._make_private_gh_config(
                        temp_root,
                        hosts_payload=(
                            "github.com:\n"
                            "    git_protocol: https\n"
                            "    users:\n"
                            "        fixture-admin:\n"
                            f"            oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                            "    user: fixture-admin\n"
                            f"    oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                        ),
                    )
                    client = ENFORCEMENT_MODULE.GitHubApiClient(
                        trusted_gh,
                        hashlib.sha256(trusted_payload).hexdigest(),
                        config_dir,
                        runtime_parent=runtime_parent,
                    )
                    run_path = client._run_directory.path

                    def forward_signal(
                        forwarded: int,
                        secondary_error: BaseException | None,
                    ) -> None:
                        raise _ForwardedFixtureSignal(
                            forwarded,
                            secondary_error,
                        )

                    bounded_context = mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "_bounded_subprocess",
                        return_value=(
                            0,
                            self._curl_response(b'{"id":1,"login":"fixture"}'),
                            b"",
                        ),
                    )
                    original_revalidate = client._revalidate_snapshot
                    revalidation_calls = 0

                    def interrupt_revalidation(
                        **kwargs: object,
                    ) -> None:
                        nonlocal revalidation_calls
                        original_revalidate(**kwargs)
                        revalidation_calls += 1
                        if revalidation_calls == 1:
                            client._termination_signal_guard._handle_signal(
                                signal.SIGTERM,
                                None,
                            )

                    def interrupt_json(*_args: object, **_kwargs: object) -> object:
                        client._termination_signal_guard._handle_signal(
                            signal.SIGTERM,
                            None,
                        )
                        self.fail("termination signal did not interrupt JSON parsing")

                    def interrupt_endpoint_validation(
                        *_args: object,
                        **_kwargs: object,
                    ) -> object:
                        client._termination_signal_guard._handle_signal(
                            signal.SIGTERM,
                            None,
                        )
                        self.fail(
                            "termination signal did not interrupt endpoint validation"
                        )

                    class InterruptingCallCount:
                        def __ge__(self, _other: object) -> bool:
                            client._termination_signal_guard._handle_signal(
                                signal.SIGTERM,
                                None,
                            )
                            raise AssertionError(
                                "termination signal did not interrupt call-limit check"
                            )

                    original_transport_binding = (
                        ENFORCEMENT_MODULE._fixed_curl_trust_binding
                    )
                    transport_revalidation_calls = 0

                    def interrupt_transport_postvalidation(
                        *_args: object,
                        **_kwargs: object,
                    ) -> object:
                        binding = original_transport_binding()
                        original_binding_revalidate = binding.revalidate

                        def interrupt_final_revalidation(
                            **kwargs: object,
                        ) -> None:
                            nonlocal transport_revalidation_calls
                            original_binding_revalidate(**kwargs)
                            transport_revalidation_calls += 1
                            if transport_revalidation_calls == 1:
                                client._termination_signal_guard._handle_signal(
                                    signal.SIGTERM,
                                    None,
                                )

                        binding.revalidate = interrupt_final_revalidation
                        return binding

                    trailer_pattern = mock.Mock()

                    def interrupt_trailer_parse(*_args: object) -> object:
                        client._termination_signal_guard._handle_signal(
                            signal.SIGTERM,
                            None,
                        )
                        self.fail(
                            "termination signal did not interrupt trailer parsing"
                        )

                    trailer_pattern.search.side_effect = interrupt_trailer_parse

                    try:
                        with (
                            mock.patch.object(
                                ENFORCEMENT_MODULE,
                                "_forward_deferred_termination_signal",
                                side_effect=forward_signal,
                            ),
                            bounded_context,
                            self.assertRaises(_ForwardedFixtureSignal) as raised,
                        ):
                            with client:
                                if phase == "request-gap":
                                    client._termination_signal_guard._handle_signal(
                                        signal.SIGTERM,
                                        None,
                                    )
                                elif phase == "endpoint-validation":
                                    with mock.patch.object(
                                        ENFORCEMENT_MODULE.re,
                                        "fullmatch",
                                        side_effect=interrupt_endpoint_validation,
                                    ):
                                        client.get_json("/user")
                                elif phase == "run-call-limit":
                                    client.calls = InterruptingCallCount()
                                    client._run(
                                        ["/fixed/gh", "auth", "token"],
                                        endpoint_class="authentication-preflight",
                                        stdout_limit=2_049,
                                        authentication_preflight=True,
                                    )
                                elif phase == "json-parse":
                                    with mock.patch.object(
                                        ENFORCEMENT_MODULE,
                                        "_parse_json_bytes",
                                        side_effect=interrupt_json,
                                    ):
                                        client.get_json("/user")
                                else:
                                    if phase == "snapshot-revalidation":
                                        patch_target = mock.patch.object(
                                            client,
                                            "_revalidate_snapshot",
                                            side_effect=interrupt_revalidation,
                                        )
                                    elif phase == "transport-postvalidation":
                                        patch_target = mock.patch.object(
                                            ENFORCEMENT_MODULE,
                                            "_fixed_curl_trust_binding",
                                            side_effect=(
                                                interrupt_transport_postvalidation
                                            ),
                                        )
                                    else:
                                        patch_target = mock.patch.object(
                                            ENFORCEMENT_MODULE,
                                            "CURL_TRAILER_PATTERN",
                                            trailer_pattern,
                                        )
                                    with patch_target:
                                        client.get_json("/user")
                    finally:
                        if not client._closed:
                            client.close()

                    self.assertEqual(
                        raised.exception.signal_number,
                        signal.SIGTERM,
                    )
                    self.assertIsNone(raised.exception.secondary_error)
                    self.assertTrue(client._closed)
                    self.assertFalse(run_path.exists())

    @unittest.skipUnless(
        os.name == "posix"
        and all(
            hasattr(signal, name)
            for name in (
                "SIGTERM",
                "pthread_sigmask",
                "sigpending",
                "sigwait",
                "SIG_BLOCK",
                "SIG_SETMASK",
            )
        ),
        "client lifecycle transaction requires POSIX signal controls",
    )
    def test_enforcement_client_closes_on_second_request_revalidation_signal(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            client = ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            )
            run_path = client._run_directory.path
            original_revalidate = client._revalidate_snapshot
            revalidation_calls = 0

            def interrupt_second_revalidation(**kwargs: object) -> None:
                nonlocal revalidation_calls
                original_revalidate(**kwargs)
                if kwargs.get("absolute_deadline") is None:
                    return
                revalidation_calls += 1
                if revalidation_calls == 2:
                    client._termination_signal_guard._handle_signal(
                        signal.SIGTERM,
                        None,
                    )

            def forward_signal(
                forwarded: int,
                secondary_error: BaseException | None,
            ) -> None:
                raise _ForwardedFixtureSignal(
                    forwarded,
                    secondary_error,
                )

            try:
                with (
                    mock.patch.object(
                        client,
                        "_revalidate_snapshot",
                        side_effect=interrupt_second_revalidation,
                    ),
                    mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "_bounded_subprocess",
                        return_value=(
                            0,
                            self._curl_response(b'{"id":1,"login":"fixture"}'),
                            b"",
                        ),
                    ),
                    mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "_forward_deferred_termination_signal",
                        side_effect=forward_signal,
                    ),
                    self.assertRaises(_ForwardedFixtureSignal) as raised,
                ):
                    client.get_json("/user")
            finally:
                if not client._closed:
                    with mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "_forward_deferred_termination_signal",
                        side_effect=forward_signal,
                    ):
                        try:
                            client.close()
                        except _ForwardedFixtureSignal:
                            pass

        self.assertEqual(raised.exception.signal_number, signal.SIGTERM)
        self.assertIsNone(raised.exception.secondary_error)
        self.assertEqual(revalidation_calls, 2)
        self.assertTrue(client._closed)
        self.assertFalse(run_path.exists())
        self.assertEqual(client.total_bytes, 0)

    @unittest.skipUnless(
        os.name == "posix"
        and all(
            hasattr(signal, name)
            for name in (
                "SIGQUIT",
                "pthread_sigmask",
                "sigpending",
                "sigwait",
                "SIG_BLOCK",
                "SIG_SETMASK",
            )
        ),
        "client lifecycle transaction requires POSIX signal controls",
    )
    def test_enforcement_client_finish_forwards_only_after_token_deletion(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(
                temp_root,
                hosts_payload=(
                    "github.com:\n"
                    "    git_protocol: https\n"
                    "    users:\n"
                    "        fixture-admin:\n"
                    f"            oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                    "    user: fixture-admin\n"
                    f"    oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                ),
            )
            client = ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            )
            run_path = client._run_directory.path
            snapshot_hosts = client._config_snapshot_directory.path / "hosts.yml"
            original_finish = client._termination_signal_guard.finish

            def inject_during_finish() -> None:
                self.assertFalse(snapshot_hosts.exists())
                self.assertFalse(run_path.exists())
                client._termination_signal_guard._handle_signal(
                    signal.SIGQUIT,
                    None,
                )
                original_finish()

            def forward_signal(
                forwarded: int,
                secondary_error: BaseException | None,
            ) -> None:
                raise _ForwardedFixtureSignal(
                    forwarded,
                    secondary_error,
                )

            with (
                mock.patch.object(
                    client._termination_signal_guard,
                    "finish",
                    side_effect=inject_during_finish,
                ),
                mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "_forward_deferred_termination_signal",
                    side_effect=forward_signal,
                ),
                self.assertRaises(_ForwardedFixtureSignal) as raised,
            ):
                client.close()

        self.assertEqual(raised.exception.signal_number, signal.SIGQUIT)
        self.assertIsNone(raised.exception.secondary_error)
        self.assertTrue(client._closed)
        self.assertFalse(run_path.exists())

    @unittest.skipUnless(
        os.name == "posix"
        and all(
            hasattr(signal, name)
            for name in (
                "SIGTERM",
                "pthread_sigmask",
                "sigpending",
                "sigwait",
                "SIG_BLOCK",
                "SIG_SETMASK",
            )
        ),
        "client lifecycle transaction requires POSIX signal controls",
    )
    def test_enforcement_client_signal_cleanup_failure_retains_recovery_identity(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(
                temp_root,
                hosts_payload=(
                    "github.com:\n"
                    "    git_protocol: https\n"
                    "    users:\n"
                    "        fixture-admin:\n"
                    f"            oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                    "    user: fixture-admin\n"
                    f"    oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                ),
            )
            client = ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            )
            run_path = client._run_directory.path
            config_fd = client._config_snapshot_directory.fd
            original_unlink = os.unlink

            def reject_token_unlink(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                *,
                dir_fd: int | None = None,
            ) -> None:
                if path == "hosts.yml" and dir_fd == config_fd:
                    raise PermissionError(
                        errno.EACCES,
                        "injected token unlink failure",
                    )
                original_unlink(path, dir_fd=dir_fd)

            def forward_signal(
                forwarded: int,
                secondary_error: BaseException | None,
            ) -> None:
                raise _ForwardedFixtureSignal(
                    forwarded,
                    secondary_error,
                ) from secondary_error

            try:
                with (
                    mock.patch.object(
                        ENFORCEMENT_MODULE.os,
                        "unlink",
                        side_effect=reject_token_unlink,
                    ),
                    mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "_forward_deferred_termination_signal",
                        side_effect=forward_signal,
                    ),
                    self.assertRaises(_ForwardedFixtureSignal) as raised,
                ):
                    with client:
                        client._termination_signal_guard._handle_signal(
                            signal.SIGTERM,
                            None,
                        )

                cleanup_error = raised.exception.secondary_error
                self.assertIsInstance(
                    cleanup_error,
                    ENFORCEMENT_MODULE.EnforcementDoctorError,
                )
                assert isinstance(
                    cleanup_error,
                    ENFORCEMENT_MODULE.EnforcementDoctorError,
                )
                cleanup = cleanup_error.cleanup_failure
                self.assertEqual(cleanup["cleanup_proof"], "inconclusive")
                self.assertEqual(
                    cleanup["retained_runtime"]["path"],
                    str(run_path),
                )
                self.assertEqual(
                    cleanup["retained_runtime"]["path_binding"],
                    "verified",
                )
                retained_labels = {
                    locator["label"] for locator in cleanup["retained_objects"]
                }
                self.assertIn(
                    "GitHub CLI private hosts.yml snapshot",
                    retained_labels,
                )
                self.assertTrue(run_path.exists())
            finally:
                for directory in (
                    run_path / "config",
                    run_path / "bin",
                    run_path / "transport",
                ):
                    if directory.exists():
                        directory.chmod(0o700)
                if run_path.exists():
                    run_path.chmod(0o700)
                    shutil.rmtree(run_path)

    def test_enforcement_run_recomputes_budget_after_snapshot_revalidation(
        self,
    ) -> None:
        client = object.__new__(ENFORCEMENT_MODULE.GitHubApiClient)
        client.executable = "/fixed/gh"
        client.calls = 0
        client.total_bytes = 0
        client.deadline = 100.0
        client._active_processes = {}
        client._environment = {}
        client._execution_cwd = tempfile.gettempdir()
        client._closed = False
        client._revalidate_snapshot = mock.Mock()

        with (
            mock.patch.object(
                ENFORCEMENT_MODULE.time,
                "monotonic",
                side_effect=(90.0, 95.0),
            ),
            mock.patch.object(
                ENFORCEMENT_MODULE,
                "_bounded_subprocess",
                return_value=(0, b"{}", b""),
            ) as bounded,
        ):
            self.assertEqual(
                client._run(
                    ["/fixed/gh", "api", "/user"],
                    endpoint_class="authenticated-user",
                    stdout_limit=1024,
                ),
                b"{}",
            )

        self.assertEqual(client.calls, 1)
        self.assertEqual(
            bounded.call_args.kwargs["timeout_seconds"],
            5.0,
        )
        self.assertEqual(
            bounded.call_args.kwargs["absolute_deadline"],
            100.0,
        )

    def test_enforcement_run_never_spawns_after_revalidation_exhausts_budget(
        self,
    ) -> None:
        client = object.__new__(ENFORCEMENT_MODULE.GitHubApiClient)
        client.executable = "/fixed/gh"
        client.calls = 0
        client.total_bytes = 0
        client.deadline = 100.0
        client._active_processes = {}
        client._environment = {}
        client._execution_cwd = tempfile.gettempdir()
        client._closed = False
        client._revalidate_snapshot = mock.Mock()

        with (
            mock.patch.object(
                ENFORCEMENT_MODULE.time,
                "monotonic",
                side_effect=(90.0, 101.0),
            ),
            mock.patch.object(
                ENFORCEMENT_MODULE,
                "_bounded_subprocess",
            ) as bounded,
            self.assertRaises(ENFORCEMENT_MODULE.EnforcementDoctorError) as raised,
        ):
            client._run(
                ["/fixed/gh", "api", "/user"],
                endpoint_class="authenticated-user",
                stdout_limit=1024,
            )

        self.assertEqual(raised.exception.reason_code, "api-timeout")
        self.assertEqual(client.calls, 0)
        bounded.assert_not_called()

    def test_enforcement_slow_content_revalidation_honors_absolute_deadline(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            client = ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            )
            client._source_content_generation = (-1, -1, -1)

            def exhaust_during_hash(
                _fd: int,
                *,
                deadline_check: object,
            ) -> tuple[str, int]:
                client.deadline = time.monotonic() - 1
                deadline_check()
                self.fail("expired content hash continued")

            try:
                with (
                    mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "_sha256_fd_bounded",
                        side_effect=exhaust_during_hash,
                    ),
                    mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "_bounded_subprocess",
                    ) as bounded,
                    self.assertRaises(
                        ENFORCEMENT_MODULE.EnforcementDoctorError
                    ) as raised,
                ):
                    client.get_json("/user")

                self.assertEqual(raised.exception.reason_code, "api-timeout")
                self.assertEqual(client.calls, 0)
                bounded.assert_not_called()
            finally:
                client._source_content_generation = (
                    ENFORCEMENT_MODULE._file_content_generation(
                        os.fstat(client._source_fd)
                    )
                )
                client.close()

    def test_enforcement_revalidation_cache_bounds_total_call_amplification(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            client = ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            )
            try:
                with (
                    mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "_sha256_fd_bounded",
                        wraps=ENFORCEMENT_MODULE._sha256_fd_bounded,
                    ) as executable_hash,
                    mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "_read_fd_payload_bounded",
                        wraps=ENFORCEMENT_MODULE._read_fd_payload_bounded,
                    ) as config_read,
                ):
                    for _ in range(ENFORCEMENT_MODULE.MAX_API_CALLS):
                        client._revalidate_snapshot()

                executable_hash.assert_not_called()
                config_read.assert_not_called()
            finally:
                client.close()

    def test_enforcement_revalidation_cache_rehashes_content_generation_drift(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            changed_payload = b"#!/bin/sh\nexit 9\n"
            self.assertEqual(len(trusted_payload), len(changed_payload))
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            client = ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            )
            trusted_gh.write_bytes(changed_payload)
            trusted_gh.chmod(0o700)
            try:
                with (
                    mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "_sha256_fd_bounded",
                        wraps=ENFORCEMENT_MODULE._sha256_fd_bounded,
                    ) as executable_hash,
                    self.assertRaises(
                        ENFORCEMENT_MODULE.EnforcementDoctorError
                    ) as raised,
                ):
                    client._revalidate_snapshot()

                self.assertEqual(
                    raised.exception.reason_code,
                    "collector-inconclusive",
                )
                self.assertGreaterEqual(executable_hash.call_count, 1)
            finally:
                client.close()

    def test_enforcement_subprocess_selector_failures_terminate_before_return(
        self,
    ) -> None:
        for failure_point in (
            "create",
            "register",
            "select",
            "read",
            "unregister",
            "wait",
        ):
            with self.subTest(failure=failure_point):
                process = mock.Mock()
                process.pid = 4242
                process.stdout = mock.Mock()
                process.stderr = mock.Mock()
                process.stdout.fileno.return_value = 101
                process.stderr.fileno.return_value = 102
                selector = mock.Mock()
                key = mock.Mock()
                key.data = ("stdout", 1024)
                key.fileobj = process.stdout
                selector.get_map.return_value = {"stdout": key}
                selector.select.return_value = [
                    (key, ENFORCEMENT_MODULE.selectors.EVENT_READ)
                ]
                if failure_point == "register":
                    selector.register.side_effect = OSError(
                        errno.EIO,
                        "injected selector register failure",
                    )
                elif failure_point == "select":
                    selector.select.side_effect = OSError(
                        errno.EIO,
                        "injected selector select failure",
                    )
                elif failure_point == "unregister":
                    selector.unregister.side_effect = OSError(
                        errno.EIO,
                        "injected selector unregister failure",
                    )
                elif failure_point == "wait":
                    selector.get_map.return_value = {}
                    process.wait.side_effect = OSError(
                        errno.EIO,
                        "injected process wait failure",
                    )

                with (
                    mock.patch.object(
                        ENFORCEMENT_MODULE.subprocess,
                        "Popen",
                        return_value=process,
                    ),
                    mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "_terminate_drain_reap",
                        return_value=[],
                    ) as cleanup,
                    mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "_seal_process_group_before_reap",
                        return_value=[],
                    ),
                ):
                    if failure_point == "create":
                        selector_context = mock.patch.object(
                            ENFORCEMENT_MODULE.selectors,
                            "DefaultSelector",
                            side_effect=OSError(
                                errno.EIO,
                                "injected selector creation failure",
                            ),
                        )
                    else:
                        selector_context = mock.patch.object(
                            ENFORCEMENT_MODULE.selectors,
                            "DefaultSelector",
                            return_value=selector,
                        )
                    with selector_context:
                        if failure_point == "read":
                            read_context = mock.patch.object(
                                ENFORCEMENT_MODULE.os,
                                "read",
                                side_effect=OSError(
                                    errno.EIO,
                                    "injected stream read failure",
                                ),
                            )
                        elif failure_point == "unregister":
                            read_context = mock.patch.object(
                                ENFORCEMENT_MODULE.os,
                                "read",
                                return_value=b"",
                            )
                        else:
                            read_context = nullcontext()
                        with read_context:
                            with self.assertRaises(
                                ENFORCEMENT_MODULE.EnforcementDoctorError
                            ) as raised:
                                ENFORCEMENT_MODULE._bounded_subprocess(
                                    ["/fixed/gh", "api", "/user"],
                                    environment={},
                                    execution_cwd=tempfile.gettempdir(),
                                    endpoint_class="authenticated-user",
                                    process_registry={},
                                    timeout_seconds=1,
                                    stdout_limit=1024,
                                    stderr_limit=1024,
                                )

                cleanup.assert_called_once()
                managed = cleanup.call_args.args[0]
                self.assertIs(managed.process, process)
                self.assertEqual(
                    raised.exception.reason_code,
                    "collector-inconclusive",
                )
                self.assertEqual(
                    raised.exception.api_failure,
                    {
                        "endpoint_class": "authenticated-user",
                        "failure_kind": "process-io",
                        "http_status": None,
                    },
                )
                process.stdout.close.assert_called_once()
                process.stderr.close.assert_called_once()
                if failure_point != "create":
                    selector.close.assert_called_once()

    @unittest.skipUnless(os.name == "posix", "requires POSIX process groups")
    def test_enforcement_subprocess_seals_group_before_reap_and_pid_reuse(
        self,
    ) -> None:
        process = mock.Mock()
        process.pid = 4242
        process.stdout = mock.Mock()
        process.stderr = mock.Mock()
        selector = mock.Mock()
        selector.get_map.return_value = {}
        process_registry: dict[int, object] = {}
        pgid_reused = False
        events: list[tuple[str, int]] = []

        def record_group_signal(process_group: int, signal_number: int) -> None:
            if pgid_reused:
                self.fail("numeric PGID was used after direct-child reap")
            events.append(("killpg", signal_number))
            self.assertEqual(process_group, process.pid)

        def reap_and_reuse(*, timeout: float) -> int:
            nonlocal pgid_reused
            self.assertGreater(timeout, 0)
            events.append(("wait", 0))
            pgid_reused = True
            return 0

        process.wait.side_effect = reap_and_reuse
        with (
            mock.patch.object(
                ENFORCEMENT_MODULE.subprocess,
                "Popen",
                return_value=process,
            ),
            mock.patch.object(
                ENFORCEMENT_MODULE.selectors,
                "DefaultSelector",
                return_value=selector,
            ),
            mock.patch.object(
                ENFORCEMENT_MODULE.os,
                "killpg",
                side_effect=record_group_signal,
            ) as killpg,
        ):
            return_code, stdout, stderr = ENFORCEMENT_MODULE._bounded_subprocess(
                ["/fixed/gh", "api", "/user"],
                environment={},
                execution_cwd=tempfile.gettempdir(),
                endpoint_class="authenticated-user",
                process_registry=process_registry,
                timeout_seconds=1,
                stdout_limit=1024,
                stderr_limit=1024,
            )

        self.assertEqual(return_code, 0)
        self.assertEqual(stdout, b"")
        self.assertEqual(stderr, b"")
        self.assertEqual(
            events,
            [("killpg", signal.SIGKILL), ("wait", 0)],
        )
        killpg.assert_called_once_with(process.pid, signal.SIGKILL)
        process.poll.assert_not_called()
        self.assertEqual(process_registry, {})
        selector.close.assert_called_once()
        process.stdout.close.assert_called_once()
        process.stderr.close.assert_called_once()

    def test_enforcement_subprocess_resource_failure_overrides_limit_error(
        self,
    ) -> None:
        process = mock.Mock()
        process.stdout = mock.Mock()
        process.stderr = mock.Mock()
        process.stdout.fileno.return_value = 101
        selector = mock.Mock()
        key = mock.Mock()
        key.data = ("stdout", 1)
        key.fileobj = process.stdout
        selector.get_map.return_value = {"stdout": key}
        selector.select.return_value = [(key, ENFORCEMENT_MODULE.selectors.EVENT_READ)]
        selector.close.side_effect = OSError(
            errno.EIO,
            "injected selector close failure",
        )
        with (
            mock.patch.object(
                ENFORCEMENT_MODULE.subprocess,
                "Popen",
                return_value=process,
            ),
            mock.patch.object(
                ENFORCEMENT_MODULE.selectors,
                "DefaultSelector",
                return_value=selector,
            ),
            mock.patch.object(
                ENFORCEMENT_MODULE.os,
                "read",
                return_value=b"too large",
            ),
            mock.patch.object(
                ENFORCEMENT_MODULE,
                "_terminate_drain_reap",
                return_value=[],
            ) as cleanup,
            self.assertRaises(ENFORCEMENT_MODULE.EnforcementDoctorError) as raised,
        ):
            ENFORCEMENT_MODULE._bounded_subprocess(
                ["/fixed/gh", "api", "/user"],
                environment={},
                execution_cwd=tempfile.gettempdir(),
                endpoint_class="authenticated-user",
                process_registry={},
                timeout_seconds=1,
                stdout_limit=1,
                stderr_limit=1024,
            )

        cleanup.assert_called_once()
        managed = cleanup.call_args.args[0]
        self.assertIs(managed.process, process)
        self.assertEqual(raised.exception.reason_code, "collector-inconclusive")
        self.assertEqual(
            raised.exception.api_failure,
            {
                "endpoint_class": "authenticated-user",
                "failure_kind": "process-resource",
                "http_status": None,
            },
        )

    def test_enforcement_subprocess_cleanup_failure_is_structured(
        self,
    ) -> None:
        process = mock.Mock()
        process.pid = 4242
        process.stdout = mock.Mock()
        process.stderr = mock.Mock()
        process_registry: dict[int, object] = {}
        with (
            mock.patch.object(
                ENFORCEMENT_MODULE.subprocess,
                "Popen",
                return_value=process,
            ),
            mock.patch.object(
                ENFORCEMENT_MODULE.selectors,
                "DefaultSelector",
                side_effect=OSError(
                    errno.EIO,
                    "injected selector creation failure",
                ),
            ),
            mock.patch.object(
                ENFORCEMENT_MODULE,
                "_terminate_drain_reap",
                return_value=["process-not-reaped"],
            ) as cleanup,
            self.assertRaises(ENFORCEMENT_MODULE.EnforcementDoctorError) as raised,
        ):
            ENFORCEMENT_MODULE._bounded_subprocess(
                ["/fixed/gh", "api", "/user"],
                environment={},
                execution_cwd=tempfile.gettempdir(),
                endpoint_class="authenticated-user",
                process_registry=process_registry,
                timeout_seconds=1,
                stdout_limit=1024,
                stderr_limit=1024,
            )

        cleanup.assert_called_once()
        managed = cleanup.call_args.args[0]
        self.assertIs(managed.process, process)
        self.assertIs(process_registry[process.pid], managed)
        self.assertEqual(raised.exception.reason_code, "collector-inconclusive")
        self.assertEqual(
            raised.exception.api_failure,
            {
                "endpoint_class": "authenticated-user",
                "failure_kind": "process-cleanup",
                "http_status": None,
            },
        )
        process.stdout.close.assert_not_called()
        process.stderr.close.assert_not_called()

    def test_enforcement_process_cleanup_bounds_kill_and_reap_failure(
        self,
    ) -> None:
        stdout_read_fd, stdout_write_fd = os.pipe()
        stderr_read_fd, stderr_write_fd = os.pipe()
        stdout = os.fdopen(stdout_read_fd, "rb", buffering=0)
        stderr = os.fdopen(stderr_read_fd, "rb", buffering=0)
        process = mock.Mock()
        process.pid = 424242
        process.stdout = stdout
        process.stderr = stderr
        observed_signals: list[int] = []
        observed_wait_timeouts: list[float] = []
        events: list[str] = []
        managed = ENFORCEMENT_MODULE._ManagedProcess(process)

        def record_signal(_managed: object, signal_number: int) -> str:
            events.append(f"signal-{signal_number}")
            observed_signals.append(signal_number)
            return "sent" if signal_number == signal.SIGTERM else "failed"

        def record_direct_kill(pid: int, signal_number: int) -> None:
            events.append("direct-kill")
            self.assertEqual((pid, signal_number), (process.pid, signal.SIGKILL))

        def reject_reap(*, timeout: float) -> None:
            events.append("wait")
            observed_wait_timeouts.append(timeout)
            raise subprocess.TimeoutExpired("fixture-gh", timeout)

        try:
            with (
                mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "GH_PROCESS_TERM_GRACE_SECONDS",
                    0.0,
                ),
                mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "GH_PROCESS_REAP_DEADLINE_SECONDS",
                    0.02,
                ),
                mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "GH_PROCESS_CLEANUP_POLL_SECONDS",
                    0.001,
                ),
                mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "_signal_managed_process",
                    side_effect=record_signal,
                ),
                mock.patch.object(
                    ENFORCEMENT_MODULE.os,
                    "kill",
                    side_effect=record_direct_kill,
                ),
            ):
                process.wait.side_effect = reject_reap
                failures = ENFORCEMENT_MODULE._terminate_drain_reap(managed)
        finally:
            stdout.close()
            stderr.close()
            os.close(stdout_write_fd)
            os.close(stderr_write_fd)

        self.assertEqual(observed_signals, [signal.SIGTERM, signal.SIGKILL])
        self.assertEqual(
            events[:3],
            [
                f"signal-{signal.SIGTERM}",
                f"signal-{signal.SIGKILL}",
                "direct-kill",
            ],
        )
        self.assertTrue(all(event == "wait" for event in events[3:]))
        self.assertTrue(observed_wait_timeouts)
        self.assertTrue(
            all(0 <= timeout <= 0.0011 for timeout in observed_wait_timeouts)
        )
        self.assertIn("process-reap-timeout", failures)
        self.assertIn("process-not-reaped", failures)
        self.assertIn("process-group-not-quiescent", failures)
        self.assertEqual(
            managed.group_state,
            ENFORCEMENT_MODULE.GROUP_SIGNAL_UNPROVEN_BEFORE_REAP,
        )
        process.poll.assert_not_called()

    def test_enforcement_darwin_permission_requires_unreaped_exit_proof(
        self,
    ) -> None:
        for leader_exited, expected_failures, expected_group_state in (
            (
                True,
                [],
                ENFORCEMENT_MODULE.GROUP_NO_SIGNALABLE_MEMBERS_BEFORE_REAP,
            ),
            (
                False,
                ["process-group-not-quiescent"],
                ENFORCEMENT_MODULE.GROUP_SIGNAL_UNPROVEN_BEFORE_REAP,
            ),
        ):
            with self.subTest(leader_exited=leader_exited):
                process = mock.Mock()
                process.pid = 4242
                managed = ENFORCEMENT_MODULE._ManagedProcess(process)
                with (
                    mock.patch.object(
                        ENFORCEMENT_MODULE.sys,
                        "platform",
                        "darwin",
                    ),
                    mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "_signal_managed_process",
                        return_value="permission",
                    ),
                    mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "_leader_exited_without_reap",
                        return_value=leader_exited,
                    ) as exit_proof,
                    mock.patch.object(
                        ENFORCEMENT_MODULE.os,
                        "kill",
                    ) as direct_kill,
                ):
                    failures = ENFORCEMENT_MODULE._seal_process_group_before_reap(
                        managed
                    )

                self.assertEqual(failures, expected_failures)
                self.assertEqual(managed.group_state, expected_group_state)
                exit_proof.assert_called_once_with(managed)
                if leader_exited:
                    direct_kill.assert_not_called()
                else:
                    direct_kill.assert_called_once_with(
                        process.pid,
                        signal.SIGKILL,
                    )

    @unittest.skipUnless(os.name == "posix", "requires POSIX process groups")
    def test_enforcement_subprocess_kills_and_reaps_term_ignoring_process(
        self,
    ) -> None:
        original_popen = subprocess.Popen
        original_signal_managed_process = ENFORCEMENT_MODULE._signal_managed_process
        spawned: list[subprocess.Popen[bytes]] = []

        def record_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            process = original_popen(*args, **kwargs)
            spawned.append(process)
            return process

        program = (
            "import signal,time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "print('ready', flush=True)\n"
            "time.sleep(60)\n"
        )
        try:
            with (
                mock.patch.object(
                    ENFORCEMENT_MODULE.subprocess,
                    "Popen",
                    side_effect=record_popen,
                ),
                mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "GH_PROCESS_TERM_GRACE_SECONDS",
                    0.05,
                ),
                mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "GH_PROCESS_REAP_DEADLINE_SECONDS",
                    1.0,
                ),
                mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "_signal_managed_process",
                    wraps=original_signal_managed_process,
                ) as signaller,
                self.assertRaises(ENFORCEMENT_MODULE.EnforcementDoctorError) as raised,
            ):
                ENFORCEMENT_MODULE._bounded_subprocess(
                    [sys.executable, "-c", program],
                    environment={"LC_ALL": "C"},
                    execution_cwd=tempfile.gettempdir(),
                    endpoint_class="authenticated-user",
                    process_registry={},
                    timeout_seconds=0.5,
                    stdout_limit=1024,
                    stderr_limit=1024,
                )
        finally:
            for process in spawned:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=1)

        self.assertEqual(raised.exception.reason_code, "api-timeout")
        self.assertEqual(len(spawned), 1)
        self.assertIsNotNone(spawned[0].returncode)
        observed_signals = [call.args[1] for call in signaller.call_args_list]
        self.assertEqual(observed_signals, [signal.SIGTERM, signal.SIGKILL])
        with self.assertRaises(ProcessLookupError):
            os.kill(spawned[0].pid, 0)

    @unittest.skipUnless(os.name == "posix", "requires POSIX process groups")
    def test_enforcement_client_reaps_active_process_before_first_unlink(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            client = ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            )
            run_path = client._run_directory.path
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    (
                        "import signal,time\n"
                        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                        "print('ready', flush=True)\n"
                        "time.sleep(60)\n"
                    ),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                close_fds=True,
            )
            assert process.stdout is not None
            readiness_selector = ENFORCEMENT_MODULE.selectors.DefaultSelector()
            readiness_selector.register(
                process.stdout,
                ENFORCEMENT_MODULE.selectors.EVENT_READ,
            )
            try:
                self.assertTrue(readiness_selector.select(timeout=2))
                self.assertEqual(process.stdout.readline(), b"ready\n")
            finally:
                readiness_selector.close()
            managed = ENFORCEMENT_MODULE._ManagedProcess(process)
            client._active_processes[process.pid] = managed
            original_unlink = os.unlink
            unlink_observations = 0

            def require_quiescence_before_unlink(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                *,
                dir_fd: int | None = None,
            ) -> None:
                nonlocal unlink_observations
                unlink_observations += 1
                self.assertIsNotNone(process.returncode)
                self.assertIn(
                    managed.group_state,
                    ENFORCEMENT_MODULE.SAFE_TERMINAL_GROUP_STATES,
                )
                original_unlink(path, dir_fd=dir_fd)

            try:
                with (
                    mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "GH_PROCESS_TERM_GRACE_SECONDS",
                        0.05,
                    ),
                    mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "GH_PROCESS_REAP_DEADLINE_SECONDS",
                        1.0,
                    ),
                    mock.patch.object(
                        ENFORCEMENT_MODULE.os,
                        "unlink",
                        side_effect=require_quiescence_before_unlink,
                    ),
                ):
                    client.close()
            finally:
                if process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=1)
                if run_path.exists():
                    shutil.rmtree(run_path)

        self.assertGreater(unlink_observations, 0)
        self.assertFalse(run_path.exists())

    @unittest.skipUnless(os.name == "posix", "requires POSIX process groups")
    def test_enforcement_client_close_retry_never_uses_reused_process_group(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            client = ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            )
            run_path = client._run_directory.path
            process = mock.Mock()
            process.pid = 4242
            process.stdout = None
            process.stderr = None
            managed = ENFORCEMENT_MODULE._ManagedProcess(process)
            pgid_reused = False
            numeric_uses_after_reap: list[tuple[str, int]] = []

            def signal_group(process_group: int, signal_number: int) -> None:
                if pgid_reused:
                    numeric_uses_after_reap.append(("killpg", signal_number))
                self.assertEqual(process_group, process.pid)
                if signal_number == signal.SIGKILL:
                    raise OSError(errno.EIO, "injected group signal failure")

            def signal_leader(pid: int, signal_number: int) -> None:
                if pgid_reused:
                    numeric_uses_after_reap.append(("kill", signal_number))
                self.assertEqual((pid, signal_number), (process.pid, signal.SIGKILL))

            def reap_and_reuse(*, timeout: float) -> int:
                nonlocal pgid_reused
                self.assertGreaterEqual(timeout, 0)
                pgid_reused = True
                return 0

            process.wait.side_effect = reap_and_reuse
            try:
                with (
                    mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "GH_PROCESS_TERM_GRACE_SECONDS",
                        0.0,
                    ),
                    mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "GH_PROCESS_REAP_DEADLINE_SECONDS",
                        0.05,
                    ),
                    mock.patch.object(
                        ENFORCEMENT_MODULE.os,
                        "killpg",
                        side_effect=signal_group,
                    ) as killpg,
                    mock.patch.object(
                        ENFORCEMENT_MODULE.os,
                        "kill",
                        side_effect=signal_leader,
                    ) as kill,
                ):
                    first_failures = ENFORCEMENT_MODULE._terminate_drain_reap(managed)
                    self.assertEqual(
                        first_failures,
                        ["process-group-not-quiescent"],
                    )
                    self.assertEqual(managed.leader_state, "reaped")
                    self.assertEqual(
                        managed.group_state,
                        ENFORCEMENT_MODULE.GROUP_SIGNAL_UNPROVEN_BEFORE_REAP,
                    )
                    client._active_processes[process.pid] = managed

                    with (
                        mock.patch.object(
                            ENFORCEMENT_MODULE.os,
                            "unlink",
                            wraps=os.unlink,
                        ) as unlink,
                        self.assertRaises(
                            ENFORCEMENT_MODULE.EnforcementDoctorError
                        ) as raised,
                    ):
                        client.close()

                    self.assertEqual(
                        killpg.call_args_list,
                        [
                            mock.call(process.pid, signal.SIGTERM),
                            mock.call(process.pid, signal.SIGKILL),
                        ],
                    )
                    kill.assert_called_once_with(process.pid, signal.SIGKILL)
                    self.assertEqual(process.wait.call_count, 1)
                    self.assertEqual(numeric_uses_after_reap, [])
                    process.poll.assert_not_called()
                    unlink.assert_not_called()

                cleanup = raised.exception.cleanup_failure
                self.assertEqual(cleanup["cleanup_proof"], "inconclusive")
                self.assertIn(
                    "active-process-cleanup",
                    cleanup["failed_operations"],
                )
                self.assertEqual(
                    cleanup["unresolved_processes"],
                    [
                        {
                            "pid": process.pid,
                            "process_group": process.pid,
                            "quiescence": "unproven",
                        }
                    ],
                )
                self.assertEqual(
                    cleanup["retained_runtime"]["path"],
                    str(run_path),
                )
                self.assertEqual(
                    cleanup["retained_runtime"]["path_binding"],
                    "verified",
                )
                retained_labels = {
                    locator["label"] for locator in cleanup["retained_objects"]
                }
                self.assertIn(
                    "GitHub CLI private hosts.yml snapshot",
                    retained_labels,
                )
                self.assertIn(
                    "GitHub CLI executable snapshot",
                    retained_labels,
                )
                self.assertTrue(run_path.exists())
            finally:
                for directory in (
                    run_path / "config",
                    run_path / "bin",
                    run_path / "transport",
                ):
                    if directory.exists():
                        directory.chmod(0o700)
                if run_path.exists():
                    run_path.chmod(0o700)
                    shutil.rmtree(run_path)

    def test_bound_regular_file_closes_fd_after_bounded_read_failure(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            config_dir = temp_root / "config"
            config_dir.mkdir(mode=0o700)
            hosts_path = config_dir / "hosts.yml"
            hosts_path.write_bytes(b"x" * (ENFORCEMENT_MODULE.MAX_GH_CONFIG_BYTES + 1))
            hosts_path.chmod(0o600)
            parent = ENFORCEMENT_MODULE._BoundDirectory(
                config_dir,
                label="fixture config directory",
            )
            original_open = os.open
            opened_fds: list[int] = []

            def capture_open(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                fd = original_open(path, flags, mode, dir_fd=dir_fd)
                if path == "hosts.yml" and dir_fd == parent.fd:
                    opened_fds.append(fd)
                return fd

            try:
                with (
                    mock.patch.object(
                        ENFORCEMENT_MODULE.os,
                        "open",
                        side_effect=capture_open,
                    ),
                    self.assertRaises(
                        ENFORCEMENT_MODULE.EnforcementDoctorError
                    ) as raised,
                ):
                    ENFORCEMENT_MODULE._BoundRegularFile(
                        parent,
                        "hosts.yml",
                        label="fixture hosts.yml",
                        max_bytes=ENFORCEMENT_MODULE.MAX_GH_CONFIG_BYTES,
                    )
            finally:
                parent.close()

        self.assertEqual(raised.exception.reason_code, "collector-unavailable")
        self.assertEqual(len(opened_fds), 1)
        with self.assertRaises(OSError) as closed:
            os.fstat(opened_fds[0])
        self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_bound_regular_file_closes_fd_after_parent_revalidation_failure(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            config_dir = temp_root / "config"
            config_dir.mkdir(mode=0o700)
            hosts_path = config_dir / "hosts.yml"
            hosts_path.write_bytes(b"fixture\n")
            hosts_path.chmod(0o600)
            parent = ENFORCEMENT_MODULE._BoundDirectory(
                config_dir,
                label="fixture config directory",
            )
            original_open = os.open
            original_revalidate = parent.revalidate
            opened_fds: list[int] = []
            revalidation_calls = 0

            def capture_open(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                fd = original_open(path, flags, mode, dir_fd=dir_fd)
                if path == "hosts.yml" and dir_fd == parent.fd:
                    opened_fds.append(fd)
                return fd

            def fail_final_parent_revalidation(
                *,
                deadline_check: object = None,
            ) -> None:
                nonlocal revalidation_calls
                revalidation_calls += 1
                if revalidation_calls == 2:
                    raise ENFORCEMENT_MODULE._blocked(
                        "collector-inconclusive",
                        "fixture parent revalidation failure",
                    )
                original_revalidate(deadline_check=deadline_check)

            try:
                with (
                    mock.patch.object(
                        ENFORCEMENT_MODULE.os,
                        "open",
                        side_effect=capture_open,
                    ),
                    mock.patch.object(
                        parent,
                        "revalidate",
                        side_effect=fail_final_parent_revalidation,
                    ),
                    self.assertRaises(
                        ENFORCEMENT_MODULE.EnforcementDoctorError
                    ) as raised,
                ):
                    ENFORCEMENT_MODULE._BoundRegularFile(
                        parent,
                        "hosts.yml",
                        label="fixture hosts.yml",
                        max_bytes=ENFORCEMENT_MODULE.MAX_GH_CONFIG_BYTES,
                    )
            finally:
                parent.close()

        self.assertEqual(raised.exception.reason_code, "collector-inconclusive")
        self.assertEqual(revalidation_calls, 2)
        self.assertEqual(len(opened_fds), 1)
        with self.assertRaises(OSError) as closed:
            os.fstat(opened_fds[0])
        self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_enforcement_gh_cleanup_removes_identity_bound_policy_drift(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            client = ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            )
            run_path = client._run_directory.path
            snapshot_hosts = client._config_snapshot_directory.path / "hosts.yml"
            snapshot_hosts.chmod(0o644)

            with self.assertRaises(ENFORCEMENT_MODULE.EnforcementDoctorError) as raised:
                client.close()

            self.assertEqual(
                raised.exception.reason_code,
                "collector-inconclusive",
            )
            self.assertEqual(
                raised.exception.cleanup_failure["cleanup_proof"],
                "complete",
            )
            self.assertIn(
                "pre-cleanup-revalidation",
                raised.exception.cleanup_failure["failed_operations"],
            )
            self.assertNotIn(
                "retained_runtime",
                raised.exception.cleanup_failure,
            )
            self.assertFalse(run_path.exists())

    def test_enforcement_gh_cleanup_reports_unlink_failure_locator(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(
                temp_root,
                hosts_payload=(
                    "github.com:\n"
                    "    git_protocol: https\n"
                    "    users:\n"
                    "        fixture-admin:\n"
                    f"            oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                    "    user: fixture-admin\n"
                    f"    oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                ),
            )
            client = ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            )
            run_path = client._run_directory.path
            run_status = run_path.stat()
            snapshot_hosts = client._config_snapshot_directory.path / "hosts.yml"
            snapshot_hosts.chmod(0o644)
            config_fd = client._config_snapshot_directory.fd
            original_unlink = os.unlink

            def reject_token_unlink(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                *,
                dir_fd: int | None = None,
            ) -> None:
                if path == "hosts.yml" and dir_fd == config_fd:
                    raise PermissionError(errno.EACCES, "fixture unlink failure")
                original_unlink(path, dir_fd=dir_fd)

            try:
                with mock.patch.object(
                    ENFORCEMENT_MODULE.os,
                    "unlink",
                    side_effect=reject_token_unlink,
                ):
                    with self.assertRaises(
                        ENFORCEMENT_MODULE.EnforcementDoctorError
                    ) as raised:
                        client.close()

                self.assertEqual(
                    raised.exception.reason_code,
                    "collector-inconclusive",
                )
                cleanup = raised.exception.cleanup_failure
                self.assertEqual(cleanup["cleanup_proof"], "inconclusive")
                self.assertIn("pre-cleanup-revalidation", cleanup["failed_operations"])
                self.assertIn("unlink-hosts.yml", cleanup["failed_operations"])
                self.assertIn(
                    "remove-config-directory",
                    cleanup["failed_operations"],
                )
                self.assertIn("remove-run-directory", cleanup["failed_operations"])
                locator = cleanup["retained_runtime"]
                self.assertEqual(locator["path"], str(run_path))
                self.assertEqual(locator["path_binding"], "verified")
                self.assertEqual(locator["device"], run_status.st_dev)
                self.assertEqual(locator["inode"], run_status.st_ino)
                self.assertTrue(snapshot_hosts.exists())
            finally:
                if run_path.exists():
                    shutil.rmtree(run_path)

    def test_enforcement_gh_cleanup_does_not_trust_missing_bound_name(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(
                temp_root,
                hosts_payload=(
                    "github.com:\n"
                    "    git_protocol: https\n"
                    "    users:\n"
                    "        fixture-admin:\n"
                    f"            oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                    "    user: fixture-admin\n"
                    f"    oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                ),
            )
            client = ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            )
            snapshot_hosts = client._config_snapshot_directory.path / "hosts.yml"
            relocated_hosts = temp_root / "relocated-hosts.yml"
            expected_status = snapshot_hosts.stat()
            client._config_snapshot_directory.set_owner_mode(0o700)
            snapshot_hosts.rename(relocated_hosts)

            try:
                with self.assertRaises(
                    ENFORCEMENT_MODULE.EnforcementDoctorError
                ) as raised:
                    client.close()

                cleanup = raised.exception.cleanup_failure
                self.assertEqual(cleanup["cleanup_proof"], "inconclusive")
                self.assertIn("unlink-hosts.yml", cleanup["failed_operations"])
                hosts_locators = [
                    locator
                    for locator in cleanup["retained_objects"]
                    if locator["label"] == "GitHub CLI private hosts.yml snapshot"
                ]
                self.assertEqual(len(hosts_locators), 1)
                self.assertEqual(
                    hosts_locators[0]["device"],
                    expected_status.st_dev,
                )
                self.assertEqual(
                    hosts_locators[0]["inode"],
                    expected_status.st_ino,
                )
                self.assertEqual(
                    hosts_locators[0]["path_binding"],
                    "unverified",
                )
                self.assertNotIn("path", hosts_locators[0])
            finally:
                if relocated_hosts.exists():
                    relocated_hosts.unlink()

    def test_enforcement_gh_cleanup_reports_rmdir_failure_locator(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            client = ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            )
            run_path = client._run_directory.path
            run_status = run_path.stat()
            run_name = client._run_name
            runtime_parent_fd = client._runtime_parent.fd
            original_rmdir = os.rmdir

            def reject_run_rmdir(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                *,
                dir_fd: int | None = None,
            ) -> None:
                if path == run_name and dir_fd == runtime_parent_fd:
                    raise PermissionError(errno.EACCES, "fixture rmdir failure")
                original_rmdir(path, dir_fd=dir_fd)

            try:
                with mock.patch.object(
                    ENFORCEMENT_MODULE.os,
                    "rmdir",
                    side_effect=reject_run_rmdir,
                ):
                    with self.assertRaises(
                        ENFORCEMENT_MODULE.EnforcementDoctorError
                    ) as raised:
                        client.close()

                cleanup = raised.exception.cleanup_failure
                self.assertEqual(cleanup["cleanup_proof"], "inconclusive")
                self.assertEqual(
                    cleanup["failed_operations"],
                    ["remove-run-directory"],
                )
                locator = cleanup["retained_runtime"]
                self.assertEqual(locator["path"], str(run_path))
                self.assertEqual(locator["path_binding"], "verified")
                self.assertEqual(locator["device"], run_status.st_dev)
                self.assertEqual(locator["inode"], run_status.st_ino)
                self.assertEqual(list(run_path.iterdir()), [])
            finally:
                if run_path.exists():
                    run_path.rmdir()

    def test_enforcement_gh_cleanup_reports_fchmod_failure_locator(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(
                temp_root,
                hosts_payload=(
                    "github.com:\n"
                    "    git_protocol: https\n"
                    "    users:\n"
                    "        fixture-admin:\n"
                    f"            oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                    "    user: fixture-admin\n"
                    f"    oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                ),
            )
            client = ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            )
            run_path = client._run_directory.path
            config_snapshot = client._config_snapshot_directory.path
            config_fd = client._config_snapshot_directory.fd
            original_fchmod = os.fchmod
            original_unlink = os.unlink

            def reject_config_fchmod(fd: int, mode: int) -> None:
                if fd == config_fd:
                    raise PermissionError(errno.EACCES, "fixture fchmod failure")
                original_fchmod(fd, mode)

            def reject_hosts_unlink(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                *,
                dir_fd: int | None = None,
            ) -> None:
                if path == "hosts.yml" and dir_fd == config_fd:
                    raise PermissionError(errno.EACCES, "fixture unlink failure")
                original_unlink(path, dir_fd=dir_fd)

            try:
                with (
                    mock.patch.object(
                        ENFORCEMENT_MODULE.os,
                        "fchmod",
                        side_effect=reject_config_fchmod,
                    ),
                    mock.patch.object(
                        ENFORCEMENT_MODULE.os,
                        "unlink",
                        side_effect=reject_hosts_unlink,
                    ),
                ):
                    with self.assertRaises(
                        ENFORCEMENT_MODULE.EnforcementDoctorError
                    ) as raised:
                        client.close()

                cleanup = raised.exception.cleanup_failure
                self.assertEqual(cleanup["cleanup_proof"], "inconclusive")
                self.assertIn(
                    "config-directory-owner-mode",
                    cleanup["failed_operations"],
                )
                self.assertIn("unlink-hosts.yml", cleanup["failed_operations"])
                self.assertEqual(
                    cleanup["retained_runtime"]["path"],
                    str(run_path),
                )
                self.assertEqual(
                    cleanup["retained_runtime"]["path_binding"],
                    "verified",
                )
            finally:
                if config_snapshot.exists():
                    config_snapshot.chmod(0o700)
                if run_path.exists():
                    shutil.rmtree(run_path)

    def test_enforcement_gh_cleanup_fchmod_failure_stays_inconclusive_after_removal(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            client = ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            )
            run_path = client._run_directory.path
            config_fd = client._config_snapshot_directory.fd
            original_fchmod = os.fchmod

            def change_then_reject_config_fchmod(fd: int, mode: int) -> None:
                original_fchmod(fd, mode)
                if fd == config_fd:
                    raise PermissionError(errno.EACCES, "fixture fchmod failure")

            with mock.patch.object(
                ENFORCEMENT_MODULE.os,
                "fchmod",
                side_effect=change_then_reject_config_fchmod,
            ):
                with self.assertRaises(
                    ENFORCEMENT_MODULE.EnforcementDoctorError
                ) as raised:
                    client.close()

            cleanup = raised.exception.cleanup_failure
            self.assertEqual(cleanup["cleanup_proof"], "inconclusive")
            self.assertEqual(
                cleanup["failed_operations"],
                ["config-directory-owner-mode"],
            )
            self.assertNotIn("retained_runtime", cleanup)
            self.assertNotIn("retained_objects", cleanup)
            self.assertFalse(run_path.exists())

    def test_enforcement_gh_constructor_reports_cleanup_failure_locator(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(
                temp_root,
                hosts_payload=(
                    "github.com:\n"
                    "    git_protocol: https\n"
                    "    users:\n"
                    "        fixture-admin:\n"
                    f"            oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                    "    user: fixture-admin\n"
                    f"    oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                ),
            )
            original_bound_regular_file = ENFORCEMENT_MODULE._BoundRegularFile
            original_unlink = os.unlink
            created_config_status: dict[str, os.stat_result] = {}

            def fail_global_snapshot_binding(
                parent: object,
                name: str,
                **kwargs: object,
            ) -> object:
                if (
                    name == "config.yml"
                    and parent.path.name == "config"
                    and parent.path.parent.parent == runtime_parent
                ):
                    created_config_status["value"] = (parent.path / name).stat()
                    raise ENFORCEMENT_MODULE._blocked(
                        "collector-unavailable",
                        "fixture config snapshot binding failure",
                    )
                return original_bound_regular_file(parent, name, **kwargs)

            def reject_config_unlink(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                *,
                dir_fd: int | None = None,
            ) -> None:
                if path == "config.yml":
                    raise PermissionError(errno.EACCES, "fixture unlink failure")
                original_unlink(path, dir_fd=dir_fd)

            run_path: Path | None = None
            try:
                with mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "_BoundRegularFile",
                    side_effect=fail_global_snapshot_binding,
                ):
                    with mock.patch.object(
                        ENFORCEMENT_MODULE.os,
                        "unlink",
                        side_effect=reject_config_unlink,
                    ):
                        with self.assertRaises(
                            ENFORCEMENT_MODULE.EnforcementDoctorError
                        ) as raised:
                            ENFORCEMENT_MODULE.GitHubApiClient(
                                trusted_gh,
                                hashlib.sha256(trusted_payload).hexdigest(),
                                config_dir,
                                runtime_parent=runtime_parent,
                            )

                self.assertEqual(
                    raised.exception.reason_code,
                    "collector-inconclusive",
                )
                self.assertIsInstance(
                    raised.exception.__cause__,
                    ENFORCEMENT_MODULE.EnforcementDoctorError,
                )
                self.assertEqual(
                    raised.exception.__cause__.reason_code,
                    "collector-unavailable",
                )
                cleanup = raised.exception.cleanup_failure
                self.assertEqual(cleanup["cleanup_proof"], "inconclusive")
                self.assertIn("unlink-config.yml", cleanup["failed_operations"])
                locator = cleanup["retained_runtime"]
                self.assertEqual(locator["path_binding"], "verified")
                run_path = Path(locator["path"])
                self.assertTrue((run_path / "config" / "config.yml").exists())
                config_locators = [
                    retained
                    for retained in cleanup["retained_objects"]
                    if retained["label"] == "GitHub CLI private config.yml snapshot"
                ]
                self.assertEqual(len(config_locators), 1)
                self.assertEqual(
                    config_locators[0]["device"],
                    created_config_status["value"].st_dev,
                )
                self.assertEqual(
                    config_locators[0]["inode"],
                    created_config_status["value"].st_ino,
                )
                self.assertEqual(config_locators[0]["path_binding"], "verified")
                self.assertEqual(
                    config_locators[0]["path"],
                    str(run_path / "config" / "config.yml"),
                )
            finally:
                if run_path is not None and run_path.exists():
                    shutil.rmtree(run_path)

    @unittest.skipUnless(
        sys.platform == "darwin",
        "requires Darwin extended ACLs",
    )
    def test_enforcement_gh_cleanup_reports_acl_drift_after_removal(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(
                temp_root,
                hosts_payload=(
                    "github.com:\n"
                    "    git_protocol: https\n"
                    "    users:\n"
                    "        fixture-admin:\n"
                    f"            oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                    "    user: fixture-admin\n"
                    f"    oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                ),
            )
            client = ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            )
            run_path = client._run_directory.path
            snapshot_hosts = client._config_snapshot_directory.path / "hosts.yml"
            self._set_darwin_acl(snapshot_hosts, "everyone allow read")
            try:
                with self.assertRaises(
                    ENFORCEMENT_MODULE.EnforcementDoctorError
                ) as raised:
                    client.close()

                self.assertEqual(
                    raised.exception.reason_code,
                    "collector-inconclusive",
                )
                cleanup = raised.exception.cleanup_failure
                self.assertEqual(cleanup["cleanup_proof"], "complete")
                self.assertEqual(
                    cleanup["failed_operations"],
                    ["pre-cleanup-revalidation"],
                )
                self.assertNotIn("retained_runtime", cleanup)
                self.assertFalse(run_path.exists())
            finally:
                if snapshot_hosts.exists():
                    self._clear_darwin_acl(snapshot_hosts)
                if run_path.exists():
                    shutil.rmtree(run_path)

    @unittest.skipUnless(
        sys.platform == "darwin",
        "requires Darwin extended ACLs",
    )
    def test_enforcement_gh_cleanup_reports_acl_drift_with_unlink_failure(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(
                temp_root,
                hosts_payload=(
                    "github.com:\n"
                    "    git_protocol: https\n"
                    "    users:\n"
                    "        fixture-admin:\n"
                    f"            oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                    "    user: fixture-admin\n"
                    f"    oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                ),
            )
            client = ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            )
            run_path = client._run_directory.path
            snapshot_hosts = client._config_snapshot_directory.path / "hosts.yml"
            config_fd = client._config_snapshot_directory.fd
            original_unlink = os.unlink
            self._set_darwin_acl(snapshot_hosts, "everyone allow read")

            def reject_token_unlink(
                path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
                *,
                dir_fd: int | None = None,
            ) -> None:
                if path == "hosts.yml" and dir_fd == config_fd:
                    raise PermissionError(errno.EACCES, "fixture unlink failure")
                original_unlink(path, dir_fd=dir_fd)

            try:
                with mock.patch.object(
                    ENFORCEMENT_MODULE.os,
                    "unlink",
                    side_effect=reject_token_unlink,
                ):
                    with self.assertRaises(
                        ENFORCEMENT_MODULE.EnforcementDoctorError
                    ) as raised:
                        client.close()

                cleanup = raised.exception.cleanup_failure
                self.assertEqual(cleanup["cleanup_proof"], "inconclusive")
                self.assertIn("pre-cleanup-revalidation", cleanup["failed_operations"])
                self.assertIn("unlink-hosts.yml", cleanup["failed_operations"])
                self.assertEqual(
                    cleanup["retained_runtime"]["path"],
                    str(run_path),
                )
                self.assertEqual(
                    cleanup["retained_runtime"]["path_binding"],
                    "verified",
                )
            finally:
                if snapshot_hosts.exists():
                    self._clear_darwin_acl(snapshot_hosts)
                if run_path.exists():
                    shutil.rmtree(run_path)

    def test_enforcement_gh_linux_host_fixed_curl_policy_is_enforced(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            with (
                mock.patch.object(
                    ENFORCEMENT_MODULE.sys,
                    "platform",
                    "linux",
                ),
                mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "_DarwinAclRuntime",
                    side_effect=AssertionError("Darwin runtime must not load"),
                ),
                mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "_bounded_subprocess",
                    return_value=(
                        0,
                        self._curl_response(b'{"id":1,"login":"linux-fixture"}'),
                        b"",
                    ),
                ) as spawned,
            ):
                try:
                    with ENFORCEMENT_MODULE.GitHubApiClient(
                        trusted_gh,
                        hashlib.sha256(trusted_payload).hexdigest(),
                        config_dir,
                        runtime_parent=runtime_parent,
                    ) as client:
                        response = client.get_json("/user")
                except ENFORCEMENT_MODULE.EnforcementDoctorError as error:
                    self.assertEqual(error.reason_code, "collector-unavailable")
                    self.assertRegex(
                        str(error),
                        (
                            r"fixed curl (?:trust-root directory is replaceable|"
                            r"transport identity or access policy is invalid|"
                            r"transport or ancestor cannot be bound safely)"
                        ),
                    )
                    spawned.assert_not_called()
                else:
                    spawned.assert_called_once()
                    self.assertEqual(response["login"], "linux-fixture")

    def test_enforcement_fixed_curl_reports_replaceable_trust_root_identity(
        self,
    ) -> None:
        root_status_fields = list(os.stat("/"))
        root_status_fields[0] = stat.S_IFDIR | 0o775
        root_status_fields[4] = 0
        root_status_fields[5] = 0
        replaceable_root = os.stat_result(root_status_fields)

        with mock.patch.object(
            ENFORCEMENT_MODULE.os,
            "fstat",
            return_value=replaceable_root,
        ):
            with self.assertRaises(ENFORCEMENT_MODULE.EnforcementDoctorError) as raised:
                ENFORCEMENT_MODULE._fixed_curl_trust_binding()

        self.assertEqual(
            raised.exception.reason_code,
            "collector-unavailable",
        )
        self.assertEqual(
            str(raised.exception),
            (
                "fixed curl trust-root directory is replaceable: "
                "path=/ uid=0 gid=0 mode=0775 "
                "is_directory=True is_symlink=False"
            ),
        )

    @unittest.skipUnless(
        sys.platform == "darwin",
        "requires Darwin extended ACLs",
    )
    def test_enforcement_fixed_curl_rejects_directory_acl_with_safe_mode(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            ancestor = temp_root / "fixed-curl"
            bin_directory = ancestor / "bin"
            bin_directory.mkdir(parents=True, mode=0o755)
            ancestor.chmod(0o755)
            bin_directory.chmod(0o755)
            executable = bin_directory / "curl"
            executable.write_bytes(b"#!/bin/sh\nexit 0\n")
            executable.chmod(0o755)
            real_fstat = os.fstat
            real_stat = os.stat

            def root_owned(status_value: os.stat_result) -> os.stat_result:
                fields = list(status_value)
                fields[4] = 0
                fields[5] = 0
                return os.stat_result(fields)

            def root_owned_fstat(fd: int) -> os.stat_result:
                return root_owned(real_fstat(fd))

            def root_owned_stat(
                path: object,
                *,
                dir_fd: int | None = None,
                follow_symlinks: bool = True,
            ) -> os.stat_result:
                return root_owned(
                    real_stat(
                        path,
                        dir_fd=dir_fd,
                        follow_symlinks=follow_symlinks,
                    )
                )

            self._set_darwin_acl(
                bin_directory,
                "everyone allow list,search,add_file,delete_child",
            )
            try:
                with (
                    mock.patch.object(
                        ENFORCEMENT_MODULE.os,
                        "fstat",
                        side_effect=root_owned_fstat,
                    ),
                    mock.patch.object(
                        ENFORCEMENT_MODULE.os,
                        "stat",
                        side_effect=root_owned_stat,
                    ),
                    self.assertRaises(
                        ENFORCEMENT_MODULE.EnforcementDoctorError
                    ) as raised,
                ):
                    ENFORCEMENT_MODULE._FixedCurlTrustBinding(executable=executable)
            finally:
                self._clear_darwin_acl(bin_directory)

            self.assertEqual(
                raised.exception.reason_code,
                "collector-unavailable",
            )
            self.assertEqual(stat.S_IMODE(bin_directory.stat().st_mode), 0o755)

            with (
                mock.patch.object(
                    ENFORCEMENT_MODULE.os,
                    "fstat",
                    side_effect=root_owned_fstat,
                ),
                mock.patch.object(
                    ENFORCEMENT_MODULE.os,
                    "stat",
                    side_effect=root_owned_stat,
                ),
                ENFORCEMENT_MODULE._FixedCurlTrustBinding(
                    executable=executable
                ) as safe_binding,
            ):
                safe_binding.revalidate()
                self.assertEqual(
                    safe_binding.executable,
                    executable,
                )

    def test_enforcement_fixed_curl_identity_drift_stops_before_spawn(
        self,
    ) -> None:
        with ENFORCEMENT_MODULE._fixed_curl_trust_binding() as binding:
            target_fd = binding._directory_fds[-1]
            real_fstat = os.fstat
            target_status = real_fstat(target_fd)
            drift_fields = list(target_status)
            drift_fields[1] += 1
            drift_status = os.stat_result(drift_fields)

            def drifted_fstat(fd: int) -> os.stat_result:
                if fd == target_fd:
                    return drift_status
                return real_fstat(fd)

            with (
                mock.patch.object(
                    ENFORCEMENT_MODULE.os,
                    "fstat",
                    side_effect=drifted_fstat,
                ),
                mock.patch.object(
                    ENFORCEMENT_MODULE.subprocess,
                    "Popen",
                ) as spawned,
                self.assertRaises(ENFORCEMENT_MODULE.EnforcementDoctorError) as raised,
            ):
                ENFORCEMENT_MODULE._bounded_subprocess_supervised(
                    [str(binding.executable), "--version"],
                    environment={"LC_ALL": "C"},
                    execution_cwd=str(REPO_ROOT),
                    endpoint_class="fixture",
                    process_registry={},
                    process_registered=lambda _managed: None,
                    timeout_seconds=5,
                    stdout_limit=1024,
                    stderr_limit=1024,
                    process_launch_binding=binding,
                )

        spawned.assert_not_called()
        self.assertEqual(
            raised.exception.reason_code,
            "collector-inconclusive",
        )

    def test_enforcement_fixed_curl_access_drift_stops_before_spawn(
        self,
    ) -> None:
        with ENFORCEMENT_MODULE._fixed_curl_trust_binding() as binding:
            target_fd = binding._directory_fds[-1]
            real_policy = ENFORCEMENT_MODULE._stable_fd_access_policy_binding

            def drifted_policy(fd: int) -> tuple[str, int, str]:
                if fd == target_fd:
                    return ("fixture-expanded-policy-v1", 1, "expanded")
                return real_policy(fd)

            with (
                mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "_stable_fd_access_policy_binding",
                    side_effect=drifted_policy,
                ),
                mock.patch.object(
                    ENFORCEMENT_MODULE.subprocess,
                    "Popen",
                ) as spawned,
                self.assertRaises(ENFORCEMENT_MODULE.EnforcementDoctorError) as raised,
            ):
                ENFORCEMENT_MODULE._bounded_subprocess_supervised(
                    [str(binding.executable), "--version"],
                    environment={"LC_ALL": "C"},
                    execution_cwd=str(REPO_ROOT),
                    endpoint_class="fixture",
                    process_registry={},
                    process_registered=lambda _managed: None,
                    timeout_seconds=5,
                    stdout_limit=1024,
                    stderr_limit=1024,
                    process_launch_binding=binding,
                )

        spawned.assert_not_called()
        self.assertEqual(
            raised.exception.reason_code,
            "collector-inconclusive",
        )

    def test_enforcement_fixed_curl_binding_cannot_guard_another_executable(
        self,
    ) -> None:
        with (
            ENFORCEMENT_MODULE._fixed_curl_trust_binding() as binding,
            mock.patch.object(
                ENFORCEMENT_MODULE.subprocess,
                "Popen",
            ) as spawned,
            self.assertRaises(ENFORCEMENT_MODULE.EnforcementDoctorError) as raised,
        ):
            ENFORCEMENT_MODULE._bounded_subprocess_supervised(
                [sys.executable, "-I", "-B", "-c", "pass"],
                environment={"LC_ALL": "C"},
                execution_cwd=str(REPO_ROOT),
                endpoint_class="fixture",
                process_registry={},
                process_registered=lambda _managed: None,
                timeout_seconds=5,
                stdout_limit=1024,
                stderr_limit=1024,
                process_launch_binding=binding,
            )

        spawned.assert_not_called()
        self.assertEqual(
            raised.exception.reason_code,
            "collector-unavailable",
        )

    def test_enforcement_fixed_curl_descriptors_span_popen_return(
        self,
    ) -> None:
        binding = ENFORCEMENT_MODULE._fixed_curl_trust_binding()
        retained_fds = tuple(binding._directory_fds) + (binding._file_fd,)
        real_popen = subprocess.Popen

        def inspect_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            for fd in retained_fds:
                os.fstat(fd)
            process = real_popen(*args, **kwargs)
            for fd in retained_fds:
                os.fstat(fd)
            return process

        try:
            with (
                mock.patch.object(
                    ENFORCEMENT_MODULE.subprocess,
                    "Popen",
                    side_effect=inspect_popen,
                ),
                mock.patch.object(
                    binding,
                    "revalidate",
                    wraps=binding.revalidate,
                ) as revalidated,
            ):
                return_code, stdout, stderr = (
                    ENFORCEMENT_MODULE._bounded_subprocess_supervised(
                        [str(binding.executable), "--version"],
                        environment={"LC_ALL": "C"},
                        execution_cwd=str(REPO_ROOT),
                        endpoint_class="fixture",
                        process_registry={},
                        process_registered=lambda _managed: None,
                        timeout_seconds=5,
                        stdout_limit=4096,
                        stderr_limit=4096,
                        process_launch_binding=binding,
                    )
                )
            self.assertEqual(return_code, 0)
            self.assertTrue(stdout.startswith(b"curl "))
            self.assertEqual(stderr, b"")
            self.assertEqual(revalidated.call_count, 2)
            for fd in retained_fds:
                os.fstat(fd)
        finally:
            close_errors = binding.close()
            self.assertEqual(close_errors, [])

        for fd in retained_fds:
            with self.assertRaises(OSError) as closed:
                os.fstat(fd)
            self.assertEqual(closed.exception.errno, errno.EBADF)

    def test_enforcement_fixed_curl_close_preserves_primary_error(
        self,
    ) -> None:
        binding = ENFORCEMENT_MODULE._fixed_curl_trust_binding()
        failed_fd = binding._file_fd
        self.assertIsNotNone(failed_fd)
        real_close = os.close
        primary = RuntimeError("fixture primary failure")

        def fail_one_close(fd: int) -> None:
            if fd == failed_fd:
                raise OSError(errno.EIO, "fixture close failure")
            real_close(fd)

        try:
            with (
                mock.patch.object(
                    ENFORCEMENT_MODULE.os,
                    "close",
                    side_effect=fail_one_close,
                ),
                self.assertRaises(RuntimeError) as raised,
            ):
                with binding:
                    raise primary
        finally:
            real_close(failed_fd)

        self.assertIs(raised.exception, primary)
        self.assertIsInstance(
            raised.exception.__cause__,
            ENFORCEMENT_MODULE.EnforcementDoctorError,
        )
        self.assertEqual(
            raised.exception.__cause__.reason_code,
            "collector-inconclusive",
        )

    def test_enforcement_gh_pin_rejects_initial_digest_mismatch(self) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_gh.write_bytes(b"#!/bin/sh\nexit 0\n")
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)

            with self.assertRaises(ENFORCEMENT_MODULE.EnforcementDoctorError) as raised:
                ENFORCEMENT_MODULE.GitHubApiClient(
                    trusted_gh,
                    "a" * 64,
                    config_dir,
                    runtime_parent=runtime_parent,
                )

        self.assertEqual(
            raised.exception.reason_code,
            "collector-digest-mismatch",
        )

    def test_enforcement_gh_pin_rejects_relative_or_symlink_trust_roots(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            trusted_digest = hashlib.sha256(trusted_payload).hexdigest()
            symlink_gh = temp_root / "symlink-gh"
            symlink_gh.symlink_to(trusted_gh)
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            cases = (
                ("relative-executable", Path("trusted-gh"), config_dir),
                ("symlink-executable", symlink_gh, config_dir),
                ("relative-config", trusted_gh, Path("gh-config")),
            )
            for label, executable, selected_config in cases:
                with self.subTest(trust_root=label):
                    with self.assertRaises(
                        ENFORCEMENT_MODULE.EnforcementDoctorError
                    ) as raised:
                        ENFORCEMENT_MODULE.GitHubApiClient(
                            executable,
                            trusted_digest,
                            selected_config,
                            runtime_parent=runtime_parent,
                        )
                    self.assertEqual(
                        raised.exception.reason_code,
                        "collector-unavailable",
                    )

    def test_enforcement_gh_pin_rejects_pre_exec_source_replacement(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            with ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            ) as client:
                trusted_gh.rename(temp_root / "trusted-gh.original")
                trusted_gh.write_bytes(b"#!/bin/sh\nexit 99\n")
                trusted_gh.chmod(0o700)
                with mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "_bounded_subprocess",
                    return_value=(0, self._curl_response(b'{"id":1}'), b""),
                ) as spawned:
                    with self.assertRaises(
                        ENFORCEMENT_MODULE.EnforcementDoctorError
                    ) as raised:
                        client.get_json("/user")

                self.assertEqual(
                    raised.exception.reason_code,
                    "collector-inconclusive",
                )
                spawned.assert_not_called()

    def test_enforcement_gh_pin_discards_output_after_post_exec_drift(
        self,
    ) -> None:
        mutations = {
            "source-content": lambda client, temp_root: client._source_path.write_bytes(
                b"#!/bin/sh\nexit 77\n"
            ),
            "source-path": lambda client, temp_root: (
                client._source_path.rename(temp_root / "source.original"),
                client._source_path.write_bytes(b"#!/bin/sh\nexit 77\n"),
                client._source_path.chmod(0o700),
            ),
            "snapshot-path": lambda client, temp_root: (
                client._executable_snapshot_directory.set_owner_mode(0o700),
                client._snapshot_path.rename(
                    client._snapshot_path.with_name("gh.original")
                ),
                client._snapshot_path.write_bytes(b"#!/bin/sh\nexit 77\n"),
                client._snapshot_path.chmod(0o500),
            ),
            "snapshot-mode": lambda client, temp_root: client._snapshot_path.chmod(
                0o700
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(drift=label):
                with owner_controlled_temp_root() as temp_root:
                    trusted_gh = temp_root / "trusted-gh"
                    trusted_payload = b"#!/bin/sh\nexit 0\n"
                    trusted_gh.write_bytes(trusted_payload)
                    trusted_gh.chmod(0o700)
                    config_dir, runtime_parent = self._make_private_gh_config(temp_root)
                    client = ENFORCEMENT_MODULE.GitHubApiClient(
                        trusted_gh,
                        hashlib.sha256(trusted_payload).hexdigest(),
                        config_dir,
                        runtime_parent=runtime_parent,
                    )
                    cleanup_error = None
                    try:

                        def drift_after_exec(
                            command: list[str],
                            **kwargs: object,
                        ) -> tuple[int, bytes, bytes]:
                            mutate(client, temp_root)
                            return (
                                0,
                                self._curl_response(
                                    b'{"id":1,"login":"must-not-be-used"}'
                                ),
                                b"",
                            )

                        with mock.patch.object(
                            ENFORCEMENT_MODULE,
                            "_bounded_subprocess",
                            side_effect=drift_after_exec,
                        ):
                            with self.assertRaises(
                                ENFORCEMENT_MODULE.EnforcementDoctorError
                            ) as raised:
                                client.get_json("/user")

                        self.assertEqual(
                            raised.exception.reason_code,
                            "collector-inconclusive",
                        )
                    finally:
                        try:
                            client.close()
                        except ENFORCEMENT_MODULE.EnforcementDoctorError as error:
                            cleanup_error = error

                    if label == "snapshot-path":
                        self.assertIsNotNone(cleanup_error)
                        self.assertEqual(
                            cleanup_error.reason_code,
                            "collector-inconclusive",
                        )
                        executable_locators = [
                            locator
                            for locator in cleanup_error.cleanup_failure[
                                "retained_objects"
                            ]
                            if locator["label"] == "GitHub CLI executable snapshot"
                        ]
                        self.assertEqual(len(executable_locators), 1)
                        self.assertEqual(
                            executable_locators[0]["path_binding"],
                            "unverified",
                        )
                        self.assertEqual(
                            Path(executable_locators[0]["last_known_path"]).name,
                            "gh",
                        )
                    else:
                        self.assertIsNone(cleanup_error)

    @unittest.skipUnless(
        sys.platform == "darwin",
        "requires Darwin extended ACLs",
    )
    def test_enforcement_gh_acl_drift_discards_command_output(
        self,
    ) -> None:
        mutations = {
            "runtime-parent": lambda client: self._set_darwin_acl(
                client._runtime_parent.path,
                "everyone allow list,search,add_file,delete_child",
            ),
            "run-directory": lambda client: self._set_darwin_acl(
                client._run_directory.path,
                "everyone allow list,search,add_file,delete_child",
            ),
            "executable-snapshot": lambda client: self._set_darwin_acl(
                client._snapshot_path,
                "everyone allow read,write,execute",
            ),
            "source-config": lambda client: self._set_darwin_acl(
                client._source_config_directory.path / "hosts.yml",
                "everyone allow read",
            ),
            "config-snapshot-directory": lambda client: self._set_darwin_acl(
                client._config_snapshot_directory.path,
                "everyone allow list,search",
            ),
            "snapshot-token": lambda client: self._set_darwin_acl(
                client._config_snapshot_directory.path / "hosts.yml",
                "everyone allow read",
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(drift=label):
                with owner_controlled_temp_root() as temp_root:
                    trusted_gh = temp_root / "trusted-gh"
                    trusted_payload = b"#!/bin/sh\nexit 0\n"
                    trusted_gh.write_bytes(trusted_payload)
                    trusted_gh.chmod(0o700)
                    config_dir, runtime_parent = self._make_private_gh_config(
                        temp_root,
                        hosts_payload=(
                            "github.com:\n"
                            "    git_protocol: https\n"
                            "    users:\n"
                            "        fixture-admin:\n"
                            f"            oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                            "    user: fixture-admin\n"
                            f"    oauth_token: {SYNTHETIC_ACCESS_TOKEN}\n"
                        ),
                    )
                    with ENFORCEMENT_MODULE.GitHubApiClient(
                        trusted_gh,
                        hashlib.sha256(trusted_payload).hexdigest(),
                        config_dir,
                        runtime_parent=runtime_parent,
                    ) as client:

                        def drift_after_exec(
                            command: list[str],
                            **kwargs: object,
                        ) -> tuple[int, bytes, bytes]:
                            mutate(client)
                            return (
                                0,
                                self._curl_response(
                                    b'{"id":1,"login":"must-not-be-used"}'
                                ),
                                b"",
                            )

                        with mock.patch.object(
                            ENFORCEMENT_MODULE,
                            "_bounded_subprocess",
                            side_effect=drift_after_exec,
                        ):
                            with self.assertRaises(
                                ENFORCEMENT_MODULE.EnforcementDoctorError
                            ) as raised:
                                client.get_json("/user")

                        self.assertEqual(
                            raised.exception.reason_code,
                            "collector-inconclusive",
                        )

    @unittest.skipUnless(
        sys.platform == "darwin",
        "requires Darwin extended ACLs",
    )
    def test_enforcement_gh_acl_restrictive_deny_churn_is_benign(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            with ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            ) as client:

                def add_restrictive_deny(
                    command: list[str],
                    **kwargs: object,
                ) -> tuple[int, bytes, bytes]:
                    self._set_darwin_acl(
                        client._runtime_parent.path,
                        "everyone deny readextattr",
                    )
                    return (
                        0,
                        self._curl_response(b'{"id":1,"login":"fixture"}'),
                        b"",
                    )

                with mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "_bounded_subprocess",
                    side_effect=add_restrictive_deny,
                ):
                    response = client.get_json("/user")

        self.assertEqual(response["login"], "fixture")

    @unittest.skipUnless(
        sys.platform == "darwin",
        "requires Darwin extended ACLs",
    )
    def test_enforcement_gh_acl_drift_is_revalidated_after_spawn_failure(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            with ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            ) as client:

                def fail_after_acl_grant(
                    command: list[str],
                    **kwargs: object,
                ) -> tuple[int, bytes, bytes]:
                    self._set_darwin_acl(
                        client._config_snapshot_directory.path / "hosts.yml",
                        "everyone allow read",
                    )
                    raise RuntimeError("fixture subprocess failure")

                with mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "_bounded_subprocess",
                    side_effect=fail_after_acl_grant,
                ):
                    with self.assertRaises(
                        ENFORCEMENT_MODULE.EnforcementDoctorError
                    ) as raised:
                        client.get_json("/user")

        self.assertEqual(raised.exception.reason_code, "collector-inconclusive")

    def test_enforcement_gh_runtime_rejects_replaceable_ancestor(self) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, _ = self._make_private_gh_config(temp_root)
            replaceable_parent = temp_root.resolve() / "replaceable"
            replaceable_parent.mkdir(mode=0o777)
            replaceable_parent.chmod(0o777)

            with self.assertRaises(ENFORCEMENT_MODULE.EnforcementDoctorError) as raised:
                ENFORCEMENT_MODULE.GitHubApiClient(
                    trusted_gh,
                    hashlib.sha256(trusted_payload).hexdigest(),
                    config_dir,
                    runtime_parent=replaceable_parent / "runtime",
                )

        self.assertEqual(raised.exception.reason_code, "collector-unavailable")
        self.assertIn("untrusted principal", str(raised.exception))

    def test_enforcement_gh_config_rejects_symlinks_and_open_permissions(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            resolved_root = temp_root.resolve()
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            expected_digest = hashlib.sha256(trusted_payload).hexdigest()

            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            config_link = resolved_root / "config-link"
            config_link.symlink_to(config_dir, target_is_directory=True)
            with self.subTest(case="directory-symlink"):
                with self.assertRaises(
                    ENFORCEMENT_MODULE.EnforcementDoctorError
                ) as raised:
                    ENFORCEMENT_MODULE.GitHubApiClient(
                        trusted_gh,
                        expected_digest,
                        config_link,
                        runtime_parent=runtime_parent,
                    )
                self.assertEqual(
                    raised.exception.reason_code,
                    "collector-unavailable",
                )

            hosts_path = config_dir / "hosts.yml"
            hosts_payload = hosts_path.read_bytes()
            hosts_path.unlink()
            external_hosts = resolved_root / "external-hosts.yml"
            external_hosts.write_bytes(hosts_payload)
            external_hosts.chmod(0o600)
            hosts_path.symlink_to(external_hosts)
            with self.subTest(case="hosts-symlink"):
                with self.assertRaises(
                    ENFORCEMENT_MODULE.EnforcementDoctorError
                ) as raised:
                    ENFORCEMENT_MODULE.GitHubApiClient(
                        trusted_gh,
                        expected_digest,
                        config_dir,
                        runtime_parent=runtime_parent,
                    )
                self.assertEqual(
                    raised.exception.reason_code,
                    "collector-unavailable",
                )
            hosts_path.unlink()
            hosts_path.write_bytes(hosts_payload)
            hosts_path.chmod(0o600)

            for label, path, mode in (
                ("directory-open", config_dir, 0o755),
                ("hosts-open", hosts_path, 0o644),
            ):
                with self.subTest(case=label):
                    path.chmod(mode)
                    with self.assertRaises(
                        ENFORCEMENT_MODULE.EnforcementDoctorError
                    ) as raised:
                        ENFORCEMENT_MODULE.GitHubApiClient(
                            trusted_gh,
                            expected_digest,
                            config_dir,
                            runtime_parent=runtime_parent,
                        )
                    self.assertEqual(
                        raised.exception.reason_code,
                        "collector-unavailable",
                    )
                    path.chmod(0o700 if path == config_dir else 0o600)

    def test_enforcement_gh_config_rejects_transport_redirects(self) -> None:
        cases = (
            (
                "global-unix-socket",
                "version: 1\nhttp_unix_socket: /tmp/attacker.sock\n",
                None,
            ),
            (
                "quoted-global-unix-socket",
                'version: 1\n"http_unix_socket": /tmp/attacker.sock\n',
                None,
            ),
            (
                "host-api-redirect",
                None,
                (
                    "github.com:\n"
                    "    git_protocol: https\n"
                    "    api_host: attacker.invalid\n"
                    "    users:\n"
                    "        fixture-admin:\n"
                    "        inactive-user:\n"
                    "            oauth_token: ghp_inactive_must_not_be_snapshotted\n"
                    "    user: fixture-admin\n"
                ),
            ),
        )
        for label, config_payload, hosts_payload in cases:
            with self.subTest(case=label):
                with owner_controlled_temp_root() as temp_root:
                    trusted_gh = temp_root / "trusted-gh"
                    trusted_payload = b"#!/bin/sh\nexit 0\n"
                    trusted_gh.write_bytes(trusted_payload)
                    trusted_gh.chmod(0o700)
                    config_dir, runtime_parent = self._make_private_gh_config(
                        temp_root,
                        config_payload=config_payload,
                        hosts_payload=hosts_payload,
                    )
                    with self.assertRaises(
                        ENFORCEMENT_MODULE.EnforcementDoctorError
                    ) as raised:
                        ENFORCEMENT_MODULE.GitHubApiClient(
                            trusted_gh,
                            hashlib.sha256(trusted_payload).hexdigest(),
                            config_dir,
                            runtime_parent=runtime_parent,
                        )
                    self.assertEqual(
                        raised.exception.reason_code,
                        "collector-unavailable",
                    )

    def test_enforcement_api_transport_refuses_every_redirect_without_egress(
        self,
    ) -> None:
        cases = (
            (301, "https://attacker.invalid/credential"),
            (302, "http://api.github.com/downgrade"),
            (303, "https://api.github.com:444/non-default-port"),
            (307, "https://first.github.com/first-hop"),
            (308, "https://first.github.com/second-hop"),
        )
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            observed_commands: list[list[str]] = []
            responses = iter(cases)

            def redirect_response(
                command: list[str],
                **_kwargs: object,
            ) -> tuple[int, bytes, bytes]:
                observed_commands.append(command)
                status, location = next(responses)
                return (
                    0,
                    self._curl_response(
                        f"server redirect body: {location}".encode("ascii"),
                        status,
                    ),
                    b"",
                )

            with ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            ) as client:
                header_path = client._transport_directory.path / "authorization.headers"
                self.assertEqual(
                    stat.S_IMODE(header_path.stat().st_mode),
                    0o400,
                )
                self.assertIn(
                    SYNTHETIC_ACCESS_TOKEN.encode("ascii"),
                    header_path.read_bytes(),
                )
                with mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "_bounded_subprocess",
                    side_effect=redirect_response,
                ):
                    for status, location in cases:
                        with self.subTest(status=status, location=location):
                            with self.assertRaises(
                                ENFORCEMENT_MODULE.EnforcementDoctorError
                            ) as raised:
                                client.get_json("/user")
                            self.assertEqual(
                                raised.exception.api_failure,
                                {
                                    "endpoint_class": "authenticated-user",
                                    "failure_kind": "redirect-refused",
                                    "http_status": status,
                                },
                            )
                            self.assertNotIn(location, str(raised.exception))
                            self.assertNotIn(
                                SYNTHETIC_ACCESS_TOKEN,
                                str(raised.exception),
                            )

        self.assertEqual(len(observed_commands), len(cases))
        for command in observed_commands:
            self.assertEqual(command[0], str(ENFORCEMENT_MODULE.CURL_EXECUTABLE))
            self.assertEqual(command[1], "--disable")
            self.assertNotIn("api", command[:4])
            self.assertNotIn("--location", command)
            self.assertNotIn("--location-trusted", command)
            self.assertEqual(
                command[command.index("--max-redirs") + 1],
                "0",
            )
            self.assertEqual(
                command[command.index("--url") + 1],
                "https://api.github.com/user",
            )
            self.assertEqual(
                command[command.index("--proxy") + 1],
                "",
            )
            self.assertNotIn(
                SYNTHETIC_ACCESS_TOKEN,
                "\0".join(command),
            )

    def test_enforcement_gh_config_drift_discards_command_output(self) -> None:
        mutations = {
            "source-config-content": lambda client, temp_root: (
                client._source_config_directory.path / "config.yml"
            ).write_text(
                "version: 1\nhttp_unix_socket: /tmp/attacker.sock\n",
                encoding="utf-8",
            ),
            "source-hosts": lambda client, temp_root: (
                (client._source_config_directory.path / "hosts.yml").rename(
                    temp_root / "hosts.original"
                ),
                (client._source_config_directory.path / "hosts.yml").write_text(
                    (
                        "github.com:\n"
                        "    git_protocol: https\n"
                        "    users:\n"
                        "        attacker:\n"
                        "            oauth_token: ghp_attacker\n"
                        "    user: attacker\n"
                        "    oauth_token: ghp_attacker\n"
                    ),
                    encoding="utf-8",
                ),
                (client._source_config_directory.path / "hosts.yml").chmod(0o600),
            ),
            "snapshot-hosts": lambda client, temp_root: (
                (client._config_snapshot_directory.path / "hosts.yml").rename(
                    temp_root / "snapshot-hosts.original"
                ),
                (client._config_snapshot_directory.path / "hosts.yml").write_text(
                    ("attacker.invalid:\n    oauth_token: ghp_attacker\n"),
                    encoding="utf-8",
                ),
                (client._config_snapshot_directory.path / "hosts.yml").chmod(0o600),
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(drift=label):
                with owner_controlled_temp_root() as temp_root:
                    trusted_gh = temp_root / "trusted-gh"
                    trusted_payload = b"#!/bin/sh\nexit 0\n"
                    trusted_gh.write_bytes(trusted_payload)
                    trusted_gh.chmod(0o700)
                    config_dir, runtime_parent = self._make_private_gh_config(temp_root)
                    client = ENFORCEMENT_MODULE.GitHubApiClient(
                        trusted_gh,
                        hashlib.sha256(trusted_payload).hexdigest(),
                        config_dir,
                        runtime_parent=runtime_parent,
                    )
                    cleanup_error = None
                    try:

                        def drift_during_execution(
                            command: list[str],
                            **kwargs: object,
                        ) -> tuple[int, bytes, bytes]:
                            if label == "snapshot-hosts":
                                client._config_snapshot_directory.set_owner_mode(0o700)
                            mutate(client, temp_root)
                            return (
                                0,
                                self._curl_response(
                                    b'{"id":1,"login":"must-not-be-used"}'
                                ),
                                b"",
                            )

                        with mock.patch.object(
                            ENFORCEMENT_MODULE,
                            "_bounded_subprocess",
                            side_effect=drift_during_execution,
                        ):
                            with self.assertRaises(
                                ENFORCEMENT_MODULE.EnforcementDoctorError
                            ) as raised:
                                client.get_json("/user")
                        self.assertEqual(
                            raised.exception.reason_code,
                            "collector-inconclusive",
                        )
                    finally:
                        try:
                            client.close()
                        except ENFORCEMENT_MODULE.EnforcementDoctorError as error:
                            cleanup_error = error

                    if label == "snapshot-hosts":
                        self.assertIsNotNone(cleanup_error)
                        hosts_locators = [
                            locator
                            for locator in cleanup_error.cleanup_failure[
                                "retained_objects"
                            ]
                            if locator["label"]
                            == "GitHub CLI private hosts.yml snapshot"
                        ]
                        self.assertEqual(len(hosts_locators), 1)
                        self.assertEqual(
                            hosts_locators[0]["path_binding"],
                            "unverified",
                        )
                        self.assertEqual(
                            Path(hosts_locators[0]["last_known_path"]).name,
                            "hosts.yml",
                        )
                    else:
                        self.assertIsNone(cleanup_error)

    def test_enforcement_gh_snapshot_excludes_non_github_authentication(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(
                temp_root,
                hosts_payload=(
                    "github.com:\n"
                    "    git_protocol: https\n"
                    "    users:\n"
                    "        fixture-admin:\n"
                    "    user: fixture-admin\n"
                    "attacker.invalid:\n"
                    "    git_protocol: https\n"
                    "    oauth_token: ghp_must_not_be_snapshotted\n"
                    "    user: attacker\n"
                ),
            )
            observed_commands: list[list[str]] = []

            def fixed_result(
                command: list[str],
                **kwargs: object,
            ) -> tuple[int, bytes, bytes]:
                observed_commands.append(command)
                return (
                    0,
                    self._curl_response(b'{"id":1,"login":"fixture"}'),
                    b"",
                )

            with ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            ) as client:
                self._prime_github_api_transport(client)
                snapshot_hosts = (
                    client._config_snapshot_directory.path / "hosts.yml"
                ).read_text(encoding="utf-8")
                self.assertIn("github.com:", snapshot_hosts)
                self.assertNotIn("attacker.invalid", snapshot_hosts)
                self.assertNotIn("ghp_must_not_be_snapshotted", snapshot_hosts)
                self.assertNotIn(
                    "ghp_inactive_must_not_be_snapshotted",
                    snapshot_hosts,
                )
                with mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "_bounded_subprocess",
                    side_effect=fixed_result,
                ):
                    client.get_json("/user")
                    for endpoint in (
                        "https://attacker.invalid/user",
                        "//attacker.invalid/user",
                    ):
                        with self.subTest(endpoint=endpoint):
                            with self.assertRaises(
                                ENFORCEMENT_MODULE.EnforcementDoctorError
                            ):
                                client.get_json(endpoint)

            self.assertEqual(len(observed_commands), 1)
            self.assertEqual(
                observed_commands[0][0],
                str(ENFORCEMENT_MODULE.CURL_EXECUTABLE),
            )
            self.assertEqual(
                observed_commands[0][observed_commands[0].index("--url") + 1],
                "https://api.github.com/user",
            )
            self.assertNotIn("attacker.invalid", " ".join(observed_commands[0]))

    def test_enforcement_auth_preflight_uses_only_local_gh_token_command(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(
                temp_root,
                hosts_payload=(
                    "github.com:\n"
                    "    git_protocol: https\n"
                    "    users:\n"
                    "        fixture-admin:\n"
                    "    user: fixture-admin\n"
                ),
            )
            observed_commands: list[list[str]] = []

            def authentication_then_api(
                command: list[str],
                **_kwargs: object,
            ) -> tuple[int, bytes, bytes]:
                observed_commands.append(command)
                if len(observed_commands) == 1:
                    return (
                        0,
                        f"{SYNTHETIC_ACCESS_TOKEN}\n".encode("ascii"),
                        b"",
                    )
                return (
                    0,
                    self._curl_response(b'{"id":123,"login":"fixture-admin"}'),
                    b"",
                )

            with ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            ) as client:
                self.assertIsNone(client._snapshot_auth_header_file)
                with mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "_bounded_subprocess",
                    side_effect=authentication_then_api,
                ):
                    authenticated = client.auth_preflight()
                header_path = client._transport_directory.path / "authorization.headers"
                self.assertEqual(
                    stat.S_IMODE(header_path.stat().st_mode),
                    0o400,
                )

        self.assertEqual(
            authenticated,
            {
                "id": 123,
                "login": "fixture-admin",
            },
        )
        self.assertEqual(
            observed_commands[0][1:],
            [
                "auth",
                "token",
                "--hostname",
                "github.com",
            ],
        )
        self.assertEqual(observed_commands[0][0], client.executable)
        self.assertNotEqual(
            observed_commands[0][0],
            str(ENFORCEMENT_MODULE.CURL_EXECUTABLE),
        )
        self.assertEqual(
            observed_commands[1][0],
            str(ENFORCEMENT_MODULE.CURL_EXECUTABLE),
        )
        flattened = "\0".join(
            argument for command in observed_commands for argument in command
        )
        self.assertNotIn("auth\0status", flattened)
        self.assertNotIn("\0api\0", flattened)
        self.assertNotIn(SYNTHETIC_ACCESS_TOKEN, flattened)

    def test_enforcement_local_token_command_failure_is_authentication(
        self,
    ) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(
                temp_root,
                hosts_payload=(
                    "github.com:\n"
                    "    git_protocol: https\n"
                    "    users:\n"
                    "        fixture-admin:\n"
                    "    user: fixture-admin\n"
                ),
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            ) as client:
                run_path = client._run_directory.path
                with (
                    mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "_bounded_subprocess",
                        return_value=(
                            ENFORCEMENT_MODULE.CURL_OPERATION_TIMED_OUT_EXIT_CODE,
                            f"{SYNTHETIC_ACCESS_TOKEN}\n".encode("ascii"),
                            (
                                f"credential lookup failed: {SYNTHETIC_ACCESS_TOKEN}"
                            ).encode("ascii"),
                        ),
                    ) as spawned,
                    redirect_stdout(stdout),
                    redirect_stderr(stderr),
                    self.assertRaises(
                        ENFORCEMENT_MODULE.EnforcementDoctorError
                    ) as raised,
                ):
                    client.auth_preflight()

        self.assertEqual(raised.exception.reason_code, "blocked-authentication")
        self.assertEqual(
            raised.exception.api_failure,
            {
                "endpoint_class": "authentication-preflight",
                "failure_kind": "authentication",
                "http_status": None,
            },
        )
        self.assertNotIn(SYNTHETIC_ACCESS_TOKEN, str(raised.exception))
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")
        self.assertFalse(run_path.exists())
        spawned.assert_called_once()
        self.assertEqual(
            spawned.call_args.args[0][1:],
            ["auth", "token", "--hostname", "github.com"],
        )

    def test_enforcement_auth_preflight_preserves_api_failure_classification(
        self,
    ) -> None:
        cases = (
            (
                "curl-timeout",
                ENFORCEMENT_MODULE.CURL_OPERATION_TIMED_OUT_EXIT_CODE,
                None,
                "",
                "api-timeout",
                "timeout",
                None,
            ),
            (
                "curl-failure",
                1,
                None,
                "",
                "api-unavailable",
                "unclassified",
                None,
            ),
            (
                "authentication",
                0,
                401,
                "",
                "blocked-authentication",
                "authentication",
                401,
            ),
            (
                "permission",
                0,
                403,
                "",
                "blocked-permission",
                "permission",
                403,
            ),
            (
                "rate-limit-403",
                0,
                403,
                "0",
                "rate-limited",
                "rate-limit",
                403,
            ),
            (
                "not-found",
                0,
                404,
                "",
                "not-found",
                "not-found",
                404,
            ),
            (
                "rate-limit-429",
                0,
                429,
                "",
                "rate-limited",
                "rate-limit",
                429,
            ),
            (
                "server-error",
                0,
                503,
                "",
                "api-unavailable",
                "server-error",
                503,
            ),
        )
        for (
            label,
            return_code,
            status,
            rate_remaining,
            reason_code,
            failure_kind,
            expected_status,
        ) in cases:
            with self.subTest(failure=label), owner_controlled_temp_root() as temp_root:
                trusted_gh = temp_root / "trusted-gh"
                trusted_payload = b"#!/bin/sh\nexit 0\n"
                trusted_gh.write_bytes(trusted_payload)
                trusted_gh.chmod(0o700)
                config_dir, runtime_parent = self._make_private_gh_config(temp_root)
                stdout = io.StringIO()
                stderr = io.StringIO()
                if status is None:
                    response = f"{SYNTHETIC_ACCESS_TOKEN}\n".encode("ascii")
                else:
                    response = self._curl_response(
                        (f'{{"secret":"{SYNTHETIC_ACCESS_TOKEN}"}}').encode("ascii"),
                        status,
                        rate_remaining=rate_remaining,
                    )
                with ENFORCEMENT_MODULE.GitHubApiClient(
                    trusted_gh,
                    hashlib.sha256(trusted_payload).hexdigest(),
                    config_dir,
                    runtime_parent=runtime_parent,
                ) as client:
                    run_path = client._run_directory.path
                    with (
                        mock.patch.object(
                            ENFORCEMENT_MODULE,
                            "_bounded_subprocess",
                            return_value=(
                                return_code,
                                response,
                                (f"transport detail: {SYNTHETIC_ACCESS_TOKEN}").encode(
                                    "ascii"
                                ),
                            ),
                        ) as spawned,
                        redirect_stdout(stdout),
                        redirect_stderr(stderr),
                        self.assertRaises(
                            ENFORCEMENT_MODULE.EnforcementDoctorError
                        ) as raised,
                    ):
                        client.auth_preflight()

                self.assertEqual(raised.exception.reason_code, reason_code)
                self.assertEqual(
                    raised.exception.api_failure,
                    {
                        "endpoint_class": "authenticated-user",
                        "failure_kind": failure_kind,
                        "http_status": expected_status,
                    },
                )
                rendered = json.dumps(
                    {
                        "reason": str(raised.exception),
                        "api_failure": raised.exception.api_failure,
                    },
                    sort_keys=True,
                )
                self.assertNotIn(SYNTHETIC_ACCESS_TOKEN, rendered)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), "")
                self.assertFalse(run_path.exists())
                spawned.assert_called_once()
                command = spawned.call_args.args[0]
                self.assertEqual(
                    command[0],
                    str(ENFORCEMENT_MODULE.CURL_EXECUTABLE),
                )
                self.assertNotIn(
                    SYNTHETIC_ACCESS_TOKEN,
                    "\0".join(command),
                )

    def test_enforcement_invalid_local_token_stops_before_network(self) -> None:
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(
                temp_root,
                hosts_payload=(
                    "github.com:\n"
                    "    git_protocol: https\n"
                    "    users:\n"
                    "        fixture-admin:\n"
                    "    user: fixture-admin\n"
                ),
            )
            with ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            ) as client:
                with (
                    mock.patch.object(
                        ENFORCEMENT_MODULE,
                        "_bounded_subprocess",
                        return_value=(
                            0,
                            b"invalid token with spaces\n",
                            b"",
                        ),
                    ) as spawned,
                    self.assertRaises(
                        ENFORCEMENT_MODULE.EnforcementDoctorError
                    ) as raised,
                ):
                    client.auth_preflight()

        self.assertEqual(raised.exception.reason_code, "blocked-authentication")
        spawned.assert_called_once()
        self.assertNotEqual(
            spawned.call_args.args[0][0],
            str(ENFORCEMENT_MODULE.CURL_EXECUTABLE),
        )

    def test_enforcement_api_failures_are_sanitized_and_actionable(
        self,
    ) -> None:
        cases = (
            ("authentication", 401, "blocked-authentication", "authentication"),
            ("permission", 403, "blocked-permission", "permission"),
            ("rate-limit-403", 403, "rate-limited", "rate-limit"),
            ("not-found", 404, "not-found", "not-found"),
            ("rate-limit-429", 429, "rate-limited", "rate-limit"),
            ("server-500", 500, "api-unavailable", "server-error"),
            ("server-503", 503, "api-unavailable", "server-error"),
        )
        endpoint = "/orgs/Joey-Tools/rulesets/97531"
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            with ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            ) as client:
                for label, status, reason_code, failure_kind in cases:
                    with self.subTest(failure=label):
                        response = self._curl_response(
                            b'{"secret":"response-body"}',
                            status,
                            rate_remaining=("0" if label == "rate-limit-403" else ""),
                        )
                        with mock.patch.object(
                            ENFORCEMENT_MODULE,
                            "_bounded_subprocess",
                            return_value=(
                                0,
                                response,
                                b"Authorization: token super-secret",
                            ),
                        ):
                            with self.assertRaises(
                                ENFORCEMENT_MODULE.EnforcementDoctorError
                            ) as raised:
                                client.get_json(endpoint)

                        error = raised.exception
                        self.assertEqual(error.reason_code, reason_code)
                        self.assertEqual(
                            error.api_failure,
                            {
                                "endpoint_class": "organization-ruleset",
                                "failure_kind": failure_kind,
                                "http_status": status,
                            },
                        )
                        rendered = json.dumps(
                            {
                                "reason": str(error),
                                "api_failure": error.api_failure,
                            },
                            sort_keys=True,
                        )
                        self.assertNotIn("super-secret", rendered)
                        self.assertNotIn("response-body", rendered)
                        self.assertNotIn("Authorization", rendered)

    def test_enforcement_api_malformed_and_timeout_failures_are_sanitized(
        self,
    ) -> None:
        endpoint = "/orgs/Joey-Tools/rulesets/97531"
        with owner_controlled_temp_root() as temp_root:
            trusted_gh = temp_root / "trusted-gh"
            trusted_payload = b"#!/bin/sh\nexit 0\n"
            trusted_gh.write_bytes(trusted_payload)
            trusted_gh.chmod(0o700)
            config_dir, runtime_parent = self._make_private_gh_config(temp_root)
            with ENFORCEMENT_MODULE.GitHubApiClient(
                trusted_gh,
                hashlib.sha256(trusted_payload).hexdigest(),
                config_dir,
                runtime_parent=runtime_parent,
            ) as client:
                with mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "_bounded_subprocess",
                    return_value=(
                        0,
                        self._curl_response(b"{malformed"),
                        b"token super-secret",
                    ),
                ):
                    with self.assertRaises(
                        ENFORCEMENT_MODULE.EnforcementDoctorError
                    ) as malformed:
                        client.get_json(endpoint)

                self.assertEqual(malformed.exception.reason_code, "api-unavailable")
                self.assertEqual(
                    malformed.exception.api_failure,
                    {
                        "endpoint_class": "organization-ruleset",
                        "failure_kind": "malformed-json",
                        "http_status": 200,
                    },
                )
                self.assertNotIn("super-secret", str(malformed.exception))

                client.deadline = time.monotonic() - 1
                with self.assertRaises(
                    ENFORCEMENT_MODULE.EnforcementDoctorError
                ) as timed_out:
                    client.get_json(endpoint)

        self.assertEqual(timed_out.exception.reason_code, "api-timeout")
        self.assertEqual(
            timed_out.exception.api_failure,
            {
                "endpoint_class": "organization-ruleset",
                "failure_kind": "timeout",
                "http_status": None,
            },
        )

    def test_enforcement_doctor_serializes_only_sanitized_api_failure(
        self,
    ) -> None:
        arguments = [
            str(CUTOVER_ENFORCEMENT_DOCTOR_PATH),
            "--contract",
            str(CUTOVER_ENFORCEMENT_CONTRACT_PATH),
            "--gh-executable",
            "/fixed/gh",
            "--expected-gh-sha256",
            "a" * 64,
            "--gh-config-dir",
            "/fixed/config",
            "--pull-request-number",
            str(self._pull_request_number),
            "--expected-ruleset-id",
            str(self._ruleset_id),
            "--expected-run-id",
            "10101",
            "--expected-run-attempt",
            "1",
            "--expected-workflow-id",
            str(self._workflow_id),
            "--expected-workflow-sha",
            self._workflow_source_commit,
            "--expected-base-sha",
            self._base_sha,
            "--candidate-head-sha",
            self._canonical_commit,
        ]
        failure = ENFORCEMENT_MODULE.EnforcementDoctorError(
            "blocked-permission",
            "GitHub API permission blocked the read",
            api_failure={
                "endpoint_class": "organization-ruleset",
                "failure_kind": "permission",
                "http_status": 403,
            },
            cleanup_failure={
                "cleanup_proof": "inconclusive",
                "failed_operations": ["remove-run-directory"],
                "retained_runtime": {
                    "device": 42,
                    "inode": 84,
                    "path": "/fixed/runtime/run-fixture",
                    "path_binding": "verified",
                },
            },
        )
        output = io.StringIO()
        with mock.patch.object(
            ENFORCEMENT_MODULE,
            "GitHubApiClient",
            side_effect=failure,
        ):
            with mock.patch.object(sys, "argv", arguments):
                with redirect_stdout(output):
                    return_code = ENFORCEMENT_MODULE.main()

        self.assertEqual(return_code, 1)
        outcome = json.loads(output.getvalue())
        self.assertEqual(outcome["schema_version"], 6)
        self.assertEqual(outcome["reason_code"], "blocked-permission")
        self.assertEqual(
            outcome["api_failure"],
            {
                "endpoint_class": "organization-ruleset",
                "failure_kind": "permission",
                "http_status": 403,
            },
        )
        self.assertEqual(
            outcome["cleanup_failure"]["retained_runtime"],
            {
                "device": 42,
                "inode": 84,
                "path": "/fixed/runtime/run-fixture",
                "path_binding": "verified",
            },
        )
        self.assertIsNone(outcome["evidence_sha256"])
        self.assertIsNone(outcome["static_equivalence"])
        self.assertEqual(outcome["expected_base_sha"], self._base_sha)
        self.assertIsNone(outcome["provider_observed_base_sha"])
        self.assertNotIn("command", outcome)
        self.assertNotIn("headers", outcome)
        self.assertNotIn("token", output.getvalue().lower())

    def test_enforcement_doctor_cli_receipt_binds_native_objects(
        self,
    ) -> None:
        expected_client = self._matching_live_api_client()
        contract = json.loads(
            CUTOVER_ENFORCEMENT_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        fixed_time = "2026-07-25T12:34:56Z"
        with mock.patch.object(
            ENFORCEMENT_MODULE,
            "_utc_now",
            return_value=fixed_time,
        ):
            expected_evidence, _ = ENFORCEMENT_MODULE._collect_and_validate_static(
                expected_client,
                contract,
                expected_run_attempt=1,
                expected_run_id=10101,
                expected_ruleset_id=self._ruleset_id,
                expected_workflow_id=self._workflow_id,
                expected_workflow_sha=self._workflow_source_commit,
                expected_base_sha=self._base_sha,
                candidate_head_sha=self._canonical_commit,
                pull_request_number=7,
            )
        expected_evidence_sha256 = hashlib.sha256(
            ENFORCEMENT_MODULE._canonical_json_bytes(expected_evidence)
        ).hexdigest()
        client = self._matching_live_api_client()
        arguments = [
            str(CUTOVER_ENFORCEMENT_DOCTOR_PATH),
            "--contract",
            str(CUTOVER_ENFORCEMENT_CONTRACT_PATH),
            "--gh-executable",
            "/fixed/gh",
            "--expected-gh-sha256",
            "a" * 64,
            "--gh-config-dir",
            "/fixed/config",
            "--pull-request-number",
            "7",
            "--expected-ruleset-id",
            str(self._ruleset_id),
            "--expected-run-id",
            "10101",
            "--expected-run-attempt",
            "1",
            "--expected-workflow-id",
            str(self._workflow_id),
            "--expected-workflow-sha",
            self._workflow_source_commit,
            "--expected-base-sha",
            self._base_sha,
            "--candidate-head-sha",
            self._canonical_commit,
        ]
        output = io.StringIO()
        with mock.patch.object(
            ENFORCEMENT_MODULE,
            "GitHubApiClient",
            return_value=client,
        ):
            with mock.patch.object(
                ENFORCEMENT_MODULE,
                "_utc_now",
                return_value=fixed_time,
            ):
                with mock.patch.object(sys, "argv", arguments):
                    with redirect_stdout(output):
                        return_code = ENFORCEMENT_MODULE.main()

        self.assertEqual(return_code, 1)
        outcome = json.loads(output.getvalue())
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertEqual(outcome["schema_version"], 6)
        self.assertEqual(
            outcome["reason_code"],
            "admission-preconditions-unavailable",
        )
        self.assertEqual(
            outcome["blockers"],
            self._expected_admission_blockers(),
        )
        self.assertEqual(outcome["static_equivalence"], "validated")
        self.assertEqual(outcome["expected_base_sha"], self._base_sha)
        self.assertEqual(
            outcome["provider_observed_base_sha"],
            self._base_sha,
        )
        self.assertEqual(
            outcome["evidence_sha256"],
            expected_evidence_sha256,
        )
        self.assertEqual(client.auth_calls, 1)
        self.assertTrue(client.calls)
        variable_endpoint = "/repos/Joey-Tools/codex-debug-triage/actions/variables"
        self.assertEqual(
            [
                query["page"]
                for endpoint, query in client.calls
                if endpoint == variable_endpoint
            ],
            [1, 2, 1, 2],
        )
        attempt_endpoint = (
            "/repos/Joey-Tools/codex-debug-triage/actions/runs/10101/attempts/1"
        )
        self.assertEqual(
            [endpoint for endpoint, _ in client.calls if endpoint == attempt_endpoint],
            [attempt_endpoint, attempt_endpoint],
        )

    def test_enforcement_doctor_stays_blocked_with_pointer_proof_test_double(
        self,
    ) -> None:
        client = self._matching_live_api_client()
        arguments = [
            str(CUTOVER_ENFORCEMENT_DOCTOR_PATH),
            "--contract",
            str(CUTOVER_ENFORCEMENT_CONTRACT_PATH),
            "--gh-executable",
            "/fixed/gh",
            "--expected-gh-sha256",
            "a" * 64,
            "--gh-config-dir",
            "/fixed/config",
            "--pull-request-number",
            "7",
            "--expected-ruleset-id",
            str(self._ruleset_id),
            "--expected-run-id",
            "10101",
            "--expected-run-attempt",
            "1",
            "--expected-workflow-id",
            str(self._workflow_id),
            "--expected-workflow-sha",
            self._workflow_source_commit,
            "--expected-base-sha",
            self._base_sha,
            "--candidate-head-sha",
            self._canonical_commit,
        ]
        output = io.StringIO()
        with mock.patch.object(
            ENFORCEMENT_MODULE,
            "GitHubApiClient",
            return_value=client,
        ):
            with mock.patch.object(
                ENFORCEMENT_MODULE,
                "_require_pointer_proof",
                return_value=None,
            ):
                with mock.patch.object(sys, "argv", arguments):
                    with redirect_stdout(output):
                        return_code = ENFORCEMENT_MODULE.main()

        self.assertEqual(return_code, 1)
        outcome = json.loads(output.getvalue())
        self.assertEqual(outcome["schema_version"], 6)
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertEqual(
            outcome["reason_code"],
            "admission-preconditions-unavailable",
        )
        self.assertEqual(
            outcome["blockers"],
            self._expected_admission_blockers(pointer_available=True),
        )
        self.assertEqual(
            outcome["expected_base_sha"],
            self._base_sha,
        )
        self.assertEqual(
            outcome["provider_observed_base_sha"],
            self._base_sha,
        )
        self.assertEqual(outcome["static_equivalence"], "validated")
        self.assertNotIn("candidate", outcome)

    def test_enforcement_accepts_distinct_source_workflow_repository(
        self,
    ) -> None:
        contract = json.loads(
            CUTOVER_ENFORCEMENT_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        evidence = self._matching_enforcement_evidence()
        source_id = 777777
        source_name = "Joey-Tools/codex-required-workflows"
        workflow = contract["required_workflow"]
        workflow["repository_id"] = source_id
        workflow["repository_full_name"] = source_name
        evidence["workflow_source_repository"].update(
            {
                "full_name": source_name,
                "id": source_id,
            }
        )
        evidence["workflow"]["url"] = (
            f"https://api.github.com/repos/{source_name}/actions/workflows/"
            f"{self._workflow_id}"
        )
        evidence["workflow_source_commit"]["url"] = (
            f"https://api.github.com/repos/{source_name}/commits/"
            f"{self._workflow_source_commit}"
        )
        evidence["workflow_runs"][0]["workflow_url"] = evidence["workflow"]["url"]
        evidence["workflow_run_definition"]["file"].update(
            {
                "repository_file_url": (
                    f"https://github.com/{source_name}/blob/"
                    f"{self._workflow_source_commit}/{workflow['path']}"
                ),
                "repository_name": source_name,
            }
        )
        for ruleset in (
            evidence["effective_rulesets"][0],
            evidence["selected_ruleset"],
        ):
            ruleset["rules"][2]["parameters"]["workflows"][0]["repository_id"] = (
                source_id
            )

        admission = self._validate_static_enforcement(
            evidence,
            contract=contract,
        )

        self.assertEqual(admission["trusted_run"]["id"], 10101)

    def test_enforcement_accepts_pull_request_target_base_run_sha(
        self,
    ) -> None:
        evidence = self._matching_enforcement_evidence()
        base_sha = evidence["pull_request"]["base"]["sha"]
        evidence["workflow_runs"][0]["head_sha"] = base_sha
        evidence["jobs"][0]["head_sha"] = base_sha
        evidence["check_runs"][0]["head_sha"] = base_sha

        admission = self._validate_static_enforcement(evidence)
        self.assertEqual(admission["trusted_run"]["id"], 10101)
        self.assertEqual(admission["trusted_check_run"]["id"], 20202)

        result = self._run_enforcement_doctor(evidence)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(
            json.loads(result.stdout)["reason_code"],
            "admission-preconditions-unavailable",
        )

    def test_enforcement_doctor_rejects_identity_and_scope_drift(
        self,
    ) -> None:
        cases: dict[
            str,
            tuple[object, str],
        ] = {
            "wrong-organization": (
                lambda evidence: evidence["organization"].update({"id": 999999}),
                "organization-identity-mismatch",
            ),
            "wrong-target-default-branch": (
                lambda evidence: evidence["pull_request"]["base"].update(
                    {"ref": "candidate"}
                ),
                "pull-request-identity-mismatch",
            ),
            "wrong-target-base-sha": (
                lambda evidence: evidence["pull_request"]["base"].update(
                    {"sha": "8" * 40}
                ),
                "pull-request-identity-mismatch",
            ),
            "wrong-provider": (
                lambda evidence: evidence["check_runs"][0]["app"].update(
                    {"id": 999999}
                ),
                "candidate-duplicate-context",
            ),
            "wrong-source-workflow-repository": (
                lambda evidence: evidence["workflow_source_repository"].update(
                    {"id": 999999}
                ),
                "workflow-source-repository-mismatch",
            ),
            "wrong-target-scope": (
                lambda evidence: (
                    evidence["effective_rulesets"][0]["conditions"][
                        "repository_id"
                    ].update({"repository_ids": [999999]}),
                    evidence["selected_ruleset"]["conditions"]["repository_id"].update(
                        {"repository_ids": [999999]}
                    ),
                ),
                "ruleset-scope-mismatch",
            ),
            "wrong-org-source": (
                lambda evidence: (
                    evidence["effective_rulesets"][0].update({"source": "Other-Org"}),
                    evidence["selected_ruleset"].update({"source": "Other-Org"}),
                ),
                "ruleset-identity-mismatch",
            ),
            "selector-pr-tamper": (
                lambda evidence: self._cutover_variable(
                    evidence,
                    "CISCO_CUTOVER_TARGET_PR_NUMBER",
                ).update({"value": "8"}),
                "selector-mismatch",
            ),
            "selector-head-tamper": (
                lambda evidence: self._cutover_variable(
                    evidence,
                    "CISCO_CUTOVER_TARGET_HEAD_SHA",
                ).update({"value": "8" * 40}),
                "selector-mismatch",
            ),
            "selector-base-tamper": (
                lambda evidence: self._cutover_variable(
                    evidence,
                    "CISCO_CUTOVER_TARGET_BASE_SHA",
                ).update({"value": "8" * 40}),
                "selector-mismatch",
            ),
            "workflow-id-input-tamper": (
                lambda evidence: self._cutover_variable(
                    evidence,
                    "CISCO_CUTOVER_EXPECTED_WORKFLOW_ID",
                ).update({"value": str(self._workflow_id + 1)}),
                "workflow-input-binding-mismatch",
            ),
            "workflow-sha-input-tamper": (
                lambda evidence: self._cutover_variable(
                    evidence,
                    "CISCO_CUTOVER_EXPECTED_WORKFLOW_SHA",
                ).update({"value": "8" * 40}),
                "workflow-input-binding-mismatch",
            ),
        }
        for label, (mutate, reason_code) in cases.items():
            with self.subTest(drift=label):
                evidence = self._matching_enforcement_evidence()
                mutate(evidence)
                result = self._run_enforcement_doctor(evidence)

                self.assertEqual(result.returncode, 1, result.stderr)
                outcome = json.loads(result.stdout)
                self.assertEqual(outcome["reason_code"], reason_code)

    def test_enforcement_doctor_rejects_base_only_pin_mismatch(self) -> None:
        evidence = self._matching_enforcement_evidence()

        result = self._run_enforcement_doctor(
            evidence,
            expected_base_sha="8" * 40,
        )

        self.assertEqual(result.returncode, 1, result.stderr)
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertEqual(
            outcome["reason_code"],
            "pull-request-identity-mismatch",
        )

    def test_enforcement_constructor_rejects_malformed_base_pin(self) -> None:
        for value in ("A" * 40, "placeholder", "0" * 40):
            with self.subTest(value=value):
                evidence = self._matching_enforcement_evidence()
                with self.assertRaises(
                    ENFORCEMENT_MODULE.EnforcementDoctorError
                ) as raised:
                    self._validate_static_enforcement(
                        evidence,
                        expected_base_sha=value,
                    )

                self.assertEqual(raised.exception.reason_code, "invalid-evidence")

    def test_enforcement_doctor_rejects_cross_pr_and_cross_head_lineage(
        self,
    ) -> None:
        cases = {
            "run-cross-pr": (
                lambda evidence: evidence["workflow_runs"][0]["pull_requests"][
                    0
                ].update({"number": 8}),
                "workflow-run-linkage-mismatch",
            ),
            "check-cross-pr": (
                lambda evidence: evidence["check_runs"][0]["pull_requests"][0].update(
                    {"number": 8}
                ),
                "candidate-pr-mismatch",
            ),
            "check-cross-head": (
                lambda evidence: evidence["check_runs"][0].update(
                    {"head_sha": "8" * 40}
                ),
                "candidate-head-mismatch",
            ),
            "run-cross-suite-url": (
                lambda evidence: evidence["workflow_runs"][0].update(
                    {
                        "check_suite_url": (
                            "https://api.github.com/repos/"
                            "Joey-Tools/codex-debug-triage/check-suites/40404"
                        )
                    }
                ),
                "workflow-run-linkage-mismatch",
            ),
            "run-cross-workflow-url": (
                lambda evidence: evidence["workflow_runs"][0].update(
                    {
                        "workflow_url": (
                            "https://api.github.com/repos/"
                            "Joey-Tools/codex-debug-triage/actions/workflows/99999"
                        )
                    }
                ),
                "workflow-run-linkage-mismatch",
            ),
        }
        for label, (mutate, reason_code) in cases.items():
            with self.subTest(lineage=label):
                evidence = self._matching_enforcement_evidence()
                mutate(evidence)
                result = self._run_enforcement_doctor(evidence)

                self.assertEqual(result.returncode, 1, result.stderr)
                outcome = json.loads(result.stdout)
                self.assertEqual(outcome["reason_code"], reason_code)

    def test_enforcement_doctor_rejects_same_name_status_only_rule(
        self,
    ) -> None:
        evidence = self._matching_enforcement_evidence()
        evidence["effective_rulesets"][0]["rules"].append(
            {
                "type": "required_status_checks",
                "parameters": {
                    "do_not_enforce_on_create": False,
                    "required_status_checks": [
                        {
                            "context": "cisco-cutover-admission",
                            "integration_id": 15368,
                        }
                    ],
                    "strict_required_status_checks_policy": True,
                },
            }
        )
        result = self._run_enforcement_doctor(evidence)

        self.assertEqual(result.returncode, 1, result.stderr)
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertEqual(outcome["reason_code"], "spoofable-status-rule")

    def test_enforcement_doctor_blocks_green_duplicate_without_trusted_run(
        self,
    ) -> None:
        evidence = self._matching_enforcement_evidence()
        evidence["workflow_runs"][0]["workflow_id"] = self._workflow_id + 1
        evidence["workflow_runs"][0]["path"] = (
            ".github/workflows/candidate.yml@candidate"
        )
        result = self._run_enforcement_doctor(evidence)

        self.assertEqual(result.returncode, 1, result.stderr)
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertEqual(outcome["reason_code"], "candidate-duplicate-context")

    def test_enforcement_doctor_blocks_green_duplicate_and_red_trusted_run(
        self,
    ) -> None:
        evidence = self._matching_enforcement_evidence()
        evidence["workflow_runs"][0]["conclusion"] = "failure"
        evidence["jobs"][0]["conclusion"] = "failure"
        evidence["check_runs"][0]["conclusion"] = "failure"
        duplicate_run = self._copy_json(evidence["workflow_runs"][0])
        duplicate_run_url = (
            "https://api.github.com/repos/"
            "Joey-Tools/codex-debug-triage/actions/runs/11111"
        )
        duplicate_run.update(
            {
                "check_suite_id": 40404,
                "check_suite_url": (
                    "https://api.github.com/repos/"
                    "Joey-Tools/codex-debug-triage/check-suites/40404"
                ),
                "conclusion": "success",
                "id": 11111,
                "jobs_url": f"{duplicate_run_url}/jobs",
                "path": ".github/workflows/candidate.yml@candidate",
                "url": duplicate_run_url,
                "workflow_id": self._workflow_id + 1,
            }
        )
        duplicate_job = self._copy_json(evidence["jobs"][0])
        duplicate_check_url = (
            "https://api.github.com/repos/"
            "Joey-Tools/codex-debug-triage/check-runs/21212"
        )
        duplicate_job.update(
            {
                "check_run_url": duplicate_check_url,
                "conclusion": "success",
                "id": 21212,
                "run_id": 11111,
                "run_url": duplicate_run_url,
                "url": (
                    "https://api.github.com/repos/"
                    "Joey-Tools/codex-debug-triage/actions/jobs/21212"
                ),
            }
        )
        duplicate_check = self._copy_json(evidence["check_runs"][0])
        duplicate_check.update(
            {
                "check_suite_id": 40404,
                "conclusion": "success",
                "id": 21212,
                "url": duplicate_check_url,
            }
        )
        evidence["workflow_runs"].append(duplicate_run)
        evidence["jobs"].append(duplicate_job)
        evidence["check_runs"].append(duplicate_check)
        result = self._run_enforcement_doctor(evidence)

        self.assertEqual(result.returncode, 1, result.stderr)
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertEqual(outcome["reason_code"], "candidate-duplicate-context")

    def test_enforcement_doctor_selects_exact_successful_rerun_attempt(
        self,
    ) -> None:
        evidence = self._matching_enforcement_evidence()
        run = evidence["workflow_runs"][0]
        run["run_attempt"] = 2
        run["run_started_at"] = "2026-07-24T12:10:00Z"
        evidence["workflow_run_definition"]["run"]["run_attempt"] = 2
        evidence["selected_run_attempt"].update(
            {
                "run_attempt": 2,
                "run_started_at": "2026-07-24T12:10:00Z",
            }
        )

        first_job = evidence["jobs"][0]
        first_check = evidence["check_runs"][0]
        first_job["conclusion"] = "failure"
        first_check["conclusion"] = "failure"

        second_check_url = (
            "https://api.github.com/repos/"
            "Joey-Tools/codex-debug-triage/check-runs/20203"
        )
        second_job = self._copy_json(first_job)
        second_job.update(
            {
                "check_run_url": second_check_url,
                "conclusion": "success",
                "html_url": (
                    "https://github.com/Joey-Tools/codex-debug-triage/"
                    "actions/runs/10101/job/20203"
                ),
                "id": 20203,
                "run_attempt": 2,
                "started_at": "2026-07-24T12:10:00Z",
                "completed_at": "2026-07-24T12:11:00Z",
                "status": "completed",
                "url": (
                    "https://api.github.com/repos/"
                    "Joey-Tools/codex-debug-triage/actions/jobs/20203"
                ),
            }
        )
        second_check = self._copy_json(first_check)
        second_check.update(
            {
                "conclusion": "success",
                "details_url": second_job["html_url"],
                "html_url": second_job["html_url"],
                "id": 20203,
                "started_at": "2026-07-24T12:10:00Z",
                "completed_at": "2026-07-24T12:11:00Z",
                "status": "completed",
                "url": second_check_url,
            }
        )
        evidence["jobs"].append(second_job)
        evidence["check_runs"].append(second_check)

        admission = self._validate_static_enforcement(
            evidence,
            expected_run_id=10101,
            expected_run_attempt=2,
        )
        self.assertEqual(admission["trusted_run"]["id"], 10101)
        self.assertEqual(admission["trusted_check_run"]["id"], 20203)

        result = self._run_enforcement_doctor(
            evidence,
            expected_run_id=10101,
            expected_run_attempt=2,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(
            json.loads(result.stdout)["reason_code"],
            "admission-preconditions-unavailable",
        )

        superseded = self._run_enforcement_doctor(
            evidence,
            expected_run_id=10101,
            expected_run_attempt=1,
        )
        self.assertEqual(superseded.returncode, 1)
        self.assertEqual(
            json.loads(superseded.stdout)["reason_code"],
            "selected-run-attempt-superseded",
        )

    def test_enforcement_doctor_requires_exact_run_and_attempt_selection(
        self,
    ) -> None:
        evidence = self._matching_enforcement_evidence()
        for label, run_id, run_attempt in (
            ("wrong-run", 10102, 1),
            ("missing-attempt", 10101, 2),
        ):
            with self.subTest(selection=label):
                result = self._run_enforcement_doctor(
                    evidence,
                    expected_run_id=run_id,
                    expected_run_attempt=run_attempt,
                )

                self.assertEqual(result.returncode, 1)
                self.assertEqual(
                    json.loads(result.stdout)["reason_code"],
                    "selected-run-attempt-missing",
                )

    def test_enforcement_doctor_requires_present_successful_trusted_run(
        self,
    ) -> None:
        cases = {
            "absent": (None, "workflow-run-linkage-missing"),
            "red": ("failure", "trusted-workflow-run-failed"),
            "pending": (None, "trusted-workflow-run-failed"),
        }
        for label, (conclusion, reason_code) in cases.items():
            with self.subTest(run=label):
                evidence = self._matching_enforcement_evidence()
                if label == "absent":
                    evidence["workflow_runs"] = []
                elif label == "pending":
                    run = evidence["workflow_runs"][0]
                    run["status"] = "in_progress"
                    run["conclusion"] = conclusion
                else:
                    evidence["workflow_runs"][0]["conclusion"] = conclusion
                result = self._run_enforcement_doctor(evidence)

                self.assertEqual(result.returncode, 1, result.stderr)
                outcome = json.loads(result.stdout)
                self.assertEqual(
                    outcome["classification"],
                    "blocked_until_trusted",
                )
                self.assertEqual(outcome["reason_code"], reason_code)

    def test_enforcement_doctor_binds_executed_workflow_file_to_ruleset_sha(
        self,
    ) -> None:
        evidence = self._matching_enforcement_evidence()

        admission = self._validate_static_enforcement(evidence)
        self.assertEqual(
            admission["protected"]["workflow_run_definition"],
            evidence["workflow_run_definition"],
        )

        cases = {
            "stale-definition-sha": lambda value: value["workflow_run_definition"][
                "file"
            ].update(
                {
                    "repository_file_url": value["workflow_run_definition"]["file"][
                        "repository_file_url"
                    ].replace(self._workflow_source_commit, "5" * 40)
                }
            ),
            "wrong-rerun-attempt": lambda value: value["workflow_run_definition"][
                "run"
            ].update({"run_attempt": 2}),
        }
        for label, mutate in cases.items():
            with self.subTest(definition=label):
                mismatched = self._copy_json(evidence)
                mutate(mismatched)
                result = self._run_enforcement_doctor(mismatched)

                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(
                    json.loads(result.stdout)["reason_code"],
                    "workflow-definition-mismatch",
                )

    def test_enforcement_doctor_rejects_mutable_or_wrong_workflow_binding(
        self,
    ) -> None:
        cases = {
            "missing-sha": ("sha", None, "workflow-binding-not-immutable"),
            "missing-ref": ("ref", None, "workflow-binding-not-immutable"),
            "wrong-sha": (
                "sha",
                "5" * 40,
                "required-workflow-binding-mismatch",
            ),
            "wrong-ref": (
                "ref",
                "refs/heads/candidate",
                "required-workflow-binding-mismatch",
            ),
            "wrong-repository": (
                "repository_id",
                999,
                "required-workflow-binding-mismatch",
            ),
            "wrong-path": (
                "path",
                ".github/workflows/candidate.yml",
                "required-workflow-binding-mismatch",
            ),
        }
        for label, (field, value, reason_code) in cases.items():
            with self.subTest(binding=label):
                evidence = self._matching_enforcement_evidence()
                for ruleset in (
                    evidence["effective_rulesets"][0],
                    evidence["selected_ruleset"],
                ):
                    binding = ruleset["rules"][2]["parameters"]["workflows"][0]
                    if value is None:
                        del binding[field]
                    else:
                        binding[field] = value
                result = self._run_enforcement_doctor(evidence)

                self.assertEqual(result.returncode, 1, result.stderr)
                outcome = json.loads(result.stdout)
                self.assertEqual(
                    outcome["classification"],
                    "blocked_until_trusted",
                )
                self.assertEqual(outcome["reason_code"], reason_code)

    def test_enforcement_doctor_rejects_wrong_ids_inactive_or_bypass_rules(
        self,
    ) -> None:
        mutations = {
            "wrong-ruleset-id": (
                lambda evidence: (
                    evidence["effective_rulesets"][0].update({"id": 42}),
                    evidence["selected_ruleset"].update({"id": 42}),
                ),
                "ruleset-identity-mismatch",
            ),
            "wrong-workflow-id": (
                lambda evidence: evidence["workflow"].update({"id": 42}),
                "workflow-identity-mismatch",
            ),
            "disabled": (
                lambda evidence: (
                    evidence["effective_rulesets"][0].update(
                        {"enforcement": "disabled"}
                    ),
                    evidence["selected_ruleset"].update({"enforcement": "disabled"}),
                ),
                "ruleset-not-active",
            ),
            "evaluate": (
                lambda evidence: (
                    evidence["effective_rulesets"][0].update(
                        {"enforcement": "evaluate"}
                    ),
                    evidence["selected_ruleset"].update({"enforcement": "evaluate"}),
                ),
                "ruleset-not-active",
            ),
            "bypass": (
                lambda evidence: (
                    evidence["effective_rulesets"][0].update(
                        {
                            "bypass_actors": [
                                {
                                    "actor_id": 5,
                                    "actor_type": "RepositoryRole",
                                    "bypass_mode": "always",
                                }
                            ]
                        }
                    ),
                    evidence["selected_ruleset"].update(
                        {
                            "bypass_actors": [
                                {
                                    "actor_id": 5,
                                    "actor_type": "RepositoryRole",
                                    "bypass_mode": "always",
                                }
                            ]
                        }
                    ),
                ),
                "ruleset-bypass-configured",
            ),
        }
        for label, (mutate, reason_code) in mutations.items():
            with self.subTest(configuration=label):
                evidence = self._matching_enforcement_evidence()
                mutate(evidence)
                result = self._run_enforcement_doctor(evidence)

                self.assertEqual(result.returncode, 1, result.stderr)
                outcome = json.loads(result.stdout)
                self.assertEqual(
                    outcome["classification"],
                    "blocked_until_trusted",
                )
                self.assertEqual(outcome["reason_code"], reason_code)

    def test_enforcement_doctor_rejects_caller_completeness_booleans(
        self,
    ) -> None:
        evidence = self._matching_enforcement_evidence()
        evidence["collection"] = {
            "check_runs_complete": True,
            "rulesets_complete": True,
        }
        result = self._run_enforcement_doctor(evidence)

        self.assertEqual(result.returncode, 1, result.stderr)
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertEqual(outcome["reason_code"], "invalid-evidence")

    def test_private_migration_fixture_binds_atomic_aggregate_cutover(self) -> None:
        fixture = json.loads(MIGRATION_FIXTURE_PATH.read_text(encoding="utf-8"))

        self.assertEqual(fixture["schema_version"], 3)
        self.assertEqual(
            fixture["canonical_repository"],
            "Joey-Tools/codex-debug-triage",
        )
        self.assertFalse(fixture["canonical_merge_changes_installed_routing"])
        self.assertEqual(
            fixture["private_aggregate_repository"],
            "Joey-Tools/codex-private-workflows",
        )
        activation = fixture["activation"]
        self.assertEqual(activation["release_kind"], "immutable-private-overlay")
        self.assertTrue(activation["atomic"])
        self.assertEqual(
            activation["provider"],
            {
                "source": "personal_codex/skills/cisco-build-artifacts",
                "target": "skills/cisco-build-artifacts",
            },
        )
        self.assertEqual(
            activation["routing_policy"],
            {
                "source": "personal_codex/AGENTS.md",
                "target": "AGENTS.md",
                "cisco_build_fetch_and_archive": "skills/cisco-build-artifacts",
                "ordinary_local_diagnosis": "base-model-no-skill-route",
            },
        )
        self.assertEqual(
            activation["catalog"],
            {
                "manifest": "personal_codex/private-sync-manifest.json",
                "active_target": "skills/cisco-build-artifacts",
                "removed_target": "skills/bug-triage-playbook",
            },
        )
        self.assertEqual(
            activation["removed_link"],
            {
                "source": "personal_codex/skills/bug-triage-playbook",
                "target": "skills/bug-triage-playbook",
                "replacement_target": "skills/cisco-build-artifacts",
                "replacement_scope": "cisco-build-fetch-and-archive-only",
            },
        )
        self.assertEqual(
            activation["public_asset"],
            {
                "repository": "Joey-Tools/codex-debug-triage",
                "status": "optional-source-only",
                "installed_route": False,
            },
        )
        self.assertEqual(
            fixture["blocked_until_trusted"],
            [
                "canonical-bug-triage-retirement-pr",
                "private-consumer-source-sync",
            ],
        )
        self.assertEqual(
            fixture["unproved_atomicity_fallback"],
            "retain-bug-triage-compat",
        )
        self.assertEqual(
            fixture["base_change_enforcement"],
            self._expected_base_change_enforcement(),
        )
        self.assertEqual(
            fixture["trust_gates"],
            [
                "private-package-validation",
                "private-overlay-verifier",
                "immutable-release-published",
                "installed-current-pointer-verified",
            ],
        )
        state_machine = fixture["retirement_state_machine"]
        self.assertEqual(
            state_machine["phases"],
            [
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
        )
        self.assertEqual(
            state_machine["base_change_transition"],
            "retirement-pr-head-frozen",
        )
        self.assertFalse(state_machine["automatic_mutation"])
        decommission = fixture["post_cutover_decommission"]
        self.assertEqual(
            decommission["trigger"],
            "retirement-pr-merged-at-frozen-range",
        )
        self.assertEqual(
            decommission["lease_variable"],
            "CISCO_CUTOVER_DECOMMISSION_LEASE",
        )
        self.assertFalse(
            decommission["compare_and_swap"]["unsafe-conditional-requests-supported"]
        )
        self.assertTrue(
            decommission["compare_and_swap"]["revalidate-before-each-mutation"]
        )
        decommission_steps = decommission["ordered_steps"]
        self.assertLess(
            decommission_steps.index("prove-ruleset-is-not-effective"),
            decommission_steps.index("remove-workflow-in-separate-reviewed-pr"),
        )
        self.assertLess(
            decommission_steps.index(
                "prove-workflow-absent-and-ruleset-still-inactive"
            ),
            decommission_steps.index(
                "delete-exact-cutover-variables-after-value-digest-and-updated-at-compare"
            ),
        )
        self.assertLess(
            decommission_steps.index(
                "delete-exact-cutover-variables-after-value-digest-and-updated-at-compare"
            ),
            decommission_steps.index(
                "delete-exact-inactive-ruleset-after-content-compare"
            ),
        )
        self.assertEqual(decommission_steps[-1], "delete-lease-last")
        self.assertFalse(decommission["automatic_mutation"])
        self.assertEqual(
            fixture["receipt_admission"],
            {
                "status_without_receipt": "blocked_until_trusted",
                "validator": ("scripts/validate_cisco_cutover_receipt.py"),
                "receipt_schema_version": 3,
                "receipt_max_bytes": 35840,
                "producer_workflow": ".github/workflows/release.yml",
                "pointer_name": "current",
                "pointer_target_template": ("releases/{private_release_commit}"),
                "required_exact_inputs": [
                    "expected_canonical_commit",
                    "expected_base_sha",
                    "expected_pull_request_number",
                    "expected_private_release_commit",
                    "expected_release_manifest_sha256",
                    "expected_receipt_sha256",
                    "expected_workflow_id",
                    "expected_workflow_sha",
                    "expected_installation_scope_id",
                    "expected_pointer_generation",
                    "expected_pointer_state_sha256",
                ],
            },
        )
        receipt_max_bytes = fixture["receipt_admission"]["receipt_max_bytes"]
        self.assertLessEqual(
            4 * ((receipt_max_bytes + 2) // 3),
            48_000,
        )
        trusted_workflow = CUTOVER_TRUSTED_WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("MAX_RECEIPT_BYTES = 35 * 1024", trusted_workflow)

    def test_post_cutover_routing_does_not_depend_on_removed_skill(self) -> None:
        fixture = json.loads(MIGRATION_FIXTURE_PATH.read_text(encoding="utf-8"))
        activation = fixture["activation"]
        self.assertEqual(
            activation["routing_policy"]["cisco_build_fetch_and_archive"],
            "skills/cisco-build-artifacts",
        )
        self.assertEqual(
            activation["routing_policy"]["ordinary_local_diagnosis"],
            "base-model-no-skill-route",
        )
        self.assertEqual(
            activation["catalog"]["removed_target"],
            "skills/bug-triage-playbook",
        )
        self.assertEqual(
            activation["removed_link"]["replacement_scope"],
            "cisco-build-fetch-and-archive-only",
        )
        self.assertFalse(activation["public_asset"]["installed_route"])

        migration = (REPO_ROOT / "docs/cisco-build-artifacts-migration.md").read_text(
            encoding="utf-8"
        )
        handoff = migration.split("## Handoff To Base-Model Diagnosis", 1)[1].split(
            "## Private Migration Tests",
            1,
        )[0]
        self.assertNotIn("explicitly invoke `$bug-triage-playbook`", handoff)
        self.assertIn("ordinary base-model diagnosis", handoff)
        self.assertIn("must not invoke or\nrecreate an installed", handoff)
        self.assertIn("optional source tool", handoff)

    def test_cutover_validator_without_receipt_remains_blocked(self) -> None:
        result = self._run_cutover_validator()

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stderr, "")
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertIn("receipt path was not provided", outcome["reason"])

    def test_cutover_validator_usage_error_is_single_line_machine_output(
        self,
    ) -> None:
        result = subprocess.run(
            [sys.executable, str(CUTOVER_VALIDATOR_PATH)],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, "")
        self.assertEqual(len(result.stdout.splitlines()), 1)
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertIn("argument error", outcome["reason"])

    def test_cutover_validator_blocks_on_unavailable_admission_preconditions(
        self,
    ) -> None:
        fixture = json.loads(MIGRATION_FIXTURE_PATH.read_text(encoding="utf-8"))
        receipt = self._matching_cutover_receipt(fixture)
        with tempfile.TemporaryDirectory() as temp_dir:
            receipt_path = Path(temp_dir) / "cutover-receipt.json"
            receipt_sha256 = self._write_cutover_receipt(
                receipt_path,
                receipt,
            )
            result = self._run_cutover_validator(
                receipt_path=receipt_path,
                receipt_sha256=receipt_sha256,
            )

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(result.stderr, "")
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertEqual(
            outcome["reason"],
            "admission-preconditions-unavailable",
        )
        self.assertEqual(
            outcome["blockers"],
            self._expected_admission_blockers(),
        )
        self.assertEqual(outcome["static_equivalence"], "validated")
        self.assertEqual(
            outcome["validation_scope"],
            "static-equivalence-only",
        )
        self.assertEqual(
            outcome["pointer_target"],
            f"releases/{self._private_release_commit}",
        )
        self.assertEqual(outcome["receipt_sha256"], receipt_sha256)

    def test_cutover_validator_requires_exact_expected_base_sha(self) -> None:
        fixture = json.loads(MIGRATION_FIXTURE_PATH.read_text(encoding="utf-8"))
        receipt = self._matching_cutover_receipt(fixture)
        cases = {
            "missing": (None, False),
            "malformed": ("A" * 40, True),
            "placeholder": ("placeholder", True),
            "all-zero": ("0" * 40, True),
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            receipt_path = temp_root / "cutover-receipt.json"
            receipt_sha256 = self._write_cutover_receipt(receipt_path, receipt)
            for label, (expected_base_sha, include_expected) in cases.items():
                with self.subTest(case=label):
                    result = self._run_cutover_validator(
                        receipt_path=receipt_path,
                        receipt_sha256=receipt_sha256,
                        expected_base_sha=expected_base_sha,
                        include_expected_base_sha=include_expected,
                    )

                    self.assertEqual(result.returncode, 1, result.stderr)
                    outcome = json.loads(result.stdout)
                    self.assertEqual(
                        outcome["classification"],
                        "blocked_until_trusted",
                    )
                    self.assertRegex(
                        outcome["reason"],
                        r"(were not provided|must be exact lowercase 40-hex)",
                    )

    def test_cutover_validator_rejects_stale_receipt_after_base_retarget(
        self,
    ) -> None:
        fixture = json.loads(MIGRATION_FIXTURE_PATH.read_text(encoding="utf-8"))
        stale_receipt = self._matching_cutover_receipt(fixture)
        with tempfile.TemporaryDirectory() as temp_dir:
            receipt_path = Path(temp_dir) / "stale-base-receipt.json"
            receipt_sha256 = self._write_cutover_receipt(
                receipt_path,
                stale_receipt,
            )
            result = self._run_cutover_validator(
                receipt_path=receipt_path,
                receipt_sha256=receipt_sha256,
                expected_base_sha="8" * 40,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertIn("receipt cutover", outcome["reason"])
        self.assertNotEqual(outcome.get("static_equivalence"), "validated")

    def test_cutover_validator_rejects_pointer_authority_and_lease_drift(
        self,
    ) -> None:
        fixture = json.loads(MIGRATION_FIXTURE_PATH.read_text(encoding="utf-8"))
        cases = {
            "installation-scope": (
                lambda pointer: pointer.update(
                    {"installation_scope_id": "other-installation-scope"}
                ),
                "installation scope differs",
            ),
            "generation": (
                lambda pointer: pointer.update(
                    {"generation": self._pointer_generation + 1}
                ),
                "generation differs",
            ),
            "state-digest": (
                lambda pointer: pointer.update({"state_sha256": "7" * 64}),
                "state digest differs",
            ),
            "authority-repository": (
                lambda pointer: pointer["live_authority"].update(
                    {"repository_full_name": "attacker/private-workflows"}
                ),
                "authority repository differs",
            ),
            "authority-workflow": (
                lambda pointer: pointer["live_authority"].update(
                    {"workflow_path": ".github/workflows/other.yml"}
                ),
                "authority workflow path differs",
            ),
            "authority-provider": (
                lambda pointer: pointer["live_authority"]["provider"].update(
                    {"id": 99999}
                ),
                "authority provider.id differs",
            ),
            "lease-status": (
                lambda pointer: pointer["merge_lease"].update({"status": "released"}),
                "merge lease status differs",
            ),
            "lease-head": (
                lambda pointer: pointer["merge_lease"].update(
                    {"pull_request_head_sha": "8" * 40}
                ),
                "merge lease pull-request head SHA differs",
            ),
            "lease-base": (
                lambda pointer: pointer["merge_lease"].update(
                    {"pull_request_base_sha": "8" * 40}
                ),
                "merge lease pull-request base SHA differs",
            ),
            "lease-scope": (
                lambda pointer: pointer["merge_lease"].update(
                    {"installation_scope_id": "other-installation-scope"}
                ),
                "merge lease installation scope ID differs",
            ),
            "lease-generation": (
                lambda pointer: pointer["merge_lease"].update(
                    {"pointer_generation": self._pointer_generation + 1}
                ),
                "merge lease generation differs",
            ),
            "pointer-expired": (
                lambda pointer: (
                    pointer.update(
                        {
                            "observed_at": "2000-01-01T00:00:00Z",
                            "expires_at": "2000-01-02T00:00:00Z",
                        }
                    ),
                    pointer["merge_lease"].update(
                        {
                            "acquired_at": "2000-01-01T00:00:00Z",
                        }
                    ),
                ),
                "pointer proof has expired",
            ),
            "pointer-future": (
                lambda pointer: (
                    pointer.update(
                        {
                            "observed_at": "2099-01-01T00:00:00Z",
                            "expires_at": "2100-01-01T00:00:00Z",
                        }
                    ),
                    pointer["merge_lease"].update(
                        {
                            "acquired_at": "2099-01-01T00:00:00Z",
                            "expires_at": "2100-01-01T00:00:00Z",
                        }
                    ),
                ),
                "observed_at is in the future",
            ),
            "lease-expired": (
                lambda pointer: (
                    pointer.update(
                        {
                            "observed_at": "2000-01-01T00:00:00Z",
                        }
                    ),
                    pointer["merge_lease"].update(
                        {
                            "acquired_at": "2000-01-01T00:00:00Z",
                            "expires_at": "2000-01-02T00:00:00Z",
                        }
                    ),
                ),
                "merge lease has expired",
            ),
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            for label, (mutate, expected_reason) in cases.items():
                with self.subTest(pointer_drift=label):
                    receipt = self._matching_cutover_receipt(fixture)
                    mutate(receipt["installed_pointer"])
                    receipt_path = temp_root / f"{label}.json"
                    receipt_sha256 = self._write_cutover_receipt(
                        receipt_path,
                        receipt,
                    )
                    result = self._run_cutover_validator(
                        receipt_path=receipt_path,
                        receipt_sha256=receipt_sha256,
                    )

                    self.assertEqual(result.returncode, 1, result.stdout)
                    outcome = json.loads(result.stdout)
                    self.assertEqual(
                        outcome["classification"],
                        "blocked_until_trusted",
                    )
                    self.assertIn(expected_reason, outcome["reason"])

    def test_cutover_pointer_generation_prevents_switch_and_rollback_replay(
        self,
    ) -> None:
        fixture = json.loads(MIGRATION_FIXTURE_PATH.read_text(encoding="utf-8"))
        old_receipt = self._matching_cutover_receipt(fixture)
        old_payload = (
            json.dumps(
                old_receipt,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            old_path = temp_root / "old-generation.json"
            old_digest = self._write_cutover_receipt(old_path, old_receipt)
            for expected_generation in (
                self._pointer_generation + 1,
                self._pointer_generation + 2,
            ):
                with self.subTest(expected_generation=expected_generation):
                    result = self._run_cutover_validator(
                        receipt_path=old_path,
                        receipt_sha256=old_digest,
                        expected_pointer_generation=expected_generation,
                        expected_pointer_state_sha256=self._pointer_state_sha256(
                            generation=expected_generation
                        ),
                    )
                    self.assertEqual(result.returncode, 1, result.stdout)
                    self.assertIn(
                        "pointer generation differs",
                        json.loads(result.stdout)["reason"],
                    )

            rollback_generation = self._pointer_generation + 2
            rollback_receipt = self._matching_cutover_receipt(fixture)
            rollback_pointer = rollback_receipt["installed_pointer"]
            rollback_pointer["generation"] = rollback_generation
            rollback_pointer["state_sha256"] = self._pointer_state_sha256(
                generation=rollback_generation
            )
            rollback_pointer["merge_lease"]["pointer_generation"] = rollback_generation
            rollback_path = temp_root / "rollback-generation.json"
            rollback_digest = self._write_cutover_receipt(
                rollback_path,
                rollback_receipt,
            )
            rollback_result = self._run_cutover_validator(
                receipt_path=rollback_path,
                receipt_sha256=rollback_digest,
                expected_pointer_generation=rollback_generation,
                expected_pointer_state_sha256=self._pointer_state_sha256(
                    generation=rollback_generation
                ),
            )

            workflow_result = self._run_trusted_workflow_program(
                environment=self._trusted_workflow_environment(
                    receipt_payload=old_payload,
                    overrides={
                        "CISCO_CUTOVER_EXPECTED_POINTER_GENERATION": str(
                            rollback_generation
                        ),
                        "CISCO_CUTOVER_EXPECTED_POINTER_STATE_SHA256": (
                            self._pointer_state_sha256(generation=rollback_generation)
                        ),
                    },
                ),
                cwd=temp_root,
            )

        self.assertEqual(rollback_result.returncode, 1, rollback_result.stdout)
        rollback_outcome = json.loads(rollback_result.stdout)
        self.assertEqual(
            rollback_outcome["reason"],
            "admission-preconditions-unavailable",
        )
        self.assertEqual(
            rollback_outcome["blockers"],
            self._expected_admission_blockers(),
        )
        self.assertEqual(
            rollback_outcome["static_equivalence"],
            "validated",
        )
        self.assertEqual(workflow_result.returncode, 1, workflow_result.stdout)
        self.assertIn(
            "pointer generation differs",
            json.loads(workflow_result.stdout)["reason"],
        )

    def test_cutover_validator_rejects_legacy_pointer_receipt_schema(
        self,
    ) -> None:
        fixture = json.loads(MIGRATION_FIXTURE_PATH.read_text(encoding="utf-8"))
        receipt = self._matching_cutover_receipt(fixture)
        receipt["schema_version"] = 2
        with tempfile.TemporaryDirectory() as temp_dir:
            receipt_path = Path(temp_dir) / "legacy-receipt.json"
            receipt_digest = self._write_cutover_receipt(receipt_path, receipt)
            result = self._run_cutover_validator(
                receipt_path=receipt_path,
                receipt_sha256=receipt_digest,
            )

        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("schema_version differs", json.loads(result.stdout)["reason"])

    def test_cutover_admission_rejects_route_back_to_removed_skill(self) -> None:
        fixture = json.loads(MIGRATION_FIXTURE_PATH.read_text(encoding="utf-8"))
        receipt = self._matching_cutover_receipt(fixture)
        receipt["activation"]["routing_policy"]["ordinary_local_diagnosis"] = (
            "skills/bug-triage-playbook"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            receipt_path = temp_root / "route-back-receipt.json"
            receipt_sha256 = self._write_cutover_receipt(receipt_path, receipt)
            local_result = self._run_cutover_validator(
                receipt_path=receipt_path,
                receipt_sha256=receipt_sha256,
            )
            receipt_payload = receipt_path.read_bytes()
            workflow_result = self._run_trusted_workflow_program(
                environment=self._trusted_workflow_environment(
                    receipt_payload=receipt_payload,
                ),
                cwd=temp_root,
            )

        for label, result in (
            ("local-validator", local_result),
            ("protected-workflow", workflow_result),
        ):
            with self.subTest(admission=label):
                self.assertEqual(result.returncode, 1, result.stderr)
                outcome = json.loads(result.stdout)
                self.assertEqual(
                    outcome["classification"],
                    "blocked_until_trusted",
                )
                self.assertIn("receipt activation", outcome["reason"])
                self.assertIn("differs", outcome["reason"])

    def test_cutover_validator_rejects_receipt_digest_not_independently_pinned(
        self,
    ) -> None:
        fixture = json.loads(MIGRATION_FIXTURE_PATH.read_text(encoding="utf-8"))
        receipt = self._matching_cutover_receipt(fixture)
        with tempfile.TemporaryDirectory() as temp_dir:
            receipt_path = Path(temp_dir) / "cutover-receipt.json"
            self._write_cutover_receipt(receipt_path, receipt)
            result = self._run_cutover_validator(
                receipt_path=receipt_path,
                receipt_sha256="4" * 64,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertIn("trusted exact digest", outcome["reason"])

    def test_cutover_validator_rejects_pointer_not_bound_to_release(
        self,
    ) -> None:
        fixture = json.loads(MIGRATION_FIXTURE_PATH.read_text(encoding="utf-8"))
        receipt = self._matching_cutover_receipt(fixture)
        receipt["installed_pointer"]["target"] = f"releases/{'4' * 40}"
        with tempfile.TemporaryDirectory() as temp_dir:
            receipt_path = Path(temp_dir) / "cutover-receipt.json"
            receipt_sha256 = self._write_cutover_receipt(
                receipt_path,
                receipt,
            )
            result = self._run_cutover_validator(
                receipt_path=receipt_path,
                receipt_sha256=receipt_sha256,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertIn("pointer target", outcome["reason"])

    def test_cutover_validator_rejects_repo_pr_head_or_workflow_drift(
        self,
    ) -> None:
        fixture = json.loads(MIGRATION_FIXTURE_PATH.read_text(encoding="utf-8"))
        cases = {
            "repository": (
                lambda receipt: receipt["cutover"]["target_repository"].update(
                    {"id": 999999}
                )
            ),
            "pull-request": (
                lambda receipt: receipt["cutover"]["pull_request"].update(
                    {"number": self._pull_request_number + 1}
                )
            ),
            "head": (
                lambda receipt: receipt["cutover"]["pull_request"].update(
                    {"head_sha": "8" * 40}
                )
            ),
            "base": (
                lambda receipt: receipt["cutover"]["pull_request"].update(
                    {"base_sha": "8" * 40}
                )
            ),
            "workflow": (
                lambda receipt: receipt["cutover"]["required_workflow"].update(
                    {"sha": "8" * 40}
                )
            ),
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            for label, mutate in cases.items():
                with self.subTest(binding=label):
                    receipt = self._matching_cutover_receipt(fixture)
                    mutate(receipt)
                    receipt_path = temp_root / f"{label}.json"
                    receipt_sha256 = self._write_cutover_receipt(
                        receipt_path,
                        receipt,
                    )
                    result = self._run_cutover_validator(
                        receipt_path=receipt_path,
                        receipt_sha256=receipt_sha256,
                    )

                    self.assertEqual(result.returncode, 1, result.stderr)
                    outcome = json.loads(result.stdout)
                    self.assertEqual(
                        outcome["classification"],
                        "blocked_until_trusted",
                    )
                    self.assertIn("receipt cutover", outcome["reason"])

    def test_cutover_validator_rejects_weakened_admission_contract(self) -> None:
        cases = {
            "non-atomic": (
                lambda contract: contract["activation"].update({"atomic": False}),
                "activation.atomic",
            ),
            "base-change-available": (
                lambda contract: contract["base_change_enforcement"].update(
                    {"status": "available"}
                ),
                "base_change_enforcement",
            ),
            "base-change-dispatch-drift": (
                lambda contract: contract["base_change_enforcement"][
                    "ruleset_dispatch_activities"
                ].append("edited"),
                "base_change_enforcement",
            ),
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            for label, (mutate, expected_reason) in cases.items():
                with self.subTest(case=label):
                    contract = json.loads(
                        MIGRATION_FIXTURE_PATH.read_text(encoding="utf-8")
                    )
                    mutate(contract)
                    contract_path = temp_root / f"{label}.json"
                    contract_path.write_text(
                        json.dumps(contract),
                        encoding="utf-8",
                    )
                    result = self._run_cutover_validator(
                        contract_path=contract_path,
                    )

                    self.assertEqual(result.returncode, 1, result.stderr)
                    outcome = json.loads(result.stdout)
                    self.assertEqual(
                        outcome["classification"],
                        "blocked_until_trusted",
                    )
                    self.assertIn(expected_reason, outcome["reason"])

    def test_cutover_validator_routes_enforcement_contract_to_doctor(self) -> None:
        result = self._run_cutover_validator(
            contract_path=CUTOVER_ENFORCEMENT_CONTRACT_PATH,
        )

        self.assertEqual(result.returncode, 1, result.stderr)
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertIn("contract profile differs", outcome["reason"])
        self.assertIn(
            "doctor_cisco_cutover_enforcement.py",
            outcome["reason"],
        )

    def test_cutover_validator_requires_exact_contract_scalar_types(self) -> None:
        fixture = json.loads(MIGRATION_FIXTURE_PATH.read_text(encoding="utf-8"))
        cases = (
            ("schema-float", ("schema_version",), 3.0),
            (
                "routing-integer",
                ("canonical_merge_changes_installed_routing",),
                0,
            ),
            ("atomic-integer", ("activation", "atomic"), 1),
            (
                "nested-string-boolean",
                ("activation", "provider", "source"),
                True,
            ),
            ("trust-gates-object", ("trust_gates",), {"gate": "passed"}),
            (
                "base-change-status-boolean",
                ("base_change_enforcement", "status"),
                True,
            ),
            (
                "receipt-schema-boolean",
                ("receipt_admission", "receipt_schema_version"),
                True,
            ),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            for label, path, replacement in cases:
                with self.subTest(case=label):
                    contract = json.loads(json.dumps(fixture))
                    target = contract
                    for component in path[:-1]:
                        target = target[component]
                    target[path[-1]] = replacement
                    contract_path = Path(temp_dir) / f"{label}.json"
                    contract_path.write_text(
                        json.dumps(contract),
                        encoding="utf-8",
                    )
                    result = self._run_cutover_validator(
                        contract_path=contract_path,
                    )

                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(result.stderr, "")
                    outcome = json.loads(result.stdout)
                    self.assertEqual(
                        outcome["classification"],
                        "blocked_until_trusted",
                    )

    def test_cutover_validator_requires_exact_receipt_scalar_types(self) -> None:
        fixture = json.loads(MIGRATION_FIXTURE_PATH.read_text(encoding="utf-8"))
        cases = (
            ("schema-boolean", ("schema_version",), True),
            ("atomic-integer", ("activation", "atomic"), 1),
            ("gate-status-boolean", ("gates", 0, "status"), True),
            ("digest-boolean", ("release_manifest_sha256",), True),
            (
                "base-sha-boolean",
                ("cutover", "pull_request", "base_sha"),
                True,
            ),
            ("pointer-name-boolean", ("installed_pointer", "name"), True),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            for label, path, replacement in cases:
                with self.subTest(case=label):
                    receipt = self._matching_cutover_receipt(
                        json.loads(json.dumps(fixture))
                    )
                    target = receipt
                    for component in path[:-1]:
                        target = target[component]
                    target[path[-1]] = replacement
                    receipt_path = Path(temp_dir) / f"{label}.json"
                    receipt_sha256 = self._write_cutover_receipt(
                        receipt_path,
                        receipt,
                    )
                    result = self._run_cutover_validator(
                        receipt_path=receipt_path,
                        receipt_sha256=receipt_sha256,
                    )

                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(result.stderr, "")
                    outcome = json.loads(result.stdout)
                    self.assertEqual(
                        outcome["classification"],
                        "blocked_until_trusted",
                    )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO support")
    def test_cutover_validator_rejects_fifo_inputs_without_waiting(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            for label in ("contract", "receipt"):
                with self.subTest(input=label):
                    input_path = Path(temp_dir) / f"{label}.fifo"
                    os.mkfifo(input_path)
                    started = time.monotonic()
                    if label == "contract":
                        result = self._run_cutover_validator(
                            contract_path=input_path,
                        )
                    else:
                        result = self._run_cutover_validator(
                            receipt_path=input_path,
                            receipt_sha256="4" * 64,
                        )
                    elapsed = time.monotonic() - started

                    self.assertLess(elapsed, 1.0)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(result.stderr, "")
                    self.assertEqual(len(result.stdout.splitlines()), 1)
                    outcome = json.loads(result.stdout)
                    self.assertEqual(
                        outcome["classification"],
                        "blocked_until_trusted",
                    )
                    self.assertIn("regular file", outcome["reason"])

    def test_cutover_validator_caps_deep_json_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            contract_path = Path(temp_dir) / "deep-contract.json"
            contract_path.write_text(
                ("[" * 65) + "0" + ("]" * 65),
                encoding="utf-8",
            )
            result = self._run_cutover_validator(
                contract_path=contract_path,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertLessEqual(len(result.stdout), 1_200)
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertIn("max JSON depth", outcome["reason"])

    def test_cutover_validator_caps_huge_integer_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            contract_path = Path(temp_dir) / "huge-integer-contract.json"
            contract_path.write_text(
                '{"schema_version":' + ("9" * 5_000) + "}",
                encoding="utf-8",
            )
            result = self._run_cutover_validator(
                contract_path=contract_path,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertLessEqual(len(result.stdout), 1_200)
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertIn("integer exceeds max digits", outcome["reason"])


if __name__ == "__main__":
    unittest.main()
