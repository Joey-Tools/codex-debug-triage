from __future__ import annotations

import argparse
import ast
import base64
import binascii
import errno
import hashlib
import importlib.util
import io
import json
import os
import shlex
import signal
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
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
        open_call.assert_called_once()

    def test_archive_growth_after_initial_fstat_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            archive_path = self._make_archive(Path(temp_dir))
            real_fstat = os.fstat
            fstat_calls = 0

            def grow_after_initial_fstat(fd: int) -> os.stat_result:
                nonlocal fstat_calls
                fstat_calls += 1
                if fstat_calls == 2:
                    growth_fd = os.open(
                        archive_path,
                        os.O_WRONLY | os.O_APPEND,
                    )
                    try:
                        os.write(growth_fd, b"concurrent-growth")
                    finally:
                        os.close(growth_fd)
                return real_fstat(fd)

            stdout = io.StringIO()
            stderr = io.StringIO()
            real_zipfile = zipfile.ZipFile
            with mock.patch.object(
                MODULE.os,
                "fstat",
                side_effect=grow_after_initial_fstat,
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
        self.assertGreaterEqual(fstat_calls, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("archive size changed after open", stderr.getvalue())

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
        os.name == "posix" and hasattr(os, "killpg"),
        "process-group containment requires POSIX",
    )
    def test_external_group_termination_reaps_catastrophic_regex_worker(
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

        def process_exists(pid: int) -> bool:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return False
            except PermissionError:
                return True
            return True

        def process_group_exists(pgid: int) -> bool:
            try:
                os.killpg(pgid, 0)
            except ProcessLookupError:
                return False
            except PermissionError:
                return True
            return True

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
                        self.assertTrue(process_exists(worker_pid))
                        time.sleep(0.05)
                        self.assertIsNone(process.poll())

                        os.killpg(helper_pgid, termination_signal)
                        process.wait(timeout=2)

                        reap_deadline = time.monotonic() + 2.0
                        worker_still_exists = True
                        group_still_exists = True
                        while time.monotonic() < reap_deadline:
                            worker_still_exists = process_exists(worker_pid)
                            group_still_exists = process_group_exists(helper_pgid)
                            if not worker_still_exists and not group_still_exists:
                                break
                            time.sleep(0.01)
                        self.assertFalse(worker_still_exists)
                        self.assertFalse(group_still_exists)
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
    _private_release_commit = "2" * 40
    _release_manifest_sha256 = "3" * 64
    _workflow_source_commit = "4" * 40
    _ruleset_id = 97531
    _workflow_id = 86420
    _trusted_gate_environment_names = (
        "EVENT_REPOSITORY",
        "PR_BASE_REF",
        "PR_HEAD_REPOSITORY",
        "PR_HEAD_SHA",
        "PR_NUMBER",
        "SELECTED_TARGET_HEAD_SHA",
        "SELECTED_TARGET_PR_NUMBER",
        "CISCO_CUTOVER_RECEIPT_BASE64",
        "CISCO_CUTOVER_EXPECTED_CANONICAL_COMMIT",
        "CISCO_CUTOVER_EXPECTED_PRIVATE_RELEASE_COMMIT",
        "CISCO_CUTOVER_EXPECTED_RELEASE_MANIFEST_SHA256",
        "CISCO_CUTOVER_EXPECTED_RECEIPT_SHA256",
        "CISCO_CUTOVER_EXPECTED_WORKFLOW_ID",
        "CISCO_CUTOVER_EXPECTED_WORKFLOW_SHA",
    )
    _selector_environment_names = (
        "EVENT_REPOSITORY",
        "PR_BASE_REF",
        "PR_HEAD_REPOSITORY",
        "PR_HEAD_SHA",
        "PR_NUMBER",
        "CISCO_CUTOVER_TARGET_HEAD_SHA",
        "CISCO_CUTOVER_TARGET_PR_NUMBER",
        "GITHUB_OUTPUT",
    )

    def _matching_cutover_receipt(
        self,
        fixture: dict[str, object],
    ) -> dict[str, object]:
        release_target = f"releases/{self._private_release_commit}"
        return {
            "schema_version": 2,
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
                ]
            )
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
                "PR_HEAD_REPOSITORY": "Joey-Tools/codex-debug-triage",
                "PR_HEAD_SHA": self._canonical_commit,
                "PR_NUMBER": str(self._pull_request_number),
                "SELECTED_TARGET_HEAD_SHA": self._canonical_commit,
                "SELECTED_TARGET_PR_NUMBER": str(self._pull_request_number),
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
        target_pr_number: int | None = None,
        target_head_sha: str | None = None,
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
                "PR_HEAD_REPOSITORY": "Joey-Tools/codex-debug-triage",
                "PR_HEAD_SHA": current_head_sha or self._canonical_commit,
                "PR_NUMBER": str(current_pr_number or self._pull_request_number),
                "CISCO_CUTOVER_TARGET_HEAD_SHA": (
                    target_head_sha or self._canonical_commit
                ),
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
                "sha": "9" * 40,
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
                "sha": "9" * 40,
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
            "jobs_url": f"{run_url}/jobs",
            "path": f"{workflow['path']}@master",
            "pull_requests": [self._copy_json(pull_request_link)],
            "repository": {
                "full_name": repository["full_name"],
                "id": repository["id"],
            },
            "run_attempt": 1,
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
            "status": "completed",
            "url": check_url,
        }
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
            "selector_target_pr_number": {
                "name": "CISCO_CUTOVER_TARGET_PR_NUMBER",
                "value": str(self._pull_request_number),
            },
            "selector_target_head_sha": {
                "name": "CISCO_CUTOVER_TARGET_HEAD_SHA",
                "value": self._canonical_commit,
            },
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
            "workflow_runs": [run],
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
            ) -> None:
                self.objects = objects
                self.collections = collections
                self.auth_calls = 0
                self.calls: list[tuple[str, dict[str, object]]] = []

            def auth_preflight(self) -> dict[str, object]:
                self.auth_calls += 1
                return {
                    "id": 4242,
                    "login": "fixture-admin",
                }

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

        objects = {
            f"/orgs/{contract['source_organization']['login']}": evidence[
                "organization"
            ],
            f"/repos/{target_name}": evidence["repository"],
            f"/repos/{target_name}/pulls/7": pull_request,
            (
                f"/repos/{target_name}/actions/variables/"
                f"{contract['applicability_selector']['target_pr_number_variable']}"
            ): evidence["selector_target_pr_number"],
            (
                f"/repos/{target_name}/actions/variables/"
                f"{contract['applicability_selector']['target_head_sha_variable']}"
            ): evidence["selector_target_head_sha"],
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
            f"/repos/{target_name}/rulesets": {
                "item_key": None,
                "pages": [ruleset_summaries],
            },
            f"/repos/{target_name}/actions/runs": {
                "item_key": "workflow_runs",
                "pages": [[run]],
            },
            f"/repos/{target_name}/commits/{pull_request['base']['sha']}/check-runs": {
                "item_key": "check_runs",
                "pages": [[check_run]],
            },
            f"/repos/{target_name}/commits/{self._canonical_commit}/check-runs": {
                "item_key": "check_runs",
                "pages": [[]],
            },
            (f"/repos/{target_name}/actions/runs/10101/attempts/1/jobs"): {
                "item_key": "jobs",
                "pages": [[job]],
            },
        }
        return FixtureApiClient(
            objects=objects,
            collections=collections,
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
        candidate_head_sha: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        contract_payload = CUTOVER_ENFORCEMENT_CONTRACT_PATH.read_bytes()
        contract = json.loads(contract_payload)
        ruleset_id = expected_ruleset_id or self._ruleset_id
        workflow_id = expected_workflow_id or self._workflow_id
        workflow_sha = expected_workflow_sha or self._workflow_source_commit
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
                candidate_head_sha=head_sha,
                pull_request_number=7,
            )
        except ENFORCEMENT_MODULE.EnforcementDoctorError as error:
            outcome = {
                "classification": "blocked_until_trusted",
                "reason": str(error),
                "reason_code": error.reason_code,
            }
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

    @staticmethod
    def _copy_json(value: dict[str, object]) -> dict[str, object]:
        return json.loads(json.dumps(value))

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
        self.assertIn("validation drain", recipe)
        self.assertIn("temporarily enables `O_NONBLOCK`", recipe)
        self.assertIn("FIFO, socket, or terminal descriptor", recipe)
        self.assertIn("monotonic 100-millisecond poll budget", recipe)
        self.assertIn("descriptor blocking state", recipe)
        self.assertIn("protects archive object identity", recipe)
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
        self.assertIn("does not authenticate where the caller obtained", migration)
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
            "producer-authored schema-2 receipt",
            "configures both selector variables",
            "creates or updates the active,\n   bypass-free organization",
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
                    output = output_path.read_text(encoding="utf-8")
                    self.assertIn(f"applicable={applicable}\n", output)

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

        self.assertEqual(contract["schema_version"], 3)
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
                "selector_job_name": "cisco-cutover-selector",
                "target_job_name": "cisco-cutover-admission",
                "neutral_job_name": "cisco-cutover-neutral",
                "non_target_classification": "not_applicable",
            },
        )

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
            "head-sha": {
                "PR_HEAD_SHA": "4" * 40,
            },
            "pull-request-number": {
                "PR_NUMBER": str(self._pull_request_number + 1),
            },
            "selector-head": {
                "SELECTED_TARGET_HEAD_SHA": "4" * 40,
            },
            "selector-pr": {
                "SELECTED_TARGET_PR_NUMBER": str(self._pull_request_number + 1),
            },
            "expected-canonical": {
                "CISCO_CUTOVER_EXPECTED_CANONICAL_COMMIT": "4" * 40,
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

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertFalse(candidate_executed)
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "admitted")
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

    def test_enforcement_doctor_admits_exact_required_workflow_identity(
        self,
    ) -> None:
        result = self._run_enforcement_doctor(self._matching_enforcement_evidence())

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stderr, "")
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "admitted")
        self.assertEqual(outcome["ruleset_id"], self._ruleset_id)
        self.assertEqual(
            outcome["trusted_workflow"],
            {
                "id": self._workflow_id,
                "path": ".github/workflows/cisco-cutover-admission.yml",
                "ref": "refs/heads/master",
                "repository_id": 1242512092,
                "sha": self._workflow_source_commit,
            },
        )
        self.assertEqual(outcome["candidate_head_sha"], self._canonical_commit)
        self.assertEqual(outcome["trusted_workflow_run_id"], 10101)
        self.assertEqual(outcome["trusted_check_run_id"], 20202)
        self.assertRegex(outcome["contract_sha256"], r"\A[0-9a-f]{64}\Z")
        self.assertRegex(outcome["evidence_sha256"], r"\A[0-9a-f]{64}\Z")

    def test_enforcement_live_collector_exhausts_pages_and_binds_lineage(
        self,
    ) -> None:
        contract = json.loads(
            CUTOVER_ENFORCEMENT_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        client = self._matching_live_api_client()

        receipt, admission = ENFORCEMENT_MODULE.collect_and_validate(
            client,
            contract,
            expected_run_attempt=1,
            expected_run_id=10101,
            expected_ruleset_id=self._ruleset_id,
            expected_workflow_id=self._workflow_id,
            expected_workflow_sha=self._workflow_source_commit,
            candidate_head_sha=self._canonical_commit,
            pull_request_number=7,
        )

        self.assertEqual(receipt["schema_version"], 2)
        self.assertEqual(receipt["collector"]["mode"], "live-gh-rest")
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
        check_bounds = [
            bound
            for bound in receipt["collector"]["page_bounds"]
            if bound["label"].startswith("selected PR ")
            and bound["label"].endswith(" check runs")
        ]
        self.assertEqual(len(check_bounds), 4)
        self.assertEqual(
            {bound["endpoint"] for bound in check_bounds},
            {
                (
                    "/repos/Joey-Tools/codex-debug-triage/commits/"
                    f"{self._canonical_commit}/check-runs"
                ),
                (f"/repos/Joey-Tools/codex-debug-triage/commits/{'9' * 40}/check-runs"),
            },
        )

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

        _, admission = ENFORCEMENT_MODULE.collect_and_validate(
            client,
            contract,
            expected_run_attempt=1,
            expected_run_id=10101,
            expected_ruleset_id=self._ruleset_id,
            expected_workflow_id=self._workflow_id,
            expected_workflow_sha=self._workflow_source_commit,
            candidate_head_sha=self._canonical_commit,
            pull_request_number=7,
        )

        self.assertEqual(admission["trusted_run"]["id"], 10101)

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
                        "--candidate-head-sha",
                        self._canonical_commit,
                    ]
                )

        self.assertEqual(raised.exception.code, 2)

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
        for label, status, reason_code, failure_kind in cases:
            with self.subTest(failure=label):
                client = object.__new__(ENFORCEMENT_MODULE.GitHubApiClient)
                client.executable = "/fixed/gh"
                client.calls = 0
                client.total_bytes = 0
                client.deadline = time.monotonic() + 30
                detail = (
                    "rate limit exceeded"
                    if label == "rate-limit-403"
                    else "sanitized fixture failure"
                )
                stderr = (
                    f"gh: {detail} (HTTP {status}) Authorization: token super-secret"
                ).encode("utf-8")
                with mock.patch.object(
                    ENFORCEMENT_MODULE,
                    "_bounded_subprocess",
                    return_value=(1, b'{"secret":"response-body"}', stderr),
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
        client = object.__new__(ENFORCEMENT_MODULE.GitHubApiClient)
        client.executable = "/fixed/gh"
        client.calls = 0
        client.total_bytes = 0
        client.deadline = time.monotonic() + 30
        with mock.patch.object(
            ENFORCEMENT_MODULE,
            "_bounded_subprocess",
            return_value=(0, b"{malformed", b"token super-secret"),
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
        with self.assertRaises(ENFORCEMENT_MODULE.EnforcementDoctorError) as timed_out:
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
        self.assertEqual(outcome["reason_code"], "blocked-permission")
        self.assertEqual(
            outcome["api_failure"],
            {
                "endpoint_class": "organization-ruleset",
                "failure_kind": "permission",
                "http_status": 403,
            },
        )
        self.assertNotIn("command", outcome)
        self.assertNotIn("headers", outcome)
        self.assertNotIn("token", output.getvalue().lower())

    def test_enforcement_doctor_cli_receipt_binds_native_objects(
        self,
    ) -> None:
        client = self._matching_live_api_client()
        arguments = [
            str(CUTOVER_ENFORCEMENT_DOCTOR_PATH),
            "--contract",
            str(CUTOVER_ENFORCEMENT_CONTRACT_PATH),
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
            "--candidate-head-sha",
            self._canonical_commit,
        ]
        output = io.StringIO()
        with mock.patch.object(
            ENFORCEMENT_MODULE,
            "GitHubApiClient",
            return_value=client,
        ):
            with mock.patch.object(sys, "argv", arguments):
                with redirect_stdout(output):
                    return_code = ENFORCEMENT_MODULE.main()

        self.assertEqual(return_code, 0)
        outcome = json.loads(output.getvalue())
        self.assertEqual(outcome["classification"], "admitted")
        self.assertEqual(outcome["schema_version"], 3)
        self.assertEqual(
            outcome["applicability_selector"],
            {
                "target_head_sha": {
                    "name": "CISCO_CUTOVER_TARGET_HEAD_SHA",
                    "value": self._canonical_commit,
                },
                "target_pr_number": {
                    "name": "CISCO_CUTOVER_TARGET_PR_NUMBER",
                    "value": str(self._pull_request_number),
                },
            },
        )
        candidate = outcome["candidate"]
        self.assertEqual(candidate["head_repository_id"], 1242512092)
        self.assertEqual(
            candidate["head_repository_full_name"],
            "Joey-Tools/codex-debug-triage",
        )
        self.assertEqual(candidate["head_sha"], self._canonical_commit)
        self.assertEqual(candidate["pull_request_id"], 7007)
        self.assertEqual(candidate["pull_request_number"], 7)
        self.assertEqual(
            candidate["pull_request_url"],
            "https://api.github.com/repos/Joey-Tools/codex-debug-triage/pulls/7",
        )
        execution = outcome["trusted_execution"]
        self.assertEqual(
            execution["selection"],
            {
                "expected_run_attempt": 1,
                "expected_run_id": 10101,
            },
        )
        self.assertEqual(execution["run"]["id"], 10101)
        self.assertEqual(execution["run"]["run_attempt"], 1)
        self.assertEqual(execution["job"]["id"], 20202)
        self.assertEqual(execution["check_run"]["id"], 20202)
        self.assertEqual(
            execution["check_run"]["app"],
            {"id": 15368, "slug": "github-actions"},
        )
        self.assertEqual(
            execution["workflow"]["repository_full_name"],
            "Joey-Tools/codex-debug-triage",
        )
        self.assertEqual(
            outcome["collection"]["authenticated_user"],
            {"id": 4242, "login": "fixture-admin"},
        )

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
        for ruleset in (
            evidence["effective_rulesets"][0],
            evidence["selected_ruleset"],
        ):
            ruleset["rules"][2]["parameters"]["workflows"][0]["repository_id"] = (
                source_id
            )

        admission = ENFORCEMENT_MODULE.validate_enforcement(
            contract,
            evidence,
            expected_run_attempt=1,
            expected_run_id=10101,
            expected_ruleset_id=self._ruleset_id,
            expected_workflow_id=self._workflow_id,
            expected_workflow_sha=self._workflow_source_commit,
            candidate_head_sha=self._canonical_commit,
            pull_request_number=7,
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

        result = self._run_enforcement_doctor(evidence)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

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
                lambda evidence: evidence["selector_target_pr_number"].update(
                    {"value": "8"}
                ),
                "selector-mismatch",
            ),
            "selector-head-tamper": (
                lambda evidence: evidence["selector_target_head_sha"].update(
                    {"value": "8" * 40}
                ),
                "selector-mismatch",
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
                "status": "completed",
                "url": second_check_url,
            }
        )
        evidence["jobs"].append(second_job)
        evidence["check_runs"].append(second_check)

        result = self._run_enforcement_doctor(
            evidence,
            expected_run_id=10101,
            expected_run_attempt=2,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["trusted_workflow_run_id"], 10101)
        self.assertEqual(outcome["trusted_check_run_id"], 20203)

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
        self.assertFalse(state_machine["automatic_mutation"])
        decommission = fixture["post_cutover_decommission"]
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
                "receipt_schema_version": 2,
                "receipt_max_bytes": 35840,
                "producer_workflow": ".github/workflows/release.yml",
                "pointer_name": "current",
                "pointer_target_template": ("releases/{private_release_commit}"),
                "required_exact_inputs": [
                    "expected_canonical_commit",
                    "expected_pull_request_number",
                    "expected_private_release_commit",
                    "expected_release_manifest_sha256",
                    "expected_receipt_sha256",
                    "expected_workflow_id",
                    "expected_workflow_sha",
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

    def test_cutover_validator_admits_exact_release_and_pointer_receipt(
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

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stderr, "")
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "admitted")
        self.assertEqual(
            outcome["pointer_target"],
            f"releases/{self._private_release_commit}",
        )
        self.assertEqual(outcome["receipt_sha256"], receipt_sha256)

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
        self.assertIn("installed pointer", outcome["reason"])

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

    def test_cutover_validator_rejects_weakened_atomic_contract(self) -> None:
        contract = json.loads(MIGRATION_FIXTURE_PATH.read_text(encoding="utf-8"))
        contract["activation"]["atomic"] = False
        with tempfile.TemporaryDirectory() as temp_dir:
            contract_path = Path(temp_dir) / "weakened-contract.json"
            contract_path.write_text(
                json.dumps(contract),
                encoding="utf-8",
            )
            result = self._run_cutover_validator(
                contract_path=contract_path,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["classification"], "blocked_until_trusted")
        self.assertIn("activation.atomic", outcome["reason"])

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
