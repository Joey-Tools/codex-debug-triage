from __future__ import annotations

import argparse
import ast
import base64
import importlib.util
import io
import json
import os
import subprocess
import struct
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
SPEC = importlib.util.spec_from_file_location("archive_triage", SCRIPT_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


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

    def _make_zip64_metadata_archive(
        self,
        directory: Path,
        *,
        classic_eocd: tuple[int, int, int, int, int, int],
    ) -> Path:
        central_header = bytearray(MODULE.CENTRAL_DIRECTORY_HEADER_SIZE)
        central_header[:4] = MODULE.CENTRAL_DIRECTORY_SIGNATURE
        zip64_eocd_offset = len(central_header)
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
            0,
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
        archive_path.write_bytes(bytes(central_header) + zip64_eocd + locator + eocd)
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
        lines = stderr.getvalue().splitlines()
        self.assertEqual(lines[0], "error=multiple matching members")
        identities = [
            self._parse_identity(line.removeprefix("member=")) for line in lines[1:]
        ]
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
                    0,
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
            "disk-number": (1, 0, 1, 1, MODULE.CENTRAL_DIRECTORY_HEADER_SIZE, 0),
            "central-directory-disk": (
                0,
                1,
                1,
                1,
                MODULE.CENTRAL_DIRECTORY_HEADER_SIZE,
                0,
            ),
            "entries-on-disk": (
                0,
                0,
                2,
                1,
                MODULE.CENTRAL_DIRECTORY_HEADER_SIZE,
                0,
            ),
            "total-entries": (
                0,
                0,
                1,
                2,
                MODULE.CENTRAL_DIRECTORY_HEADER_SIZE,
                0,
            ),
            "central-directory-size": (
                0,
                0,
                1,
                1,
                MODULE.CENTRAL_DIRECTORY_HEADER_SIZE - 1,
                0,
            ),
            "central-directory-offset": (
                0,
                0,
                1,
                1,
                MODULE.CENTRAL_DIRECTORY_HEADER_SIZE,
                1,
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
        ambiguity_identities = [
            self._parse_identity(line.removeprefix("member="))
            for line in ambiguous_stderr.getvalue().splitlines()
            if line.startswith("member=")
        ]
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
        self.assertLessEqual(
            len(ambiguity_lines),
            MODULE.DEFAULT_MAX_AMBIGUITY_REPORT_LINES,
        )
        self.assertLessEqual(
            len(ambiguous_stderr.getvalue()),
            MODULE.DEFAULT_MAX_AMBIGUITY_REPORT_CHARS,
        )
        ambiguous_names = [
            self._parse_identity(line.removeprefix("member="))["name"]
            for line in ambiguity_lines
            if line.startswith("member=")
        ]
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
    def test_skill_is_explicit_only_and_hands_off_provider_work(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        metadata = (SKILL_ROOT / "agents/openai.yaml").read_text(encoding="utf-8")

        self.assertIn("Optional, explicitly invoked framework", skill)
        self.assertIn("In environments with the GitHub plugin", skill)
        self.assertIn("Actions belongs to that plugin", skill)
        self.assertIn("skill or tool. That owner", skill)
        self.assertIn("allow_implicit_invocation: false", metadata)

    def test_generic_skill_has_no_remote_auth_helper_contract(self) -> None:
        generic_files = [
            SKILL_ROOT / "SKILL.md",
            SKILL_ROOT / "references/local-artifact-recipes.md",
            SKILL_ROOT / "scripts/archive_triage.py",
        ]
        generic_text = "\n".join(
            path.read_text(encoding="utf-8") for path in generic_files
        )

        self.assertNotIn("JENKINS_ARTIFACT_USER", generic_text)
        self.assertNotIn("JENKINS_ARTIFACT_TOKEN", generic_text)
        self.assertNotIn("--auth-profile", generic_text)
        self.assertNotIn("probe-url", generic_text)
        self.assertNotIn("fetch-url", generic_text)
        self.assertNotIn("urllib.request", generic_text)

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
        self.assertIn("protects archive object identity", recipe)
        self.assertIn("Before constructing Python `ZipInfo` objects", recipe)
        self.assertIn("accepts only stored and DEFLATE members", recipe)
        self.assertIn("rejects those\nmethods before opening a decompressor", recipe)
        self.assertIn("absence of trailing compressed data", recipe)

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
        self.assertIn("Do not copy private fixtures", migration)


if __name__ == "__main__":
    unittest.main()
