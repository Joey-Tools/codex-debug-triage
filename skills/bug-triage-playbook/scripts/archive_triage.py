#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import binascii
import codecs
import collections
import contextlib
import io
import json
import os
import pathlib
import re
import stat
import struct
import sys
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass

try:
    import zlib
except ImportError:
    zlib = None
    ZlibError = None
else:
    ZlibError = zlib.error


DEFAULT_LIST_LIMIT = 200
DEFAULT_MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_ARCHIVE_MEMBERS = 10_000
DEFAULT_MAX_CENTRAL_DIRECTORY_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_MEMBERS = 20
DEFAULT_MAX_MEMBER_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_TOTAL_MEMBER_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_MEMBER_LINES = 100_000
DEFAULT_MAX_INPUT_LINE_CHARS = 128 * 1024
DEFAULT_MAX_OUTPUT_LINES = 200
DEFAULT_MAX_OUTPUT_CHARS = 64 * 1024
DEFAULT_CANDIDATE_REPORT_LIMIT = 20
DEFAULT_MAX_RAW_MEMBER_NAME_BYTES = 512
DEFAULT_MAX_ERROR_DETAIL_CHARS = 1_024
DEFAULT_MAX_AMBIGUITY_REPORT_LINES = DEFAULT_CANDIDATE_REPORT_LIMIT + 2
DEFAULT_MAX_AMBIGUITY_REPORT_CHARS = DEFAULT_MAX_OUTPUT_CHARS
AMBIGUITY_NOTICE_RESERVE_CHARS = 128
TRUNCATION_MARKER = "... [truncated]"
EOCD_SIGNATURE = b"PK\x05\x06"
EOCD_MIN_SIZE = 22
EOCD_MAX_COMMENT = 65_535
ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
ZIP64_LOCATOR_SIZE = 20
ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
ZIP64_EOCD_MIN_SIZE = 56
CENTRAL_DIRECTORY_SIGNATURE = b"PK\x01\x02"
CENTRAL_DIRECTORY_HEADER_SIZE = 46
LOCAL_FILE_HEADER_SIGNATURE = b"PK\x03\x04"
LOCAL_FILE_HEADER_SIZE = 30
DATA_DESCRIPTOR_SIGNATURE = b"PK\x07\x08"
DATA_DESCRIPTOR_FLAG = 0x08
ENCRYPTED_FLAG = 0x01
UTF8_FILENAME_FLAG = 0x800
ZIP64_EXTRA_FIELD_ID = 0x0001
UINT32_MAX = 0xFFFFFFFF
UINT64_MAX = 0xFFFFFFFFFFFFFFFF
DEFLATE_INPUT_CHUNK_BYTES = 64 * 1024


def _member_identity_character_limit(max_raw_name_bytes: int) -> int:
    """Return the exact JSON upper bound for any accepted member identity."""

    fixed_chars = len(
        json.dumps(
            {
                "flag_bits": 0xFFFF,
                "name": "",
                "ordinal": UINT64_MAX,
                "raw_name_b64": "",
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    max_escaped_name_chars = 6 * max_raw_name_bytes
    max_base64_chars = 4 * ((max_raw_name_bytes + 2) // 3)
    return fixed_chars + max_escaped_name_chars + max_base64_chars


DEFAULT_MAX_MEMBER_IDENTITY_CHARS = _member_identity_character_limit(
    DEFAULT_MAX_RAW_MEMBER_NAME_BYTES
)


class ArtifactLimitError(ValueError):
    pass


class MemberReadError(ValueError):
    pass


@dataclass(frozen=True)
class CentralDirectoryIdentity:
    ordinal: int
    raw_name: bytes
    decoded_name: str
    flag_bits: int


@dataclass(frozen=True)
class CentralDirectoryLayout:
    identities: list[CentralDirectoryIdentity]
    central_start: int


@dataclass(frozen=True)
class ArchiveMember:
    info: zipfile.ZipInfo
    identity: CentralDirectoryIdentity
    local_record_end: int


@dataclass(frozen=True)
class MemberPayloadLayout:
    data_start: int
    payload_end: int
    local_data_end: int
    uses_data_descriptor: bool
    uses_zip64_descriptor: bool


class DecompressedByteBudget:
    """Track actual decompressed bytes across all selected members."""

    def __init__(self, max_total_bytes: int) -> None:
        self.max_total_bytes = max_total_bytes
        self.total_bytes = 0

    def consume(self, byte_count: int) -> None:
        next_total = self.total_bytes + byte_count
        if next_total > self.max_total_bytes:
            raise ArtifactLimitError(
                "decompressed members exceed aggregate max bytes: "
                f"{next_total} > {self.max_total_bytes}"
            )
        self.total_bytes = next_total


class BoundedMemberReader(io.RawIOBase):
    """Stream one validated STORED/DEFLATED member under actual byte caps."""

    def __init__(
        self,
        archive_stream: io.BufferedReader,
        member: ArchiveMember,
        layout: MemberPayloadLayout,
        *,
        max_member_bytes: int,
        aggregate_budget: DecompressedByteBudget,
    ) -> None:
        super().__init__()
        self._archive_stream = archive_stream
        self._member = member
        self._layout = layout
        self._max_member_bytes = max_member_bytes
        self._aggregate_budget = aggregate_budget
        self._member_bytes = 0
        self._compressed_remaining = member.info.compress_size
        self._compressed_buffer = b""
        self._crc = 0
        self._finished = False
        self._archive_stream.seek(layout.data_start)
        if member.info.compress_type == zipfile.ZIP_DEFLATED:
            if zlib is None:
                raise NotImplementedError(
                    "DEFLATE extraction requires the Python zlib module"
                )
            self._decompressor = zlib.decompressobj(-15)
        else:
            self._decompressor = None

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: object) -> int | None:
        if self._finished:
            return 0
        destination = memoryview(buffer).cast("B")
        if not destination:
            return 0
        read_limit = min(
            len(destination),
            self._max_member_bytes - self._member_bytes + 1,
            self._aggregate_budget.max_total_bytes
            - self._aggregate_budget.total_bytes
            + 1,
        )
        if read_limit <= 0:
            raise ArtifactLimitError("decompressed byte budget is exhausted")

        if self._member.info.compress_type == zipfile.ZIP_STORED:
            data = self._read_stored(read_limit)
        else:
            data = self._read_deflated(read_limit)
        if not data:
            self._finish()
            return 0

        next_member_bytes = self._member_bytes + len(data)
        if next_member_bytes > self._max_member_bytes:
            raise ArtifactLimitError(
                "decompressed member exceeds max bytes: "
                f"{next_member_bytes} > {self._max_member_bytes}"
            )
        self._aggregate_budget.consume(len(data))
        self._member_bytes = next_member_bytes
        self._crc = binascii.crc32(data, self._crc)
        destination[: len(data)] = data
        if self._stream_complete():
            self._finish()
        return len(data)

    def _read_stored(self, max_bytes: int) -> bytes:
        if self._compressed_remaining == 0:
            return b""
        read_size = min(max_bytes, self._compressed_remaining)
        data = self._archive_stream.read(read_size)
        if len(data) != read_size:
            raise zipfile.BadZipFile("truncated stored member payload")
        self._compressed_remaining -= len(data)
        return data

    def _read_deflated(self, max_bytes: int) -> bytes:
        assert self._decompressor is not None
        while True:
            if self._decompressor.eof:
                if (
                    self._decompressor.unused_data
                    or self._compressed_buffer
                    or self._compressed_remaining
                ):
                    raise zipfile.BadZipFile(
                        "deflate member contains trailing compressed data"
                    )
                return b""

            if self._compressed_buffer:
                compressed = self._compressed_buffer
                self._compressed_buffer = b""
            elif self._compressed_remaining:
                read_size = min(
                    DEFLATE_INPUT_CHUNK_BYTES,
                    self._compressed_remaining,
                )
                compressed = self._archive_stream.read(read_size)
                if len(compressed) != read_size:
                    raise zipfile.BadZipFile("truncated deflate member payload")
                self._compressed_remaining -= len(compressed)
            else:
                raise zipfile.BadZipFile(
                    "deflate stream did not terminate within its compressed span"
                )

            data = self._decompressor.decompress(compressed, max_bytes)
            self._compressed_buffer = self._decompressor.unconsumed_tail
            if self._decompressor.unused_data:
                raise zipfile.BadZipFile(
                    "deflate member contains trailing compressed data"
                )
            if data:
                return data

    def _stream_complete(self) -> bool:
        if self._member.info.compress_type == zipfile.ZIP_STORED:
            return self._compressed_remaining == 0
        assert self._decompressor is not None
        return (
            self._decompressor.eof
            and not self._decompressor.unused_data
            and not self._compressed_buffer
            and self._compressed_remaining == 0
        )

    def _finish(self) -> None:
        if self._finished:
            return
        if not self._stream_complete():
            if self._member.info.compress_type == zipfile.ZIP_DEFLATED:
                raise zipfile.BadZipFile(
                    "deflate stream did not terminate within its compressed span"
                )
            raise zipfile.BadZipFile("stored member payload was not fully consumed")

        info = self._member.info
        if self._member_bytes != info.file_size:
            raise zipfile.BadZipFile(
                "decompressed member size differs from central directory: "
                f"{self._member_bytes} != {info.file_size}"
            )
        if self._crc & UINT32_MAX != info.CRC:
            raise zipfile.BadZipFile("Bad CRC-32 for file")
        if self._layout.uses_data_descriptor:
            _validate_data_descriptor(
                self._archive_stream,
                self._member,
                self._layout,
            )
        self._finished = True


class OutputBudget:
    """Buffer bounded output until the command has completed successfully."""

    def __init__(self, max_lines: int, max_chars: int) -> None:
        self.max_lines = max_lines
        self.max_chars = max_chars
        self.lines = 0
        self.chars = 0
        self.truncated = False
        self._buffer: list[str] = []

    def add(
        self,
        text: str,
        *,
        allow_line_truncation: bool = True,
    ) -> bool:
        if self.lines >= self.max_lines or self.chars >= self.max_chars:
            self.truncated = True
            return False

        remaining = self.max_chars - self.chars
        rendered = text
        if len(rendered) + 1 > remaining:
            if not allow_line_truncation:
                self.truncated = True
                return False
            available = remaining - len(TRUNCATION_MARKER) - 1
            if available < 0:
                self.truncated = True
                return False
            rendered = f"{rendered[:available]}{TRUNCATION_MARKER}"
            self.truncated = True

        self._buffer.append(rendered)
        self.lines += 1
        self.chars += len(rendered) + 1
        return not self.truncated

    def flush(self, stream: io.TextIOBase | None = None) -> None:
        destination = stream if stream is not None else sys.stdout
        for line in self._buffer:
            print(line, file=destination)


def _nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be nonnegative")
    return parsed


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _compile_pattern(pattern: str, ignore_case: bool = False) -> re.Pattern[str]:
    flags = re.IGNORECASE if ignore_case else 0
    return re.compile(pattern, flags)


@contextlib.contextmanager
def _open_pinned_archive(
    path: pathlib.Path,
    max_archive_bytes: int,
) -> Iterator[io.BufferedReader]:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("archive path must identify a regular file")
        if metadata.st_size > max_archive_bytes:
            raise ArtifactLimitError(
                "archive file exceeds max bytes: "
                f"{metadata.st_size} > {max_archive_bytes}"
            )
        stream = os.fdopen(fd, "rb", closefd=True)
        fd = -1
        with stream:
            yield stream
    finally:
        if fd >= 0:
            os.close(fd)


def _read_exact_at(
    stream: io.BufferedReader,
    offset: int,
    size: int,
) -> bytes:
    if offset < 0:
        raise zipfile.BadZipFile("ZIP structure has a negative offset")
    stream.seek(offset)
    data = stream.read(size)
    if len(data) != size:
        raise zipfile.BadZipFile("truncated ZIP structure")
    return data


def _find_eocd(
    stream: io.BufferedReader,
    archive_size: int,
) -> tuple[int, tuple[int, int, int, int, int, int]]:
    """Return the one EOCD view whose declared comment reaches physical EOF.

    The bounded tail can contain an entire second ZIP inside the outer EOCD
    comment.  Both EOCD records then describe individually valid parser views,
    so choosing the last one would hide the outer view.  Enumerate the fixed
    65,557-byte window once and fail closed as soon as a second EOF-bound
    candidate appears.  Raw signatures are not counted or capped.
    """

    tail_size = min(
        archive_size,
        EOCD_MIN_SIZE + EOCD_MAX_COMMENT,
    )
    tail_start = archive_size - tail_size
    tail = _read_exact_at(stream, tail_start, tail_size)
    search_start = 0
    candidate: tuple[int, tuple[int, int, int, int, int, int]] | None = None
    last_signature_offset = -1
    while True:
        relative_offset = tail.find(
            EOCD_SIGNATURE,
            search_start,
        )
        if relative_offset < 0:
            break
        last_signature_offset = relative_offset
        search_start = relative_offset + 1
        if relative_offset + EOCD_MIN_SIZE <= len(tail):
            fields = struct.unpack_from(
                "<4s4H2LH",
                tail,
                relative_offset,
            )
            comment_length = fields[-1]
            if relative_offset + EOCD_MIN_SIZE + comment_length == len(tail):
                if candidate is not None:
                    raise zipfile.BadZipFile(
                        "ambiguous end-of-central-directory signature"
                    )
                candidate = (
                    relative_offset,
                    (
                        fields[1],
                        fields[2],
                        fields[3],
                        fields[4],
                        fields[5],
                        fields[6],
                    ),
                )

    if candidate is None:
        raise zipfile.BadZipFile("end-of-central-directory record not found")
    relative_offset, eocd = candidate
    if relative_offset != last_signature_offset:
        raise zipfile.BadZipFile("ambiguous end-of-central-directory signature")
    return (
        tail_start + relative_offset,
        eocd,
    )


def _read_zip64_directory_metadata(
    stream: io.BufferedReader,
    eocd_offset: int,
) -> tuple[int, int, int, int]:
    locator_offset = eocd_offset - ZIP64_LOCATOR_SIZE
    locator = _read_exact_at(
        stream,
        locator_offset,
        ZIP64_LOCATOR_SIZE,
    )
    signature, disk_number, zip64_offset, total_disks = struct.unpack(
        "<4sLQL",
        locator,
    )
    if signature != ZIP64_LOCATOR_SIGNATURE:
        raise zipfile.BadZipFile("ZIP64 locator not found")
    if disk_number != 0 or total_disks != 1:
        raise zipfile.BadZipFile("multi-disk ZIP archives are unsupported")

    physical_zip64_offset = locator_offset - ZIP64_EOCD_MIN_SIZE
    record = _read_exact_at(
        stream,
        physical_zip64_offset,
        ZIP64_EOCD_MIN_SIZE,
    )
    fields = struct.unpack("<4sQ2H2L4Q", record)
    if fields[0] != ZIP64_EOCD_SIGNATURE:
        raise zipfile.BadZipFile("ZIP64 end-of-directory record not found")
    record_size = fields[1]
    if record_size != ZIP64_EOCD_MIN_SIZE - 12:
        raise zipfile.BadZipFile(
            "ZIP64 extensible end-of-directory data is unsupported"
        )
    if zip64_offset > physical_zip64_offset:
        raise zipfile.BadZipFile(
            "ZIP64 locator points beyond the physical end-of-directory record"
        )
    concatenation_offset = physical_zip64_offset - zip64_offset

    disk_number = fields[4]
    central_disk = fields[5]
    entries_on_disk = fields[6]
    total_entries = fields[7]
    central_size = fields[8]
    if disk_number != 0 or central_disk != 0:
        raise zipfile.BadZipFile("multi-disk ZIP archives are unsupported")
    if entries_on_disk != total_entries:
        raise zipfile.BadZipFile("inconsistent ZIP64 member counts")
    logical_central_offset = fields[9]
    physical_central_start = logical_central_offset + concatenation_offset
    if (
        physical_central_start < 0
        or physical_central_start + central_size != physical_zip64_offset
    ):
        raise zipfile.BadZipFile(
            "inconsistent ZIP64 locator and central-directory offsets"
        )
    return (
        total_entries,
        central_size,
        physical_central_start,
        physical_zip64_offset,
    )


def _has_zip64_locator(
    stream: io.BufferedReader,
    eocd_offset: int,
) -> bool:
    locator_offset = eocd_offset - ZIP64_LOCATOR_SIZE
    if locator_offset < 0:
        return False
    return (
        _read_exact_at(
            stream,
            locator_offset,
            len(ZIP64_LOCATOR_SIGNATURE),
        )
        == ZIP64_LOCATOR_SIGNATURE
    )


def _decode_central_directory_name(
    raw_name: bytes,
    *,
    flag_bits: int,
    ordinal: int,
) -> str:
    if len(raw_name) > DEFAULT_MAX_RAW_MEMBER_NAME_BYTES:
        raise ArtifactLimitError(
            "central-directory member raw name exceeds max bytes: "
            f"ordinal={ordinal}; {len(raw_name)} > "
            f"{DEFAULT_MAX_RAW_MEMBER_NAME_BYTES}"
        )
    if b"\0" in raw_name:
        raise zipfile.BadZipFile(
            f"central-directory member name contains a NUL byte: ordinal={ordinal}"
        )
    if flag_bits & UTF8_FILENAME_FLAG:
        try:
            return raw_name.decode("utf-8")
        except UnicodeDecodeError as error:
            raise zipfile.BadZipFile(
                f"central-directory member has an invalid UTF-8 name: ordinal={ordinal}"
            ) from error
    return raw_name.decode("cp437")


def _read_central_directory_identities(
    stream: io.BufferedReader,
    *,
    central_start: int,
    central_size: int,
    max_archive_members: int,
) -> list[CentralDirectoryIdentity]:
    central_end = central_start + central_size
    cursor = central_start
    identities: list[CentralDirectoryIdentity] = []
    while cursor < central_end:
        header = _read_exact_at(
            stream,
            cursor,
            CENTRAL_DIRECTORY_HEADER_SIZE,
        )
        if header[:4] != CENTRAL_DIRECTORY_SIGNATURE:
            raise zipfile.BadZipFile("invalid central-directory entry signature")
        filename_length, extra_length, comment_length = struct.unpack_from(
            "<3H",
            header,
            28,
        )
        record_size = (
            CENTRAL_DIRECTORY_HEADER_SIZE
            + filename_length
            + extra_length
            + comment_length
        )
        if cursor + record_size > central_end:
            raise zipfile.BadZipFile("central-directory entry exceeds its bounds")
        ordinal = len(identities) + 1
        if ordinal > max_archive_members:
            raise ArtifactLimitError(
                f"archive member count exceeds limit: > {max_archive_members}"
            )
        if filename_length > DEFAULT_MAX_RAW_MEMBER_NAME_BYTES:
            raise ArtifactLimitError(
                "central-directory member raw name exceeds max bytes: "
                f"ordinal={ordinal}; {filename_length} > "
                f"{DEFAULT_MAX_RAW_MEMBER_NAME_BYTES}"
            )
        raw_name = _read_exact_at(
            stream,
            cursor + CENTRAL_DIRECTORY_HEADER_SIZE,
            filename_length,
        )
        flag_bits = struct.unpack_from("<H", header, 8)[0]
        decoded_name = _decode_central_directory_name(
            raw_name,
            flag_bits=flag_bits,
            ordinal=ordinal,
        )
        identity = CentralDirectoryIdentity(
            ordinal=ordinal,
            raw_name=raw_name,
            decoded_name=decoded_name,
            flag_bits=flag_bits,
        )
        identities.append(identity)
        cursor += record_size
    if cursor != central_end:
        raise zipfile.BadZipFile("central-directory size mismatch")
    return identities


def _preflight_central_directory(
    stream: io.BufferedReader,
    *,
    max_archive_members: int,
    max_central_directory_bytes: int,
) -> CentralDirectoryLayout:
    archive_size = os.fstat(stream.fileno()).st_size
    eocd_offset, eocd = _find_eocd(stream, archive_size)
    (
        disk_number,
        central_disk,
        entries_on_disk,
        total_entries,
        central_size,
        central_offset,
    ) = eocd
    uses_zip64_sentinel = (
        disk_number == 0xFFFF
        or central_disk == 0xFFFF
        or entries_on_disk == 0xFFFF
        or total_entries == 0xFFFF
        or central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
    )
    uses_zip64 = uses_zip64_sentinel or _has_zip64_locator(
        stream,
        eocd_offset,
    )
    if uses_zip64:
        (
            total_entries,
            central_size,
            central_start,
            central_end,
        ) = _read_zip64_directory_metadata(stream, eocd_offset)
    else:
        if disk_number != 0 or central_disk != 0:
            raise zipfile.BadZipFile("multi-disk ZIP archives are unsupported")
        if entries_on_disk != total_entries:
            raise zipfile.BadZipFile("inconsistent ZIP member counts")
        central_end = eocd_offset
        central_start = central_end - central_size

    if total_entries > max_archive_members:
        raise ArtifactLimitError(
            "archive member count exceeds limit: "
            f"{total_entries} > {max_archive_members}"
        )
    if central_size > max_central_directory_bytes:
        raise ArtifactLimitError(
            "central directory exceeds max bytes: "
            f"{central_size} > {max_central_directory_bytes}"
        )
    if central_start < 0:
        raise zipfile.BadZipFile("central directory starts before the archive")
    if not uses_zip64 and central_offset > central_start:
        raise zipfile.BadZipFile("invalid central-directory offset")

    identities = _read_central_directory_identities(
        stream,
        central_start=central_start,
        central_size=central_size,
        max_archive_members=max_archive_members,
    )
    if len(identities) != total_entries:
        raise zipfile.BadZipFile(
            "declared and counted central-directory entries differ"
        )
    return CentralDirectoryLayout(
        identities=identities,
        central_start=central_start,
    )


def _render_member_identity(identity: CentralDirectoryIdentity) -> str:
    rendered = json.dumps(
        {
            "flag_bits": identity.flag_bits,
            "name": identity.decoded_name,
            "ordinal": identity.ordinal,
            "raw_name_b64": base64.b64encode(identity.raw_name).decode("ascii"),
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    if len(rendered) > DEFAULT_MAX_MEMBER_IDENTITY_CHARS:
        raise ArtifactLimitError(
            "rendered member identity exceeds max characters: "
            f"ordinal={identity.ordinal}; {len(rendered)} > "
            f"{DEFAULT_MAX_MEMBER_IDENTITY_CHARS}"
        )
    return rendered


def _validated_members(
    archive: zipfile.ZipFile,
    directory: CentralDirectoryLayout,
    max_archive_members: int,
) -> list[ArchiveMember]:
    if archive.start_dir != directory.central_start:
        raise zipfile.BadZipFile(
            "ZipFile and preflight central-directory offsets differ"
        )
    infos = archive.infolist()
    if len(infos) > max_archive_members:
        raise ArtifactLimitError(
            f"archive member count exceeds limit: {len(infos)} > {max_archive_members}"
        )
    if len(infos) != len(directory.identities):
        raise zipfile.BadZipFile("ZipInfo and central-directory member counts differ")

    header_offsets = [info.header_offset for info in infos]
    if len(set(header_offsets)) != len(header_offsets) or any(
        offset < 0 or offset >= directory.central_start for offset in header_offsets
    ):
        raise zipfile.BadZipFile("invalid or duplicate local-header offsets")
    sorted_offsets = sorted(header_offsets)
    record_ends = {
        offset: (
            sorted_offsets[index + 1]
            if index + 1 < len(sorted_offsets)
            else directory.central_start
        )
        for index, offset in enumerate(sorted_offsets)
    }

    members = []
    for info, identity in zip(infos, directory.identities):
        if info.orig_filename != identity.decoded_name:
            raise zipfile.BadZipFile(
                "ZipInfo and central-directory names differ: "
                f"ordinal={identity.ordinal}"
            )
        if info.flag_bits != identity.flag_bits:
            raise zipfile.BadZipFile(
                "ZipInfo and central-directory flags differ: "
                f"ordinal={identity.ordinal}"
            )
        members.append(
            ArchiveMember(
                info=info,
                identity=identity,
                local_record_end=record_ends[info.header_offset],
            )
        )
    return members


def _render_archive_member(member: ArchiveMember) -> str:
    return _render_member_identity(member.identity)


def _parse_extra_fields(extra: bytes) -> dict[int, bytes]:
    fields: dict[int, bytes] = {}
    cursor = 0
    while cursor < len(extra):
        if len(extra) - cursor < 4:
            raise zipfile.BadZipFile("truncated local extra-field header")
        field_id, field_size = struct.unpack_from("<HH", extra, cursor)
        cursor += 4
        field_end = cursor + field_size
        if field_end > len(extra):
            raise zipfile.BadZipFile("local extra field exceeds its bounds")
        if field_id in fields:
            raise zipfile.BadZipFile("duplicate local extra-field identifier")
        fields[field_id] = extra[cursor:field_end]
        cursor = field_end
    return fields


def _resolved_local_sizes(
    *,
    local_file_size: int,
    local_compress_size: int,
    extra: bytes,
) -> tuple[int, int, bool]:
    needs_file_size = local_file_size == UINT32_MAX
    needs_compress_size = local_compress_size == UINT32_MAX
    if not needs_file_size and not needs_compress_size:
        return local_file_size, local_compress_size, False

    fields = _parse_extra_fields(extra)
    zip64 = fields.get(ZIP64_EXTRA_FIELD_ID)
    if zip64 is None:
        raise zipfile.BadZipFile("local ZIP64 sizes are missing")
    cursor = 0

    def take_size() -> int:
        nonlocal cursor
        if len(zip64) - cursor < 8:
            raise zipfile.BadZipFile("truncated local ZIP64 size")
        value = struct.unpack_from("<Q", zip64, cursor)[0]
        cursor += 8
        return value

    resolved_file_size = take_size() if needs_file_size else local_file_size
    resolved_compress_size = take_size() if needs_compress_size else local_compress_size
    return resolved_file_size, resolved_compress_size, True


def _member_payload_layout(
    archive_stream: io.BufferedReader,
    member: ArchiveMember,
    *,
    central_start: int,
) -> MemberPayloadLayout:
    info = member.info
    header = _read_exact_at(
        archive_stream,
        info.header_offset,
        LOCAL_FILE_HEADER_SIZE,
    )
    fields = struct.unpack("<4s5H3L2H", header)
    if fields[0] != LOCAL_FILE_HEADER_SIGNATURE:
        raise zipfile.BadZipFile("invalid local-file-header signature")
    local_flags = fields[2]
    local_compression = fields[3]
    local_crc = fields[6]
    local_compress_size = fields[7]
    local_file_size = fields[8]
    name_length = fields[9]
    extra_length = fields[10]
    if local_flags != info.flag_bits:
        raise zipfile.BadZipFile(
            f"local and central member flags differ: ordinal={member.identity.ordinal}"
        )
    if local_flags & ENCRYPTED_FLAG:
        raise NotImplementedError("encrypted ZIP members are unsupported")
    if local_compression != info.compress_type:
        raise zipfile.BadZipFile(
            "local and central compression methods differ: "
            f"ordinal={member.identity.ordinal}"
        )

    variable_start = info.header_offset + LOCAL_FILE_HEADER_SIZE
    data_start = variable_start + name_length + extra_length
    payload_end = data_start + info.compress_size
    if (
        variable_start < 0
        or data_start < variable_start
        or payload_end < data_start
        or payload_end > member.local_record_end
        or member.local_record_end > central_start
    ):
        raise zipfile.BadZipFile("member payload exceeds the local-data region")
    raw_name = _read_exact_at(archive_stream, variable_start, name_length)
    if raw_name != member.identity.raw_name:
        raise zipfile.BadZipFile(
            "local and central raw member names differ: "
            f"ordinal={member.identity.ordinal}"
        )
    extra = _read_exact_at(
        archive_stream,
        variable_start + name_length,
        extra_length,
    )
    (
        resolved_file_size,
        resolved_compress_size,
        uses_zip64_sizes,
    ) = _resolved_local_sizes(
        local_file_size=local_file_size,
        local_compress_size=local_compress_size,
        extra=extra,
    )
    uses_data_descriptor = bool(local_flags & DATA_DESCRIPTOR_FLAG)
    if uses_data_descriptor:
        if local_crc not in (0, info.CRC):
            raise zipfile.BadZipFile(
                "local and central CRC values differ before data descriptor"
            )
        if resolved_file_size not in (0, info.file_size):
            raise zipfile.BadZipFile(
                "local and central file sizes differ before data descriptor"
            )
        if resolved_compress_size not in (0, info.compress_size):
            raise zipfile.BadZipFile(
                "local and central compressed sizes differ before data descriptor"
            )
    else:
        if local_crc != info.CRC:
            raise zipfile.BadZipFile("local and central CRC values differ")
        if resolved_file_size != info.file_size:
            raise zipfile.BadZipFile("local and central file sizes differ")
        if resolved_compress_size != info.compress_size:
            raise zipfile.BadZipFile("local and central compressed sizes differ")
    return MemberPayloadLayout(
        data_start=data_start,
        payload_end=payload_end,
        local_data_end=member.local_record_end,
        uses_data_descriptor=uses_data_descriptor,
        uses_zip64_descriptor=uses_zip64_sizes,
    )


def _validate_data_descriptor(
    archive_stream: io.BufferedReader,
    member: ArchiveMember,
    layout: MemberPayloadLayout,
) -> None:
    value_format = "<LQQ" if layout.uses_zip64_descriptor else "<LLL"
    value_size = struct.calcsize(value_format)
    available_size = layout.local_data_end - layout.payload_end
    if available_size < value_size:
        raise zipfile.BadZipFile("data descriptor exceeds the local-data region")
    read_size = min(
        available_size,
        value_size + len(DATA_DESCRIPTOR_SIGNATURE),
    )
    available = _read_exact_at(
        archive_stream,
        layout.payload_end,
        read_size,
    )
    expected = (
        member.info.CRC,
        member.info.compress_size,
        member.info.file_size,
    )
    candidates = [struct.unpack_from(value_format, available, 0)]
    if len(available) >= value_size + len(
        DATA_DESCRIPTOR_SIGNATURE
    ) and available.startswith(DATA_DESCRIPTOR_SIGNATURE):
        candidates.append(
            struct.unpack_from(
                value_format,
                available,
                len(DATA_DESCRIPTOR_SIGNATURE),
            )
        )
    if expected not in candidates:
        raise zipfile.BadZipFile(
            "data descriptor differs from validated member metadata"
        )


def _find_members(
    members: list[ArchiveMember],
    needle: str,
    use_regex: bool,
    ignore_case: bool,
) -> list[ArchiveMember]:
    if use_regex:
        pattern = _compile_pattern(needle, ignore_case)
        return [
            member for member in members if pattern.search(member.identity.decoded_name)
        ]

    compare = needle.lower() if ignore_case else needle
    matches = []
    for member in members:
        name = member.identity.decoded_name
        candidate = name.lower() if ignore_case else name
        if candidate == compare:
            matches.append(member)
    return matches


def _validate_member_budget(
    member: ArchiveMember,
    *,
    max_member_bytes: int,
    total_member_bytes: int,
    max_total_member_bytes: int,
) -> int:
    info = member.info
    if info.is_dir():
        raise ValueError(
            f"member is not a regular file: member={_render_archive_member(member)}"
        )
    if info.file_size > max_member_bytes:
        raise ArtifactLimitError(
            "member exceeds max bytes: "
            f"member={_render_archive_member(member)}; "
            f"{info.file_size} > {max_member_bytes}"
        )
    next_total = total_member_bytes + info.file_size
    if next_total > max_total_member_bytes:
        raise ArtifactLimitError(
            "selected members exceed aggregate max bytes: "
            f"{next_total} > {max_total_member_bytes}"
        )
    return next_total


def _preflight_selected_members(
    selected: list[ArchiveMember],
    args: argparse.Namespace,
) -> None:
    """Preflight every selected member before opening any decompressor."""

    total_member_bytes = 0
    for member in selected:
        if member.info.compress_type not in (
            zipfile.ZIP_STORED,
            zipfile.ZIP_DEFLATED,
        ):
            raise NotImplementedError(
                "compression method is unsupported for bounded extraction: "
                f"method={member.info.compress_type}; "
                f"member={_render_archive_member(member)}"
            )
        if member.info.compress_type == zipfile.ZIP_DEFLATED and zlib is None:
            raise NotImplementedError(
                "DEFLATE extraction requires the Python zlib module"
            )
        total_member_bytes = _validate_member_budget(
            member,
            max_member_bytes=args.max_member_bytes,
            total_member_bytes=total_member_bytes,
            max_total_member_bytes=args.max_total_member_bytes,
        )


def _iter_member_lines(
    archive_stream: io.BufferedReader,
    member: ArchiveMember,
    *,
    central_start: int,
    encoding: str,
    max_member_bytes: int,
    aggregate_budget: DecompressedByteBudget,
    max_member_lines: int,
    max_input_line_chars: int,
) -> Iterator[tuple[int, str]]:
    layout = _member_payload_layout(
        archive_stream,
        member,
        central_start=central_start,
    )
    bounded_stream = BoundedMemberReader(
        archive_stream,
        member,
        layout,
        max_member_bytes=max_member_bytes,
        aggregate_budget=aggregate_budget,
    )
    buffered_stream = io.BufferedReader(bounded_stream)
    text_stream = io.TextIOWrapper(
        buffered_stream,
        encoding=encoding,
        errors="replace",
        newline=None,
    )
    try:
        line_number = 0
        while True:
            raw_line = text_stream.readline(max_input_line_chars + 1)
            if not raw_line:
                break
            if len(raw_line) > max_input_line_chars:
                raise ArtifactLimitError(
                    f"input line exceeds max characters: > {max_input_line_chars}"
                )
            line_number += 1
            if line_number > max_member_lines:
                raise ArtifactLimitError(
                    f"member line count exceeds limit: > {max_member_lines}"
                )
            yield line_number, raw_line.rstrip("\r\n")
    finally:
        text_stream.close()


def _select_stream_lines(
    lines: Iterator[tuple[int, str]],
    *,
    grep_pattern: re.Pattern[str] | None,
    context: int,
    head: int,
    tail: int,
) -> Iterator[tuple[int, str]]:
    if grep_pattern:
        previous: collections.deque[tuple[int, str]] = collections.deque(maxlen=context)
        last_emitted = 0
        trailing = 0
        for item in lines:
            line_number, line = item
            if grep_pattern.search(line):
                for candidate in previous:
                    if candidate[0] > last_emitted:
                        yield candidate
                        last_emitted = candidate[0]
                if line_number > last_emitted:
                    yield item
                    last_emitted = line_number
                trailing = context
            elif trailing:
                if line_number > last_emitted:
                    yield item
                    last_emitted = line_number
                trailing -= 1
            previous.append(item)
        return

    if head:
        emitted = 0
        for item in lines:
            yield item
            emitted += 1
            if emitted >= head:
                return
        return

    if tail:
        trailing_lines: collections.deque[tuple[int, str]] = collections.deque(
            maxlen=tail
        )
        for item in lines:
            trailing_lines.append(item)
        yield from trailing_lines
        return

    yield from lines


def _add_member_output(
    archive_stream: io.BufferedReader,
    member: ArchiveMember,
    central_start: int,
    args: argparse.Namespace,
    grep_pattern: re.Pattern[str] | None,
    output: OutputBudget,
    aggregate_budget: DecompressedByteBudget,
) -> None:
    line_iterator = _iter_member_lines(
        archive_stream,
        member,
        central_start=central_start,
        encoding=args.encoding,
        max_member_bytes=args.max_member_bytes,
        aggregate_budget=aggregate_budget,
        max_member_lines=args.max_member_lines,
        max_input_line_chars=args.max_input_line_chars,
    )
    selected_lines = _select_stream_lines(
        line_iterator,
        grep_pattern=grep_pattern,
        context=args.context,
        head=args.head,
        tail=args.tail,
    )
    try:
        collecting_output = not output.truncated
        for line_number, line in selected_lines:
            rendered = f"{line_number}:{line}" if args.line_numbers else line
            if collecting_output:
                collecting_output = output.add(rendered)
        for _ in line_iterator:
            pass
    except _archive_errors() as error:
        error_type, detail = _bounded_member_error(error, member)
        raise MemberReadError(
            f"member={_render_archive_member(member)} read failed: "
            f"type={error_type}; detail={detail}"
        ) from error
    finally:
        selected_lines.close()
        line_iterator.close()


def _bounded_member_error(
    error: BaseException,
    member: ArchiveMember,
) -> tuple[str, str]:
    if ZlibError is not None and isinstance(error, ZlibError):
        error_type = "zlib.error"
        detail_text = "invalid deflate stream"
    else:
        error_type = type(error).__name__
        detail_text = str(error)

    detail = json.dumps(detail_text, ensure_ascii=True)
    if len(detail) > DEFAULT_MAX_ERROR_DETAIL_CHARS:
        detail = json.dumps(
            "diagnostic omitted because its escaped form exceeds the limit"
        )
    return error_type, detail


def _archive_errors() -> tuple[type[BaseException], ...]:
    errors: tuple[type[BaseException], ...] = (
        ArtifactLimitError,
        EOFError,
        KeyError,
        LookupError,
        NotImplementedError,
        OSError,
        OverflowError,
        RuntimeError,
        ValueError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    )
    optional_errors = tuple(error for error in (ZlibError,) if error is not None)
    return errors + optional_errors


def cmd_zip_list(args: argparse.Namespace) -> int:
    zip_path = pathlib.Path(args.zip_path)
    try:
        pattern = _compile_pattern(args.match, args.ignore_case) if args.match else None
        with _open_pinned_archive(
            zip_path,
            args.max_archive_bytes,
        ) as archive_stream:
            directory = _preflight_central_directory(
                archive_stream,
                max_archive_members=args.max_archive_members,
                max_central_directory_bytes=args.max_central_directory_bytes,
            )
            with zipfile.ZipFile(archive_stream) as archive:
                members = _validated_members(
                    archive,
                    directory,
                    args.max_archive_members,
                )
                output = OutputBudget(args.limit, args.max_output_chars)
                for member in members:
                    if pattern and not pattern.search(member.identity.decoded_name):
                        continue
                    if not output.add(
                        f"{member.info.file_size}\t"
                        f"{member.info.compress_size}\t"
                        f"{_render_archive_member(member)}",
                        allow_line_truncation=False,
                    ):
                        break
    except _archive_errors() + (re.error,) as error:
        print(f"error={error}", file=sys.stderr)
        return 1

    output.flush()
    if output.truncated:
        print(
            "notice=output truncated by configured entry or character limit",
            file=sys.stderr,
        )
    return 0


def _report_ambiguous_members(matches: list[ArchiveMember]) -> None:
    lines = ["error=multiple matching members"]
    char_count = len(lines[0]) + 1
    report_char_limit = (
        DEFAULT_MAX_AMBIGUITY_REPORT_CHARS - AMBIGUITY_NOTICE_RESERVE_CHARS
    )
    reported = 0
    for member in matches[:DEFAULT_CANDIDATE_REPORT_LIMIT]:
        candidate = f"member={_render_archive_member(member)}"
        if (
            len(lines) >= DEFAULT_MAX_AMBIGUITY_REPORT_LINES - 1
            or char_count + len(candidate) + 1 > report_char_limit
        ):
            break
        lines.append(candidate)
        char_count += len(candidate) + 1
        reported += 1

    omitted = len(matches) - reported
    if omitted:
        notice = f"notice=additional matching members omitted: {omitted}"
        lines.append(notice)
        char_count += len(notice) + 1

    if (
        len(lines) > DEFAULT_MAX_AMBIGUITY_REPORT_LINES
        or char_count > DEFAULT_MAX_AMBIGUITY_REPORT_CHARS
    ):
        raise ArtifactLimitError("ambiguity report exceeds internal budget")

    for line in lines:
        print(line, file=sys.stderr)


def _validate_show_args(args: argparse.Namespace) -> re.Pattern[str] | None:
    if args.head > args.max_output_lines:
        raise ArtifactLimitError(
            f"head exceeds max output lines: {args.head} > {args.max_output_lines}"
        )
    if args.tail > args.max_output_lines:
        raise ArtifactLimitError(
            f"tail exceeds max output lines: {args.tail} > {args.max_output_lines}"
        )
    if args.context > args.max_output_lines:
        raise ArtifactLimitError(
            "context exceeds max output lines: "
            f"{args.context} > {args.max_output_lines}"
        )
    codecs.lookup(args.encoding)
    return _compile_pattern(args.grep, args.ignore_case) if args.grep else None


def cmd_zip_show(args: argparse.Namespace) -> int:
    zip_path = pathlib.Path(args.zip_path)
    try:
        grep_pattern = _validate_show_args(args)
        with _open_pinned_archive(
            zip_path,
            args.max_archive_bytes,
        ) as archive_stream:
            directory = _preflight_central_directory(
                archive_stream,
                max_archive_members=args.max_archive_members,
                max_central_directory_bytes=args.max_central_directory_bytes,
            )
            with zipfile.ZipFile(archive_stream) as archive:
                members = _validated_members(
                    archive,
                    directory,
                    args.max_archive_members,
                )
                matches = _find_members(
                    members,
                    args.member,
                    args.regex,
                    args.ignore_case,
                )
                if not matches:
                    print("error=no matching members", file=sys.stderr)
                    return 1
                if len(matches) > 1 and not args.all:
                    _report_ambiguous_members(matches)
                    return 1
                if args.all and len(matches) > args.max_members:
                    print(
                        "error=matching members exceed limit: "
                        f"{len(matches)} > {args.max_members}",
                        file=sys.stderr,
                    )
                    return 1

                selected = matches if args.all else matches[:1]
                _preflight_selected_members(selected, args)
                output = OutputBudget(
                    args.max_output_lines,
                    args.max_output_chars,
                )
                aggregate_budget = DecompressedByteBudget(args.max_total_member_bytes)
                for index, member in enumerate(selected):
                    if index and not output.truncated:
                        output.add("")
                    if not output.truncated:
                        output.add(
                            f"== {_render_archive_member(member)} ==",
                            allow_line_truncation=False,
                        )
                    _add_member_output(
                        archive_stream,
                        member,
                        directory.central_start,
                        args,
                        grep_pattern,
                        output,
                        aggregate_budget,
                    )
    except _archive_errors() + (re.error,) as error:
        print(f"error={error}", file=sys.stderr)
        return 1

    output.flush()
    if output.truncated:
        print(
            "notice=output truncated by configured line or character limit",
            file=sys.stderr,
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect text members in a local ZIP archive."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    zip_list = subparsers.add_parser(
        "zip-list",
        help="List a bounded set of members in a ZIP archive.",
    )
    zip_list.add_argument("zip_path")
    zip_list.add_argument("--match")
    zip_list.add_argument("--ignore-case", action="store_true")
    zip_list.add_argument(
        "--limit",
        type=_positive_int,
        default=DEFAULT_LIST_LIMIT,
    )
    zip_list.add_argument(
        "--max-archive-bytes",
        type=_positive_int,
        default=DEFAULT_MAX_ARCHIVE_BYTES,
    )
    zip_list.add_argument(
        "--max-archive-members",
        type=_positive_int,
        default=DEFAULT_MAX_ARCHIVE_MEMBERS,
    )
    zip_list.add_argument(
        "--max-central-directory-bytes",
        type=_positive_int,
        default=DEFAULT_MAX_CENTRAL_DIRECTORY_BYTES,
    )
    zip_list.add_argument(
        "--max-output-chars",
        type=_positive_int,
        default=DEFAULT_MAX_OUTPUT_CHARS,
    )
    zip_list.set_defaults(func=cmd_zip_list)

    zip_show = subparsers.add_parser(
        "zip-show",
        help="Show bounded text selected from local ZIP members.",
    )
    zip_show.add_argument("zip_path")
    zip_show.add_argument("member")
    zip_show.add_argument("--regex", action="store_true")
    zip_show.add_argument("--all", action="store_true")
    selection = zip_show.add_mutually_exclusive_group()
    selection.add_argument("--grep")
    selection.add_argument("--head", type=_positive_int, default=0)
    selection.add_argument("--tail", type=_positive_int, default=0)
    zip_show.add_argument("--ignore-case", action="store_true")
    zip_show.add_argument("--context", type=_nonnegative_int, default=0)
    zip_show.add_argument("--encoding", default="utf-8")
    zip_show.add_argument("--line-numbers", action="store_true")
    zip_show.add_argument(
        "--max-archive-bytes",
        type=_positive_int,
        default=DEFAULT_MAX_ARCHIVE_BYTES,
    )
    zip_show.add_argument(
        "--max-archive-members",
        type=_positive_int,
        default=DEFAULT_MAX_ARCHIVE_MEMBERS,
    )
    zip_show.add_argument(
        "--max-central-directory-bytes",
        type=_positive_int,
        default=DEFAULT_MAX_CENTRAL_DIRECTORY_BYTES,
    )
    zip_show.add_argument(
        "--max-members",
        type=_positive_int,
        default=DEFAULT_MAX_MEMBERS,
    )
    zip_show.add_argument(
        "--max-member-bytes",
        type=_positive_int,
        default=DEFAULT_MAX_MEMBER_BYTES,
    )
    zip_show.add_argument(
        "--max-total-member-bytes",
        type=_positive_int,
        default=DEFAULT_MAX_TOTAL_MEMBER_BYTES,
    )
    zip_show.add_argument(
        "--max-member-lines",
        type=_positive_int,
        default=DEFAULT_MAX_MEMBER_LINES,
    )
    zip_show.add_argument(
        "--max-input-line-chars",
        type=_positive_int,
        default=DEFAULT_MAX_INPUT_LINE_CHARS,
    )
    zip_show.add_argument(
        "--max-output-lines",
        type=_positive_int,
        default=DEFAULT_MAX_OUTPUT_LINES,
    )
    zip_show.add_argument(
        "--max-output-chars",
        type=_positive_int,
        default=DEFAULT_MAX_OUTPUT_CHARS,
    )
    zip_show.set_defaults(func=cmd_zip_show)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
