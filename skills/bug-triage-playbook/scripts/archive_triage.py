#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import binascii
import codecs
import collections
import contextlib
import errno
import io
import json
import os
import pathlib
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import threading
import time
import unicodedata
import zipfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass

try:
    import fcntl
except ImportError:
    fcntl = None

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
DEFAULT_ARCHIVE_COMMAND_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_ENCODING_NAME_CHARS = 64
DEFAULT_MAX_ERROR_CHARS = 8 * 1024

# These ceilings are intentionally equal to the conservative defaults.  The
# command-line budget flags may narrow a run, but they must never turn the
# local inspection helper into an unbounded archive processor.
HARD_MAX_LIST_LIMIT = DEFAULT_LIST_LIMIT
HARD_MAX_ARCHIVE_BYTES = DEFAULT_MAX_ARCHIVE_BYTES
HARD_MAX_ARCHIVE_MEMBERS = DEFAULT_MAX_ARCHIVE_MEMBERS
HARD_MAX_CENTRAL_DIRECTORY_BYTES = DEFAULT_MAX_CENTRAL_DIRECTORY_BYTES
HARD_MAX_MEMBERS = DEFAULT_MAX_MEMBERS
HARD_MAX_MEMBER_BYTES = DEFAULT_MAX_MEMBER_BYTES
HARD_MAX_TOTAL_MEMBER_BYTES = DEFAULT_MAX_TOTAL_MEMBER_BYTES
HARD_MAX_MEMBER_LINES = DEFAULT_MAX_MEMBER_LINES
HARD_MAX_INPUT_LINE_CHARS = DEFAULT_MAX_INPUT_LINE_CHARS
HARD_MAX_OUTPUT_LINES = DEFAULT_MAX_OUTPUT_LINES
HARD_MAX_OUTPUT_CHARS = DEFAULT_MAX_OUTPUT_CHARS
HARD_MAX_ARCHIVE_COMMAND_TIMEOUT_SECONDS = DEFAULT_ARCHIVE_COMMAND_TIMEOUT_SECONDS
HARD_MAX_ENCODING_NAME_CHARS = DEFAULT_MAX_ENCODING_NAME_CHARS
HARD_MAX_ERROR_CHARS = DEFAULT_MAX_ERROR_CHARS
DEFAULT_CANDIDATE_REPORT_LIMIT = 20
DEFAULT_MAX_RAW_MEMBER_NAME_BYTES = 512
DEFAULT_MAX_ERROR_DETAIL_CHARS = 1_024
AMBIGUITY_NOTICE_RESERVE_CHARS = 128
TRUNCATION_MARKER = "... [truncated]"
ARCHIVE_DEADLINE_RETRY_SECONDS = 0.1
MAX_PENDING_ALARM_DRAINS = 8
FALLBACK_DIAGNOSTIC_TIMEOUT_SECONDS = 0.1
FALLBACK_DIAGNOSTIC_RESTORE_TIMEOUT_SECONDS = 0.1
FALLBACK_DIAGNOSTIC_MAX_BYTES = 4 * 1024
FALLBACK_DIAGNOSTIC_MIN_BYTES = 512
EOCD_SIGNATURE = b"PK\x05\x06"
EOCD_MIN_SIZE = 22
EOCD_MAX_COMMENT = 65_535
ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
ZIP64_LOCATOR_SIZE = 20
ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
ZIP64_EOCD_MIN_SIZE = 56
ZIP64_MIN_VERSION = 45
CENTRAL_DIRECTORY_SIGNATURE = b"PK\x01\x02"
CENTRAL_DIRECTORY_HEADER_SIZE = 46
LOCAL_FILE_HEADER_SIGNATURE = b"PK\x03\x04"
LOCAL_FILE_HEADER_SIZE = 30
DATA_DESCRIPTOR_SIGNATURE = b"PK\x07\x08"
DATA_DESCRIPTOR_FLAG = 0x08
UTF8_FILENAME_FLAG = 0x800
SUPPORTED_GENERAL_PURPOSE_FLAGS = DATA_DESCRIPTOR_FLAG | UTF8_FILENAME_FLAG
ZIP64_EXTRA_FIELD_ID = 0x0001
UINT32_MAX = 0xFFFFFFFF
UINT64_MAX = 0xFFFFFFFFFFFFFFFF
DEFLATE_INPUT_CHUNK_BYTES = 64 * 1024
DEFAULT_MAX_REGEX_PATTERN_CHARS = 4 * 1024
DEFAULT_REGEX_WORKER_START_TIMEOUT_SECONDS = 1.0
DEFAULT_REGEX_MATCH_TIMEOUT_SECONDS = 0.25
DEFAULT_REGEX_AGGREGATE_TIMEOUT_SECONDS = 5.0
REGEX_WORKER_RESPONSE_BYTES = 4 * 1024
REGEX_WORKER_MAX_REQUEST_BYTES = (12 * DEFAULT_MAX_INPUT_LINE_CHARS) + 4 * 1024
REGEX_WORKER_STOP_TIMEOUT_SECONDS = 0.5
REGEX_WORKER_ARG = "--archive-triage-regex-worker"


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


class ArchiveCommandDeadline:
    """Apply one in-process best-effort wall-clock budget to a command."""

    def __init__(
        self,
        timeout_seconds: float = DEFAULT_ARCHIVE_COMMAND_TIMEOUT_SECONDS,
    ) -> None:
        if (
            timeout_seconds <= 0
            or timeout_seconds > HARD_MAX_ARCHIVE_COMMAND_TIMEOUT_SECONDS
        ):
            raise ArtifactLimitError(
                "archive command timeout exceeds immutable hard max: "
                f"{timeout_seconds} > "
                f"{HARD_MAX_ARCHIVE_COMMAND_TIMEOUT_SECONDS}"
            )
        self.deadline = time.monotonic() + timeout_seconds
        self._armed = False
        self._closing = False
        self._diagnostic_timer_safe = False
        self._previous_handler: object | None = None

    @staticmethod
    def _require_signal_support() -> None:
        required_names = (
            "SIGALRM",
            "ITIMER_REAL",
            "getitimer",
            "setitimer",
            "pthread_sigmask",
            "sigpending",
            "sigwait",
            "SIG_BLOCK",
            "SIG_SETMASK",
        )
        if any(not hasattr(signal, name) for name in required_names):
            raise ArtifactLimitError(
                "archive command in-process deadline is unavailable on this platform"
            )

    @staticmethod
    def _drain_pending_alarm() -> None:
        for _ in range(MAX_PENDING_ALARM_DRAINS):
            if signal.SIGALRM not in signal.sigpending():
                return
            received = signal.sigwait({signal.SIGALRM})
            if received != signal.SIGALRM:
                raise ArtifactLimitError(
                    "archive command received an unexpected signal while "
                    "draining its deadline alarm"
                )
        if signal.SIGALRM in signal.sigpending():
            raise ArtifactLimitError(
                "archive command could not drain its pending deadline alarm"
            )

    def _close_while_alarm_blocked(self) -> None:
        self._diagnostic_timer_safe = False
        signal.setitimer(signal.ITIMER_REAL, 0.0)
        self._drain_pending_alarm()
        signal.signal(signal.SIGALRM, self._previous_handler)
        self._previous_handler = None
        self._armed = False

    def arm(self) -> None:
        """Install a timer that can interrupt ordinary interruptible operations."""

        self.check("deadline setup")
        if self._armed:
            raise ArtifactLimitError("archive command deadline is already armed")
        if threading.current_thread() is not threading.main_thread():
            raise ArtifactLimitError(
                "archive command in-process deadline requires the main thread"
            )
        self._require_signal_support()
        previous_mask = signal.pthread_sigmask(
            signal.SIG_BLOCK,
            {signal.SIGALRM},
        )
        if signal.SIGALRM in previous_mask:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            raise ArtifactLimitError(
                "archive command refuses to arm while SIGALRM is blocked"
            )
        restore_mask = True
        try:
            if signal.SIGALRM in signal.sigpending():
                raise ArtifactLimitError(
                    "archive command refuses to consume a pre-existing pending SIGALRM"
                )
            previous_timer = signal.getitimer(signal.ITIMER_REAL)
            if previous_timer != (0.0, 0.0):
                raise ArtifactLimitError(
                    "archive command refuses to replace an existing process timer"
                )
            self._previous_handler = signal.getsignal(signal.SIGALRM)
            signal.signal(signal.SIGALRM, self._raise_timeout)
            self._armed = True
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise ArtifactLimitError(
                    "archive command deadline exceeded during deadline setup"
                )
            signal.setitimer(
                signal.ITIMER_REAL,
                remaining,
                ARCHIVE_DEADLINE_RETRY_SECONDS,
            )
        except BaseException:
            if self._armed:
                try:
                    self._close_while_alarm_blocked()
                except BaseException as cleanup_error:
                    restore_mask = False
                    raise ArtifactLimitError(
                        "archive command deadline setup cleanup failed with "
                        "SIGALRM retained blocked"
                    ) from cleanup_error
            raise
        finally:
            if restore_mask:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
                if self._armed:
                    self._diagnostic_timer_safe = True

    def close(self) -> None:
        if not self._armed:
            self._diagnostic_timer_safe = False
            return
        self._diagnostic_timer_safe = False
        self._closing = True
        self._require_signal_support()
        previous_mask = signal.pthread_sigmask(
            signal.SIG_BLOCK,
            {signal.SIGALRM},
        )
        handler_restored = False
        try:
            self._close_while_alarm_blocked()
            handler_restored = True
        finally:
            if handler_restored:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
                self._closing = False

    def timer_backed_diagnostics_safe(self) -> bool:
        """Return whether an ordinary stream write still has timer protection."""

        return self._diagnostic_timer_safe and self._armed and not self._closing

    def _raise_timeout(self, _signum: int, _frame: object) -> None:
        if self._closing:
            return
        raise ArtifactLimitError("archive command deadline exceeded")

    def check(self, phase: str) -> None:
        if time.monotonic() >= self.deadline:
            raise ArtifactLimitError(
                f"archive command deadline exceeded during {phase}"
            )


@dataclass(frozen=True)
class CentralDirectoryIdentity:
    ordinal: int
    raw_name: bytes
    decoded_name: str
    flag_bits: int
    extract_version: int
    compression_method: int
    crc: int
    compress_size: int
    file_size: int
    has_zip64_extra: bool
    uses_zip64_sizes: bool
    local_header_offset: int


@dataclass(frozen=True)
class CentralDirectoryLayout:
    identities: list[CentralDirectoryIdentity]
    central_start: int


@dataclass(frozen=True)
class Zip64DirectoryMetadata:
    disk_number: int
    central_disk: int
    entries_on_disk: int
    total_entries: int
    central_size: int
    central_start: int
    central_end: int


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


class PinnedArchiveReader(io.RawIOBase):
    """Expose the initially accepted archive extent as an immutable EOF."""

    def __init__(
        self,
        raw_stream: io.FileIO,
        archive_size: int,
        deadline: ArchiveCommandDeadline,
    ) -> None:
        super().__init__()
        self._raw_stream = raw_stream
        self.archive_size = archive_size
        self._deadline = deadline

    def _validate_size(self) -> None:
        self._deadline.check("archive metadata validation")
        current_size = os.fstat(self._raw_stream.fileno()).st_size
        self._deadline.check("archive metadata validation")
        if current_size != self.archive_size:
            raise zipfile.BadZipFile(
                "archive size changed after open: "
                f"initial={self.archive_size}; current={current_size}"
            )

    def validate_unchanged(self) -> None:
        self._validate_size()

    def check_deadline(self, phase: str) -> None:
        self._deadline.check(phase)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def fileno(self) -> int:
        return self._raw_stream.fileno()

    def tell(self) -> int:
        return self._raw_stream.tell()

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        self._deadline.check("archive seek")
        self._validate_size()
        if whence == os.SEEK_SET:
            target = offset
        elif whence == os.SEEK_CUR:
            target = self.tell() + offset
        elif whence == os.SEEK_END:
            target = self.archive_size + offset
        else:
            raise ValueError(f"unsupported seek mode: {whence}")
        if target < 0 or target > self.archive_size:
            raise zipfile.BadZipFile("archive seek exceeds the initially accepted size")
        result = self._raw_stream.seek(target, os.SEEK_SET)
        self._deadline.check("archive seek")
        return result

    def readinto(self, buffer: object) -> int | None:
        self._deadline.check("archive read")
        self._validate_size()
        position = self.tell()
        if position < 0 or position > self.archive_size:
            raise zipfile.BadZipFile(
                "archive read starts outside the initially accepted size"
            )
        remaining = self.archive_size - position
        if remaining == 0:
            return 0
        view = memoryview(buffer)
        bounded_view = view[: min(len(view), remaining)]
        byte_count = self._raw_stream.readinto(bounded_view)
        self._deadline.check("archive read")
        return byte_count

    def close(self) -> None:
        if not self.closed:
            try:
                self._raw_stream.close()
            finally:
                super().close()


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
        archive_stream: PinnedArchiveReader,
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
        self._archive_stream.check_deadline("member extraction")
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
        self._archive_stream.check_deadline("member extraction")
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
            self._archive_stream.check_deadline("DEFLATE extraction")
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
            self._archive_stream.check_deadline("DEFLATE extraction")
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

    def flush(
        self,
        stream: io.TextIOBase | None = None,
        *,
        deadline: ArchiveCommandDeadline | None = None,
    ) -> None:
        destination = stream if stream is not None else sys.stdout
        payload = "".join(f"{line}\n" for line in self._buffer)
        if deadline is not None:
            deadline.check("output publication")
        written = destination.write(payload)
        if written is not None and written != len(payload):
            raise OSError("output stream accepted only part of the bounded payload")
        if deadline is not None:
            deadline.check("output publication")
        destination.flush()
        if deadline is not None:
            deadline.check("output flush")


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


def _bounded_positive_int(
    option_name: str,
    hard_max: int,
) -> Callable[[str], int]:
    def parse(value: str) -> int:
        parsed = _positive_int(value)
        if parsed > hard_max:
            raise argparse.ArgumentTypeError(
                f"{option_name} exceeds immutable hard max: {parsed} > {hard_max}"
            )
        return parsed

    return parse


def _require_bounded_positive(
    option_name: str,
    value: int,
    hard_max: int,
) -> None:
    if value <= 0:
        raise ArtifactLimitError(f"{option_name} must be positive")
    if value > hard_max:
        raise ArtifactLimitError(
            f"{option_name} exceeds immutable hard max: {value} > {hard_max}"
        )


def _terminal_escape_token(character: str) -> str:
    if character.isprintable() and not unicodedata.category(character).startswith("C"):
        return character
    codepoint = ord(character)
    if codepoint <= 0xFF:
        return f"\\x{codepoint:02x}"
    if codepoint <= 0xFFFF:
        return f"\\u{codepoint:04x}"
    return f"\\U{codepoint:08x}"


def _escape_terminal_text(value: str) -> str:
    return "".join(_terminal_escape_token(character) for character in value)


def _bounded_terminal_escape(value: str, max_chars: int) -> str:
    if max_chars < len(TRUNCATION_MARKER):
        raise ValueError("terminal escape budget is too small")
    escaped: list[str] = []
    char_count = 0
    for character in value:
        token = _terminal_escape_token(character)
        if char_count + len(token) <= max_chars:
            escaped.append(token)
            char_count += len(token)
            continue
        while escaped and char_count + len(TRUNCATION_MARKER) > max_chars:
            char_count -= len(escaped.pop())
        escaped.append(TRUNCATION_MARKER)
        break
    return "".join(escaped)


def _fcntl_retry_timeout(
    deadline: float | None,
    *,
    operation: str,
    error: InterruptedError,
) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise OSError(
            errno.ETIMEDOUT,
            f"diagnostic publisher timed out during {operation}",
        ) from error


def _fcntl_get_flags(fd: int, *, deadline: float | None = None) -> int:
    if fcntl is None:
        raise OSError(errno.ENOSYS, "fcntl is unavailable")
    while True:
        try:
            return int(fcntl.fcntl(fd, fcntl.F_GETFL))
        except InterruptedError as error:
            _fcntl_retry_timeout(
                deadline,
                operation="F_GETFL",
                error=error,
            )
            continue


def _fcntl_set_flags(
    fd: int,
    flags: int,
    *,
    deadline: float | None = None,
) -> None:
    if fcntl is None:
        raise OSError(errno.ENOSYS, "fcntl is unavailable")
    while True:
        try:
            fcntl.fcntl(fd, fcntl.F_SETFL, flags)
            return
        except InterruptedError as error:
            _fcntl_retry_timeout(
                deadline,
                operation="F_SETFL",
                error=error,
            )
            continue


def _restore_fd_nonblocking_state(
    fd: int,
    *,
    originally_nonblocking: bool,
    deadline: float | None = None,
) -> None:
    current_flags = _fcntl_get_flags(fd, deadline=deadline)
    if originally_nonblocking:
        restored_flags = current_flags | os.O_NONBLOCK
    else:
        restored_flags = current_flags & ~os.O_NONBLOCK
    if restored_flags != current_flags:
        _fcntl_set_flags(fd, restored_flags, deadline=deadline)
    verified_flags = _fcntl_get_flags(fd, deadline=deadline)
    if bool(verified_flags & os.O_NONBLOCK) != originally_nonblocking:
        raise OSError(
            errno.EIO,
            "diagnostic publisher could not restore O_NONBLOCK",
        )


def _bounded_diagnostic_payload(payload: str, fd: int) -> bytes:
    encoded = payload.encode("ascii", errors="backslashreplace")
    try:
        pipe_buf = int(os.fpathconf(fd, "PC_PIPE_BUF"))
    except (OSError, ValueError):
        pipe_buf = FALLBACK_DIAGNOSTIC_MAX_BYTES
    byte_limit = min(
        FALLBACK_DIAGNOSTIC_MAX_BYTES,
        max(FALLBACK_DIAGNOSTIC_MIN_BYTES, pipe_buf),
    )
    if len(encoded) <= byte_limit:
        return encoded
    marker = f"{TRUNCATION_MARKER}\n".encode("ascii")
    return encoded[: byte_limit - len(marker)] + marker


def _publish_terminal_line_without_timer(
    payload: str,
    stream: io.TextIOBase,
) -> bool:
    """Best-effort one-line publication without a signal or blocking write."""

    if type(stream) is io.StringIO:
        stream.write(payload)
        stream.flush()
        return True
    if fcntl is None or not hasattr(os, "O_NONBLOCK"):
        return False
    try:
        fd = stream.fileno()
    except (AttributeError, io.UnsupportedOperation, OSError, ValueError):
        return False
    if type(fd) is not int or fd < 0:
        return False
    try:
        mode = os.fstat(fd).st_mode
    except OSError:
        return False
    if not (
        stat.S_ISFIFO(mode)
        or stat.S_ISSOCK(mode)
        or (stat.S_ISCHR(mode) and os.isatty(fd))
    ):
        return False

    deadline = time.monotonic() + FALLBACK_DIAGNOSTIC_TIMEOUT_SECONDS
    original_flags = _fcntl_get_flags(fd, deadline=deadline)
    originally_nonblocking = bool(original_flags & os.O_NONBLOCK)
    selector: selectors.BaseSelector | None = None
    try:
        if not originally_nonblocking:
            _fcntl_set_flags(
                fd,
                original_flags | os.O_NONBLOCK,
                deadline=deadline,
            )
        bounded_payload = _bounded_diagnostic_payload(payload, fd)
        view = memoryview(bounded_payload)
        while view:
            if time.monotonic() >= deadline:
                return False
            try:
                written = os.write(fd, view)
            except InterruptedError:
                continue
            except BlockingIOError:
                if selector is None:
                    selector = selectors.DefaultSelector()
                    try:
                        selector.register(fd, selectors.EVENT_WRITE)
                    except (KeyError, OSError, ValueError):
                        return False
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    return False
                continue
            if written <= 0:
                return False
            view = view[written:]
        return True
    finally:
        restore_deadline = (
            time.monotonic() + FALLBACK_DIAGNOSTIC_RESTORE_TIMEOUT_SECONDS
        )
        try:
            _restore_fd_nonblocking_state(
                fd,
                originally_nonblocking=originally_nonblocking,
                deadline=restore_deadline,
            )
        finally:
            if selector is not None:
                selector.close()


def _write_terminal_line(
    prefix: str,
    value: object,
    *,
    stream: io.TextIOBase,
    deadline: ArchiveCommandDeadline | None = None,
) -> None:
    max_value_chars = HARD_MAX_ERROR_CHARS - len(prefix) - 1
    rendered = _bounded_terminal_escape(str(value), max_value_chars)
    payload = f"{prefix}{rendered}\n"
    if deadline is None or not deadline.timer_backed_diagnostics_safe():
        _publish_terminal_line_without_timer(payload, stream)
        return
    written = stream.write(payload)
    if written is not None and written != len(payload):
        raise OSError("diagnostic stream accepted only part of the bounded payload")
    stream.flush()
    if not deadline.timer_backed_diagnostics_safe():
        raise ArtifactLimitError("diagnostic output escaped the archive command timer")


def _emit_error(
    error: object,
    *,
    deadline: ArchiveCommandDeadline | None = None,
) -> None:
    _write_terminal_line(
        "error=",
        error,
        stream=sys.stderr,
        deadline=deadline,
    )


def _emit_notice(
    notice: str,
    *,
    deadline: ArchiveCommandDeadline,
) -> None:
    _write_terminal_line(
        "notice=",
        notice,
        stream=sys.stderr,
        deadline=deadline,
    )


def _validate_encoding_name(value: object) -> str:
    if not isinstance(value, str):
        raise ArtifactLimitError("encoding name must be text")
    if not value:
        raise ArtifactLimitError("encoding name must not be empty")
    if len(value) > HARD_MAX_ENCODING_NAME_CHARS:
        raise ArtifactLimitError(
            "encoding name exceeds immutable hard max: "
            f"{len(value)} > {HARD_MAX_ENCODING_NAME_CHARS}"
        )
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", value) is None:
        raise ArtifactLimitError("encoding name contains unsupported characters")
    codecs.lookup(value)
    return value


def _encoding_argument(value: str) -> str:
    try:
        return _validate_encoding_name(value)
    except (ArtifactLimitError, LookupError) as error:
        raise argparse.ArgumentTypeError(str(error)) from error


class RegexMatchBudget:
    """Share one aggregate deadline across all regex workers in a command."""

    def __init__(self) -> None:
        self.deadline = time.monotonic() + DEFAULT_REGEX_AGGREGATE_TIMEOUT_SECONDS

    def _bounded_deadline(
        self,
        timeout_seconds: float,
        timeout_kind: str,
    ) -> tuple[float, str]:
        now = time.monotonic()
        remaining = self.deadline - now
        if remaining <= 0:
            raise ArtifactLimitError("regular expression aggregate deadline exceeded")
        if remaining <= timeout_seconds:
            return self.deadline, "aggregate"
        return (
            now + timeout_seconds,
            timeout_kind,
        )

    def startup_deadline(self) -> tuple[float, str]:
        return self._bounded_deadline(
            DEFAULT_REGEX_WORKER_START_TIMEOUT_SECONDS,
            "startup",
        )

    def request_deadline(self) -> tuple[float, str]:
        return self._bounded_deadline(
            DEFAULT_REGEX_MATCH_TIMEOUT_SECONDS,
            "per-match",
        )


class IsolatedRegexMatcher:
    """Run Python's backtracking regex engine in a terminable subprocess."""

    def __init__(
        self,
        pattern: str,
        *,
        ignore_case: bool,
        budget: RegexMatchBudget,
    ) -> None:
        if len(pattern) > DEFAULT_MAX_REGEX_PATTERN_CHARS:
            raise ArtifactLimitError(
                "regular expression exceeds max characters: "
                f"{len(pattern)} > {DEFAULT_MAX_REGEX_PATTERN_CHARS}"
            )
        self._pattern = pattern
        self._ignore_case = ignore_case
        self._budget = budget
        self._process: subprocess.Popen[bytes] | None = None

    def __enter__(self) -> IsolatedRegexMatcher:
        script_path = pathlib.Path(__file__).resolve()
        self._process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-B",
                str(script_path),
                REGEX_WORKER_ARG,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
            close_fds=True,
            start_new_session=True,
        )
        try:
            if self._process.stdin is None:
                raise RuntimeError(
                    "regular expression worker request pipe is unavailable"
                )
            os.set_blocking(self._process.stdin.fileno(), False)
            response = self._request(
                {
                    "op": "compile",
                    "pattern": self._pattern,
                    "ignore_case": self._ignore_case,
                },
                startup=True,
            )
            if response.get("status") != "ready":
                detail = response.get(
                    "detail",
                    "regular expression worker rejected the pattern",
                )
                raise re.error(str(detail))
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        self.close()

    def _running_process(self) -> subprocess.Popen[bytes]:
        process = self._process
        if process is None or process.poll() is not None:
            raise RuntimeError("regular expression worker is unavailable")
        if process.stdin is None or process.stdout is None:
            raise RuntimeError("regular expression worker pipes are unavailable")
        return process

    def _deadline_exceeded(self, deadline_kind: str) -> None:
        if not self._terminate():
            raise RuntimeError(
                "regular expression "
                f"{deadline_kind} deadline exceeded and the worker "
                "could not be reaped"
            )
        raise ArtifactLimitError(
            f"regular expression {deadline_kind} deadline exceeded"
        )

    def _send_request(
        self,
        request: dict[str, object],
        *,
        deadline: float,
        deadline_kind: str,
    ) -> None:
        process = self._running_process()
        assert process.stdin is not None
        payload = (
            json.dumps(
                request,
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        if len(payload) > REGEX_WORKER_MAX_REQUEST_BYTES:
            raise ArtifactLimitError(
                "regular expression request exceeds the worker byte limit"
            )
        view = memoryview(payload)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdin.fileno(), selectors.EVENT_WRITE)
            while view:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    self._deadline_exceeded(deadline_kind)
                try:
                    written = os.write(process.stdin.fileno(), view)
                except BlockingIOError:
                    continue
                if written <= 0:
                    raise RuntimeError("regular expression worker request pipe closed")
                view = view[written:]

    def _read_response(
        self,
        *,
        deadline: float,
        deadline_kind: str,
    ) -> dict[str, object]:
        process = self._process
        if process is None or process.stdout is None:
            raise RuntimeError("regular expression worker is unavailable")
        response = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout.fileno(), selectors.EVENT_READ)
            while b"\n" not in response:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    self._deadline_exceeded(deadline_kind)
                chunk = os.read(
                    process.stdout.fileno(),
                    REGEX_WORKER_RESPONSE_BYTES + 1 - len(response),
                )
                if not chunk:
                    self._terminate()
                    raise RuntimeError(
                        "regular expression worker closed its response pipe"
                    )
                response.extend(chunk)
                if len(response) > REGEX_WORKER_RESPONSE_BYTES:
                    self._terminate()
                    raise ArtifactLimitError(
                        "regular expression worker response exceeds its limit"
                    )
        line, separator, trailing = bytes(response).partition(b"\n")
        if separator != b"\n" or trailing:
            self._terminate()
            raise RuntimeError("invalid regular expression worker framing")
        try:
            decoded = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            self._terminate()
            raise RuntimeError("invalid regular expression worker response") from error
        if not isinstance(decoded, dict):
            self._terminate()
            raise RuntimeError("invalid regular expression worker response")
        return decoded

    def _request(
        self,
        request: dict[str, object],
        *,
        startup: bool = False,
    ) -> dict[str, object]:
        if startup:
            deadline, deadline_kind = self._budget.startup_deadline()
        else:
            deadline, deadline_kind = self._budget.request_deadline()
        try:
            self._send_request(
                request,
                deadline=deadline,
                deadline_kind=deadline_kind,
            )
            return self._read_response(
                deadline=deadline,
                deadline_kind=deadline_kind,
            )
        except (BrokenPipeError, OSError) as error:
            self._terminate()
            raise RuntimeError(
                "regular expression worker communication failed"
            ) from error

    def search(self, candidate: str) -> bool:
        response = self._request(
            {
                "op": "search",
                "candidate": candidate,
            }
        )
        if response.get("status") != "matched":
            self._terminate()
            raise RuntimeError("regular expression worker returned an error")
        matched = response.get("matched")
        if not isinstance(matched, bool):
            self._terminate()
            raise RuntimeError("regular expression worker returned an error")
        return matched

    def _terminate(self) -> bool:
        process = self._process
        if process is None:
            return True
        reaped = process.poll() is not None
        try:
            if not reaped:
                try:
                    process.terminate()
                except OSError:
                    pass
                try:
                    process.wait(REGEX_WORKER_STOP_TIMEOUT_SECONDS)
                    reaped = True
                except subprocess.TimeoutExpired:
                    try:
                        process.kill()
                    except OSError:
                        pass
                    try:
                        process.wait(REGEX_WORKER_STOP_TIMEOUT_SECONDS)
                        reaped = True
                    except subprocess.TimeoutExpired:
                        reaped = False
        finally:
            for pipe in (process.stdin, process.stdout):
                if pipe is not None:
                    try:
                        pipe.close()
                    except OSError:
                        pass
            self._process = None
        return reaped

    def close(self) -> None:
        if not self._terminate():
            raise RuntimeError("regular expression worker could not be reaped")


def _write_regex_worker_response(response: dict[str, object]) -> None:
    payload = (
        json.dumps(
            response,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    if len(payload) > REGEX_WORKER_RESPONSE_BYTES:
        raise RuntimeError("regular expression worker response is too large")
    view = memoryview(payload)
    while view:
        written = os.write(sys.stdout.fileno(), view)
        if written <= 0:
            raise RuntimeError("regular expression worker response pipe closed")
        view = view[written:]


def _read_regex_worker_request() -> dict[str, object] | None:
    payload = sys.stdin.buffer.readline(REGEX_WORKER_MAX_REQUEST_BYTES + 1)
    if not payload:
        return None
    if len(payload) > REGEX_WORKER_MAX_REQUEST_BYTES or not payload.endswith(b"\n"):
        raise RuntimeError("invalid regular expression worker request framing")
    decoded = json.loads(payload)
    if not isinstance(decoded, dict):
        raise RuntimeError("invalid regular expression worker request")
    return decoded


def _regex_worker_main() -> int:
    request = _read_regex_worker_request()
    if request is None or request.get("op") != "compile":
        return 2
    pattern_text = request.get("pattern")
    ignore_case = request.get("ignore_case")
    if not isinstance(pattern_text, str) or not isinstance(ignore_case, bool):
        return 2
    try:
        pattern = re.compile(
            pattern_text,
            re.IGNORECASE if ignore_case else 0,
        )
    except re.error as error:
        _write_regex_worker_response(
            {
                "status": "error",
                "detail": _escape_terminal_text(str(error))[
                    :DEFAULT_MAX_ERROR_DETAIL_CHARS
                ],
            }
        )
        return 1
    _write_regex_worker_response({"status": "ready"})
    while True:
        request = _read_regex_worker_request()
        if request is None:
            return 0
        if request.get("op") != "search":
            return 2
        candidate = request.get("candidate")
        if not isinstance(candidate, str):
            return 2
        matched = pattern.search(candidate) is not None
        _write_regex_worker_response(
            {
                "status": "matched",
                "matched": matched,
            }
        )


@contextlib.contextmanager
def _open_pinned_archive(
    path: pathlib.Path,
    max_archive_bytes: int,
    *,
    deadline: ArchiveCommandDeadline | None = None,
) -> Iterator[PinnedArchiveReader]:
    command_deadline = deadline or ArchiveCommandDeadline()
    command_deadline.check("archive open")
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        command_deadline.check("archive open")
        metadata = os.fstat(fd)
        command_deadline.check("archive metadata validation")
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("archive path must identify a regular file")
        if metadata.st_size > max_archive_bytes:
            raise ArtifactLimitError(
                "archive file exceeds max bytes: "
                f"{metadata.st_size} > {max_archive_bytes}"
            )
        raw_stream = os.fdopen(
            fd,
            "rb",
            buffering=0,
            closefd=True,
        )
        fd = -1
        stream = PinnedArchiveReader(
            raw_stream,
            metadata.st_size,
            command_deadline,
        )
        with stream:
            yield stream
    finally:
        if fd >= 0:
            os.close(fd)


def _read_exact_at(
    stream: PinnedArchiveReader,
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
    stream: PinnedArchiveReader,
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
    stream: PinnedArchiveReader,
    eocd_offset: int,
) -> Zip64DirectoryMetadata:
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
    if zip64_offset != physical_zip64_offset:
        raise zipfile.BadZipFile(
            "concatenated or prefixed ZIP64 archives are unsupported"
        )

    disk_number = fields[4]
    central_disk = fields[5]
    entries_on_disk = fields[6]
    total_entries = fields[7]
    central_size = fields[8]
    if disk_number != 0 or central_disk != 0:
        raise zipfile.BadZipFile("multi-disk ZIP archives are unsupported")
    if entries_on_disk != total_entries:
        raise zipfile.BadZipFile("inconsistent ZIP64 member counts")
    central_start = fields[9]
    if central_start < 0 or central_start + central_size != physical_zip64_offset:
        raise zipfile.BadZipFile(
            "inconsistent ZIP64 locator and central-directory offsets"
        )
    return Zip64DirectoryMetadata(
        disk_number=disk_number,
        central_disk=central_disk,
        entries_on_disk=entries_on_disk,
        total_entries=total_entries,
        central_size=central_size,
        central_start=central_start,
        central_end=physical_zip64_offset,
    )


def _validate_classic_eocd_against_zip64(
    eocd: tuple[int, int, int, int, int, int],
    metadata: Zip64DirectoryMetadata,
) -> None:
    comparisons = (
        ("disk-number", eocd[0], 0xFFFF, metadata.disk_number),
        ("central-directory-disk", eocd[1], 0xFFFF, metadata.central_disk),
        ("entries-on-disk", eocd[2], 0xFFFF, metadata.entries_on_disk),
        ("total-entries", eocd[3], 0xFFFF, metadata.total_entries),
        ("central-directory-size", eocd[4], UINT32_MAX, metadata.central_size),
        ("central-directory-offset", eocd[5], UINT32_MAX, metadata.central_start),
    )
    for field, classic_value, sentinel, zip64_value in comparisons:
        if classic_value != sentinel and classic_value != zip64_value:
            raise zipfile.BadZipFile(
                "classic EOCD and ZIP64 metadata differ: "
                f"field={field}; classic={classic_value}; zip64={zip64_value}"
            )


def _has_zip64_locator(
    stream: PinnedArchiveReader,
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


def _validate_general_purpose_flags(
    flag_bits: int,
    *,
    ordinal: int,
) -> None:
    unsupported = flag_bits & ~SUPPORTED_GENERAL_PURPOSE_FLAGS
    if unsupported:
        raise NotImplementedError(
            "unsupported ZIP general-purpose flag bits: "
            f"ordinal={ordinal}; flags=0x{flag_bits:04x}; "
            f"unsupported=0x{unsupported:04x}"
        )


def _resolved_central_directory_disk_start(
    header: bytes,
    extra: bytes,
    *,
    ordinal: int,
) -> int:
    disk_start = struct.unpack_from("<H", header, 34)[0]
    if disk_start != 0xFFFF:
        return disk_start

    fields = _parse_extra_fields(
        extra,
        record_label="central-directory",
    )
    zip64 = fields.get(ZIP64_EXTRA_FIELD_ID)
    if zip64 is None:
        raise zipfile.BadZipFile(
            f"central-directory ZIP64 disk-start is missing: ordinal={ordinal}"
        )
    cursor = 0

    def skip_field(size: int, label: str) -> None:
        nonlocal cursor
        if len(zip64) - cursor < size:
            raise zipfile.BadZipFile(
                f"truncated central-directory ZIP64 {label}: ordinal={ordinal}"
            )
        cursor += size

    central_compress_size = struct.unpack_from("<L", header, 20)[0]
    central_file_size = struct.unpack_from("<L", header, 24)[0]
    local_header_offset = struct.unpack_from("<L", header, 42)[0]
    if central_file_size == UINT32_MAX:
        skip_field(8, "file size")
    if central_compress_size == UINT32_MAX:
        skip_field(8, "compressed size")
    if local_header_offset == UINT32_MAX:
        skip_field(8, "local-header offset")
    skip_field(4, "disk-start")
    return struct.unpack_from("<L", zip64, cursor - 4)[0]


def _resolved_central_directory_local_header_offset(
    header: bytes,
    extra: bytes,
    *,
    ordinal: int,
) -> int:
    local_header_offset = struct.unpack_from("<L", header, 42)[0]
    if local_header_offset != UINT32_MAX:
        return local_header_offset

    fields = _parse_extra_fields(
        extra,
        record_label="central-directory",
    )
    zip64 = fields.get(ZIP64_EXTRA_FIELD_ID)
    if zip64 is None:
        raise zipfile.BadZipFile(
            f"central-directory ZIP64 local-header offset is missing: ordinal={ordinal}"
        )
    cursor = 0

    def skip_field(size: int, label: str) -> None:
        nonlocal cursor
        if len(zip64) - cursor < size:
            raise zipfile.BadZipFile(
                f"truncated central-directory ZIP64 {label}: ordinal={ordinal}"
            )
        cursor += size

    central_compress_size = struct.unpack_from("<L", header, 20)[0]
    central_file_size = struct.unpack_from("<L", header, 24)[0]
    if central_file_size == UINT32_MAX:
        skip_field(8, "file size")
    if central_compress_size == UINT32_MAX:
        skip_field(8, "compressed size")
    skip_field(8, "local-header offset")
    return struct.unpack_from("<Q", zip64, cursor - 8)[0]


def _resolved_central_directory_sizes(
    header: bytes,
    extra: bytes,
    *,
    ordinal: int,
) -> tuple[int, int, bool]:
    compress_size = struct.unpack_from("<L", header, 20)[0]
    file_size = struct.unpack_from("<L", header, 24)[0]
    if compress_size != UINT32_MAX and file_size != UINT32_MAX:
        return compress_size, file_size, False

    fields = _parse_extra_fields(
        extra,
        record_label="central-directory",
    )
    zip64 = fields.get(ZIP64_EXTRA_FIELD_ID)
    if zip64 is None:
        raise zipfile.BadZipFile(
            f"central-directory ZIP64 sizes are missing: ordinal={ordinal}"
        )
    cursor = 0

    def take_size(label: str) -> int:
        nonlocal cursor
        if len(zip64) - cursor < 8:
            raise zipfile.BadZipFile(
                f"truncated central-directory ZIP64 {label}: ordinal={ordinal}"
            )
        value = struct.unpack_from("<Q", zip64, cursor)[0]
        cursor += 8
        return value

    resolved_file_size = (
        take_size("file size") if file_size == UINT32_MAX else file_size
    )
    resolved_compress_size = (
        take_size("compressed size") if compress_size == UINT32_MAX else compress_size
    )
    return resolved_compress_size, resolved_file_size, True


def _read_central_directory_identities(
    stream: PinnedArchiveReader,
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
        extra = _read_exact_at(
            stream,
            cursor + CENTRAL_DIRECTORY_HEADER_SIZE + filename_length,
            extra_length,
        )
        disk_start = _resolved_central_directory_disk_start(
            header,
            extra,
            ordinal=ordinal,
        )
        if disk_start != 0:
            raise zipfile.BadZipFile(
                "multi-disk ZIP archives are unsupported: "
                f"member ordinal={ordinal}; disk-start={disk_start}"
            )
        local_header_offset = _resolved_central_directory_local_header_offset(
            header,
            extra,
            ordinal=ordinal,
        )
        compress_size, file_size, uses_zip64_sizes = _resolved_central_directory_sizes(
            header,
            extra,
            ordinal=ordinal,
        )
        extract_version = struct.unpack_from("<H", header, 6)[0]
        if uses_zip64_sizes and extract_version < ZIP64_MIN_VERSION:
            raise zipfile.BadZipFile(
                "central-directory ZIP64 sizes require extract version 4.5: "
                f"ordinal={ordinal}"
            )
        has_zip64_extra = ZIP64_EXTRA_FIELD_ID in _parse_extra_fields(
            extra,
            record_label="central-directory",
        )
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
            extract_version=extract_version,
            compression_method=struct.unpack_from("<H", header, 10)[0],
            crc=struct.unpack_from("<L", header, 16)[0],
            compress_size=compress_size,
            file_size=file_size,
            has_zip64_extra=has_zip64_extra,
            uses_zip64_sizes=uses_zip64_sizes,
            local_header_offset=local_header_offset,
        )
        identities.append(identity)
        cursor += record_size
    if cursor != central_end:
        raise zipfile.BadZipFile("central-directory size mismatch")
    return identities


def _uses_zip64_data_descriptor(
    identity: CentralDirectoryIdentity,
    *,
    local_extract_version: int,
    local_extra: bytes,
    local_uses_zip64_sizes: bool,
) -> bool:
    local_has_zip64_extra = ZIP64_EXTRA_FIELD_ID in _parse_extra_fields(
        local_extra,
    )
    uses_zip64_descriptor = (
        local_uses_zip64_sizes
        or identity.uses_zip64_sizes
        or (
            local_has_zip64_extra
            and identity.has_zip64_extra
            and local_extract_version >= ZIP64_MIN_VERSION
            and identity.extract_version >= ZIP64_MIN_VERSION
        )
    )
    if uses_zip64_descriptor and (
        local_extract_version < ZIP64_MIN_VERSION
        or identity.extract_version < ZIP64_MIN_VERSION
    ):
        raise zipfile.BadZipFile(
            "ZIP64 data descriptor requires extract version 4.5: "
            f"ordinal={identity.ordinal}"
        )
    return uses_zip64_descriptor


def _validate_data_descriptor_values(
    stream: PinnedArchiveReader,
    *,
    payload_end: int,
    local_data_end: int,
    expected: tuple[int, int, int],
    uses_zip64_descriptor: bool,
) -> int:
    value_format = "<LQQ" if uses_zip64_descriptor else "<LLL"
    value_size = struct.calcsize(value_format)
    available_size = local_data_end - payload_end
    if available_size < value_size:
        raise zipfile.BadZipFile("data descriptor exceeds the local-data region")
    read_size = min(
        available_size,
        value_size + len(DATA_DESCRIPTOR_SIGNATURE),
    )
    available = _read_exact_at(
        stream,
        payload_end,
        read_size,
    )
    matching_ends: list[int] = []
    if struct.unpack_from(value_format, available, 0) == expected:
        matching_ends.append(payload_end + value_size)
    if len(available) >= value_size + len(
        DATA_DESCRIPTOR_SIGNATURE
    ) and available.startswith(DATA_DESCRIPTOR_SIGNATURE):
        if (
            struct.unpack_from(
                value_format,
                available,
                len(DATA_DESCRIPTOR_SIGNATURE),
            )
            == expected
        ):
            matching_ends.append(
                payload_end + len(DATA_DESCRIPTOR_SIGNATURE) + value_size
            )
    if not matching_ends:
        raise zipfile.BadZipFile(
            "data descriptor differs from validated member metadata"
        )
    if local_data_end not in matching_ends:
        raise zipfile.BadZipFile("unexplained bytes between local records")
    return local_data_end


def _validate_local_record(
    stream: PinnedArchiveReader,
    identity: CentralDirectoryIdentity,
    *,
    local_record_end: int,
    central_start: int,
) -> None:
    local_offset = identity.local_header_offset
    label = (
        "first local record"
        if local_offset == 0
        else f"local record ordinal={identity.ordinal}"
    )
    header = _read_exact_at(
        stream,
        local_offset,
        LOCAL_FILE_HEADER_SIZE,
    )
    fields = struct.unpack("<4s5H3L2H", header)
    if fields[0] != LOCAL_FILE_HEADER_SIGNATURE:
        raise zipfile.BadZipFile(f"{label} has an invalid local-file-header signature")
    local_extract_version = fields[1]
    local_flags = fields[2]
    local_compression = fields[3]
    local_crc = fields[6]
    local_compress_size = fields[7]
    local_file_size = fields[8]
    name_length = fields[9]
    extra_length = fields[10]
    if local_flags != identity.flag_bits:
        raise zipfile.BadZipFile(f"{label} flags differ from the central directory")
    if local_compression != identity.compression_method:
        raise zipfile.BadZipFile(
            f"{label} compression method differs from the central directory"
        )
    if name_length != len(identity.raw_name):
        raise zipfile.BadZipFile(
            f"{label} name length differs from the central directory"
        )

    variable_start = local_offset + LOCAL_FILE_HEADER_SIZE
    data_start = variable_start + name_length + extra_length
    payload_end = data_start + identity.compress_size
    if (
        variable_start < local_offset
        or data_start < variable_start
        or payload_end < data_start
        or payload_end > local_record_end
        or local_record_end > central_start
    ):
        raise zipfile.BadZipFile("member payload exceeds the local-data region")
    raw_name = _read_exact_at(stream, variable_start, name_length)
    if raw_name != identity.raw_name:
        raise zipfile.BadZipFile(f"{label} name differs from the central directory")
    extra = _read_exact_at(
        stream,
        variable_start + name_length,
        extra_length,
    )
    (
        resolved_file_size,
        resolved_compress_size,
        local_uses_zip64_sizes,
    ) = _resolved_local_sizes(
        local_file_size=local_file_size,
        local_compress_size=local_compress_size,
        extra=extra,
    )
    uses_data_descriptor = bool(local_flags & DATA_DESCRIPTOR_FLAG)
    if uses_data_descriptor:
        if local_crc not in (0, identity.crc):
            raise zipfile.BadZipFile(f"{label} CRC differs from the central directory")
        if resolved_file_size not in (0, identity.file_size):
            raise zipfile.BadZipFile(
                f"{label} file size differs from the central directory"
            )
        if resolved_compress_size not in (0, identity.compress_size):
            raise zipfile.BadZipFile(
                f"{label} compressed size differs from the central directory"
            )
        uses_zip64_descriptor = _uses_zip64_data_descriptor(
            identity,
            local_extract_version=local_extract_version,
            local_extra=extra,
            local_uses_zip64_sizes=local_uses_zip64_sizes,
        )
        _validate_data_descriptor_values(
            stream,
            payload_end=payload_end,
            local_data_end=local_record_end,
            expected=(
                identity.crc,
                identity.compress_size,
                identity.file_size,
            ),
            uses_zip64_descriptor=uses_zip64_descriptor,
        )
    else:
        if local_crc != identity.crc:
            raise zipfile.BadZipFile(f"{label} CRC differs from the central directory")
        if resolved_file_size != identity.file_size:
            raise zipfile.BadZipFile(
                f"{label} file size differs from the central directory"
            )
        if resolved_compress_size != identity.compress_size:
            raise zipfile.BadZipFile(
                f"{label} compressed size differs from the central directory"
            )
        if payload_end != local_record_end:
            raise zipfile.BadZipFile("unexplained bytes between local records")


def _validate_local_records(
    stream: PinnedArchiveReader,
    identities: list[CentralDirectoryIdentity],
    *,
    central_start: int,
) -> None:
    offsets = [identity.local_header_offset for identity in identities]
    if len(set(offsets)) != len(offsets) or any(
        offset < 0 or offset >= central_start for offset in offsets
    ):
        raise zipfile.BadZipFile("invalid or duplicate local-header offsets")
    ordered = sorted(identities, key=lambda identity: identity.local_header_offset)
    if ordered[0].local_header_offset != 0:
        raise zipfile.BadZipFile(
            "concatenated or prefixed ZIP archives are unsupported"
        )
    for index, identity in enumerate(ordered):
        local_record_end = (
            ordered[index + 1].local_header_offset
            if index + 1 < len(ordered)
            else central_start
        )
        _validate_local_record(
            stream,
            identity,
            local_record_end=local_record_end,
            central_start=central_start,
        )


def _preflight_central_directory(
    stream: PinnedArchiveReader,
    *,
    max_archive_members: int,
    max_central_directory_bytes: int,
) -> CentralDirectoryLayout:
    archive_size = stream.archive_size
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
        zip64_metadata = _read_zip64_directory_metadata(stream, eocd_offset)
        _validate_classic_eocd_against_zip64(eocd, zip64_metadata)
        total_entries = zip64_metadata.total_entries
        central_size = zip64_metadata.central_size
        central_start = zip64_metadata.central_start
        central_end = zip64_metadata.central_end
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
    if not uses_zip64 and central_offset != central_start:
        raise zipfile.BadZipFile(
            "concatenated or prefixed ZIP archives are unsupported"
        )

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
    if identities:
        _validate_local_records(
            stream,
            identities,
            central_start=central_start,
        )
    elif central_start != 0:
        raise zipfile.BadZipFile(
            "concatenated or prefixed empty ZIP archives are unsupported"
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


def _parse_extra_fields(
    extra: bytes,
    *,
    record_label: str = "local",
) -> dict[int, bytes]:
    fields: dict[int, bytes] = {}
    cursor = 0
    while cursor < len(extra):
        if len(extra) - cursor < 4:
            raise zipfile.BadZipFile(f"truncated {record_label} extra-field header")
        field_id, field_size = struct.unpack_from("<HH", extra, cursor)
        cursor += 4
        field_end = cursor + field_size
        if field_end > len(extra):
            raise zipfile.BadZipFile(f"{record_label} extra field exceeds its bounds")
        if field_id in fields:
            raise zipfile.BadZipFile(f"duplicate {record_label} extra-field identifier")
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
    archive_stream: PinnedArchiveReader,
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
    local_extract_version = fields[1]
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
    _validate_general_purpose_flags(
        local_flags,
        ordinal=member.identity.ordinal,
    )
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
    uses_zip64_descriptor = False
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
        uses_zip64_descriptor = _uses_zip64_data_descriptor(
            member.identity,
            local_extract_version=local_extract_version,
            local_extra=extra,
            local_uses_zip64_sizes=uses_zip64_sizes,
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
        uses_zip64_descriptor=uses_zip64_descriptor,
    )


def _validate_data_descriptor(
    archive_stream: PinnedArchiveReader,
    member: ArchiveMember,
    layout: MemberPayloadLayout,
) -> None:
    _validate_data_descriptor_values(
        archive_stream,
        payload_end=layout.payload_end,
        local_data_end=layout.local_data_end,
        expected=(
            member.info.CRC,
            member.info.compress_size,
            member.info.file_size,
        ),
        uses_zip64_descriptor=layout.uses_zip64_descriptor,
    )


def _find_members(
    members: list[ArchiveMember],
    needle: str,
    use_regex: bool,
    ignore_case: bool,
    regex_matcher: IsolatedRegexMatcher | None,
) -> list[ArchiveMember]:
    if use_regex:
        if regex_matcher is None:
            raise RuntimeError("member regex matcher is unavailable")
        return [
            member
            for member in members
            if regex_matcher.search(member.identity.decoded_name)
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
        _validate_general_purpose_flags(
            member.info.flag_bits,
            ordinal=member.identity.ordinal,
        )
        total_member_bytes = _validate_member_budget(
            member,
            max_member_bytes=args.max_member_bytes,
            total_member_bytes=total_member_bytes,
            max_total_member_bytes=args.max_total_member_bytes,
        )


def _iter_member_lines(
    archive_stream: PinnedArchiveReader,
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
    grep_matcher: IsolatedRegexMatcher | None,
    context: int,
    head: int,
    tail: int,
) -> Iterator[tuple[int, str]]:
    if grep_matcher:
        previous: collections.deque[tuple[int, str]] = collections.deque(maxlen=context)
        last_emitted = 0
        trailing = 0
        for item in lines:
            line_number, line = item
            if grep_matcher.search(line):
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
    archive_stream: PinnedArchiveReader,
    member: ArchiveMember,
    central_start: int,
    args: argparse.Namespace,
    grep_matcher: IsolatedRegexMatcher | None,
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
        grep_matcher=grep_matcher,
        context=args.context,
        head=args.head,
        tail=args.tail,
    )
    try:
        collecting_output = not output.truncated
        for line_number, line in selected_lines:
            archive_stream.check_deadline("member output selection")
            safe_line = _escape_terminal_text(line)
            rendered = f"{line_number}:{safe_line}" if args.line_numbers else safe_line
            if collecting_output:
                collecting_output = output.add(rendered)
        for _ in line_iterator:
            archive_stream.check_deadline("member validation drain")
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


def _run_archive_command(
    operation: Callable[[ArchiveCommandDeadline], None],
) -> int:
    deadline = ArchiveCommandDeadline()
    command_errors = (Exception,)
    primary_error: BaseException | None = None
    arm_completed = False
    try:
        deadline.arm()
        arm_completed = True
        operation(deadline)
    except command_errors as error:
        primary_error = error
        try:
            _emit_error(
                error,
                deadline=deadline if arm_completed else None,
            )
        except command_errors:
            pass
    finally:
        try:
            deadline.close()
        except command_errors as cleanup_error:
            if primary_error is None:
                primary_error = cleanup_error
            try:
                _emit_error(cleanup_error)
            except command_errors:
                pass
    return 1 if primary_error is not None else 0


def _validate_list_args(args: argparse.Namespace) -> None:
    for option_name, value, hard_max in (
        ("limit", args.limit, HARD_MAX_LIST_LIMIT),
        (
            "max archive bytes",
            args.max_archive_bytes,
            HARD_MAX_ARCHIVE_BYTES,
        ),
        (
            "max archive members",
            args.max_archive_members,
            HARD_MAX_ARCHIVE_MEMBERS,
        ),
        (
            "max central-directory bytes",
            args.max_central_directory_bytes,
            HARD_MAX_CENTRAL_DIRECTORY_BYTES,
        ),
        (
            "max output characters",
            args.max_output_chars,
            HARD_MAX_OUTPUT_CHARS,
        ),
    ):
        _require_bounded_positive(option_name, value, hard_max)


def cmd_zip_list(args: argparse.Namespace) -> int:
    def operation(deadline: ArchiveCommandDeadline) -> None:
        zip_path = pathlib.Path(args.zip_path)
        _validate_list_args(args)
        deadline.check("argument validation")
        regex_budget = RegexMatchBudget()
        with contextlib.ExitStack() as workers:
            matcher = (
                workers.enter_context(
                    IsolatedRegexMatcher(
                        args.match,
                        ignore_case=args.ignore_case,
                        budget=regex_budget,
                    )
                )
                if args.match
                else None
            )
            with _open_pinned_archive(
                zip_path,
                args.max_archive_bytes,
                deadline=deadline,
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
                        if matcher and not matcher.search(member.identity.decoded_name):
                            continue
                        if not output.add(
                            f"{member.info.file_size}\t"
                            f"{member.info.compress_size}\t"
                            f"{_render_archive_member(member)}",
                            allow_line_truncation=False,
                        ):
                            break
                archive_stream.validate_unchanged()
        output.flush(deadline=deadline)
        if output.truncated:
            _emit_notice(
                "output truncated by configured entry or character limit",
                deadline=deadline,
            )

    return _run_archive_command(operation)


def _format_ambiguous_members(matches: list[ArchiveMember]) -> str:
    candidates: list[str] = []
    for member in matches[:DEFAULT_CANDIDATE_REPORT_LIMIT]:
        candidate = _render_archive_member(member)
        proposed = candidates + [candidate]
        omitted = len(matches) - len(proposed)
        rendered = (
            "multiple matching members; candidates=["
            f"{','.join(proposed)}]; omitted={omitted}"
        )
        if (
            len(rendered) + len("error=") + 1
            > HARD_MAX_ERROR_CHARS - AMBIGUITY_NOTICE_RESERVE_CHARS
        ):
            break
        candidates = proposed
    omitted = len(matches) - len(candidates)
    rendered = (
        "multiple matching members; candidates=["
        f"{','.join(candidates)}]; omitted={omitted}"
    )
    if len(rendered) + len("error=") + 1 > HARD_MAX_ERROR_CHARS:
        raise ArtifactLimitError("ambiguity report exceeds internal budget")
    return rendered


def _validate_show_args(args: argparse.Namespace) -> None:
    for option_name, value, hard_max in (
        (
            "max archive bytes",
            args.max_archive_bytes,
            HARD_MAX_ARCHIVE_BYTES,
        ),
        (
            "max archive members",
            args.max_archive_members,
            HARD_MAX_ARCHIVE_MEMBERS,
        ),
        (
            "max central-directory bytes",
            args.max_central_directory_bytes,
            HARD_MAX_CENTRAL_DIRECTORY_BYTES,
        ),
        ("max members", args.max_members, HARD_MAX_MEMBERS),
        (
            "max member bytes",
            args.max_member_bytes,
            HARD_MAX_MEMBER_BYTES,
        ),
        (
            "max total member bytes",
            args.max_total_member_bytes,
            HARD_MAX_TOTAL_MEMBER_BYTES,
        ),
        (
            "max member lines",
            args.max_member_lines,
            HARD_MAX_MEMBER_LINES,
        ),
        (
            "max input line characters",
            args.max_input_line_chars,
            HARD_MAX_INPUT_LINE_CHARS,
        ),
        (
            "max output lines",
            args.max_output_lines,
            HARD_MAX_OUTPUT_LINES,
        ),
        (
            "max output characters",
            args.max_output_chars,
            HARD_MAX_OUTPUT_CHARS,
        ),
    ):
        _require_bounded_positive(option_name, value, hard_max)
    for option_name, value in (
        ("head", args.head),
        ("tail", args.tail),
        ("context", args.context),
    ):
        if value < 0:
            raise ArtifactLimitError(f"{option_name} must be nonnegative")
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
    _validate_encoding_name(args.encoding)


def cmd_zip_show(args: argparse.Namespace) -> int:
    def operation(deadline: ArchiveCommandDeadline) -> None:
        zip_path = pathlib.Path(args.zip_path)
        _validate_show_args(args)
        deadline.check("argument validation")
        regex_budget = RegexMatchBudget()
        with contextlib.ExitStack() as workers:
            member_matcher = (
                workers.enter_context(
                    IsolatedRegexMatcher(
                        args.member,
                        ignore_case=args.ignore_case,
                        budget=regex_budget,
                    )
                )
                if args.regex
                else None
            )
            grep_matcher = (
                workers.enter_context(
                    IsolatedRegexMatcher(
                        args.grep,
                        ignore_case=args.ignore_case,
                        budget=regex_budget,
                    )
                )
                if args.grep
                else None
            )
            with _open_pinned_archive(
                zip_path,
                args.max_archive_bytes,
                deadline=deadline,
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
                        member_matcher,
                    )
                    if not matches:
                        raise ArtifactLimitError("no matching members")
                    if len(matches) > 1 and not args.all:
                        raise ArtifactLimitError(_format_ambiguous_members(matches))
                    if args.all and len(matches) > args.max_members:
                        raise ArtifactLimitError(
                            "matching members exceed limit: "
                            f"{len(matches)} > {args.max_members}",
                        )
                        return 1

                    selected = matches if args.all else matches[:1]
                    _preflight_selected_members(selected, args)
                    output = OutputBudget(
                        args.max_output_lines,
                        args.max_output_chars,
                    )
                    aggregate_budget = DecompressedByteBudget(
                        args.max_total_member_bytes
                    )
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
                            grep_matcher,
                            output,
                            aggregate_budget,
                        )
                archive_stream.validate_unchanged()
        output.flush(deadline=deadline)
        if output.truncated:
            _emit_notice(
                "output truncated by configured line or character limit",
                deadline=deadline,
            )

    return _run_archive_command(operation)


class TerminalArgumentParser(argparse.ArgumentParser):
    """Render parser failures as one bounded terminal-safe diagnostic."""

    def error(self, message: str) -> None:
        try:
            _emit_error(f"argument error: {message}")
        finally:
            raise SystemExit(2)


def build_parser() -> argparse.ArgumentParser:
    parser = TerminalArgumentParser(
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
        type=_bounded_positive_int("--limit", HARD_MAX_LIST_LIMIT),
        default=DEFAULT_LIST_LIMIT,
    )
    zip_list.add_argument(
        "--max-archive-bytes",
        type=_bounded_positive_int(
            "--max-archive-bytes",
            HARD_MAX_ARCHIVE_BYTES,
        ),
        default=DEFAULT_MAX_ARCHIVE_BYTES,
    )
    zip_list.add_argument(
        "--max-archive-members",
        type=_bounded_positive_int(
            "--max-archive-members",
            HARD_MAX_ARCHIVE_MEMBERS,
        ),
        default=DEFAULT_MAX_ARCHIVE_MEMBERS,
    )
    zip_list.add_argument(
        "--max-central-directory-bytes",
        type=_bounded_positive_int(
            "--max-central-directory-bytes",
            HARD_MAX_CENTRAL_DIRECTORY_BYTES,
        ),
        default=DEFAULT_MAX_CENTRAL_DIRECTORY_BYTES,
    )
    zip_list.add_argument(
        "--max-output-chars",
        type=_bounded_positive_int(
            "--max-output-chars",
            HARD_MAX_OUTPUT_CHARS,
        ),
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
    zip_show.add_argument(
        "--encoding",
        type=_encoding_argument,
        default="utf-8",
    )
    zip_show.add_argument("--line-numbers", action="store_true")
    zip_show.add_argument(
        "--max-archive-bytes",
        type=_bounded_positive_int(
            "--max-archive-bytes",
            HARD_MAX_ARCHIVE_BYTES,
        ),
        default=DEFAULT_MAX_ARCHIVE_BYTES,
    )
    zip_show.add_argument(
        "--max-archive-members",
        type=_bounded_positive_int(
            "--max-archive-members",
            HARD_MAX_ARCHIVE_MEMBERS,
        ),
        default=DEFAULT_MAX_ARCHIVE_MEMBERS,
    )
    zip_show.add_argument(
        "--max-central-directory-bytes",
        type=_bounded_positive_int(
            "--max-central-directory-bytes",
            HARD_MAX_CENTRAL_DIRECTORY_BYTES,
        ),
        default=DEFAULT_MAX_CENTRAL_DIRECTORY_BYTES,
    )
    zip_show.add_argument(
        "--max-members",
        type=_bounded_positive_int("--max-members", HARD_MAX_MEMBERS),
        default=DEFAULT_MAX_MEMBERS,
    )
    zip_show.add_argument(
        "--max-member-bytes",
        type=_bounded_positive_int(
            "--max-member-bytes",
            HARD_MAX_MEMBER_BYTES,
        ),
        default=DEFAULT_MAX_MEMBER_BYTES,
    )
    zip_show.add_argument(
        "--max-total-member-bytes",
        type=_bounded_positive_int(
            "--max-total-member-bytes",
            HARD_MAX_TOTAL_MEMBER_BYTES,
        ),
        default=DEFAULT_MAX_TOTAL_MEMBER_BYTES,
    )
    zip_show.add_argument(
        "--max-member-lines",
        type=_bounded_positive_int(
            "--max-member-lines",
            HARD_MAX_MEMBER_LINES,
        ),
        default=DEFAULT_MAX_MEMBER_LINES,
    )
    zip_show.add_argument(
        "--max-input-line-chars",
        type=_bounded_positive_int(
            "--max-input-line-chars",
            HARD_MAX_INPUT_LINE_CHARS,
        ),
        default=DEFAULT_MAX_INPUT_LINE_CHARS,
    )
    zip_show.add_argument(
        "--max-output-lines",
        type=_bounded_positive_int(
            "--max-output-lines",
            HARD_MAX_OUTPUT_LINES,
        ),
        default=DEFAULT_MAX_OUTPUT_LINES,
    )
    zip_show.add_argument(
        "--max-output-chars",
        type=_bounded_positive_int(
            "--max-output-chars",
            HARD_MAX_OUTPUT_CHARS,
        ),
        default=DEFAULT_MAX_OUTPUT_CHARS,
    )
    zip_show.set_defaults(func=cmd_zip_show)

    return parser


def main() -> int:
    if sys.argv[1:] == [REGEX_WORKER_ARG]:
        return _regex_worker_main()
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
