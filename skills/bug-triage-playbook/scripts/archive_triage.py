#!/usr/bin/env python3

from __future__ import annotations

import argparse
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
DEFAULT_MAX_MEMBER_NAME_CHARS = 512
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


class ArtifactLimitError(ValueError):
    pass


class MemberReadError(ValueError):
    pass


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
    """Count actual decompressed bytes returned by one ZipExtFile."""

    def __init__(
        self,
        raw_stream: zipfile.ZipExtFile,
        *,
        max_member_bytes: int,
        aggregate_budget: DecompressedByteBudget,
    ) -> None:
        super().__init__()
        self._raw_stream = raw_stream
        self._max_member_bytes = max_member_bytes
        self._aggregate_budget = aggregate_budget
        self._member_bytes = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: object) -> int | None:
        byte_count = self._raw_stream.readinto(buffer)
        if not byte_count:
            return byte_count

        next_member_bytes = self._member_bytes + byte_count
        if next_member_bytes > self._max_member_bytes:
            raise ArtifactLimitError(
                "decompressed member exceeds max bytes: "
                f"{next_member_bytes} > {self._max_member_bytes}"
            )
        self._aggregate_budget.consume(byte_count)
        self._member_bytes = next_member_bytes
        return byte_count

    def close(self) -> None:
        try:
            self._raw_stream.close()
        finally:
            super().close()


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
    tail_size = min(
        archive_size,
        EOCD_MIN_SIZE + EOCD_MAX_COMMENT,
    )
    tail_start = archive_size - tail_size
    tail = _read_exact_at(stream, tail_start, tail_size)
    search_end = len(tail)
    while True:
        relative_offset = tail.rfind(
            EOCD_SIGNATURE,
            0,
            search_end,
        )
        if relative_offset < 0:
            raise zipfile.BadZipFile("end-of-central-directory record not found")
        if relative_offset + EOCD_MIN_SIZE <= len(tail):
            fields = struct.unpack_from(
                "<4s4H2LH",
                tail,
                relative_offset,
            )
            comment_length = fields[-1]
            if relative_offset + EOCD_MIN_SIZE + comment_length == len(tail):
                if tail.find(
                    EOCD_SIGNATURE,
                    relative_offset + 1,
                ) >= 0:
                    raise zipfile.BadZipFile(
                        "ambiguous end-of-central-directory signature"
                    )
                return (
                    tail_start + relative_offset,
                    (
                        fields[1],
                        fields[2],
                        fields[3],
                        fields[4],
                        fields[5],
                        fields[6],
                    ),
                )
        search_end = relative_offset


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

    record = _read_exact_at(
        stream,
        zip64_offset,
        ZIP64_EOCD_MIN_SIZE,
    )
    fields = struct.unpack("<4sQ2H2L4Q", record)
    if fields[0] != ZIP64_EOCD_SIGNATURE:
        raise zipfile.BadZipFile("ZIP64 end-of-directory record not found")
    record_size = fields[1]
    if record_size < ZIP64_EOCD_MIN_SIZE - 12:
        raise zipfile.BadZipFile("invalid ZIP64 end-of-directory size")
    if zip64_offset + 12 + record_size > locator_offset:
        raise zipfile.BadZipFile("overlapping ZIP64 directory records")

    disk_number = fields[4]
    central_disk = fields[5]
    entries_on_disk = fields[6]
    total_entries = fields[7]
    central_size = fields[8]
    if disk_number != 0 or central_disk != 0:
        raise zipfile.BadZipFile("multi-disk ZIP archives are unsupported")
    if entries_on_disk != total_entries:
        raise zipfile.BadZipFile("inconsistent ZIP64 member counts")
    return total_entries, central_size, fields[9], zip64_offset


def _count_central_directory_entries(
    stream: io.BufferedReader,
    *,
    central_start: int,
    central_size: int,
    max_archive_members: int,
) -> int:
    central_end = central_start + central_size
    cursor = central_start
    count = 0
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
        count += 1
        if count > max_archive_members:
            raise ArtifactLimitError(
                "archive member count exceeds limit: "
                f"> {max_archive_members}"
            )
        cursor += record_size
    if cursor != central_end:
        raise zipfile.BadZipFile("central-directory size mismatch")
    return count


def _preflight_central_directory(
    stream: io.BufferedReader,
    *,
    max_archive_members: int,
    max_central_directory_bytes: int,
) -> None:
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
    uses_zip64 = (
        disk_number == 0xFFFF
        or central_disk == 0xFFFF
        or entries_on_disk == 0xFFFF
        or total_entries == 0xFFFF
        or central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
    )
    if uses_zip64:
        (
            total_entries,
            central_size,
            central_offset,
            central_end,
        ) = _read_zip64_directory_metadata(stream, eocd_offset)
    else:
        if disk_number != 0 or central_disk != 0:
            raise zipfile.BadZipFile("multi-disk ZIP archives are unsupported")
        if entries_on_disk != total_entries:
            raise zipfile.BadZipFile("inconsistent ZIP member counts")
        central_end = eocd_offset

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
    central_start = central_end - central_size
    if central_start < 0:
        raise zipfile.BadZipFile("central directory starts before the archive")
    if central_offset > central_start:
        raise zipfile.BadZipFile("invalid central-directory offset")

    counted_entries = _count_central_directory_entries(
        stream,
        central_start=central_start,
        central_size=central_size,
        max_archive_members=max_archive_members,
    )
    if counted_entries != total_entries:
        raise zipfile.BadZipFile(
            "declared and counted central-directory entries differ"
        )


def _validated_infos(
    archive: zipfile.ZipFile,
    max_archive_members: int,
) -> list[zipfile.ZipInfo]:
    infos = archive.infolist()
    if len(infos) > max_archive_members:
        raise ArtifactLimitError(
            "archive member count exceeds limit: "
            f"{len(infos)} > {max_archive_members}"
        )
    return infos


def _find_members(
    infos: list[zipfile.ZipInfo],
    needle: str,
    use_regex: bool,
    ignore_case: bool,
) -> list[zipfile.ZipInfo]:
    if use_regex:
        pattern = _compile_pattern(needle, ignore_case)
        return [info for info in infos if pattern.search(info.filename)]

    compare = needle.lower() if ignore_case else needle
    matches = []
    for info in infos:
        candidate = info.filename.lower() if ignore_case else info.filename
        if candidate == compare:
            matches.append(info)
    return matches


def _escape_member_name(name: str) -> str:
    """Return one reversible, single-line JSON representation."""

    escaped_name = json.dumps(name, ensure_ascii=True)
    if len(escaped_name) > DEFAULT_MAX_MEMBER_NAME_CHARS:
        raise ArtifactLimitError(
            "escaped member name exceeds max characters: "
            f"{len(escaped_name)} > {DEFAULT_MAX_MEMBER_NAME_CHARS}"
        )
    return escaped_name


def _validate_member_budget(
    info: zipfile.ZipInfo,
    escaped_name: str,
    *,
    max_member_bytes: int,
    total_member_bytes: int,
    max_total_member_bytes: int,
) -> int:
    if info.is_dir():
        raise ValueError(
            f"member is not a regular file: member={escaped_name}"
        )
    if info.file_size > max_member_bytes:
        raise ArtifactLimitError(
            "member exceeds max bytes: "
            f"member={escaped_name}; {info.file_size} > {max_member_bytes}"
        )
    next_total = total_member_bytes + info.file_size
    if next_total > max_total_member_bytes:
        raise ArtifactLimitError(
            "selected members exceed aggregate max bytes: "
            f"{next_total} > {max_total_member_bytes}"
        )
    return next_total


def _prepare_selected_members(
    selected: list[zipfile.ZipInfo],
    args: argparse.Namespace,
) -> list[tuple[zipfile.ZipInfo, str]]:
    """Escape names and preflight every selected metadata budget."""

    prepared: list[tuple[zipfile.ZipInfo, str]] = []
    total_member_bytes = 0
    for info in selected:
        escaped_name = _escape_member_name(info.filename)
        total_member_bytes = _validate_member_budget(
            info,
            escaped_name,
            max_member_bytes=args.max_member_bytes,
            total_member_bytes=total_member_bytes,
            max_total_member_bytes=args.max_total_member_bytes,
        )
        prepared.append((info, escaped_name))
    return prepared


def _iter_member_lines(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    encoding: str,
    max_member_bytes: int,
    aggregate_budget: DecompressedByteBudget,
    max_member_lines: int,
    max_input_line_chars: int,
) -> Iterator[tuple[int, str]]:
    raw_stream = archive.open(info)
    bounded_stream = BoundedMemberReader(
        raw_stream,
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
                    "input line exceeds max characters: "
                    f"> {max_input_line_chars}"
                )
            line_number += 1
            if line_number > max_member_lines:
                raise ArtifactLimitError(
                    "member line count exceeds limit: "
                    f"> {max_member_lines}"
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
        previous: collections.deque[tuple[int, str]] = collections.deque(
            maxlen=context
        )
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
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    escaped_name: str,
    args: argparse.Namespace,
    grep_pattern: re.Pattern[str] | None,
    output: OutputBudget,
    aggregate_budget: DecompressedByteBudget,
) -> None:
    line_iterator = _iter_member_lines(
        archive,
        info,
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
        detail = json.dumps(str(error), ensure_ascii=True)
        raise MemberReadError(
            f"member={escaped_name} read failed: "
            f"type={type(error).__name__}; detail={detail}"
        ) from error
    finally:
        selected_lines.close()
        line_iterator.close()


def _archive_errors() -> tuple[type[BaseException], ...]:
    return (
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


def cmd_zip_list(args: argparse.Namespace) -> int:
    zip_path = pathlib.Path(args.zip_path)
    try:
        pattern = (
            _compile_pattern(args.match, args.ignore_case)
            if args.match
            else None
        )
        with _open_pinned_archive(
            zip_path,
            args.max_archive_bytes,
        ) as archive_stream:
            _preflight_central_directory(
                archive_stream,
                max_archive_members=args.max_archive_members,
                max_central_directory_bytes=args.max_central_directory_bytes,
            )
            with zipfile.ZipFile(archive_stream) as archive:
                infos = _validated_infos(
                    archive,
                    args.max_archive_members,
                )
                output = OutputBudget(args.limit, args.max_output_chars)
                for info in infos:
                    if pattern and not pattern.search(info.filename):
                        continue
                    escaped_name = _escape_member_name(info.filename)
                    if not output.add(
                        f"{info.file_size}\t{info.compress_size}\t"
                        f"{escaped_name}",
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


def _report_ambiguous_members(matches: list[zipfile.ZipInfo]) -> None:
    lines = ["error=multiple matching members"]
    char_count = len(lines[0]) + 1
    report_char_limit = (
        DEFAULT_MAX_AMBIGUITY_REPORT_CHARS
        - AMBIGUITY_NOTICE_RESERVE_CHARS
    )
    reported = 0
    for info in matches[:DEFAULT_CANDIDATE_REPORT_LIMIT]:
        candidate = f"member={_escape_member_name(info.filename)}"
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
            "head exceeds max output lines: "
            f"{args.head} > {args.max_output_lines}"
        )
    if args.tail > args.max_output_lines:
        raise ArtifactLimitError(
            "tail exceeds max output lines: "
            f"{args.tail} > {args.max_output_lines}"
        )
    if args.context > args.max_output_lines:
        raise ArtifactLimitError(
            "context exceeds max output lines: "
            f"{args.context} > {args.max_output_lines}"
        )
    codecs.lookup(args.encoding)
    return (
        _compile_pattern(args.grep, args.ignore_case)
        if args.grep
        else None
    )


def cmd_zip_show(args: argparse.Namespace) -> int:
    zip_path = pathlib.Path(args.zip_path)
    try:
        grep_pattern = _validate_show_args(args)
        with _open_pinned_archive(
            zip_path,
            args.max_archive_bytes,
        ) as archive_stream:
            _preflight_central_directory(
                archive_stream,
                max_archive_members=args.max_archive_members,
                max_central_directory_bytes=args.max_central_directory_bytes,
            )
            with zipfile.ZipFile(archive_stream) as archive:
                infos = _validated_infos(
                    archive,
                    args.max_archive_members,
                )
                matches = _find_members(
                    infos,
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
                prepared = _prepare_selected_members(selected, args)
                output = OutputBudget(
                    args.max_output_lines,
                    args.max_output_chars,
                )
                aggregate_budget = DecompressedByteBudget(
                    args.max_total_member_bytes
                )
                for index, (info, escaped_name) in enumerate(prepared):
                    if index and not output.truncated:
                        output.add("")
                    if not output.truncated:
                        output.add(
                            f"== {escaped_name} ==",
                            allow_line_truncation=False,
                        )
                    _add_member_output(
                        archive,
                        info,
                        escaped_name,
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
