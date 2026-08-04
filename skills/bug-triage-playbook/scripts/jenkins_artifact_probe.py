#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import collections
import contextlib
import http.client
import json
import math
import os
import pathlib
import re
import secrets
import signal
import stat
import struct
import sys
import tempfile
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from dataclasses import dataclass
from typing import BinaryIO, Deque, Dict, Iterable, Iterator, List, Optional, Pattern, Sequence, Tuple


DEFAULT_ALLOWED_HOSTS = frozenset({"jenkins.example.com"})
AUTH_PROFILES = {
    "default": (
        "JENKINS_ARTIFACT_USER",
        "JENKINS_ARTIFACT_TOKEN",
    ),
}

CHUNK_BYTES = 64 * 1024
HARD_DEADLINE_SECONDS = 300.0
HARD_SOCKET_TIMEOUT_SECONDS = 30.0
HARD_REDIRECTS = 5
HARD_PREVIEW_BYTES = 64 * 1024
HARD_METADATA_BYTES = 4 * 1024
HARD_AUTH_BYTES = 16 * 1024
HARD_REMOTE_BYTES = 512 * 1024 * 1024
HARD_TEXT_BYTES = 64 * 1024 * 1024
HARD_SCAN_LINES = 1_000_000
HARD_LINE_BYTES = 64 * 1024
HARD_EMIT_LINES = 1_000
HARD_EMIT_BYTES = 2 * 1024 * 1024
HARD_CONTEXT_LINES = 100
HARD_ARCHIVE_BYTES = 512 * 1024 * 1024
HARD_CENTRAL_DIRECTORY_BYTES = 32 * 1024 * 1024
HARD_ZIP_MEMBERS = 10_000
HARD_MEMBER_NAME_BYTES = 4 * 1024
HARD_MEMBER_COMPRESSED_BYTES = 256 * 1024 * 1024
HARD_MEMBER_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
HARD_TOTAL_COMPRESSED_BYTES = 512 * 1024 * 1024
HARD_TOTAL_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
HARD_COMPRESSION_RATIO = 200.0
HARD_SELECTED_MEMBERS = 32
ALLOWED_ENCODINGS = ("ascii", "latin-1", "utf-8")
ZIP_ENCRYPTION_FLAGS = 0x2041
ZIP_ALLOWED_FLAGS = 0x080E


class ArtifactError(Exception):
    """Base class for bounded artifact handling failures."""


class LimitExceeded(ArtifactError):
    """A configured or hard resource budget was exceeded."""


class UnsafeRedirectError(urllib.error.URLError):
    """A redirect violated the fixed HTTPS-origin policy."""


@dataclass(frozen=True)
class TextLimits:
    max_bytes: int
    max_scan_lines: int
    max_line_bytes: int
    max_emit_lines: int
    max_emit_bytes: int


@dataclass(frozen=True)
class ZipLimits:
    max_archive_bytes: int
    max_central_directory_bytes: int
    max_members: int
    max_member_name_bytes: int
    max_member_compressed_bytes: int
    max_member_uncompressed_bytes: int
    max_total_compressed_bytes: int
    max_total_uncompressed_bytes: int
    max_ratio: float
    max_selected_members: int


@dataclass(frozen=True)
class ParentSnapshot:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int


@dataclass(frozen=True)
class TempReceipt:
    parent_path: str
    parent_device: int
    parent_inode: int
    parent_mode: int
    parent_uid: int
    parent_gid: int
    final_name: str
    temp_name: str
    temp_device: int
    temp_inode: int


def _compile_pattern(pattern: str, ignore_case: bool = False) -> Pattern[str]:
    flags = re.IGNORECASE if ignore_case else 0
    return re.compile(pattern, flags)


def _effective_origin(parsed: urllib.parse.ParseResult) -> Tuple[str, str, int]:
    if parsed.hostname is None:
        raise ValueError("URL must include a host")
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("URL contains an invalid port") from error
    return parsed.scheme, parsed.hostname.lower(), 443 if port is None else port


def _ensure_allowed_url(url: str) -> urllib.parse.ParseResult:
    if not isinstance(url, str) or not url:
        raise ValueError("URL must be a non-empty string")
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in url):
        raise ValueError("URL contains unsafe whitespace, control, or non-ASCII characters")
    if "#" in url:
        raise ValueError("URL fragments are not allowed")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("only https URLs are allowed")
    if parsed.hostname is None:
        raise ValueError("URL must include a host")
    if parsed.hostname.lower() not in DEFAULT_ALLOWED_HOSTS:
        raise ValueError("host not allowed: {}".format(parsed.hostname))
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("inline URL credentials are not allowed")
    if _effective_origin(parsed)[2] != 443:
        raise ValueError("only the default HTTPS port 443 is allowed")
    return parsed


def _add_basic_auth(
    request: urllib.request.Request,
    auth_profile: Optional[str],
) -> str:
    if not auth_profile:
        return "absent"
    try:
        user_env, token_env = AUTH_PROFILES[auth_profile]
    except KeyError as error:
        raise ValueError("unknown auth profile: {}".format(auth_profile)) from error

    user = os.getenv(user_env)
    token = os.getenv(token_env)
    if not user or not token:
        raise ValueError(
            "missing auth env for profile {}: expected {} and {}".format(
                auth_profile, user_env, token_env
            )
        )
    if ":" in user:
        raise ValueError("auth profile username cannot contain a colon")
    try:
        raw = "{}:{}".format(user, token).encode("utf-8")
    except UnicodeError:
        raise ValueError("auth profile values must be valid UTF-8") from None
    if len(raw) > HARD_AUTH_BYTES:
        raise ValueError("auth profile values exceed the fixed byte limit")
    request.add_header("Authorization", "Basic {}".format(base64.b64encode(raw).decode("ascii")))
    return "present"


def _build_remote_request(
    url: str,
    *,
    method: str,
    auth_profile: Optional[str],
) -> Tuple[urllib.request.Request, str]:
    _ensure_allowed_url(url)
    request = urllib.request.Request(url, method=method)
    auth_state = _add_basic_auth(request, auth_profile)
    return request, auth_state


def _safe_remote_label(url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(url)
        hostname = parsed.hostname
        if not parsed.scheme or hostname is None:
            return "remote-url"
        display_host = "[{}]".format(hostname) if ":" in hostname else hostname
        port = parsed.port
        if port is not None:
            display_host = "{}:{}".format(display_host, port)
        label = urllib.parse.urlunsplit(
            (parsed.scheme, display_host, parsed.path or "/", "", "")
        )
    except (TypeError, ValueError):
        return "remote-url"
    return "".join(character if character.isprintable() else "?" for character in label)


class SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, initial_url: str, max_redirects: int) -> None:
        super().__init__()
        self._origin = _effective_origin(_ensure_allowed_url(initial_url))
        self._max_redirects = max_redirects
        self._redirects = 0

    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: BinaryIO,
        code: int,
        message: str,
        headers: object,
        new_url: str,
    ) -> Optional[urllib.request.Request]:
        if code not in (301, 302, 303, 307, 308):
            raise UnsafeRedirectError("redirect rejected: unsupported status")
        if not isinstance(new_url, str):
            raise UnsafeRedirectError("redirect rejected: invalid Location header")
        if "#" in new_url:
            raise UnsafeRedirectError("redirect rejected: URL fragments are not allowed")
        target = urllib.parse.urljoin(request.full_url, new_url)
        try:
            parsed = _ensure_allowed_url(target)
        except ValueError as error:
            raise UnsafeRedirectError("redirect rejected: {}".format(error)) from error
        if _effective_origin(parsed) != self._origin:
            raise UnsafeRedirectError("redirect rejected: HTTPS origin changed")
        self._redirects += 1
        if self._redirects > self._max_redirects:
            raise UnsafeRedirectError("redirect rejected: hop limit exceeded")

        method = request.get_method()
        if method not in ("GET", "HEAD"):
            raise UnsafeRedirectError("redirect rejected: unsupported method")
        redirected = urllib.request.Request(target, method=method)
        for header, value in request.header_items():
            if header.lower() == "authorization":
                redirected.add_header(header, value)
        return redirected

    def _handle_redirect(
        self,
        request: urllib.request.Request,
        file_pointer: BinaryIO,
        code: int,
        message: str,
        headers: object,
    ) -> object:
        getter = getattr(headers, "get", None)
        location = None
        if callable(getter):
            location = getter("Location") or getter("URI")
        if not location:
            file_pointer.close()
            raise urllib.error.HTTPError(
                request.full_url, code, message, headers, file_pointer
            )
        try:
            redirected = self.redirect_request(
                request,
                file_pointer,
                code,
                message,
                headers,
                location,
            )
        finally:
            file_pointer.close()
        if redirected is None:
            raise urllib.error.HTTPError(
                request.full_url, code, message, headers, file_pointer
            )
        timeout = getattr(request, "timeout", None)
        return self.parent.open(redirected, timeout=timeout)

    http_error_301 = _handle_redirect
    http_error_302 = _handle_redirect
    http_error_303 = _handle_redirect
    http_error_307 = _handle_redirect
    http_error_308 = _handle_redirect


def _build_opener(initial_url: str, max_redirects: int) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        SameOriginRedirectHandler(initial_url, max_redirects)
    )


@contextlib.contextmanager
def _open_remote(
    request: urllib.request.Request,
    *,
    socket_timeout: float,
    max_redirects: int,
) -> Iterator[object]:
    initial_origin = _effective_origin(_ensure_allowed_url(request.full_url))
    opener = _build_opener(request.full_url, max_redirects)
    response = opener.open(request, timeout=socket_timeout)
    try:
        get_url = getattr(response, "geturl", None)
        final_url = get_url() if callable(get_url) else request.full_url
        final_origin = _effective_origin(_ensure_allowed_url(final_url))
        if final_origin != initial_origin:
            raise UnsafeRedirectError("final response HTTPS origin changed")
        yield response
    finally:
        response.close()


def _header_values(headers: object, name: str) -> List[str]:
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        raw_values = get_all(name) or []
    else:
        getter = getattr(headers, "get", None)
        raw = getter(name) if callable(getter) else None
        raw_values = [] if raw is None else [raw]
    values = []
    for raw in raw_values:
        if not isinstance(raw, str):
            raise ArtifactError("invalid {} header".format(name))
        values.append(raw)
    return values


def _single_line_header(headers: object, name: str) -> Optional[str]:
    values = _header_values(headers, name)
    if not values:
        return None
    if len(values) != 1:
        raise ArtifactError("duplicate {} headers are not allowed".format(name))
    value = values[0]
    if (
        not value
        or len(value.encode("utf-8", errors="replace")) > HARD_METADATA_BYTES
        or not value.isascii()
        or any(not character.isprintable() for character in value)
    ):
        raise ArtifactError("invalid {} header".format(name))
    return value


def _response_content_length(headers: object) -> Optional[int]:
    raw = _single_line_header(headers, "Content-Length")
    transfer_encoding = _single_line_header(headers, "Transfer-Encoding")
    if transfer_encoding is not None:
        if transfer_encoding.lower() != "chunked":
            raise ArtifactError("unsupported Transfer-Encoding header")
        if raw is not None:
            raise ArtifactError("Transfer-Encoding and Content-Length cannot coexist")
    if raw is None:
        return None
    if not raw or not raw.isdecimal():
        raise ArtifactError("invalid Content-Length header")
    return int(raw)


def _check_content_length(headers: object, limit: int) -> Optional[int]:
    length = _response_content_length(headers)
    if length is not None and length > limit:
        raise LimitExceeded(
            "Content-Length {} exceeds byte limit {}".format(length, limit)
        )
    return length


def _iter_limited_chunks(
    stream: BinaryIO,
    limit: int,
    expected_length: Optional[int] = None,
) -> Iterator[bytes]:
    total = 0
    while True:
        allowance = limit - total
        if allowance <= 0:
            if stream.read(1):
                raise LimitExceeded("byte limit {} exceeded".format(limit))
            if expected_length is not None and total != expected_length:
                raise ArtifactError(
                    "body length {} does not match declared length {}".format(
                        total, expected_length
                    )
                )
            return
        chunk = stream.read(min(CHUNK_BYTES, allowance))
        if not chunk:
            if expected_length is not None and total != expected_length:
                raise ArtifactError(
                    "body length {} does not match declared length {}".format(
                        total, expected_length
                    )
                )
            return
        total += len(chunk)
        if total > limit:
            raise LimitExceeded("byte limit {} exceeded".format(limit))
        if expected_length is not None and total > expected_length:
            raise ArtifactError("body exceeds its declared length")
        yield chunk


def _read_preview(stream: BinaryIO, limit: int) -> bytes:
    remaining = limit
    chunks = []
    while remaining > 0:
        chunk = stream.read(min(CHUNK_BYTES, remaining))
        if not chunk:
            break
        if len(chunk) > remaining:
            chunk = chunk[:remaining]
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _iter_bounded_text_lines(
    stream: BinaryIO,
    *,
    encoding: str,
    limits: TextLimits,
    expected_length: Optional[int] = None,
) -> Iterator[Tuple[int, str]]:
    pending = bytearray()
    line_number = 0
    for chunk in _iter_limited_chunks(
        stream, limits.max_bytes, expected_length=expected_length
    ):
        pending.extend(chunk)
        while True:
            newline = pending.find(b"\n")
            if newline < 0:
                if len(pending) > limits.max_line_bytes:
                    raise LimitExceeded(
                        "line byte limit {} exceeded".format(limits.max_line_bytes)
                    )
                break
            raw = bytes(pending[:newline])
            del pending[: newline + 1]
            if raw.endswith(b"\r"):
                raw = raw[:-1]
            if len(raw) > limits.max_line_bytes:
                raise LimitExceeded(
                    "line byte limit {} exceeded".format(limits.max_line_bytes)
                )
            line_number += 1
            if line_number > limits.max_scan_lines:
                raise LimitExceeded(
                    "line scan limit {} exceeded".format(limits.max_scan_lines)
                )
            yield line_number, raw.decode(encoding, errors="replace")

    if pending:
        if len(pending) > limits.max_line_bytes:
            raise LimitExceeded(
                "line byte limit {} exceeded".format(limits.max_line_bytes)
            )
        line_number += 1
        if line_number > limits.max_scan_lines:
            raise LimitExceeded(
                "line scan limit {} exceeded".format(limits.max_scan_lines)
            )
        yield line_number, bytes(pending).decode(encoding, errors="replace")


class OutputCollector:
    def __init__(self, max_lines: int, max_bytes: int) -> None:
        self._max_lines = max_lines
        self._max_bytes = max_bytes
        self._bytes = 0
        self.lines: List[str] = []

    def add(self, line: str) -> None:
        line = _escape_output_line(line)
        encoded_bytes = len(line.encode("utf-8")) + 1
        if len(self.lines) + 1 > self._max_lines:
            raise LimitExceeded(
                "emitted line limit {} exceeded".format(self._max_lines)
            )
        if self._bytes + encoded_bytes > self._max_bytes:
            raise LimitExceeded(
                "emitted byte limit {} exceeded".format(self._max_bytes)
            )
        self.lines.append(line)
        self._bytes += encoded_bytes

    def extend(self, lines: Iterable[str]) -> None:
        for line in lines:
            self.add(line)

    def emit(self) -> None:
        payload = b"".join((line + "\n").encode("utf-8") for line in self.lines)
        if len(payload) != self._bytes:
            raise ArtifactError("internal error: emitted byte accounting mismatch")
        binary_stream = getattr(sys.stdout, "buffer", None)
        if binary_stream is None:
            sys.stdout.write(payload.decode("utf-8"))
            return
        view = memoryview(payload)
        while view:
            written = binary_stream.write(view)
            if written is None or written <= 0:
                raise OSError("stdout write did not make progress")
            view = view[written:]
        binary_stream.flush()


def _escape_output_line(line: str) -> str:
    escaped = []
    for character in line:
        if character.isprintable():
            escaped.append(character)
            continue
        codepoint = ord(character)
        if codepoint <= 0xFF:
            escaped.append("\\x{:02x}".format(codepoint))
        elif codepoint <= 0xFFFF:
            escaped.append("\\u{:04x}".format(codepoint))
        else:
            escaped.append("\\U{:08x}".format(codepoint))
    return "".join(escaped)


class _BoundedSeekableFile:
    def __init__(self, file_object: BinaryIO, size: int) -> None:
        self._file_object = file_object
        self._size = size

    def read(self, size: int = -1) -> bytes:
        remaining = self._size - self.tell()
        if remaining < 0:
            raise ArtifactError("bounded file position exceeds its size")
        requested = remaining if size is None or size < 0 else min(size, remaining)
        return self._file_object.read(requested)

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            target = offset
        elif whence == os.SEEK_CUR:
            target = self.tell() + offset
        elif whence == os.SEEK_END:
            target = self._size + offset
        else:
            raise ValueError("invalid seek origin")
        if target < 0 or target > self._size:
            raise ArtifactError("bounded file seek exceeds its size")
        return self._file_object.seek(target, os.SEEK_SET)

    def tell(self) -> int:
        return self._file_object.tell()

    def seekable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True


def _format_line(line_number: int, line: str, numbered: bool) -> str:
    return "{}:{}".format(line_number, line) if numbered else line


def _select_text_lines(
    lines: Iterable[Tuple[int, str]],
    *,
    grep: Optional[str],
    ignore_case: bool,
    context: int,
    head: int,
    tail: int,
    line_numbers: bool,
    collector: OutputCollector,
) -> None:
    if grep:
        pattern = _compile_pattern(grep, ignore_case)
        before: Deque[Tuple[int, str]] = collections.deque(maxlen=context)
        through = 0
        last_emitted = 0
        for line_number, line in lines:
            if pattern.search(line):
                for candidate_number, candidate in before:
                    if candidate_number > last_emitted:
                        collector.add(
                            _format_line(candidate_number, candidate, line_numbers)
                        )
                        last_emitted = candidate_number
                if line_number > last_emitted:
                    collector.add(_format_line(line_number, line, line_numbers))
                    last_emitted = line_number
                through = max(through, line_number + context)
            elif line_number <= through and line_number > last_emitted:
                collector.add(_format_line(line_number, line, line_numbers))
                last_emitted = line_number
            before.append((line_number, line))
        return

    if tail:
        selected: Deque[Tuple[int, str]] = collections.deque(maxlen=tail)
        selected_bytes = 0
        for item in lines:
            rendered = _format_line(item[0], item[1], line_numbers)
            rendered_bytes = len(rendered.encode("utf-8", errors="replace")) + 1
            if len(selected) == tail:
                old = selected[0]
                old_rendered = _format_line(old[0], old[1], line_numbers)
                selected_bytes -= len(old_rendered.encode("utf-8", errors="replace")) + 1
            selected.append(item)
            selected_bytes += rendered_bytes
            if selected_bytes > collector._max_bytes:
                raise LimitExceeded(
                    "tail buffer exceeds emitted byte limit {}".format(
                        collector._max_bytes
                    )
                )
        for line_number, line in selected:
            collector.add(_format_line(line_number, line, line_numbers))
        return

    emitted = 0
    for line_number, line in lines:
        collector.add(_format_line(line_number, line, line_numbers))
        emitted += 1
        if head and emitted >= head:
            break


def _under_path(path: str, root: str) -> bool:
    try:
        return os.path.commonpath((path, root)) == root
    except ValueError:
        return False


def _canonical_output_path(output: str) -> Tuple[str, str, str]:
    expanded = os.path.expanduser(output)
    lexical = os.path.abspath(expanded)
    cwd_lexical = os.path.abspath(os.getcwd())
    cwd_root = os.path.realpath(cwd_lexical)
    tmp_lexical = os.path.abspath("/tmp")
    tmp_root = os.path.realpath(tmp_lexical)

    if not os.path.basename(lexical) or os.path.basename(lexical) in (".", ".."):
        raise ValueError("output must name a file")
    if _under_path(lexical, cwd_lexical):
        relative = os.path.relpath(lexical, cwd_lexical)
        root = cwd_root
    elif _under_path(lexical, tmp_lexical):
        relative = os.path.relpath(lexical, tmp_lexical)
        root = tmp_root
    elif _under_path(lexical, tmp_root):
        relative = os.path.relpath(lexical, tmp_root)
        root = tmp_root
    else:
        raise ValueError(
            "output path must stay under {} or {}".format(cwd_root, tmp_root)
        )
    canonical = os.path.normpath(os.path.join(root, relative))
    if not _under_path(canonical, root):
        raise ValueError("output path escapes its allowed root")
    return canonical, os.path.dirname(canonical), os.path.basename(canonical)


def _ensure_safe_directory_policy(info: os.stat_result) -> None:
    if not stat.S_ISDIR(info.st_mode):
        raise ArtifactError("output path component is not a directory")
    mode = stat.S_IMODE(info.st_mode)
    trusted_owner = info.st_uid in (0, os.geteuid())
    if not trusted_owner:
        raise ArtifactError("output path has an untrusted directory owner")
    if mode & 0o022:
        sticky = bool(info.st_mode & stat.S_ISVTX)
        if not sticky:
            raise ArtifactError(
                "output path has an unsafe group/other-writable directory"
            )


def _open_directory_no_symlinks(path: str) -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW")
    if any(not hasattr(os, name) for name in required):
        raise ArtifactError("platform lacks required no-follow directory support")
    if not os.path.isabs(path):
        raise ArtifactError("internal error: directory path is not absolute")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    current_fd = os.open(os.path.sep, flags)
    try:
        _ensure_safe_directory_policy(os.fstat(current_fd))
        for component in pathlib.PurePath(path).parts[1:]:
            next_fd = os.open(component, flags, dir_fd=current_fd)
            try:
                _ensure_safe_directory_policy(os.fstat(next_fd))
            except BaseException:
                os.close(next_fd)
                raise
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _snapshot_parent(info: os.stat_result) -> ParentSnapshot:
    if not stat.S_ISDIR(info.st_mode):
        raise ArtifactError("output parent is not a directory")
    return ParentSnapshot(
        device=info.st_dev,
        inode=info.st_ino,
        mode=stat.S_IMODE(info.st_mode),
        uid=info.st_uid,
        gid=info.st_gid,
    )


def _same_parent_property(left: ParentSnapshot, right: ParentSnapshot) -> bool:
    return left == right


class AtomicPublisher:
    def __init__(
        self,
        final_path: str,
        parent_path: str,
        final_name: str,
        parent_fd: int,
        parent_snapshot: ParentSnapshot,
        temp_name: str,
        temp_fd: int,
        temp_info: os.stat_result,
    ) -> None:
        self.final_path = final_path
        self.parent_path = parent_path
        self.final_name = final_name
        self.parent_fd = parent_fd
        self.parent_snapshot = parent_snapshot
        self.temp_name = temp_name
        self.temp_fd = temp_fd
        self.temp_device = temp_info.st_dev
        self.temp_inode = temp_info.st_ino
        self._published = False

    @classmethod
    def prepare(cls, output: str, receipt_fd: Optional[int] = None) -> "AtomicPublisher":
        final_path, parent_path, final_name = _canonical_output_path(output)
        try:
            parent_fd = _open_directory_no_symlinks(parent_path)
        except FileNotFoundError as error:
            raise ArtifactError("output parent must already exist") from error
        try:
            parent_snapshot = _snapshot_parent(os.fstat(parent_fd))
            cls._revalidate_parent_path(parent_path, parent_snapshot)
            try:
                os.lstat(final_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            else:
                raise ArtifactError("output already exists; refusing to overwrite")

            temp_name = ".{}.artifact-{}.tmp".format(
                final_name, secrets.token_hex(12)
            )
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            temp_fd = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
            try:
                os.fchmod(temp_fd, 0o600)
                temp_info = os.fstat(temp_fd)
                if not stat.S_ISREG(temp_info.st_mode):
                    raise ArtifactError("temporary output is not a regular file")
                if stat.S_IMODE(temp_info.st_mode) != 0o600:
                    raise ArtifactError("temporary output mode is not 0600")
            except BaseException:
                os.close(temp_fd)
                with contextlib.suppress(OSError):
                    os.unlink(temp_name, dir_fd=parent_fd)
                raise

            publisher = cls(
                final_path,
                parent_path,
                final_name,
                parent_fd,
                parent_snapshot,
                temp_name,
                temp_fd,
                temp_info,
            )
            try:
                publisher._send_receipt(receipt_fd)
            except BaseException:
                publisher.abort()
                os.close(temp_fd)
                raise
            return publisher
        except BaseException:
            os.close(parent_fd)
            raise

    @staticmethod
    def _revalidate_parent_path(
        parent_path: str, expected: ParentSnapshot
    ) -> None:
        try:
            observed = _snapshot_parent(os.stat(parent_path, follow_symlinks=False))
        except OSError as error:
            raise ArtifactError("output parent revalidation failed") from error
        if not _same_parent_property(expected, observed):
            raise ArtifactError("output parent identity or access policy changed")

    def _send_receipt(self, receipt_fd: Optional[int]) -> None:
        if receipt_fd is None:
            return
        receipt = {
            "parent_path": self.parent_path,
            "parent_device": self.parent_snapshot.device,
            "parent_inode": self.parent_snapshot.inode,
            "parent_mode": self.parent_snapshot.mode,
            "parent_uid": self.parent_snapshot.uid,
            "parent_gid": self.parent_snapshot.gid,
            "final_name": self.final_name,
            "temp_name": self.temp_name,
            "temp_device": self.temp_device,
            "temp_inode": self.temp_inode,
        }
        payload = (json.dumps(receipt, separators=(",", ":")) + "\n").encode("utf-8")
        if len(payload) > 4096:
            raise ArtifactError("internal error: temporary-file receipt is too large")
        if os.write(receipt_fd, payload) != len(payload):
            raise ArtifactError("temporary-file receipt write was incomplete")

    def file(self) -> BinaryIO:
        return os.fdopen(os.dup(self.temp_fd), "wb", closefd=True)

    def _temp_matches(self) -> bool:
        try:
            info = os.lstat(self.temp_name, dir_fd=self.parent_fd)
        except FileNotFoundError:
            return False
        return (
            info.st_dev == self.temp_device
            and info.st_ino == self.temp_inode
            and stat.S_ISREG(info.st_mode)
        )

    def publish(self, expected_size: int) -> None:
        if self._published:
            raise ArtifactError("output was already published")
        os.fsync(self.temp_fd)
        current_temp = os.fstat(self.temp_fd)
        if (
            current_temp.st_dev != self.temp_device
            or current_temp.st_ino != self.temp_inode
            or not stat.S_ISREG(current_temp.st_mode)
            or stat.S_IMODE(current_temp.st_mode) != 0o600
            or current_temp.st_size != expected_size
        ):
            raise ArtifactError(
                "temporary output identity, length, or access policy changed"
            )
        if not self._temp_matches():
            raise ArtifactError("temporary output directory entry changed")
        self._revalidate_parent_path(self.parent_path, self.parent_snapshot)
        try:
            os.link(
                self.temp_name,
                self.final_name,
                src_dir_fd=self.parent_fd,
                dst_dir_fd=self.parent_fd,
                follow_symlinks=False,
            )
        except FileExistsError as error:
            raise ArtifactError("output appeared before publication; refusing to overwrite") from error

        rollback = True
        try:
            final_info = os.lstat(self.final_name, dir_fd=self.parent_fd)
            if (
                final_info.st_dev != self.temp_device
                or final_info.st_ino != self.temp_inode
                or not stat.S_ISREG(final_info.st_mode)
                or stat.S_IMODE(final_info.st_mode) != 0o600
                or final_info.st_size != expected_size
            ):
                raise ArtifactError("published output identity, length, or mode mismatch")
            self._revalidate_parent_path(self.parent_path, self.parent_snapshot)
            os.fsync(self.parent_fd)
            os.unlink(self.temp_name, dir_fd=self.parent_fd)
            os.fsync(self.parent_fd)
            self._published = True
            rollback = False
        finally:
            if rollback:
                with contextlib.suppress(OSError):
                    final_info = os.lstat(self.final_name, dir_fd=self.parent_fd)
                    if (
                        final_info.st_dev == self.temp_device
                        and final_info.st_ino == self.temp_inode
                    ):
                        os.unlink(self.final_name, dir_fd=self.parent_fd)

    def abort(self) -> None:
        if not self._published and self._temp_matches():
            with contextlib.suppress(OSError):
                os.unlink(self.temp_name, dir_fd=self.parent_fd)

    def close(self) -> None:
        with contextlib.suppress(OSError):
            os.close(self.temp_fd)
        with contextlib.suppress(OSError):
            os.close(self.parent_fd)

    def __enter__(self) -> "AtomicPublisher":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        if exc_type is not None:
            self.abort()
        self.close()
        return False


def _text_limits(args: argparse.Namespace, default_bytes: int) -> TextLimits:
    return TextLimits(
        max_bytes=getattr(args, "max_bytes", default_bytes),
        max_scan_lines=getattr(args, "max_scan_lines", HARD_SCAN_LINES),
        max_line_bytes=getattr(args, "max_line_bytes", HARD_LINE_BYTES),
        max_emit_lines=getattr(args, "max_emit_lines", HARD_EMIT_LINES),
        max_emit_bytes=getattr(args, "max_emit_bytes", HARD_EMIT_BYTES),
    )


def _zip_limits(args: argparse.Namespace) -> ZipLimits:
    return ZipLimits(
        max_archive_bytes=getattr(args, "max_archive_bytes", HARD_ARCHIVE_BYTES),
        max_central_directory_bytes=getattr(
            args, "max_central_directory_bytes", HARD_CENTRAL_DIRECTORY_BYTES
        ),
        max_members=getattr(args, "max_members", HARD_ZIP_MEMBERS),
        max_member_name_bytes=getattr(
            args, "max_member_name_bytes", HARD_MEMBER_NAME_BYTES
        ),
        max_member_compressed_bytes=getattr(
            args, "max_member_compressed_bytes", HARD_MEMBER_COMPRESSED_BYTES
        ),
        max_member_uncompressed_bytes=getattr(
            args, "max_member_uncompressed_bytes", HARD_MEMBER_UNCOMPRESSED_BYTES
        ),
        max_total_compressed_bytes=getattr(
            args, "max_total_compressed_bytes", HARD_TOTAL_COMPRESSED_BYTES
        ),
        max_total_uncompressed_bytes=getattr(
            args, "max_total_uncompressed_bytes", HARD_TOTAL_UNCOMPRESSED_BYTES
        ),
        max_ratio=getattr(args, "max_ratio", HARD_COMPRESSION_RATIO),
        max_selected_members=getattr(
            args, "max_selected_members", HARD_SELECTED_MEMBERS
        ),
    )


def _portable_member_key(name: str) -> str:
    trimmed = name[:-1] if name.endswith("/") else name
    components = unicodedata.normalize("NFC", trimmed).split("/")
    return "/".join(component.rstrip(" .").casefold() for component in components)


def _validate_member_name(name: str, name_limit: int) -> None:
    if not name:
        raise ArtifactError("zip member name is empty")
    if len(name.encode("utf-8")) > name_limit:
        raise LimitExceeded("zip member-name byte limit exceeded")
    if any(not character.isprintable() for character in name):
        raise ArtifactError("zip member name contains non-printable characters")
    if "\\" in name:
        raise ArtifactError("zip member name contains a portable path separator")
    if name.startswith("/") or name.startswith("//"):
        raise ArtifactError("zip member path is absolute")
    if re.match(r"^[A-Za-z]:", name):
        raise ArtifactError("zip member path contains a drive prefix")
    trimmed = name[:-1] if name.endswith("/") else name
    components = trimmed.split("/")
    if not components or any(component in ("", ".", "..") for component in components):
        raise ArtifactError("zip member path contains an unsafe component")
    if any(component.endswith((" ", ".")) for component in components):
        raise ArtifactError("zip member path is not portable")


def _validate_zip_flags(flags: int, compression_method: int) -> None:
    if flags & ZIP_ENCRYPTION_FLAGS:
        raise ArtifactError("encrypted zip members are not allowed")
    if flags & ~ZIP_ALLOWED_FLAGS:
        raise ArtifactError("zip general-purpose flags are not allowlisted")
    if compression_method != zipfile.ZIP_DEFLATED and flags & 0x0006:
        raise ArtifactError("zip compression-option flags disagree with the method")


def _validate_member_type(info: zipfile.ZipInfo) -> None:
    _validate_zip_flags(info.flag_bits, info.compress_type)
    if info.create_system == 0:
        dos_attributes = info.external_attr & 0xFF
        if dos_attributes & 0x08:
            raise ArtifactError("zip volume-label members are not allowed")
        if bool(dos_attributes & 0x10) != info.is_dir():
            raise ArtifactError("zip DOS type and member name disagree")
        return
    if info.create_system != 3:
        raise ArtifactError("zip member origin system is not allowlisted")
    unix_mode = info.external_attr >> 16
    file_type = stat.S_IFMT(unix_mode)
    if file_type == stat.S_IFDIR:
        if not info.is_dir():
            raise ArtifactError("zip directory type and member name disagree")
        return
    if file_type == stat.S_IFREG:
        if info.is_dir():
            raise ArtifactError("zip regular-file type and member name disagree")
        return
    if file_type == 0:
        return
    if file_type == stat.S_IFLNK:
        raise ArtifactError("symbolic-link zip members are not allowed")
    raise ArtifactError("special-file zip members are not allowed")


def _validate_zip_inventory(
    archive: zipfile.ZipFile, limits: ZipLimits
) -> Dict[str, zipfile.ZipInfo]:
    infos = archive.infolist()
    if len(infos) > limits.max_members:
        raise LimitExceeded(
            "zip member limit {} exceeded".format(limits.max_members)
        )
    names: Dict[str, zipfile.ZipInfo] = {}
    portable_names: Dict[str, str] = {}
    total_compressed = 0
    total_uncompressed = 0
    for info in infos:
        original_name = getattr(info, "orig_filename", info.filename)
        if not isinstance(original_name, str) or original_name != info.filename:
            raise ArtifactError("zip member name was truncated or is ambiguous")
        if getattr(info, "volume", 0) != 0:
            raise ArtifactError("multi-disk zip members are not supported")
        _validate_member_name(original_name, limits.max_member_name_bytes)
        _validate_member_type(info)
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise ArtifactError("zip compression method is not allowlisted")
        if (
            info.compress_type == zipfile.ZIP_STORED
            and info.compress_size != info.file_size
        ):
            raise ArtifactError("stored zip member sizes do not match")
        portable_key = _portable_member_key(info.filename)
        if info.filename in names or portable_key in portable_names:
            raise ArtifactError("duplicate portable zip member name")
        names[info.filename] = info
        portable_names[portable_key] = info.filename
        if info.compress_size > limits.max_member_compressed_bytes:
            raise LimitExceeded("zip member compressed-byte limit exceeded")
        if info.file_size > limits.max_member_uncompressed_bytes:
            raise LimitExceeded("zip member uncompressed-byte limit exceeded")
        total_compressed += info.compress_size
        total_uncompressed += info.file_size
        if total_compressed > limits.max_total_compressed_bytes:
            raise LimitExceeded("zip aggregate compressed-byte limit exceeded")
        if total_uncompressed > limits.max_total_uncompressed_bytes:
            raise LimitExceeded("zip aggregate uncompressed-byte limit exceeded")
        if info.file_size:
            if info.compress_size == 0:
                raise LimitExceeded("zip member compression ratio is unbounded")
            ratio = float(info.file_size) / float(info.compress_size)
            if ratio > limits.max_ratio:
                raise LimitExceeded("zip member compression-ratio limit exceeded")
    return names


def _reject_zip64_extra(extra: bytes) -> None:
    offset = 0
    while offset < len(extra):
        if len(extra) - offset < 4:
            raise zipfile.BadZipFile("truncated zip extra-field header")
        header_id, data_size = struct.unpack_from("<HH", extra, offset)
        offset += 4
        if offset + data_size > len(extra):
            raise zipfile.BadZipFile("truncated zip extra-field data")
        if header_id == 0x0001:
            raise ArtifactError("ZIP64 archives are not supported by this bounded helper")
        offset += data_size


def _preflight_zip_directory(
    file_object: BinaryIO,
    archive_size: int,
    member_limit: int,
    central_directory_limit: int,
) -> None:
    eocd_struct = struct.Struct("<4s4H2LH")
    minimum_size = eocd_struct.size
    if archive_size < minimum_size:
        raise zipfile.BadZipFile("archive is too short for an end record")
    tail_size = min(archive_size, minimum_size + 0xFFFF)
    file_object.seek(archive_size - tail_size)
    tail = file_object.read(tail_size)
    if len(tail) != tail_size:
        raise ArtifactError("zip end-record preflight read was incomplete")

    signature = b"PK\x05\x06"
    position = tail.rfind(signature)
    if position < 0 or position + minimum_size > len(tail):
        raise zipfile.BadZipFile("valid zip end record not found")
    record = eocd_struct.unpack_from(tail, position)
    comment_length = record[-1]
    if position + minimum_size + comment_length != len(tail):
        raise zipfile.BadZipFile("last zip end-record signature is malformed")

    (
        _,
        disk_number,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        _,
    ) = record
    absolute_eocd = archive_size - tail_size + position
    if absolute_eocd >= 20:
        file_object.seek(absolute_eocd - 20)
        if file_object.read(4) == b"PK\x06\x07":
            raise ArtifactError("ZIP64 archives are not supported by this bounded helper")
    if (
        total_entries == 0xFFFF
        or disk_entries == 0xFFFF
        or central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
    ):
        raise ArtifactError("ZIP64 archives are not supported by this bounded helper")
    if disk_number != 0 or central_disk != 0 or disk_entries != total_entries:
        raise ArtifactError("multi-disk zip archives are not supported")
    if total_entries > member_limit:
        raise LimitExceeded("zip member limit {} exceeded".format(member_limit))
    if central_size > central_directory_limit:
        raise LimitExceeded("zip central-directory byte limit exceeded")
    concatenated_prefix = absolute_eocd - central_size - central_offset
    if concatenated_prefix < 0:
        raise zipfile.BadZipFile("zip central directory exceeds the end record")
    central_start = central_offset + concatenated_prefix
    central_end = central_start + central_size
    file_object.seek(central_start)
    observed_entries = 0
    local_ranges: List[Tuple[int, int, Tuple[int, ...]]] = []
    local_metadata_bytes = 0
    fixed_header_size = 46
    while file_object.tell() < central_end:
        if central_end - file_object.tell() < fixed_header_size:
            raise zipfile.BadZipFile("truncated zip central-directory record")
        header = file_object.read(fixed_header_size)
        if len(header) != fixed_header_size or header[:4] != b"PK\x01\x02":
            raise zipfile.BadZipFile("invalid zip central-directory record")
        central_flags, central_method = struct.unpack_from("<HH", header, 8)
        central_crc, compressed_size, uncompressed_size = struct.unpack_from(
            "<LLL", header, 16
        )
        name_length, extra_length, comment_length = struct.unpack_from("<HHH", header, 28)
        disk_start = struct.unpack_from("<H", header, 34)[0]
        local_offset = struct.unpack_from("<L", header, 42)[0]
        if (
            compressed_size == 0xFFFFFFFF
            or uncompressed_size == 0xFFFFFFFF
            or local_offset == 0xFFFFFFFF
        ):
            raise ArtifactError("ZIP64 archives are not supported by this bounded helper")
        if disk_start != 0:
            raise ArtifactError("multi-disk zip members are not supported")
        if central_method not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise ArtifactError("zip compression method is not allowlisted")
        _validate_zip_flags(central_flags, central_method)
        variable_size = name_length + extra_length + comment_length
        if file_object.tell() + variable_size > central_end:
            raise zipfile.BadZipFile("zip central-directory record exceeds its bound")
        central_name = file_object.read(name_length)
        central_extra = file_object.read(extra_length)
        if len(central_name) != name_length or len(central_extra) != extra_length:
            raise zipfile.BadZipFile("truncated zip central-directory metadata")
        _reject_zip64_extra(central_extra)
        file_object.seek(comment_length, os.SEEK_CUR)
        next_central = file_object.tell()

        actual_local_offset = local_offset + concatenated_prefix
        local_header_size = 30
        if (
            actual_local_offset < 0
            or actual_local_offset + local_header_size > central_start
        ):
            raise zipfile.BadZipFile("zip local header lies outside the bounded payload area")
        file_object.seek(actual_local_offset)
        local_header = file_object.read(local_header_size)
        if len(local_header) != local_header_size or local_header[:4] != b"PK\x03\x04":
            raise zipfile.BadZipFile("invalid zip local-file header")
        (
            _,
            _,
            local_flags,
            local_method,
            _,
            _,
            local_crc,
            local_compressed_size,
            local_uncompressed_size,
            local_name_length,
            local_extra_length,
        ) = struct.unpack("<4s5H3L2H", local_header)
        if (
            local_compressed_size == 0xFFFFFFFF
            or local_uncompressed_size == 0xFFFFFFFF
        ):
            raise ArtifactError("ZIP64 archives are not supported by this bounded helper")
        _validate_zip_flags(local_flags, local_method)
        if local_flags != central_flags or local_method != central_method:
            raise ArtifactError("zip local and central header flags or methods disagree")
        local_metadata_end = (
            actual_local_offset
            + local_header_size
            + local_name_length
            + local_extra_length
        )
        data_end = local_metadata_end + compressed_size
        if local_metadata_end > central_start or data_end > central_start:
            raise zipfile.BadZipFile("zip local member exceeds the bounded payload area")
        local_metadata_bytes += local_header_size + local_name_length + local_extra_length
        if local_metadata_bytes > central_directory_limit:
            raise LimitExceeded("zip local-header metadata byte limit exceeded")
        local_name = file_object.read(local_name_length)
        local_extra = file_object.read(local_extra_length)
        if len(local_name) != local_name_length or len(local_extra) != local_extra_length:
            raise zipfile.BadZipFile("truncated zip local-file metadata")
        if local_name != central_name:
            raise ArtifactError("zip local and central member names disagree")
        _reject_zip64_extra(local_extra)
        if not (central_flags & 0x08) and (
            local_crc != central_crc
            or local_compressed_size != compressed_size
            or local_uncompressed_size != uncompressed_size
        ):
            raise ArtifactError("zip local and central member metadata disagree")
        if central_flags & 0x08 and (
            local_crc not in (0, central_crc)
            or local_compressed_size not in (0, compressed_size)
            or local_uncompressed_size not in (0, uncompressed_size)
        ):
            raise ArtifactError("zip local data-descriptor metadata is inconsistent")
        descriptor_ends: List[int] = []
        if central_flags & 0x08:
            available = central_start - data_end
            if available < 12:
                raise zipfile.BadZipFile("truncated zip data descriptor")
            file_object.seek(data_end)
            descriptor = file_object.read(min(16, available))
            if len(descriptor) >= 12:
                values = struct.unpack_from("<LLL", descriptor, 0)
                if values == (central_crc, compressed_size, uncompressed_size):
                    descriptor_ends.append(data_end + 12)
            if len(descriptor) >= 16 and descriptor[:4] == b"PK\x07\x08":
                values = struct.unpack_from("<LLL", descriptor, 4)
                if values == (central_crc, compressed_size, uncompressed_size):
                    descriptor_ends.append(data_end + 16)
            if not descriptor_ends:
                raise ArtifactError("zip data descriptor disagrees with central metadata")
        local_ranges.append(
            (actual_local_offset, data_end, tuple(descriptor_ends))
        )
        file_object.seek(next_central)
        observed_entries += 1
        if observed_entries > member_limit:
            raise LimitExceeded("zip member limit {} exceeded".format(member_limit))
    if file_object.tell() != central_end or observed_entries != total_entries:
        raise zipfile.BadZipFile("zip member count does not match the central directory")
    local_ranges.sort()
    for index, current in enumerate(local_ranges):
        next_start = (
            local_ranges[index + 1][0]
            if index + 1 < len(local_ranges)
            else central_start
        )
        if current[2] and next_start not in current[2]:
            raise ArtifactError("zip data descriptor has an unsupported layout")
        current_end = next_start if current[2] else current[1]
        if next_start < current_end:
            raise ArtifactError("zip local member ranges overlap")
    file_object.seek(0)


@contextlib.contextmanager
def _open_validated_zip(
    zip_path: str, limits: ZipLimits
) -> Iterator[Tuple[zipfile.ZipFile, Dict[str, zipfile.ZipInfo]]]:
    source = open(zip_path, "rb")
    snapshot: Optional[BinaryIO] = None
    source_before: Optional[os.stat_result] = None
    acquisition_error: Optional[BaseException] = None
    try:
        source_before = os.fstat(source.fileno())
        if not stat.S_ISREG(source_before.st_mode):
            raise ArtifactError("zip input is not a regular file")
        if source_before.st_size > limits.max_archive_bytes:
            raise LimitExceeded("zip archive byte limit exceeded")
        snapshot = tempfile.TemporaryFile(
            mode="w+b", prefix="artifact-zip-", dir="/tmp"
        )
        for chunk in _iter_limited_chunks(
            source,
            limits.max_archive_bytes,
            expected_length=source_before.st_size,
        ):
            snapshot.write(chunk)
        snapshot.flush()
    except BaseException as error:
        acquisition_error = error
        raise
    finally:
        if source_before is None:
            source.close()
        else:
            try:
                source_after = os.fstat(source.fileno())
            except OSError as error:
                source.close()
                if snapshot is not None:
                    snapshot.close()
                message = "zip source revalidation failed"
                if acquisition_error is not None:
                    message += " after an acquisition error"
                raise ArtifactError(message) from error
            source.close()
            source_changed = (
                source_before.st_dev != source_after.st_dev
                or source_before.st_ino != source_after.st_ino
                or source_before.st_size != source_after.st_size
                or source_before.st_mtime_ns != source_after.st_mtime_ns
            )
            if source_changed:
                if snapshot is not None:
                    snapshot.close()
                message = (
                    "zip source identity or content-stability signal changed "
                    "during snapshot acquisition"
                )
                if acquisition_error is not None:
                    message += " while acquisition also failed"
                raise ArtifactError(message) from acquisition_error
            if acquisition_error is not None and snapshot is not None:
                snapshot.close()

    if snapshot is None or source_before is None:
        raise ArtifactError("zip snapshot acquisition did not complete")
    snapshot.seek(0)
    bounded_snapshot = _BoundedSeekableFile(snapshot, source_before.st_size)
    operation_error: Optional[BaseException] = None
    snapshot_before: Optional[os.stat_result] = None
    try:
        snapshot_before = os.fstat(snapshot.fileno())
        if (
            not stat.S_ISREG(snapshot_before.st_mode)
            or snapshot_before.st_size != source_before.st_size
        ):
            raise ArtifactError("zip snapshot identity or size is invalid")
        _preflight_zip_directory(
            bounded_snapshot,
            snapshot_before.st_size,
            limits.max_members,
            limits.max_central_directory_bytes,
        )
        try:
            archive = zipfile.ZipFile(bounded_snapshot)
        except NotImplementedError as error:
            raise ArtifactError("unsupported ZIP feature version") from error
        with archive:
            inventory = _validate_zip_inventory(archive, limits)
            yield archive, inventory
    except BaseException as error:
        operation_error = error
        raise
    finally:
        if snapshot_before is None:
            snapshot.close()
        else:
            try:
                snapshot_after = os.fstat(snapshot.fileno())
            except OSError as error:
                message = "zip snapshot revalidation failed"
                if operation_error is not None:
                    message += " after an operation error"
                snapshot.close()
                raise ArtifactError(message) from error
            changed = (
                snapshot_before.st_dev != snapshot_after.st_dev
                or snapshot_before.st_ino != snapshot_after.st_ino
                or snapshot_before.st_size != snapshot_after.st_size
                or snapshot_before.st_mtime_ns != snapshot_after.st_mtime_ns
            )
            snapshot.close()
            if changed:
                message = (
                    "zip snapshot identity or content-stability signal changed "
                    "during inspection"
                )
                if operation_error is not None:
                    message += " while the operation also failed"
                raise ArtifactError(message) from operation_error


def _find_members(
    inventory: Dict[str, zipfile.ZipInfo],
    needle: str,
    use_regex: bool,
    ignore_case: bool,
) -> List[zipfile.ZipInfo]:
    if use_regex:
        pattern = _compile_pattern(needle, ignore_case)
        return [info for name, info in inventory.items() if pattern.search(name)]
    compare = needle.casefold() if ignore_case else needle
    return [
        info
        for name, info in inventory.items()
        if (name.casefold() if ignore_case else name) == compare
    ]


def _iter_member_compressed_chunks(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
) -> Iterator[bytes]:
    source = archive.fp
    if source is None:
        raise ArtifactError("zip archive is not open")
    source.seek(info.header_offset)
    local_header = source.read(30)
    if len(local_header) != 30 or local_header[:4] != b"PK\x03\x04":
        raise zipfile.BadZipFile("invalid zip local-file header")
    (
        _,
        _,
        local_flags,
        local_method,
        _,
        _,
        local_crc,
        local_compressed_size,
        local_uncompressed_size,
        local_name_length,
        local_extra_length,
    ) = struct.unpack("<4s5H3L2H", local_header)
    if local_flags != info.flag_bits or local_method != info.compress_type:
        raise ArtifactError("zip local and central header flags or methods disagree")
    if not (local_flags & 0x08) and (
        local_crc != info.CRC
        or local_compressed_size != info.compress_size
        or local_uncompressed_size != info.file_size
    ):
        raise ArtifactError("zip local and central member metadata disagree")
    if local_flags & 0x08 and (
        local_crc not in (0, info.CRC)
        or local_compressed_size not in (0, info.compress_size)
        or local_uncompressed_size not in (0, info.file_size)
    ):
        raise ArtifactError("zip local data-descriptor metadata is inconsistent")

    source.seek(local_name_length + local_extra_length, os.SEEK_CUR)
    remaining = info.compress_size
    while remaining:
        chunk = source.read(min(CHUNK_BYTES, remaining))
        if not chunk:
            raise zipfile.BadZipFile("truncated zip member payload")
        if len(chunk) > remaining:
            raise ArtifactError("zip member payload read exceeded its declared span")
        remaining -= len(chunk)
        yield chunk


def _update_member_integrity(
    output: bytes,
    *,
    info: zipfile.ZipInfo,
    total: int,
    crc: int,
) -> Tuple[int, int]:
    total += len(output)
    if total > info.file_size:
        raise ArtifactError("zip member expands beyond its declared length")
    return total, zlib.crc32(output, crc) & 0xFFFFFFFF


def _verify_member_payload(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    limit: int,
) -> None:
    if info.file_size > limit:
        raise LimitExceeded("byte limit {} exceeded".format(limit))
    total = 0
    crc = 0
    if info.compress_type == zipfile.ZIP_STORED:
        for chunk in _iter_member_compressed_chunks(archive, info):
            total, crc = _update_member_integrity(
                chunk, info=info, total=total, crc=crc
            )
    elif info.compress_type == zipfile.ZIP_DEFLATED:
        decompressor = zlib.decompressobj(-15)
        for compressed_chunk in _iter_member_compressed_chunks(archive, info):
            if decompressor.eof:
                raise ArtifactError(
                    "zip DEFLATE payload contains trailing compressed data"
                )
            pending = compressed_chunk
            while pending:
                allowance = min(CHUNK_BYTES, info.file_size - total + 1)
                try:
                    output = decompressor.decompress(pending, allowance)
                except zlib.error as error:
                    raise ArtifactError("malformed DEFLATE member payload") from error
                total, crc = _update_member_integrity(
                    output, info=info, total=total, crc=crc
                )
                if decompressor.unused_data:
                    raise ArtifactError(
                        "zip DEFLATE payload contains trailing compressed data"
                    )
                next_pending = decompressor.unconsumed_tail
                if next_pending and len(next_pending) == len(pending) and not output:
                    raise ArtifactError("malformed DEFLATE member payload")
                pending = next_pending
        while not decompressor.eof:
            allowance = min(CHUNK_BYTES, info.file_size - total + 1)
            try:
                output = decompressor.decompress(b"", allowance)
            except zlib.error as error:
                raise ArtifactError("malformed DEFLATE member payload") from error
            if not output:
                break
            total, crc = _update_member_integrity(
                output, info=info, total=total, crc=crc
            )
            if decompressor.unused_data or decompressor.unconsumed_tail:
                raise ArtifactError(
                    "zip DEFLATE payload contains trailing compressed data"
                )
        if decompressor.unused_data or decompressor.unconsumed_tail:
            raise ArtifactError(
                "zip DEFLATE payload contains trailing compressed data"
            )
        if not decompressor.eof:
            raise ArtifactError("malformed or truncated DEFLATE member payload")
    else:
        raise ArtifactError("zip compression method is not allowlisted")

    if total != info.file_size:
        raise ArtifactError(
            "zip member length {} does not match declared length {}".format(
                total, info.file_size
            )
        )
    if crc != info.CRC:
        raise zipfile.BadZipFile("Bad CRC-32 for file {!r}".format(info.filename))


def _stream_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    limit: int,
) -> Iterator[bytes]:
    _verify_member_payload(archive, info, limit)
    with archive.open(info, "r") as member:
        yield from _iter_limited_chunks(
            member, limit, expected_length=info.file_size
        )


def _diagnostic_text(value: object) -> str:
    escaped = _escape_output_line(str(value))
    encoded = escaped.encode("ascii", errors="backslashreplace")
    if len(encoded) > HARD_METADATA_BYTES:
        encoded = encoded[: HARD_METADATA_BYTES - 3] + b"..."
    return encoded.decode("ascii")


def _report_usage_error(subject: str, error: Exception) -> int:
    print("subject={}".format(_diagnostic_text(subject)), file=sys.stderr)
    print("error={}".format(_diagnostic_text(error)), file=sys.stderr)
    return 2


def _report_operation_error(subject: str, auth_state: Optional[str], error: Exception) -> int:
    print("subject={}".format(_diagnostic_text(subject)), file=sys.stderr)
    if auth_state is not None:
        print("auth={}".format(auth_state), file=sys.stderr)
    if isinstance(error, urllib.error.HTTPError):
        print("status={}".format(error.code), file=sys.stderr)
        detail = "remote HTTP failure"
    elif isinstance(error, UnsafeRedirectError):
        detail = error.reason
    elif isinstance(error, urllib.error.URLError):
        detail = "remote transport failure ({})".format(
            type(error.reason).__name__
        )
    elif isinstance(error, http.client.HTTPException):
        detail = "remote protocol failure ({})".format(type(error).__name__)
    elif isinstance(error, zlib.error):
        detail = "malformed DEFLATE member payload"
    elif auth_state is not None and isinstance(error, OSError):
        detail = "remote I/O failure ({}, errno={})".format(
            type(error).__name__, error.errno
        )
    else:
        detail = error
    print("error={}".format(_diagnostic_text(detail)), file=sys.stderr)
    return 1


def _socket_timeout(args: argparse.Namespace) -> float:
    return getattr(args, "socket_timeout", getattr(args, "timeout", HARD_SOCKET_TIMEOUT_SECONDS))


def _max_redirects(args: argparse.Namespace) -> int:
    return getattr(args, "max_redirects", HARD_REDIRECTS)


def _add_preview_lines(
    collector: OutputCollector, body: bytes, encoding: str
) -> None:
    decoded = body.decode(encoding, errors="replace")
    for line in decoded.splitlines():
        if len(line.encode("utf-8")) > HARD_LINE_BYTES:
            raise LimitExceeded("preview line byte limit exceeded")
        collector.add(line)


def cmd_probe_url(args: argparse.Namespace) -> int:
    try:
        request, auth_state = _build_remote_request(
            args.url, method=args.method, auth_profile=args.auth_profile
        )
    except ValueError as error:
        return _report_usage_error(_safe_remote_label(args.url), error)
    collector = OutputCollector(HARD_EMIT_LINES, HARD_EMIT_BYTES)
    try:
        with _open_remote(
            request,
            socket_timeout=_socket_timeout(args),
            max_redirects=_max_redirects(args),
        ) as response:
            sniff_bytes = getattr(args, "sniff_bytes", 0)
            body = _read_preview(response, sniff_bytes) if sniff_bytes else b""
            content_type = _single_line_header(response.headers, "Content-Type")
            content_length = _response_content_length(response.headers)
            collector.add("url={}".format(_safe_remote_label(args.url)))
            collector.add("status={}".format(response.status))
            collector.add("auth={}".format(auth_state))
            if content_type is not None:
                collector.add("content_type={}".format(content_type))
            if content_length is not None:
                collector.add("content_length={}".format(content_length))
            if body:
                collector.add("--- body preview ---")
                _add_preview_lines(collector, body, args.encoding)
        collector.emit()
        return 0
    except (
        ArtifactError,
        OSError,
        http.client.HTTPException,
        urllib.error.HTTPError,
        urllib.error.URLError,
        ValueError,
    ) as error:
        return _report_operation_error(_safe_remote_label(args.url), auth_state, error)


def cmd_show_url(args: argparse.Namespace) -> int:
    try:
        request, auth_state = _build_remote_request(
            args.url, method="GET", auth_profile=args.auth_profile
        )
    except ValueError as error:
        return _report_usage_error(_safe_remote_label(args.url), error)
    limits = _text_limits(args, HARD_TEXT_BYTES)
    collector = OutputCollector(limits.max_emit_lines, limits.max_emit_bytes)
    try:
        with _open_remote(
            request,
            socket_timeout=_socket_timeout(args),
            max_redirects=_max_redirects(args),
        ) as response:
            if args.head:
                declared_length = _response_content_length(response.headers)
            else:
                declared_length = _check_content_length(
                    response.headers, limits.max_bytes
                )
            _select_text_lines(
                _iter_bounded_text_lines(
                    response,
                    encoding=args.encoding,
                    limits=limits,
                    expected_length=declared_length,
                ),
                grep=args.grep,
                ignore_case=args.ignore_case,
                context=args.context,
                head=args.head,
                tail=args.tail,
                line_numbers=args.line_numbers,
                collector=collector,
            )
        collector.emit()
        return 0
    except (
        ArtifactError,
        OSError,
        re.error,
        http.client.HTTPException,
        urllib.error.HTTPError,
        urllib.error.URLError,
        ValueError,
    ) as error:
        return _report_operation_error(_safe_remote_label(args.url), auth_state, error)


def cmd_fetch_url(args: argparse.Namespace) -> int:
    try:
        request, auth_state = _build_remote_request(
            args.url, method="GET", auth_profile=args.auth_profile
        )
        publisher = AtomicPublisher.prepare(
            args.output, getattr(args, "_receipt_fd", None)
        )
    except (ArtifactError, OSError, ValueError) as error:
        return _report_usage_error(_safe_remote_label(args.url), error)
    max_bytes = getattr(args, "max_bytes", HARD_REMOTE_BYTES)
    try:
        with publisher:
            total = 0
            with _open_remote(
                request,
                socket_timeout=_socket_timeout(args),
                max_redirects=_max_redirects(args),
            ) as response:
                declared_length = _check_content_length(
                    response.headers, max_bytes
                )
                with publisher.file() as output:
                    for chunk in _iter_limited_chunks(
                        response,
                        max_bytes,
                        expected_length=declared_length,
                    ):
                        output.write(chunk)
                        total += len(chunk)
                    output.flush()
            publisher.publish(total)
        collector = OutputCollector(HARD_EMIT_LINES, HARD_EMIT_BYTES)
        collector.add("url={}".format(_safe_remote_label(args.url)))
        collector.add("output={}".format(publisher.final_path))
        collector.add("bytes={}".format(total))
        collector.add("auth={}".format(auth_state))
        collector.emit()
        return 0
    except (
        ArtifactError,
        OSError,
        http.client.HTTPException,
        urllib.error.HTTPError,
        urllib.error.URLError,
        ValueError,
    ) as error:
        return _report_operation_error(_safe_remote_label(args.url), auth_state, error)


def cmd_zip_list(args: argparse.Namespace) -> int:
    limits = _zip_limits(args)
    collector = OutputCollector(
        getattr(args, "max_emit_lines", HARD_EMIT_LINES),
        getattr(args, "max_emit_bytes", HARD_EMIT_BYTES),
    )
    try:
        pattern = _compile_pattern(args.match, args.ignore_case) if args.match else None
        with _open_validated_zip(args.zip_path, limits) as (_, inventory):
            matched = 0
            for info in inventory.values():
                if pattern and not pattern.search(info.filename):
                    continue
                matched += 1
                collector.add(
                    "uncompressed={} compressed={} member={}".format(
                        info.file_size, info.compress_size, info.filename
                    )
                )
                if args.limit and matched >= args.limit:
                    break
        collector.emit()
        return 0
    except (
        ArtifactError,
        OSError,
        re.error,
        zipfile.BadZipFile,
        ValueError,
    ) as error:
        return _report_operation_error(args.zip_path, None, error)


def cmd_zip_show(args: argparse.Namespace) -> int:
    limits = _zip_limits(args)
    text_limits = _text_limits(args, HARD_MEMBER_UNCOMPRESSED_BYTES)
    collector = OutputCollector(text_limits.max_emit_lines, text_limits.max_emit_bytes)
    try:
        with _open_validated_zip(args.zip_path, limits) as (archive, inventory):
            matches = _find_members(
                inventory, args.member, args.regex, args.ignore_case
            )
            if not matches:
                raise ArtifactError("no matching members")
            if len(matches) > 1 and not args.all:
                raise ArtifactError("multiple matching members")
            selected = matches if args.all else matches[:1]
            if len(selected) > limits.max_selected_members:
                raise LimitExceeded("selected-member limit exceeded")
            for index, info in enumerate(selected):
                if info.is_dir():
                    raise ArtifactError("cannot show a directory member")
                _verify_member_payload(archive, info, text_limits.max_bytes)
                if index:
                    collector.add("")
                collector.add("== {} ==".format(info.filename))
                with archive.open(info, "r") as member:
                    _select_text_lines(
                        _iter_bounded_text_lines(
                            member,
                            encoding=args.encoding,
                            limits=text_limits,
                            expected_length=info.file_size,
                        ),
                        grep=args.grep,
                        ignore_case=args.ignore_case,
                        context=args.context,
                        head=args.head,
                        tail=args.tail,
                        line_numbers=args.line_numbers,
                        collector=collector,
                    )
        collector.emit()
        return 0
    except (
        ArtifactError,
        OSError,
        re.error,
        zipfile.BadZipFile,
        zlib.error,
        ValueError,
    ) as error:
        return _report_operation_error(args.zip_path, None, error)


def cmd_zip_extract(args: argparse.Namespace) -> int:
    limits = _zip_limits(args)
    try:
        publisher = AtomicPublisher.prepare(
            args.output, getattr(args, "_receipt_fd", None)
        )
    except (ArtifactError, OSError, ValueError) as error:
        return _report_usage_error(args.output, error)
    try:
        with publisher:
            with _open_validated_zip(args.zip_path, limits) as (archive, inventory):
                try:
                    info = inventory[args.member]
                except KeyError as error:
                    raise ArtifactError("no exact matching member") from error
                if info.is_dir():
                    raise ArtifactError("cannot extract a directory member")
                limit = min(
                    getattr(args, "max_bytes", HARD_MEMBER_UNCOMPRESSED_BYTES),
                    limits.max_member_uncompressed_bytes,
                    info.file_size,
                )
                total = 0
                with publisher.file() as output:
                    for chunk in _stream_member(archive, info, limit):
                        output.write(chunk)
                        total += len(chunk)
                    output.flush()
            publisher.publish(total)
        collector = OutputCollector(HARD_EMIT_LINES, HARD_EMIT_BYTES)
        collector.add("archive={}".format(args.zip_path))
        collector.add("member={}".format(args.member))
        collector.add("output={}".format(publisher.final_path))
        collector.add("bytes={}".format(total))
        collector.emit()
        return 0
    except (
        ArtifactError,
        OSError,
        zipfile.BadZipFile,
        zlib.error,
        ValueError,
    ) as error:
        return _report_operation_error(args.zip_path, None, error)


def _bounded_int(name: str, hard_limit: int, allow_zero: bool = False):
    def parse(raw: str) -> int:
        try:
            value = int(raw)
        except ValueError as error:
            raise argparse.ArgumentTypeError("{} must be an integer".format(name)) from error
        minimum = 0 if allow_zero else 1
        if value < minimum or value > hard_limit:
            raise argparse.ArgumentTypeError(
                "{} must be between {} and {}".format(name, minimum, hard_limit)
            )
        return value

    return parse


def _bounded_float(name: str, hard_limit: float):
    def parse(raw: str) -> float:
        try:
            value = float(raw)
        except ValueError as error:
            raise argparse.ArgumentTypeError("{} must be a number".format(name)) from error
        if not math.isfinite(value) or value <= 0 or value > hard_limit:
            raise argparse.ArgumentTypeError(
                "{} must be greater than zero and at most {}".format(name, hard_limit)
            )
        return value

    return parse


def _add_runtime_limits(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--deadline-seconds",
        type=_bounded_float("deadline", HARD_DEADLINE_SECONDS),
        default=HARD_DEADLINE_SECONDS,
        help="Full worker wall deadline; may only tighten the hard ceiling.",
    )


def _add_remote_limits(parser: argparse.ArgumentParser) -> None:
    _add_runtime_limits(parser)
    parser.add_argument(
        "--socket-timeout",
        "--timeout",
        dest="socket_timeout",
        type=_bounded_float("socket timeout", HARD_SOCKET_TIMEOUT_SECONDS),
        default=HARD_SOCKET_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--max-redirects",
        type=_bounded_int("redirect limit", HARD_REDIRECTS, allow_zero=True),
        default=HARD_REDIRECTS,
    )


def _add_text_limits(parser: argparse.ArgumentParser, default_bytes: int) -> None:
    parser.add_argument(
        "--max-bytes",
        type=_bounded_int("byte limit", default_bytes),
        default=default_bytes,
    )
    parser.add_argument(
        "--max-scan-lines",
        type=_bounded_int("line scan limit", HARD_SCAN_LINES),
        default=HARD_SCAN_LINES,
    )
    parser.add_argument(
        "--max-line-bytes",
        type=_bounded_int("line byte limit", HARD_LINE_BYTES),
        default=HARD_LINE_BYTES,
    )
    parser.add_argument(
        "--max-emit-lines",
        type=_bounded_int("emitted line limit", HARD_EMIT_LINES),
        default=HARD_EMIT_LINES,
    )
    parser.add_argument(
        "--max-emit-bytes",
        type=_bounded_int("emitted byte limit", HARD_EMIT_BYTES),
        default=HARD_EMIT_BYTES,
    )


def _add_text_selection(parser: argparse.ArgumentParser) -> None:
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--grep")
    parser.add_argument("--ignore-case", action="store_true")
    parser.add_argument(
        "--context",
        type=_bounded_int("context", HARD_CONTEXT_LINES, allow_zero=True),
        default=0,
    )
    selection.add_argument(
        "--head",
        type=_bounded_int("head", HARD_EMIT_LINES, allow_zero=True),
        default=0,
    )
    selection.add_argument(
        "--tail",
        type=_bounded_int("tail", HARD_EMIT_LINES, allow_zero=True),
        default=0,
    )
    parser.add_argument("--encoding", choices=ALLOWED_ENCODINGS, default="utf-8")
    parser.add_argument("--line-numbers", action="store_true")


def _add_zip_limits(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--max-archive-bytes",
        type=_bounded_int("archive byte limit", HARD_ARCHIVE_BYTES),
        default=HARD_ARCHIVE_BYTES,
    )
    parser.add_argument(
        "--max-central-directory-bytes",
        type=_bounded_int(
            "central-directory byte limit", HARD_CENTRAL_DIRECTORY_BYTES
        ),
        default=HARD_CENTRAL_DIRECTORY_BYTES,
    )
    parser.add_argument(
        "--max-members",
        type=_bounded_int("zip member limit", HARD_ZIP_MEMBERS),
        default=HARD_ZIP_MEMBERS,
    )
    parser.add_argument(
        "--max-member-name-bytes",
        type=_bounded_int("member-name byte limit", HARD_MEMBER_NAME_BYTES),
        default=HARD_MEMBER_NAME_BYTES,
    )
    parser.add_argument(
        "--max-member-compressed-bytes",
        type=_bounded_int("member compressed-byte limit", HARD_MEMBER_COMPRESSED_BYTES),
        default=HARD_MEMBER_COMPRESSED_BYTES,
    )
    parser.add_argument(
        "--max-member-uncompressed-bytes",
        type=_bounded_int("member uncompressed-byte limit", HARD_MEMBER_UNCOMPRESSED_BYTES),
        default=HARD_MEMBER_UNCOMPRESSED_BYTES,
    )
    parser.add_argument(
        "--max-total-compressed-bytes",
        type=_bounded_int("aggregate compressed-byte limit", HARD_TOTAL_COMPRESSED_BYTES),
        default=HARD_TOTAL_COMPRESSED_BYTES,
    )
    parser.add_argument(
        "--max-total-uncompressed-bytes",
        type=_bounded_int("aggregate uncompressed-byte limit", HARD_TOTAL_UNCOMPRESSED_BYTES),
        default=HARD_TOTAL_UNCOMPRESSED_BYTES,
    )
    parser.add_argument(
        "--max-ratio",
        type=_bounded_float("compression ratio", HARD_COMPRESSION_RATIO),
        default=HARD_COMPRESSION_RATIO,
    )


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(2, "error={}\n".format(_diagnostic_text(message)))


def build_parser() -> argparse.ArgumentParser:
    parser = SafeArgumentParser(
        prog="jenkins-artifact-probe",
        description=(
            "Fetch allowlisted HTTPS artifacts and inspect ZIP content with fixed safety ceilings."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    probe = subparsers.add_parser("probe-url", help="Probe an allowlisted HTTPS URL.")
    probe.add_argument("url")
    probe.add_argument("--method", default="HEAD", choices=("HEAD", "GET"))
    probe.add_argument("--auth-profile", choices=sorted(AUTH_PROFILES))
    probe.add_argument(
        "--sniff-bytes",
        type=_bounded_int("preview byte limit", HARD_PREVIEW_BYTES, allow_zero=True),
        default=0,
    )
    probe.add_argument("--encoding", choices=ALLOWED_ENCODINGS, default="utf-8")
    _add_remote_limits(probe)
    probe.set_defaults(func=cmd_probe_url)

    show = subparsers.add_parser("show-url", help="Show bounded text from an allowlisted HTTPS URL.")
    show.add_argument("url")
    show.add_argument("--auth-profile", choices=sorted(AUTH_PROFILES))
    _add_text_selection(show)
    _add_text_limits(show, HARD_TEXT_BYTES)
    _add_remote_limits(show)
    show.set_defaults(func=cmd_show_url)

    fetch = subparsers.add_parser("fetch-url", help="Fetch to a new mode-0600 file without overwrite.")
    fetch.add_argument("url")
    fetch.add_argument("--output", required=True)
    fetch.add_argument("--auth-profile", choices=sorted(AUTH_PROFILES))
    fetch.add_argument(
        "--max-bytes",
        type=_bounded_int("byte limit", HARD_REMOTE_BYTES),
        default=HARD_REMOTE_BYTES,
    )
    _add_remote_limits(fetch)
    fetch.set_defaults(func=cmd_fetch_url)

    zip_list = subparsers.add_parser("zip-list", help="Validate and list bounded ZIP members.")
    zip_list.add_argument("zip_path")
    zip_list.add_argument("--match")
    zip_list.add_argument("--ignore-case", action="store_true")
    zip_list.add_argument(
        "--limit",
        type=_bounded_int("list limit", HARD_EMIT_LINES, allow_zero=True),
        default=0,
    )
    zip_list.add_argument(
        "--max-emit-lines",
        type=_bounded_int("emitted line limit", HARD_EMIT_LINES),
        default=HARD_EMIT_LINES,
    )
    zip_list.add_argument(
        "--max-emit-bytes",
        type=_bounded_int("emitted byte limit", HARD_EMIT_BYTES),
        default=HARD_EMIT_BYTES,
    )
    _add_zip_limits(zip_list)
    _add_runtime_limits(zip_list)
    zip_list.set_defaults(func=cmd_zip_list)

    zip_show = subparsers.add_parser("zip-show", help="Validate and show bounded ZIP member text.")
    zip_show.add_argument("zip_path")
    zip_show.add_argument("member")
    zip_show.add_argument("--regex", action="store_true")
    zip_show.add_argument("--all", action="store_true")
    _add_text_selection(zip_show)
    _add_text_limits(zip_show, HARD_MEMBER_UNCOMPRESSED_BYTES)
    _add_zip_limits(zip_show)
    zip_show.add_argument(
        "--max-selected-members",
        type=_bounded_int("selected-member limit", HARD_SELECTED_MEMBERS),
        default=HARD_SELECTED_MEMBERS,
    )
    _add_runtime_limits(zip_show)
    zip_show.set_defaults(func=cmd_zip_show)

    zip_extract = subparsers.add_parser("zip-extract", help="Extract one exact ZIP member atomically.")
    zip_extract.add_argument("zip_path")
    zip_extract.add_argument("member")
    zip_extract.add_argument("--output", required=True)
    zip_extract.add_argument(
        "--max-bytes",
        type=_bounded_int("extraction byte limit", HARD_MEMBER_UNCOMPRESSED_BYTES),
        default=HARD_MEMBER_UNCOMPRESSED_BYTES,
    )
    _add_zip_limits(zip_extract)
    _add_runtime_limits(zip_extract)
    zip_extract.set_defaults(func=cmd_zip_extract)
    return parser


def _parse_receipt(raw: bytes) -> Optional[TempReceipt]:
    if not raw:
        return None
    line = raw.splitlines()[0]
    if len(line) > 4096:
        return None
    try:
        value = json.loads(line.decode("utf-8"))
        return TempReceipt(
            parent_path=value["parent_path"],
            parent_device=int(value["parent_device"]),
            parent_inode=int(value["parent_inode"]),
            parent_mode=int(value["parent_mode"]),
            parent_uid=int(value["parent_uid"]),
            parent_gid=int(value["parent_gid"]),
            final_name=value["final_name"],
            temp_name=value["temp_name"],
            temp_device=int(value["temp_device"]),
            temp_inode=int(value["temp_inode"]),
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _cleanup_receipt(receipt: Optional[TempReceipt]) -> str:
    if receipt is None:
        return "not-needed"
    if (
        os.path.basename(receipt.temp_name) != receipt.temp_name
        or os.path.basename(receipt.final_name) != receipt.final_name
    ):
        return "inconclusive"
    try:
        parent_fd = _open_directory_no_symlinks(receipt.parent_path)
    except (ArtifactError, OSError):
        return "inconclusive"
    try:
        parent_info = os.fstat(parent_fd)
        observed_parent = _snapshot_parent(parent_info)
        expected_parent = ParentSnapshot(
            device=receipt.parent_device,
            inode=receipt.parent_inode,
            mode=receipt.parent_mode,
            uid=receipt.parent_uid,
            gid=receipt.parent_gid,
        )
        if not _same_parent_property(expected_parent, observed_parent):
            return "inconclusive"
        consecutive_absent_passes = 0
        saw_foreign_entry = False
        for _ in range(4):
            removed = False
            for name in (receipt.final_name, receipt.temp_name):
                try:
                    info = os.lstat(name, dir_fd=parent_fd)
                except FileNotFoundError:
                    continue
                if (
                    info.st_dev != receipt.temp_device
                    or info.st_ino != receipt.temp_inode
                ):
                    saw_foreign_entry = True
                    continue
                os.unlink(name, dir_fd=parent_fd)
                removed = True
            if removed:
                consecutive_absent_passes = 0
            else:
                consecutive_absent_passes += 1
                if consecutive_absent_passes == 2:
                    break
        if consecutive_absent_passes < 2:
            return "inconclusive"
        AtomicPublisher._revalidate_parent_path(
            receipt.parent_path, expected_parent
        )
        os.fsync(parent_fd)
        return "inconclusive" if saw_foreign_entry else "complete"
    except (ArtifactError, OSError):
        return "inconclusive"
    finally:
        os.close(parent_fd)


@dataclass
class _WorkerProcess:
    pid: int = -1
    read_fd: int = -1
    write_fd: int = -1
    status: int = 0
    reaped: bool = False
    setup_mask: Optional[Iterable[int]] = None
    setup_mask_active: bool = False
    sigchld_handler: object = None
    sigchld_handler_active: bool = False


def _blockable_signals() -> frozenset:
    blocked = set(signal.valid_signals())
    for name in ("SIGKILL", "SIGSTOP"):
        unmaskable = getattr(signal, name, None)
        if unmaskable is not None:
            blocked.discard(unmaskable)
    return frozenset(blocked)


def _restore_setup_signals(worker: _WorkerProcess) -> None:
    if not worker.setup_mask_active or worker.setup_mask is None:
        return
    previous = worker.setup_mask
    worker.setup_mask_active = False
    signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def _restore_sigchld_handler(worker: _WorkerProcess) -> None:
    if not worker.sigchld_handler_active:
        return
    signal.signal(signal.SIGCHLD, worker.sigchld_handler)
    worker.sigchld_handler_active = False


def _run_worker_child(args: argparse.Namespace, worker: _WorkerProcess) -> None:
    return_code = 1
    try:
        os.close(worker.read_fd)
        worker.read_fd = -1
        _restore_sigchld_handler(worker)
        _restore_setup_signals(worker)
        setattr(args, "_receipt_fd", worker.write_fd)
        return_code = int(args.func(args))
    except BaseException as error:
        print(
            "error=unhandled worker failure ({})".format(type(error).__name__),
            file=sys.stderr,
        )
    finally:
        with contextlib.suppress(Exception):
            sys.stdout.flush()
            sys.stderr.flush()
        with contextlib.suppress(OSError):
            os.close(worker.write_fd)
    os._exit(max(0, min(return_code, 255)))


def _start_worker(
    args: argparse.Namespace,
    worker: _WorkerProcess,
    blocked_signals: frozenset,
) -> None:
    worker.setup_mask = signal.pthread_sigmask(signal.SIG_BLOCK, blocked_signals)
    worker.setup_mask_active = True
    worker.sigchld_handler = signal.getsignal(signal.SIGCHLD)
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    worker.sigchld_handler_active = True
    worker.read_fd, worker.write_fd = os.pipe()
    os.set_blocking(worker.read_fd, False)
    worker.pid = os.fork()
    if worker.pid == 0:
        _run_worker_child(args, worker)
    os.close(worker.write_fd)
    worker.write_fd = -1
    _restore_setup_signals(worker)


def _waitpid_tracked(
    worker: _WorkerProcess, options: int, blocked_signals: frozenset
) -> int:
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, blocked_signals)
    try:
        try:
            waited_pid, status = os.waitpid(worker.pid, options)
        except ChildProcessError:
            worker.reaped = True
            _restore_sigchld_handler(worker)
            raise
        if waited_pid == worker.pid:
            worker.status = status
            worker.reaped = True
            _restore_sigchld_handler(worker)
        return waited_pid
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def _kill_and_reap_worker(
    worker: _WorkerProcess, blocked_signals: frozenset
) -> None:
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, blocked_signals)
    try:
        if worker.pid <= 0 or worker.reaped:
            _restore_sigchld_handler(worker)
            return
        with contextlib.suppress(ProcessLookupError):
            os.kill(worker.pid, signal.SIGKILL)
        try:
            waited_pid, status = os.waitpid(worker.pid, 0)
        except ChildProcessError:
            worker.reaped = True
            _restore_sigchld_handler(worker)
            return
        if waited_pid != worker.pid:
            raise RuntimeError("waitpid returned an unexpected worker PID")
        worker.status = status
        worker.reaped = True
        _restore_sigchld_handler(worker)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def _run_with_hard_deadline(args: argparse.Namespace) -> int:
    if not hasattr(os, "fork") or not hasattr(signal, "pthread_sigmask"):
        print("error=platform lacks required worker-process deadline support", file=sys.stderr)
        return 2
    started = time.monotonic()
    deadline = started + args.deadline_seconds
    blocked_signals = _blockable_signals()
    worker = _WorkerProcess()
    receipt_bytes = bytearray()
    timed_out = False
    parent_error: Optional[BaseException] = None
    try:
        _start_worker(args, worker, blocked_signals)
        while True:
            if time.monotonic() >= deadline:
                timed_out = True
                _waitpid_tracked(worker, os.WNOHANG, blocked_signals)
                if not worker.reaped:
                    _kill_and_reap_worker(worker, blocked_signals)
                break
            with contextlib.suppress(BlockingIOError):
                chunk = os.read(worker.read_fd, 4096 - len(receipt_bytes))
                if chunk:
                    receipt_bytes.extend(chunk)
            _waitpid_tracked(worker, os.WNOHANG, blocked_signals)
            observed = time.monotonic()
            if observed >= deadline:
                timed_out = True
                if not worker.reaped:
                    _kill_and_reap_worker(worker, blocked_signals)
                break
            if worker.reaped:
                break
            remaining = deadline - observed
            time.sleep(min(0.01, remaining))
    except BaseException as error:
        parent_error = error
        if worker.pid > 0 and not worker.reaped:
            with contextlib.suppress(BaseException):
                _kill_and_reap_worker(worker, blocked_signals)
    finally:
        if worker.sigchld_handler_active and (
            worker.pid <= 0 or worker.reaped
        ):
            try:
                _restore_sigchld_handler(worker)
            except BaseException as error:
                if parent_error is None:
                    parent_error = error
        if worker.setup_mask_active:
            try:
                _restore_setup_signals(worker)
            except BaseException as error:
                if parent_error is None:
                    parent_error = error
                if worker.pid > 0 and not worker.reaped:
                    with contextlib.suppress(BaseException):
                        _kill_and_reap_worker(worker, blocked_signals)
        if worker.write_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(worker.write_fd)
            worker.write_fd = -1
        if worker.read_fd >= 0:
            while len(receipt_bytes) < 4096:
                try:
                    chunk = os.read(worker.read_fd, 4096 - len(receipt_bytes))
                except BlockingIOError:
                    break
                if not chunk:
                    break
                receipt_bytes.extend(chunk)
            os.close(worker.read_fd)
            worker.read_fd = -1

    receipt = _parse_receipt(bytes(receipt_bytes))
    if parent_error is not None:
        cleanup = _cleanup_receipt(receipt)
        if receipt is None and hasattr(args, "output"):
            cleanup = "inconclusive"
        print("cleanup={}".format(cleanup), file=sys.stderr)
        raise parent_error
    if timed_out:
        cleanup = _cleanup_receipt(receipt)
        if receipt is None and hasattr(args, "output"):
            cleanup = "inconclusive"
        print("error=wall deadline exceeded", file=sys.stderr)
        print("cleanup={}".format(cleanup), file=sys.stderr)
        return 124
    if os.WIFEXITED(worker.status):
        return_code = os.WEXITSTATUS(worker.status)
        if return_code != 0 and (
            receipt is not None or hasattr(args, "output")
        ):
            cleanup = _cleanup_receipt(receipt)
            if receipt is None:
                cleanup = "inconclusive"
            print("cleanup={}".format(cleanup), file=sys.stderr)
        return return_code
    cleanup = _cleanup_receipt(receipt)
    if receipt is None and hasattr(args, "output"):
        cleanup = "inconclusive"
    print(
        "error=worker terminated by signal {}".format(
            os.WTERMSIG(worker.status)
        ),
        file=sys.stderr,
    )
    print("cleanup={}".format(cleanup), file=sys.stderr)
    return 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return _run_with_hard_deadline(args)


if __name__ == "__main__":
    raise SystemExit(main())
