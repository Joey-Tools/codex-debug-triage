#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import collections
import ctypes
import errno
import hashlib
import http.client
import importlib.util
import json
import math
import os
import pathlib
import re
import secrets
import selectors
import signal
import ssl
import stat
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Iterator


WORKER_ARG = "--cisco-build-artifacts-worker"
EXIT_REMOTE = 1
EXIT_USAGE = 2
EXIT_PUBLICATION = 3
EXIT_PRODUCER = 4

DEFAULT_ALLOWED_ORIGINS = frozenset({("jenkins.example.com", 443)})
ALLOWED_ORIGINS_ENV = "CISCO_BUILD_ARTIFACT_ALLOWED_HOSTS"
TEMP_ROOT = pathlib.Path("/private/tmp" if sys.platform == "darwin" else "/tmp")
TEMP_DIRECTORY_PREFIX = "cisco-build-artifacts."

DEFAULT_MAX_REDIRECTS = 5
HARD_MAX_REDIRECTS = 10
DEFAULT_CONNECT_TIMEOUT_SECONDS = 10.0
HARD_MAX_CONNECT_TIMEOUT_SECONDS = 60.0
DEFAULT_READ_TIMEOUT_SECONDS = 15.0
HARD_MAX_READ_TIMEOUT_SECONDS = 60.0
DEFAULT_TOTAL_TIMEOUT_SECONDS = 60.0
HARD_MAX_TOTAL_TIMEOUT_SECONDS = 300.0
PRODUCER_TERM_GRACE_SECONDS = 1.0
PRODUCER_KILL_GRACE_SECONDS = 2.0
DEFAULT_PROBE_SNIFF_BYTES = 4 * 1024
HARD_MAX_PROBE_SNIFF_BYTES = 64 * 1024
DEFAULT_MAX_BODY_BYTES = 256 * 1024 * 1024
HARD_MAX_BODY_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_OUTPUT_LINES = 200
HARD_MAX_OUTPUT_LINES = 200
DEFAULT_MAX_OUTPUT_CHARS = 64 * 1024
HARD_MAX_OUTPUT_CHARS = 64 * 1024
DEFAULT_MAX_INPUT_LINE_BYTES = 128 * 1024
HARD_MAX_INPUT_LINE_BYTES = 128 * 1024
DEFAULT_MAX_INPUT_LINES = 100_000
HARD_MAX_INPUT_LINES = 100_000
HARD_MAX_GREP_PATTERN_CHARS = 4 * 1024
DEFAULT_MAX_ENCODING_NAME_CHARS = 64
HARD_MAX_URL_CHARS = 8 * 1024
HARD_MAX_WORKER_REQUEST_BYTES = 32 * 1024
HARD_MAX_WORKER_STDOUT_BYTES = 256 * 1024
HARD_MAX_WORKER_STDERR_BYTES = 8 * 1024
HTTP_CHUNK_BYTES = 64 * 1024
HASH_CHUNK_BYTES = 1024 * 1024
MAX_ERROR_DETAIL_CHARS = 1024
MAX_STAGE_ATTEMPTS = 64
TRUNCATION_MARKER = "... [truncated]"
SENSITIVE_REDIRECT_HEADERS = frozenset(
    {"authorization", "proxy-authorization", "cookie"}
)
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


@dataclass(frozen=True)
class AuthProfile:
    user_env: str
    token_env: str
    allowed_origins_env: str
    default_origins: frozenset[tuple[str, int]]


AUTH_PROFILES = {
    "default": AuthProfile(
        user_env="JENKINS_ARTIFACT_USER",
        token_env="JENKINS_ARTIFACT_TOKEN",
        allowed_origins_env="CISCO_BUILD_ARTIFACT_DEFAULT_HOSTS",
        default_origins=DEFAULT_ALLOWED_ORIGINS,
    ),
}


class CommandFailure(RuntimeError):
    def __init__(
        self,
        classification: str,
        detail: str,
        *,
        exit_code: int,
        cleanup: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(detail)
        self.classification = classification
        self.detail = _safe_detail(detail)
        self.exit_code = exit_code
        self.cleanup = cleanup
        self.metadata = metadata or {}


class UsageFailure(CommandFailure):
    def __init__(self, classification: str, detail: str) -> None:
        super().__init__(
            classification,
            detail,
            exit_code=EXIT_USAGE,
        )


class ProducerFailure(CommandFailure):
    def __init__(
        self,
        classification: str,
        detail: str,
        *,
        cleanup: str,
    ) -> None:
        super().__init__(
            classification,
            detail,
            exit_code=EXIT_PRODUCER,
            cleanup=cleanup,
        )


@dataclass(frozen=True)
class ValidatedUrl:
    canonical: str
    safe: str
    scheme: str
    host: str
    port: int
    path: str
    query: str
    query_redacted: bool

    @property
    def origin(self) -> tuple[str, int]:
        return (self.host, self.port)

    @property
    def request_target(self) -> str:
        return self.path + (f"?{self.query}" if self.query else "")


@dataclass(frozen=True)
class DirectoryIdentity:
    device: int
    inode: int
    owner: int
    mode: int
    access_policy: tuple[str, int, str]


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    owner: int
    mode: int
    links: int
    size: int
    access_policy: tuple[str, int, str]


@dataclass(frozen=True)
class PublicationOutcome:
    publication: str
    durability: str
    cleanup: str
    classification: str


class _NoReplaceRenameRuntime:
    def __init__(self) -> None:
        self._libc = ctypes.CDLL(None, use_errno=True)
        if sys.platform == "darwin":
            function = self._libc.renameatx_np
            function.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            self._flag = 0x00000004  # RENAME_EXCL
        elif sys.platform.startswith("linux"):
            function = self._libc.renameat2
            function.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            self._flag = 0x00000001  # RENAME_NOREPLACE
        else:
            raise OSError(
                errno.ENOTSUP,
                "atomic no-replace rename is unsupported on this platform",
            )
        function.restype = ctypes.c_int
        self._function = function

    def rename(self, directory_fd: int, source: str, destination: str) -> None:
        ctypes.set_errno(0)
        result = self._function(
            directory_fd,
            os.fsencode(source),
            directory_fd,
            os.fsencode(destination),
            self._flag,
        )
        if result != 0:
            error_number = ctypes.get_errno() or errno.EIO
            raise OSError(error_number, "atomic no-replace rename failed")


_NO_REPLACE_RENAME_RUNTIME: _NoReplaceRenameRuntime | None = None


def _rename_noreplace(directory_fd: int, source: str, destination: str) -> None:
    global _NO_REPLACE_RENAME_RUNTIME
    if _NO_REPLACE_RENAME_RUNTIME is None:
        try:
            _NO_REPLACE_RENAME_RUNTIME = _NoReplaceRenameRuntime()
        except (AttributeError, OSError) as error:
            raise OSError(
                errno.ENOTSUP,
                "atomic no-replace rename runtime is unavailable",
            ) from error
    _NO_REPLACE_RENAME_RUNTIME.rename(directory_fd, source, destination)


def _safe_detail(value: object, limit: int = MAX_ERROR_DETAIL_CHARS) -> str:
    text = str(value)
    escaped: list[str] = []
    escaped_length = 0
    truncated = False
    for character in text:
        codepoint = ord(character)
        if character in "\t " or 0x21 <= codepoint <= 0x7E:
            piece = character
        else:
            piece = f"\\u{codepoint:04x}"
        if escaped_length + len(piece) > limit:
            truncated = True
            break
        escaped.append(piece)
        escaped_length += len(piece)
    rendered = "".join(escaped)
    if truncated:
        rendered = rendered[: max(0, limit - len(TRUNCATION_MARKER))]
        rendered += TRUNCATION_MARKER
    return rendered


def _terminal_safe(value: str) -> str:
    return _safe_detail(value, HARD_MAX_INPUT_LINE_BYTES)


def _normalize_host(host: str) -> str:
    if not host or host.endswith(".") or "%" in host:
        raise UsageFailure("url-policy-rejected", "host is not canonical")
    try:
        normalized = host.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise UsageFailure(
            "url-policy-rejected",
            "host IDNA normalization failed",
        ) from error
    if not re.fullmatch(r"[a-z0-9.-]+", normalized):
        raise UsageFailure(
            "url-policy-rejected", "host contains unsupported characters"
        )
    labels = normalized.split(".")
    if any(not label or len(label) > 63 for label in labels):
        raise UsageFailure("url-policy-rejected", "host labels are invalid")
    return normalized


def _parse_origin_entry(entry: str) -> tuple[str, int]:
    if not entry or any(character.isspace() for character in entry):
        raise UsageFailure(
            "configuration-rejected", "origin entry is empty or ambiguous"
        )
    try:
        parsed = urllib.parse.urlsplit(f"//{entry}")
        port = parsed.port or 443
    except ValueError as error:
        raise UsageFailure(
            "configuration-rejected", "origin port is invalid"
        ) from error
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or parsed.hostname is None
    ):
        raise UsageFailure("configuration-rejected", "origin entry must be host[:443]")
    host = _normalize_host(parsed.hostname)
    if port != 443:
        raise UsageFailure(
            "configuration-rejected",
            "only the default HTTPS port 443 is allowed",
        )
    return (host, port)


def _origins_from_environment(
    env_name: str,
    default: frozenset[tuple[str, int]],
) -> frozenset[tuple[str, int]]:
    raw = os.getenv(env_name)
    if raw is None:
        return default
    entries = [item.strip() for item in raw.split(",")]
    if not entries or any(not item for item in entries):
        raise UsageFailure(
            "configuration-rejected",
            f"{env_name} must be a nonempty comma-separated exact host list",
        )
    origins = frozenset(_parse_origin_entry(entry) for entry in entries)
    if not origins:
        raise UsageFailure("configuration-rejected", f"{env_name} is empty")
    return origins


def _allowed_origins() -> frozenset[tuple[str, int]]:
    return _origins_from_environment(
        ALLOWED_ORIGINS_ENV,
        DEFAULT_ALLOWED_ORIGINS,
    )


def _profile(auth_profile: str | None) -> AuthProfile | None:
    if auth_profile is None:
        return None
    try:
        return AUTH_PROFILES[auth_profile]
    except KeyError as error:
        raise UsageFailure(
            "unknown-auth-profile",
            f"unknown authentication profile: {auth_profile}",
        ) from error


def _profile_allowed_origins(auth_profile: str) -> frozenset[tuple[str, int]]:
    profile = _profile(auth_profile)
    assert profile is not None
    return _origins_from_environment(
        profile.allowed_origins_env,
        profile.default_origins,
    )


def _authorize_profile_origin(
    auth_profile: str | None,
    origin: tuple[str, int],
) -> None:
    if auth_profile is None:
        return
    if origin not in _profile_allowed_origins(auth_profile):
        raise UsageFailure(
            "auth-origin-rejected",
            "selected authentication profile does not authorize this exact origin",
        )


def _authorization_value(
    auth_profile: str | None,
    origin: tuple[str, int],
) -> tuple[str | None, str]:
    if auth_profile is None:
        return None, "absent"
    _authorize_profile_origin(auth_profile, origin)
    profile = _profile(auth_profile)
    assert profile is not None
    user = os.getenv(profile.user_env)
    token = os.getenv(profile.token_env)
    if not user or not token:
        raise UsageFailure(
            "authentication-missing",
            f"missing credentials for authentication profile {auth_profile}",
        )
    encoded = base64.b64encode(f"{user}:{token}".encode("utf-8")).decode("ascii")
    return f"Basic {encoded}", "present"


def _redact_url(raw_url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(raw_url)
    except ValueError:
        return "unavailable"
    host = parsed.hostname
    if host is None:
        return "unavailable"
    try:
        normalized_host = _normalize_host(host)
        port = parsed.port or 443
    except (UsageFailure, ValueError):
        return "unavailable"
    netloc = normalized_host if port == 443 else f"{normalized_host}:{port}"
    path = parsed.path or "/"
    query = "redacted" if parsed.query else ""
    return urllib.parse.urlunsplit(("https", netloc, path, query, ""))


def _validate_url(raw_url: str) -> ValidatedUrl:
    if not raw_url or len(raw_url) > HARD_MAX_URL_CHARS:
        raise UsageFailure("url-policy-rejected", "URL length is invalid")
    if "\\" in raw_url or any(character.isspace() for character in raw_url):
        raise UsageFailure("url-policy-rejected", "URL contains ambiguous characters")
    try:
        parsed = urllib.parse.urlsplit(raw_url)
        port = parsed.port or 443
    except ValueError as error:
        raise UsageFailure("url-policy-rejected", "URL cannot be normalized") from error
    if parsed.scheme.lower() != "https":
        raise UsageFailure("url-policy-rejected", "only HTTPS URLs are allowed")
    if parsed.username is not None or parsed.password is not None:
        raise UsageFailure(
            "url-policy-rejected", "inline URL credentials are not allowed"
        )
    if parsed.hostname is None:
        raise UsageFailure("url-policy-rejected", "URL must include a host")
    host = _normalize_host(parsed.hostname)
    if port != 443:
        raise UsageFailure(
            "url-policy-rejected",
            "only the default HTTPS port 443 is allowed",
        )
    origin = (host, port)
    if origin not in _allowed_origins():
        raise UsageFailure("url-policy-rejected", "URL origin is not allowlisted")
    path = parsed.path or "/"
    if not path.startswith("//") and not path.startswith("/"):
        path = "/" + path
    if path.startswith("//"):
        raise UsageFailure("url-policy-rejected", "URL path is authority-ambiguous")
    netloc = host
    canonical = urllib.parse.urlunsplit(("https", netloc, path, parsed.query, ""))
    safe = urllib.parse.urlunsplit(
        ("https", netloc, path, "redacted" if parsed.query else "", "")
    )
    return ValidatedUrl(
        canonical=canonical,
        safe=safe,
        scheme="https",
        host=host,
        port=port,
        path=path,
        query=parsed.query,
        query_redacted=bool(parsed.query),
    )


def _artifact_identity(url: ValidatedUrl) -> str:
    stable = urllib.parse.urlunsplit((url.scheme, url.host, url.path, "", ""))
    return "url-path-sha256:" + hashlib.sha256(stable.encode("utf-8")).hexdigest()


def _positive_bounded_int(option: str, hard_max: int):
    def parse(raw: str) -> int:
        try:
            value = int(raw)
        except ValueError as error:
            raise argparse.ArgumentTypeError(f"{option} must be an integer") from error
        if value <= 0 or value > hard_max:
            raise argparse.ArgumentTypeError(
                f"{option} must be between 1 and {hard_max}"
            )
        return value

    return parse


def _positive_bounded_float(option: str, hard_max: float):
    def parse(raw: str) -> float:
        try:
            value = float(raw)
        except ValueError as error:
            raise argparse.ArgumentTypeError(f"{option} must be a number") from error
        if not math.isfinite(value) or value <= 0 or value > hard_max:
            raise argparse.ArgumentTypeError(
                f"{option} must be greater than 0 and at most {hard_max}"
            )
        return value

    return parse


def _grep_pattern(raw: str) -> str:
    if not raw or len(raw) > HARD_MAX_GREP_PATTERN_CHARS:
        raise argparse.ArgumentTypeError(
            "--grep must be nonempty and at most "
            f"{HARD_MAX_GREP_PATTERN_CHARS} characters"
        )
    try:
        re.compile(raw)
    except re.error as error:
        raise argparse.ArgumentTypeError(
            "--grep must be a valid regular expression"
        ) from error
    return raw


def _nonnegative_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as error:
        raise argparse.ArgumentTypeError("value must be an integer") from error
    if value < 0:
        raise argparse.ArgumentTypeError("value must be nonnegative")
    return value


def _encoding_name(raw: str) -> str:
    if (
        not raw
        or len(raw) > DEFAULT_MAX_ENCODING_NAME_CHARS
        or re.fullmatch(r"[A-Za-z0-9._+-]+", raw) is None
    ):
        raise argparse.ArgumentTypeError("encoding name is invalid")
    try:
        "".encode(raw)
    except LookupError as error:
        raise argparse.ArgumentTypeError("encoding is unavailable") from error
    return raw


def _remaining(deadline: float, stage: str) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ProducerFailure(
            "producer-timeout",
            f"hard wall deadline expired during {stage}",
            cleanup="not-started",
        )
    return remaining


def _header_values(headers: Any, name: str) -> list[str]:
    if hasattr(headers, "get_all"):
        values = headers.get_all(name)
        return list(values or [])
    value = headers.get(name)
    if value is None:
        return []
    return [str(value)]


def _content_length(headers: Any) -> int | None:
    values = [value.strip() for value in _header_values(headers, "Content-Length")]
    if not values:
        return None
    expanded: list[str] = []
    for value in values:
        expanded.extend(part.strip() for part in value.split(","))
    if not expanded or any(not item.isdigit() for item in expanded):
        raise CommandFailure(
            "remote-protocol-error",
            "Content-Length is malformed",
            exit_code=EXIT_REMOTE,
        )
    lengths = {int(item) for item in expanded}
    if len(lengths) != 1:
        raise CommandFailure(
            "remote-protocol-error",
            "conflicting Content-Length values",
            exit_code=EXIT_REMOTE,
        )
    return lengths.pop()


def _validate_content_encoding(headers: Any) -> None:
    values = [
        item.strip().lower()
        for value in _header_values(headers, "Content-Encoding")
        for item in value.split(",")
        if item.strip()
    ]
    if any(value != "identity" for value in values):
        raise CommandFailure(
            "content-encoding-rejected",
            "only identity HTTP content encoding is supported",
            exit_code=EXIT_REMOTE,
        )


def _make_https_connection(
    host: str,
    port: int,
    timeout: float,
    context: ssl.SSLContext,
) -> http.client.HTTPSConnection:
    return http.client.HTTPSConnection(
        host,
        port=port,
        timeout=timeout,
        context=context,
    )


def _open_final_response(
    raw_url: str,
    *,
    method: str,
    auth_profile: str | None,
    max_redirects: int,
    connect_timeout: float,
    read_timeout: float,
    deadline: float,
) -> tuple[Any, Any, ValidatedUrl, int, str]:
    current = _validate_url(raw_url)
    _authorize_profile_origin(auth_profile, current.origin)
    visited = {current.canonical}
    context = ssl.create_default_context()
    redirects = 0
    while True:
        remaining = _remaining(deadline, "connection setup")
        authorization, auth_state = _authorization_value(auth_profile, current.origin)
        headers = {
            "Accept-Encoding": "identity",
            "Connection": "close",
            "User-Agent": "codex-cisco-build-artifacts/1",
        }
        if authorization is not None:
            headers["Authorization"] = authorization
        if any(
            name.lower() in SENSITIVE_REDIRECT_HEADERS
            for name in headers
            if name != "Authorization"
        ):
            raise AssertionError("sensitive headers must be rebuilt, not forwarded")
        connection = _make_https_connection(
            current.host,
            current.port,
            min(connect_timeout, remaining),
            context,
        )
        try:
            connection.request(method, current.request_target, headers=headers)
            socket_before_headers = getattr(connection, "sock", None)
            if socket_before_headers is None:
                raise OSError(errno.ENOTCONN, "HTTPS response socket is unavailable")
            # http.client may clear connection.sock for Connection: close after
            # getresponse(). Bind the body-read timeout before that transition;
            # the parent supervisor independently enforces the hard wall clock.
            socket_before_headers.settimeout(
                min(read_timeout, _remaining(deadline, "response headers"))
            )
            response = connection.getresponse()
        except (OSError, http.client.HTTPException, ssl.SSLError) as error:
            connection.close()
            raise CommandFailure(
                "remote-transport-error",
                f"HTTPS request failed: {type(error).__name__}",
                exit_code=EXIT_REMOTE,
                metadata={
                    "auth": auth_state,
                    "query_redacted": current.query_redacted,
                    "source_url": current.safe,
                },
            ) from error
        if response.status not in REDIRECT_STATUSES:
            return response, connection, current, redirects, auth_state
        location = response.getheader("Location")
        response.close()
        connection.close()
        if not location:
            raise CommandFailure(
                "redirect-rejected",
                "redirect response omitted Location",
                exit_code=EXIT_REMOTE,
            )
        if redirects >= max_redirects:
            raise CommandFailure(
                "redirect-limit-exceeded",
                "redirect count exceeds the configured hard bound",
                exit_code=EXIT_REMOTE,
            )
        if (
            len(location) > HARD_MAX_URL_CHARS
            or "\\" in location
            or any(character.isspace() for character in location)
        ):
            raise CommandFailure(
                "redirect-rejected",
                "redirect Location is ambiguous",
                exit_code=EXIT_REMOTE,
            )
        candidate = urllib.parse.urljoin(current.canonical, location)
        target = _validate_url(candidate)
        _authorize_profile_origin(auth_profile, target.origin)
        if target.canonical in visited:
            raise CommandFailure(
                "redirect-loop",
                "redirect loop detected",
                exit_code=EXIT_REMOTE,
            )
        visited.add(target.canonical)
        current = target
        redirects += 1


def _response_chunks(
    response: Any,
    *,
    max_bytes: int,
    deadline: float,
) -> Iterator[bytes]:
    consumed = 0
    while True:
        _remaining(deadline, "response read")
        request_size = min(HTTP_CHUNK_BYTES, max_bytes - consumed + 1)
        try:
            chunk = response.read(request_size)
        except (OSError, http.client.HTTPException, ssl.SSLError) as error:
            raise CommandFailure(
                "remote-read-error",
                f"response read failed: {type(error).__name__}",
                exit_code=EXIT_REMOTE,
            ) from error
        if not chunk:
            return
        consumed += len(chunk)
        if consumed > max_bytes:
            accepted = len(chunk) - (consumed - max_bytes)
            if accepted > 0:
                yield chunk[:accepted]
            raise CommandFailure(
                "body-limit-exceeded",
                "response body exceeds the configured byte cap",
                exit_code=EXIT_REMOTE,
                metadata={"consumed_bytes": max_bytes},
            )
        yield chunk


class OutputBudget:
    def __init__(self, max_lines: int, max_chars: int) -> None:
        self.max_lines = max_lines
        self.max_chars = max_chars
        self.lines: list[tuple[int, str]] = []
        self.characters = 0
        self.truncated = False

    def add(self, line_number: int, line: str) -> bool:
        if len(self.lines) >= self.max_lines:
            self.truncated = True
            return False
        remaining = self.max_chars - self.characters
        separator = 1 if self.lines else 0
        if remaining <= separator:
            self.truncated = True
            return False
        safe = _terminal_safe(line)
        allowed = remaining - separator
        if len(safe) > allowed:
            marker = TRUNCATION_MARKER
            if allowed <= len(marker):
                safe = marker[:allowed]
            else:
                safe = safe[: allowed - len(marker)] + marker
            self.truncated = True
        self.lines.append((line_number, safe))
        self.characters += separator + len(safe)
        return not self.truncated


class TextSelector:
    def __init__(
        self,
        *,
        mode: str,
        count: int,
        grep: str | None,
        ignore_case: bool,
        context: int,
        encoding: str,
        max_input_line_bytes: int,
        max_input_lines: int,
        max_output_lines: int,
        max_output_chars: int,
    ) -> None:
        self.mode = mode
        self.count = count
        self.context = context
        self.encoding = encoding
        self.max_input_line_bytes = max_input_line_bytes
        self.max_input_lines = max_input_lines
        self.output = OutputBudget(max_output_lines, max_output_chars)
        self.pattern = (
            re.compile(grep, re.IGNORECASE if ignore_case else 0) if grep else None
        )
        self.buffer = bytearray()
        self.discarding = False
        self.input_lines = 0
        self.input_bytes = 0
        self.stop_requested = False
        self.input_truncated = False
        self.tail: collections.deque[tuple[int, str]] = collections.deque()
        self.tail_chars = 0
        self.previous: collections.deque[tuple[int, str]] = collections.deque()
        self.previous_chars = 0
        self.trailing = 0
        self.last_emitted = 0

    def _bounded_line(self, raw: bytes, truncated: bool) -> str:
        text = raw.rstrip(b"\r").decode(self.encoding, errors="replace")
        if truncated:
            text += TRUNCATION_MARKER
            self.input_truncated = True
        return text

    def _append_tail(self, item: tuple[int, str]) -> None:
        limit = max(1, self.count)
        safe = _terminal_safe(item[1])
        if len(safe) > self.output.max_chars:
            if self.output.max_chars <= len(TRUNCATION_MARKER):
                safe = TRUNCATION_MARKER[: self.output.max_chars]
            else:
                safe = (
                    safe[: self.output.max_chars - len(TRUNCATION_MARKER)]
                    + TRUNCATION_MARKER
                )
            self.input_truncated = True
        item = (item[0], safe)
        self.tail.append(item)
        self.tail_chars += len(safe)
        while len(self.tail) > limit or self.tail_chars > self.output.max_chars:
            removed = self.tail.popleft()
            self.tail_chars -= len(removed[1])

    def _append_previous(self, item: tuple[int, str]) -> None:
        if self.context <= 0:
            return
        safe = _terminal_safe(item[1])
        if len(safe) > self.output.max_chars:
            if self.output.max_chars <= len(TRUNCATION_MARKER):
                safe = TRUNCATION_MARKER[: self.output.max_chars]
            else:
                safe = (
                    safe[: self.output.max_chars - len(TRUNCATION_MARKER)]
                    + TRUNCATION_MARKER
                )
            self.input_truncated = True
        item = (item[0], safe)
        self.previous.append(item)
        self.previous_chars += len(safe)
        while (
            len(self.previous) > self.context
            or self.previous_chars > self.output.max_chars
        ):
            removed = self.previous.popleft()
            self.previous_chars -= len(removed[1])

    def _emit(self, item: tuple[int, str]) -> None:
        if item[0] <= self.last_emitted:
            return
        if not self.output.add(item[0], item[1]):
            self.stop_requested = True
        self.last_emitted = item[0]

    def _accept_line(self, raw: bytes, *, truncated: bool = False) -> None:
        self.input_lines += 1
        if self.input_lines > self.max_input_lines:
            self.input_truncated = True
            self.stop_requested = True
            return
        item = (self.input_lines, self._bounded_line(raw, truncated))
        if self.mode == "tail":
            self._append_tail(item)
            return
        if self.mode == "grep":
            assert self.pattern is not None
            if self.pattern.search(item[1]):
                for previous in self.previous:
                    self._emit(previous)
                self._emit(item)
                self.trailing = self.context
            elif self.trailing:
                self._emit(item)
                self.trailing -= 1
            self._append_previous(item)
            return
        self._emit(item)
        desired = self.count if self.mode == "head" else self.output.max_lines
        if len(self.output.lines) >= desired:
            self.stop_requested = True

    def feed(self, chunk: bytes) -> None:
        if self.stop_requested:
            return
        self.input_bytes += len(chunk)
        cursor = 0
        while cursor < len(chunk) and not self.stop_requested:
            if self.discarding:
                newline = chunk.find(b"\n", cursor)
                if newline < 0:
                    return
                self.discarding = False
                cursor = newline + 1
                continue
            newline = chunk.find(b"\n", cursor)
            if newline < 0:
                self.buffer.extend(chunk[cursor:])
                if len(self.buffer) > self.max_input_line_bytes:
                    accepted = bytes(self.buffer[: self.max_input_line_bytes])
                    self.buffer.clear()
                    self._accept_line(accepted, truncated=True)
                    self.discarding = True
                return
            self.buffer.extend(chunk[cursor:newline])
            raw = bytes(self.buffer)
            self.buffer.clear()
            if len(raw) > self.max_input_line_bytes:
                raw = raw[: self.max_input_line_bytes]
                self._accept_line(raw, truncated=True)
            else:
                self._accept_line(raw)
            cursor = newline + 1

    def finish(self) -> None:
        if self.buffer and not self.stop_requested and not self.discarding:
            raw = bytes(self.buffer)
            self.buffer.clear()
            if len(raw) > self.max_input_line_bytes:
                self._accept_line(raw[: self.max_input_line_bytes], truncated=True)
            else:
                self._accept_line(raw)
        if self.mode == "tail":
            for item in self.tail:
                self._emit(item)


def _base_result(
    initial: ValidatedUrl,
    final: ValidatedUrl,
    *,
    status: int,
    auth_profile: str | None,
    auth_state: str,
    redirects: int,
) -> dict[str, Any]:
    return {
        "ok": True,
        "source_url": initial.safe,
        "final_url": final.safe,
        "query_redacted": initial.query_redacted or final.query_redacted,
        "artifact_identity": _artifact_identity(final),
        "status": status,
        "auth_profile": auth_profile or "none",
        "auth": auth_state,
        "redirects": redirects,
    }


def _classify_http_status(
    status: int,
    *,
    initial: ValidatedUrl,
    final: ValidatedUrl,
    auth_profile: str | None,
    auth_state: str,
) -> None:
    if 200 <= status < 300:
        return
    if status in (401, 403):
        classification = "remote-authentication-failed"
    else:
        classification = "remote-http-error"
    raise CommandFailure(
        classification,
        f"remote HTTP status {status}",
        exit_code=EXIT_REMOTE,
        metadata={
            "auth": auth_state,
            "auth_profile": auth_profile or "none",
            "final_url": final.safe,
            "query_redacted": initial.query_redacted or final.query_redacted,
            "source_url": initial.safe,
            "status": status,
        },
    )


def _worker_probe(payload: dict[str, Any], deadline: float) -> dict[str, Any]:
    initial = _validate_url(payload["url"])
    response, connection, final, redirects, auth_state = _open_final_response(
        payload["url"],
        method=payload["method"],
        auth_profile=payload["auth_profile"],
        max_redirects=payload["max_redirects"],
        connect_timeout=payload["connect_timeout"],
        read_timeout=payload["read_timeout"],
        deadline=deadline,
    )
    try:
        _classify_http_status(
            response.status,
            initial=initial,
            final=final,
            auth_profile=payload["auth_profile"],
            auth_state=auth_state,
        )
        _validate_content_encoding(response.headers)
        declared = _content_length(response.headers)
        body = bytearray()
        truncated = False
        if payload["method"] == "GET":
            cap = min(payload["sniff_bytes"], payload["max_body_bytes"])
            try:
                for chunk in _response_chunks(
                    response,
                    max_bytes=cap,
                    deadline=deadline,
                ):
                    body.extend(chunk)
            except CommandFailure as error:
                if error.classification != "body-limit-exceeded":
                    raise
                truncated = True
        result = _base_result(
            initial,
            final,
            status=response.status,
            auth_profile=payload["auth_profile"],
            auth_state=auth_state,
            redirects=redirects,
        )
        result.update(
            {
                "content_type": response.getheader("Content-Type") or "",
                "content_length": declared,
                "wire_bytes": len(body),
                "entity_bytes": len(body),
                "representation": "identity-http-entity",
                "truncated": truncated
                or (declared is not None and declared > len(body)),
                "preview": body.decode(payload["encoding"], errors="replace"),
            }
        )
        return result
    finally:
        response.close()
        connection.close()


def _worker_show(payload: dict[str, Any], deadline: float) -> dict[str, Any]:
    initial = _validate_url(payload["url"])
    response, connection, final, redirects, auth_state = _open_final_response(
        payload["url"],
        method="GET",
        auth_profile=payload["auth_profile"],
        max_redirects=payload["max_redirects"],
        connect_timeout=payload["connect_timeout"],
        read_timeout=payload["read_timeout"],
        deadline=deadline,
    )
    selector = TextSelector(
        mode=payload["selection_mode"],
        count=payload["selection_count"],
        grep=payload["grep"],
        ignore_case=payload["ignore_case"],
        context=payload["context"],
        encoding=payload["encoding"],
        max_input_line_bytes=payload["max_input_line_bytes"],
        max_input_lines=payload["max_input_lines"],
        max_output_lines=payload["max_output_lines"],
        max_output_chars=payload["max_output_chars"],
    )
    consumed = 0
    body_truncated = False
    try:
        _classify_http_status(
            response.status,
            initial=initial,
            final=final,
            auth_profile=payload["auth_profile"],
            auth_state=auth_state,
        )
        _validate_content_encoding(response.headers)
        declared = _content_length(response.headers)
        try:
            for chunk in _response_chunks(
                response,
                max_bytes=payload["max_body_bytes"],
                deadline=deadline,
            ):
                consumed += len(chunk)
                selector.feed(chunk)
                if selector.stop_requested:
                    body_truncated = True
                    break
        except CommandFailure as error:
            if error.classification != "body-limit-exceeded":
                raise
            body_truncated = True
        selector.finish()
        result = _base_result(
            initial,
            final,
            status=response.status,
            auth_profile=payload["auth_profile"],
            auth_state=auth_state,
            redirects=redirects,
        )
        result.update(
            {
                "content_type": response.getheader("Content-Type") or "",
                "content_length": declared,
                "wire_bytes": consumed,
                "entity_bytes": consumed,
                "representation": "identity-http-entity",
                "input_lines": selector.input_lines,
                "output_lines": len(selector.output.lines),
                "output_chars": selector.output.characters,
                "truncated": body_truncated
                or selector.input_truncated
                or selector.output.truncated
                or (declared is not None and declared > consumed),
                "lines": selector.output.lines,
            }
        )
        return result
    finally:
        response.close()
        connection.close()


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError(errno.EIO, "short write")
        view = view[written:]


def _worker_fetch(payload: dict[str, Any], deadline: float) -> dict[str, Any]:
    initial = _validate_url(payload["url"])
    stage_fd = int(payload["stage_fd"])
    stage_stat = os.fstat(stage_fd)
    if (
        not stat.S_ISREG(stage_stat.st_mode)
        or stage_stat.st_uid != os.geteuid()
        or stat.S_IMODE(stage_stat.st_mode) != 0o600
        or stage_stat.st_nlink != 1
        or stage_stat.st_size != 0
    ):
        raise CommandFailure(
            "staging-policy-mismatch",
            "inherited staging descriptor failed policy validation",
            exit_code=EXIT_PUBLICATION,
        )
    response, connection, final, redirects, auth_state = _open_final_response(
        payload["url"],
        method="GET",
        auth_profile=payload["auth_profile"],
        max_redirects=payload["max_redirects"],
        connect_timeout=payload["connect_timeout"],
        read_timeout=payload["read_timeout"],
        deadline=deadline,
    )
    digest = hashlib.sha256()
    consumed = 0
    try:
        _classify_http_status(
            response.status,
            initial=initial,
            final=final,
            auth_profile=payload["auth_profile"],
            auth_state=auth_state,
        )
        _validate_content_encoding(response.headers)
        declared = _content_length(response.headers)
        if declared is not None and declared > payload["max_body_bytes"]:
            raise CommandFailure(
                "body-limit-exceeded",
                "declared response body exceeds the configured byte cap",
                exit_code=EXIT_REMOTE,
            )
        for chunk in _response_chunks(
            response,
            max_bytes=payload["max_body_bytes"],
            deadline=deadline,
        ):
            _write_all(stage_fd, chunk)
            digest.update(chunk)
            consumed += len(chunk)
        if declared is not None and consumed != declared:
            raise CommandFailure(
                "remote-read-error",
                "response body length did not match declared Content-Length",
                exit_code=EXIT_REMOTE,
                metadata={
                    "consumed_bytes": consumed,
                    "declared_bytes": declared,
                },
            )
        result = _base_result(
            initial,
            final,
            status=response.status,
            auth_profile=payload["auth_profile"],
            auth_state=auth_state,
            redirects=redirects,
        )
        result.update(
            {
                "content_type": response.getheader("Content-Type") or "",
                "content_length": declared,
                "wire_bytes": consumed,
                "entity_bytes": consumed,
                "persisted_bytes": consumed,
                "representation": "identity-http-entity",
                "sha256": digest.hexdigest(),
                "truncated": False,
            }
        )
        return result
    finally:
        response.close()
        connection.close()


def _worker_error(error: BaseException) -> dict[str, Any]:
    if isinstance(error, CommandFailure):
        return {
            "ok": False,
            "classification": error.classification,
            "detail": error.detail,
            "exit_code": error.exit_code,
            "metadata": error.metadata,
        }
    return {
        "ok": False,
        "classification": "worker-internal-error",
        "detail": type(error).__name__,
        "exit_code": EXIT_PRODUCER,
        "metadata": {},
    }


def _worker_main() -> int:
    raw = sys.stdin.buffer.read(HARD_MAX_WORKER_REQUEST_BYTES + 1)
    if len(raw) > HARD_MAX_WORKER_REQUEST_BYTES:
        result = _worker_error(
            ProducerFailure(
                "worker-request-overflow",
                "worker request exceeds its hard byte cap",
                cleanup="self",
            )
        )
    else:
        try:
            payload = json.loads(raw.decode("utf-8"))
            deadline = time.monotonic() + float(payload["worker_timeout"])
            command = payload["command"]
            if command == "probe-url":
                result = _worker_probe(payload, deadline)
            elif command == "show-url":
                result = _worker_show(payload, deadline)
            elif command == "fetch-url":
                result = _worker_fetch(payload, deadline)
            else:
                raise UsageFailure("worker-request-rejected", "unknown worker command")
        except BaseException as error:
            result = _worker_error(error)
    encoded = json.dumps(
        result,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > HARD_MAX_WORKER_STDOUT_BYTES:
        encoded = json.dumps(
            _worker_error(
                ProducerFailure(
                    "worker-output-overflow",
                    "worker result exceeds its hard byte cap",
                    cleanup="self",
                )
            ),
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()
    return 0


def _worker_environment(
    auth_profile: str | None,
    initial_origin: tuple[str, int],
) -> dict[str, str]:
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    if os.getenv(ALLOWED_ORIGINS_ENV) is not None:
        environment[ALLOWED_ORIGINS_ENV] = os.environ[ALLOWED_ORIGINS_ENV]
    if auth_profile is None:
        return environment
    _authorize_profile_origin(auth_profile, initial_origin)
    profile = _profile(auth_profile)
    assert profile is not None
    user = os.getenv(profile.user_env)
    token = os.getenv(profile.token_env)
    if not user or not token:
        raise UsageFailure(
            "authentication-missing",
            f"missing credentials for authentication profile {auth_profile}",
        )
    environment[profile.user_env] = user
    environment[profile.token_env] = token
    if os.getenv(profile.allowed_origins_env) is not None:
        environment[profile.allowed_origins_env] = os.environ[
            profile.allowed_origins_env
        ]
    return environment


def _terminate_producer(
    process: subprocess.Popen[bytes],
) -> str:
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError:
        return "unverified"
    try:
        process.wait(timeout=PRODUCER_TERM_GRACE_SECONDS)
        return "term-reaped"
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        return "unverified"
    try:
        process.wait(timeout=PRODUCER_KILL_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        return "unverified"
    return "kill-reaped"


def _bounded_worker_exchange(
    process: subprocess.Popen[bytes],
    request: bytes,
    *,
    deadline: float,
    stdout_cap: int = HARD_MAX_WORKER_STDOUT_BYTES,
    stderr_cap: int = HARD_MAX_WORKER_STDERR_BYTES,
) -> tuple[bytes, bytes]:
    if process.stdin is None or process.stdout is None or process.stderr is None:
        cleanup = _terminate_producer(process)
        raise ProducerFailure(
            "producer-pipe-unavailable",
            "producer did not expose all supervised pipes",
            cleanup=cleanup,
        )

    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    request_offset = 0

    def close_stream(stream: Any) -> None:
        try:
            selector.unregister(stream)
        except (KeyError, ValueError):
            pass
        try:
            stream.close()
        except OSError:
            pass

    def fail(classification: str, detail: str) -> None:
        cleanup = _terminate_producer(process)
        raise ProducerFailure(classification, detail, cleanup=cleanup)

    try:
        try:
            for stream in (process.stdin, process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        except OSError as error:
            fail(
                "producer-supervision-failed",
                f"producer pipe setup failed: {type(error).__name__}",
            )

        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                fail(
                    "producer-timeout",
                    "hard wall deadline terminated the network producer",
                )
            try:
                events = selector.select(remaining)
            except OSError as error:
                fail(
                    "producer-supervision-failed",
                    f"producer pipe wait failed: {type(error).__name__}",
                )
            if not events:
                fail(
                    "producer-timeout",
                    "hard wall deadline terminated the network producer",
                )
            for key, _ in events:
                stream = key.fileobj
                label = key.data
                if label == "stdin":
                    if request_offset >= len(request):
                        close_stream(stream)
                        continue
                    try:
                        written = os.write(
                            stream.fileno(),
                            request[request_offset : request_offset + HTTP_CHUNK_BYTES],
                        )
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        close_stream(stream)
                        continue
                    except OSError as error:
                        fail(
                            "producer-supervision-failed",
                            f"producer request write failed: {type(error).__name__}",
                        )
                    if written <= 0:
                        fail(
                            "producer-supervision-failed",
                            "producer request write made no progress",
                        )
                    request_offset += written
                    if request_offset >= len(request):
                        close_stream(stream)
                    continue

                buffer = buffers[label]
                cap = stdout_cap if label == "stdout" else stderr_cap
                read_size = min(HTTP_CHUNK_BYTES, max(1, cap - len(buffer) + 1))
                try:
                    chunk = os.read(stream.fileno(), read_size)
                except BlockingIOError:
                    continue
                except OSError as error:
                    fail(
                        "producer-supervision-failed",
                        f"producer {label} read failed: {type(error).__name__}",
                    )
                if not chunk:
                    close_stream(stream)
                    continue
                if len(buffer) + len(chunk) > cap:
                    classification = (
                        "producer-output-overflow"
                        if label == "stdout"
                        else "producer-error-overflow"
                    )
                    fail(
                        classification,
                        f"producer {label} exceeds its hard retained-byte cap",
                    )
                buffer.extend(chunk)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail(
                "producer-timeout",
                "hard wall deadline terminated the network producer",
            )
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            fail(
                "producer-timeout",
                "hard wall deadline terminated the network producer",
            )
        return bytes(buffers["stdout"]), bytes(buffers["stderr"])
    except ProducerFailure:
        raise
    except BaseException:
        _terminate_producer(process)
        raise
    finally:
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                try:
                    stream.close()
                except OSError:
                    pass


def _run_worker(
    payload: dict[str, Any],
    *,
    deadline: float,
    pass_fds: tuple[int, ...] = (),
) -> dict[str, Any]:
    if os.name != "posix":
        raise ProducerFailure(
            "producer-supervision-unavailable",
            "hard process-group supervision requires POSIX",
            cleanup="not-started",
        )
    initial = _validate_url(payload["url"])
    environment = _worker_environment(payload["auth_profile"], initial.origin)
    remaining = _remaining(deadline, "producer launch")
    payload = dict(payload)
    payload["worker_timeout"] = remaining
    request = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(request) > HARD_MAX_WORKER_REQUEST_BYTES:
        raise ProducerFailure(
            "worker-request-overflow",
            "worker request exceeds its hard byte cap",
            cleanup="not-started",
        )
    command = [
        sys.executable,
        "-I",
        "-B",
        "-S",
        str(pathlib.Path(__file__).resolve()),
        WORKER_ARG,
    ]
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            close_fds=True,
            pass_fds=pass_fds,
            start_new_session=True,
        )
    except OSError as error:
        raise ProducerFailure(
            "producer-launch-failed",
            f"producer launch failed: {type(error).__name__}",
            cleanup="not-started",
        ) from error
    stdout, stderr = _bounded_worker_exchange(
        process,
        request,
        deadline=deadline,
    )
    if process.returncode != 0:
        raise ProducerFailure(
            "producer-failed",
            f"producer exited with status {process.returncode}",
            cleanup="reaped",
        )
    try:
        result = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProducerFailure(
            "producer-protocol-error",
            "producer returned malformed bounded JSON",
            cleanup="reaped",
        ) from error
    if not isinstance(result, dict) or not isinstance(result.get("ok"), bool):
        raise ProducerFailure(
            "producer-protocol-error",
            "producer result shape is invalid",
            cleanup="reaped",
        )
    if not result["ok"]:
        raise CommandFailure(
            str(result.get("classification", "producer-failed")),
            str(result.get("detail", "producer rejected the request")),
            exit_code=int(result.get("exit_code", EXIT_PRODUCER)),
            cleanup="reaped",
            metadata=(
                result.get("metadata")
                if isinstance(result.get("metadata"), dict)
                else {}
            ),
        )
    return result


_ARCHIVE_POLICY_MODULE: Any | None = None


def _archive_policy_module() -> Any:
    global _ARCHIVE_POLICY_MODULE
    if _ARCHIVE_POLICY_MODULE is not None:
        return _ARCHIVE_POLICY_MODULE
    module_path = pathlib.Path(__file__).resolve().with_name("archive_triage.py")
    spec = importlib.util.spec_from_file_location(
        "_cisco_build_artifacts_archive_policy",
        module_path,
    )
    if spec is None or spec.loader is None:
        raise OSError(errno.ENOTSUP, "archive access-policy runtime is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(spec.name, None)
        raise
    _ARCHIVE_POLICY_MODULE = module
    return module


def _access_policy_binding(fd: int) -> tuple[str, int, str]:
    module = _archive_policy_module()
    return module._stable_snapshot_access_policy_binding(fd)


def _directory_identity(fd: int) -> DirectoryIdentity:
    metadata = os.fstat(fd)
    return DirectoryIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
        access_policy=_access_policy_binding(fd),
    )


def _file_identity(fd: int) -> FileIdentity:
    metadata = os.fstat(fd)
    return FileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
        links=metadata.st_nlink,
        size=metadata.st_size,
        access_policy=_access_policy_binding(fd),
    )


def _validate_directory_policy(
    fd: int,
    metadata: os.stat_result,
    *,
    allow_sticky_root: bool = False,
    require_private_owner: bool = False,
) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise UsageFailure(
            "output-policy-rejected", "output path component is not a directory"
        )
    effective_uid = os.geteuid()
    if require_private_owner:
        if metadata.st_uid != effective_uid or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise UsageFailure(
                "output-policy-rejected",
                "task-scoped temporary directory must be owner-private mode 0700",
            )
        _access_policy_binding(fd)
        return
    if metadata.st_uid not in (0, effective_uid):
        raise UsageFailure(
            "output-policy-rejected",
            "output path component has an untrusted owner",
        )
    writable = stat.S_IMODE(metadata.st_mode) & 0o022
    # On Linux, the POSIX ACL mask is reflected in the group mode bits. The
    # raw ACL digest is bound separately, so a named-entry change cannot hide
    # behind an unchanged effective mask. Darwin ACL grants are rejected by
    # the descriptor policy runtime itself.
    if writable:
        sticky_root = (
            allow_sticky_root
            and metadata.st_uid == 0
            and bool(metadata.st_mode & stat.S_ISVTX)
        )
        if not sticky_root:
            raise UsageFailure(
                "output-policy-rejected",
                "output path component is writable by an untrusted principal",
            )
    _access_policy_binding(fd)


def _open_absolute_directory(path: pathlib.Path) -> int:
    if not path.is_absolute():
        raise UsageFailure("output-policy-rejected", "directory path is not absolute")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open("/", flags)
    current = pathlib.Path("/")
    try:
        _validate_directory_policy(descriptor, os.fstat(descriptor))
        for component in path.parts[1:]:
            next_descriptor = os.open(
                component,
                flags | nofollow,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
            current = current / component
            allow_sticky = current == TEMP_ROOT
            _validate_directory_policy(
                descriptor,
                os.fstat(descriptor),
                allow_sticky_root=allow_sticky,
            )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _walk_relative_directory(
    root_fd: int,
    relative: pathlib.Path,
) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.dup(root_fd)
    try:
        for component in relative.parts:
            if component in ("", "."):
                continue
            if component == "..":
                raise UsageFailure(
                    "output-policy-rejected", "parent traversal is not allowed"
                )
            next_descriptor = os.open(
                component,
                flags | nofollow,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
            _validate_directory_policy(descriptor, os.fstat(descriptor))
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _path_is_within(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _lexical_output_path(raw: str) -> pathlib.Path:
    if not raw:
        raise UsageFailure("output-policy-rejected", "output path is empty")
    candidate = pathlib.Path(raw)
    if not candidate.is_absolute():
        candidate = pathlib.Path.cwd() / candidate
    normalized = pathlib.Path(os.path.abspath(os.path.normpath(str(candidate))))
    if sys.platform == "darwin" and str(normalized).startswith("/tmp/"):
        normalized = pathlib.Path("/private") / normalized.relative_to("/")
    if normalized.name in ("", ".", ".."):
        raise UsageFailure("output-policy-rejected", "output filename is invalid")
    return normalized


class OutputTransaction:
    def __init__(self, output: str) -> None:
        self.anchor_fd = -1
        self.parent_fd = -1
        self.stage_name: str | None = None
        self.stage_fd: int | None = None
        self.stage_initial_identity: FileIdentity | None = None
        self.published = False
        self.output = _lexical_output_path(output)
        self.anchor_path: pathlib.Path
        self.relative_parent: pathlib.Path
        workspace = pathlib.Path.cwd()
        if _path_is_within(self.output, workspace):
            self.anchor_path = workspace
            self.relative_parent = self.output.parent.relative_to(workspace)
        elif _path_is_within(self.output, TEMP_ROOT):
            relative = self.output.relative_to(TEMP_ROOT)
            if len(relative.parts) < 2 or not relative.parts[0].startswith(
                TEMP_DIRECTORY_PREFIX
            ):
                raise UsageFailure(
                    "output-policy-rejected",
                    "temporary output must be inside an owner-private task directory",
                )
            self.anchor_path = TEMP_ROOT / relative.parts[0]
            self.relative_parent = pathlib.Path(*relative.parts[1:-1])
        else:
            raise UsageFailure(
                "output-policy-rejected",
                "output must stay under the current workspace or fixed task temp root",
            )
        try:
            self.anchor_fd = _open_absolute_directory(self.anchor_path)
            if self.anchor_path.parent == TEMP_ROOT:
                _validate_directory_policy(
                    self.anchor_fd,
                    os.fstat(self.anchor_fd),
                    require_private_owner=True,
                )
            self.anchor_identity = _directory_identity(self.anchor_fd)
            self.parent_fd = _walk_relative_directory(
                self.anchor_fd,
                self.relative_parent,
            )
            self.parent_identity = _directory_identity(self.parent_fd)
            self.destination_name = self.output.name
            self._require_destination_absent()
            self._create_stage()
        except BaseException as error:
            cleanup = self.abort()
            self.close()
            if isinstance(error, CommandFailure):
                if error.cleanup is None and cleanup != "complete":
                    error.cleanup = cleanup
                raise
            if not isinstance(error, Exception):
                raise
            if isinstance(error, FileNotFoundError):
                classification = "output-parent-missing"
                detail = "validated output parent is missing"
                exit_code = EXIT_USAGE
            elif isinstance(error, PermissionError):
                classification = "output-policy-unreadable"
                detail = "output access policy could not be read"
                exit_code = EXIT_USAGE
            else:
                classification = "output-policy-unverified"
                detail = (
                    f"output access policy validation failed: {type(error).__name__}"
                )
                exit_code = EXIT_PUBLICATION
            raise CommandFailure(
                classification,
                detail,
                exit_code=exit_code,
                cleanup=cleanup,
            ) from error

    def _require_destination_absent(self) -> None:
        try:
            metadata = os.stat(
                self.destination_name,
                dir_fd=self.parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        except PermissionError as error:
            raise CommandFailure(
                "destination-revalidation-unreadable",
                "destination absence could not be verified",
                exit_code=EXIT_PUBLICATION,
            ) from error
        except OSError as error:
            raise CommandFailure(
                "destination-revalidation-failed",
                f"destination absence check failed: {type(error).__name__}",
                exit_code=EXIT_PUBLICATION,
            ) from error
        kind = "symlink" if stat.S_ISLNK(metadata.st_mode) else "object"
        raise UsageFailure(
            "destination-present",
            f"destination already contains a {kind}; default no-clobber refused",
        )

    def _create_stage(self) -> None:
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        for _ in range(MAX_STAGE_ATTEMPTS):
            name = f".cisco-build-artifacts.{secrets.token_hex(16)}.tmp"
            try:
                descriptor = os.open(name, flags, 0o600, dir_fd=self.parent_fd)
            except FileExistsError:
                continue
            except OSError as error:
                raise CommandFailure(
                    "staging-create-failed",
                    f"same-directory staging create failed: {type(error).__name__}",
                    exit_code=EXIT_PUBLICATION,
                ) from error
            self.stage_name = name
            self.stage_fd = descriptor
            try:
                identity = _file_identity(descriptor)
            except OSError as error:
                raise CommandFailure(
                    "staging-policy-unverified",
                    f"staging access policy query failed: {type(error).__name__}",
                    exit_code=EXIT_PUBLICATION,
                ) from error
            self.stage_initial_identity = identity
            if (
                identity.owner != os.geteuid()
                or identity.mode != 0o600
                or identity.links != 1
                or identity.size != 0
            ):
                raise CommandFailure(
                    "staging-policy-mismatch",
                    "new staging file failed owner/mode/link/size validation",
                    exit_code=EXIT_PUBLICATION,
                )
            return
        raise CommandFailure(
            "staging-create-failed",
            "could not allocate a unique same-directory staging file",
            exit_code=EXIT_PUBLICATION,
        )

    def _rewalk_parent(self) -> None:
        if _directory_identity(self.anchor_fd) != self.anchor_identity:
            raise CommandFailure(
                "output-root-identity-mismatch",
                "held output root identity or access policy changed",
                exit_code=EXIT_PUBLICATION,
            )
        if _directory_identity(self.parent_fd) != self.parent_identity:
            raise CommandFailure(
                "output-parent-identity-mismatch",
                "held output parent identity or access policy changed",
                exit_code=EXIT_PUBLICATION,
            )
        held_parent_fd = _walk_relative_directory(
            self.anchor_fd,
            self.relative_parent,
        )
        try:
            if _directory_identity(held_parent_fd) != self.parent_identity:
                raise CommandFailure(
                    "output-parent-identity-mismatch",
                    "held output root no longer reaches the bound parent",
                    exit_code=EXIT_PUBLICATION,
                )
        finally:
            os.close(held_parent_fd)
        anchor_fd = _open_absolute_directory(self.anchor_path)
        try:
            if _directory_identity(anchor_fd) != self.anchor_identity:
                raise CommandFailure(
                    "output-root-identity-mismatch",
                    "validated output root was replaced",
                    exit_code=EXIT_PUBLICATION,
                )
            if self.anchor_path.parent == TEMP_ROOT:
                _validate_directory_policy(
                    anchor_fd,
                    os.fstat(anchor_fd),
                    require_private_owner=True,
                )
            parent_fd = _walk_relative_directory(anchor_fd, self.relative_parent)
            try:
                if _directory_identity(parent_fd) != self.parent_identity:
                    raise CommandFailure(
                        "output-parent-identity-mismatch",
                        "validated output parent was replaced",
                        exit_code=EXIT_PUBLICATION,
                    )
            finally:
                os.close(parent_fd)
        finally:
            os.close(anchor_fd)

    def _require_initial_stage_binding(self, identity: FileIdentity) -> None:
        initial = self.stage_initial_identity
        if initial is None:
            raise CommandFailure(
                "staging-state-invalid",
                "staging object has no initial identity binding",
                exit_code=EXIT_PUBLICATION,
            )
        if (
            identity.device != initial.device
            or identity.inode != initial.inode
            or identity.owner != initial.owner
            or identity.mode != initial.mode
            or identity.access_policy != initial.access_policy
        ):
            raise CommandFailure(
                "staging-identity-mismatch",
                "staging object identity or access policy changed",
                exit_code=EXIT_PUBLICATION,
            )

    def _stage_identity(self) -> FileIdentity:
        if self.stage_fd is None:
            raise CommandFailure(
                "staging-state-invalid",
                "staging descriptor is unavailable",
                exit_code=EXIT_PUBLICATION,
            )
        try:
            identity = _file_identity(self.stage_fd)
        except OSError as error:
            raise CommandFailure(
                "staging-revalidation-failed",
                f"staging descriptor revalidation failed: {type(error).__name__}",
                exit_code=EXIT_PUBLICATION,
            ) from error
        self._require_initial_stage_binding(identity)
        return identity

    def _reopen_stage(self) -> int:
        if self.stage_name is None:
            raise CommandFailure(
                "staging-state-invalid",
                "staging name is unavailable",
                exit_code=EXIT_PUBLICATION,
            )
        try:
            descriptor = os.open(
                self.stage_name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=self.parent_fd,
            )
        except FileNotFoundError as error:
            raise CommandFailure(
                "staging-entry-missing",
                "staging pathname is missing",
                exit_code=EXIT_PUBLICATION,
            ) from error
        except PermissionError as error:
            raise CommandFailure(
                "staging-revalidation-unreadable",
                "staging pathname could not be opened for revalidation",
                exit_code=EXIT_PUBLICATION,
            ) from error
        except OSError as error:
            raise CommandFailure(
                "staging-revalidation-failed",
                f"staging pathname revalidation failed: {type(error).__name__}",
                exit_code=EXIT_PUBLICATION,
            ) from error
        try:
            reopened_identity = _file_identity(descriptor)
            held_identity = self._stage_identity()
        except OSError as error:
            os.close(descriptor)
            raise CommandFailure(
                "staging-revalidation-failed",
                f"staging pathname policy query failed: {type(error).__name__}",
                exit_code=EXIT_PUBLICATION,
            ) from error
        except CommandFailure:
            os.close(descriptor)
            raise
        if reopened_identity != held_identity:
            os.close(descriptor)
            raise CommandFailure(
                "staging-identity-mismatch",
                "staging pathname no longer names the held object",
                exit_code=EXIT_PUBLICATION,
            )
        return descriptor

    def verify_content(
        self,
        expected_size: int,
        expected_digest: str,
        *,
        expected_links: int = 1,
    ) -> None:
        identity = self._stage_identity()
        if (
            identity.owner != os.geteuid()
            or identity.links != expected_links
            or identity.size != expected_size
        ):
            raise CommandFailure(
                "download-content-mismatch",
                "staged object identity, policy, or size changed",
                exit_code=EXIT_PUBLICATION,
            )
        digest = hashlib.sha256()
        offset = 0
        while offset < expected_size:
            chunk = os.pread(
                self.stage_fd,
                min(HASH_CHUNK_BYTES, expected_size - offset),
                offset,
            )
            if not chunk:
                raise CommandFailure(
                    "download-content-mismatch",
                    "staged content ended before its verified size",
                    exit_code=EXIT_PUBLICATION,
                )
            digest.update(chunk)
            offset += len(chunk)
        if digest.hexdigest() != expected_digest:
            raise CommandFailure(
                "download-content-mismatch",
                "staged content digest differs from the producer receipt",
                exit_code=EXIT_PUBLICATION,
            )

    def _seal_stage(self, expected_size: int, expected_digest: str) -> None:
        assert self.stage_fd is not None
        self.verify_content(expected_size, expected_digest)
        initial = self.stage_initial_identity
        assert initial is not None
        try:
            os.fchmod(self.stage_fd, 0o400)
            sealed = _file_identity(self.stage_fd)
        except OSError as error:
            raise CommandFailure(
                "staging-seal-failed",
                f"staging read-only seal failed: {type(error).__name__}",
                exit_code=EXIT_PUBLICATION,
            ) from error
        if (
            sealed.device != initial.device
            or sealed.inode != initial.inode
            or sealed.owner != initial.owner
            or sealed.mode != 0o400
            or sealed.links != 1
            or sealed.size != expected_size
        ):
            raise CommandFailure(
                "staging-seal-mismatch",
                "staging identity, access policy, or size changed while sealing",
                exit_code=EXIT_PUBLICATION,
            )
        # The mode transition is an intentional policy narrowing. The newly
        # sampled descriptor ACL is the sealed baseline; it is not treated as
        # content mutation or object replacement.
        self.stage_initial_identity = sealed
        try:
            os.fsync(self.stage_fd)
        except OSError as error:
            raise CommandFailure(
                "staging-fsync-failed",
                f"staging file fsync failed: {type(error).__name__}",
                exit_code=EXIT_PUBLICATION,
            ) from error
        self.verify_content(expected_size, expected_digest)
        readonly = self._reopen_stage()
        old_descriptor = self.stage_fd
        self.stage_fd = readonly
        os.close(old_descriptor)
        self.verify_content(expected_size, expected_digest)

    def publish(self, expected_size: int, expected_digest: str) -> PublicationOutcome:
        assert self.stage_fd is not None
        assert self.stage_name is not None
        self._seal_stage(expected_size, expected_digest)
        try:
            self._rewalk_parent()
        except FileNotFoundError as error:
            raise CommandFailure(
                "output-parent-missing",
                "validated output parent is missing during revalidation",
                exit_code=EXIT_PUBLICATION,
            ) from error
        except PermissionError as error:
            raise CommandFailure(
                "output-revalidation-unreadable",
                "validated output parent could not be read during revalidation",
                exit_code=EXIT_PUBLICATION,
            ) from error
        except OSError as error:
            raise CommandFailure(
                "output-revalidation-failed",
                f"output parent revalidation failed: {type(error).__name__}",
                exit_code=EXIT_PUBLICATION,
            ) from error
        reopened = self._reopen_stage()
        os.close(reopened)
        self._require_destination_absent()
        try:
            _rename_noreplace(
                self.parent_fd,
                self.stage_name,
                self.destination_name,
            )
        except FileExistsError as error:
            raise CommandFailure(
                "destination-present",
                "atomic no-replace publication found an existing destination",
                exit_code=EXIT_PUBLICATION,
            ) from error
        except OSError as error:
            raise CommandFailure(
                "atomic-no-replace-failed",
                f"atomic no-replace rename failed: {type(error).__name__}",
                exit_code=EXIT_PUBLICATION,
            ) from error
        self.published = True
        self.stage_name = None
        destination_fd: int | None = None
        try:
            destination_fd = os.open(
                self.destination_name,
                os.O_RDONLY
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=self.parent_fd,
            )
            if _file_identity(destination_fd) != self._stage_identity():
                return PublicationOutcome(
                    publication="published",
                    durability="unverified",
                    cleanup="complete",
                    classification="published-identity-unverified",
                )
        except (OSError, CommandFailure):
            return PublicationOutcome(
                publication="published",
                durability="unverified",
                cleanup="complete",
                classification="published-identity-unverified",
            )
        finally:
            if destination_fd is not None:
                os.close(destination_fd)
        try:
            self.verify_content(
                expected_size,
                expected_digest,
                expected_links=1,
            )
        except CommandFailure:
            return PublicationOutcome(
                publication="published",
                durability="unverified",
                cleanup="complete",
                classification="published-content-unverified",
            )
        try:
            os.fsync(self.parent_fd)
        except OSError:
            return PublicationOutcome(
                publication="published",
                durability="unverified",
                cleanup="complete",
                classification="durability-unverified",
            )
        return PublicationOutcome(
            publication="published",
            durability="verified",
            cleanup="complete",
            classification="published",
        )

    def abort(self) -> str:
        if self.stage_fd is None or self.stage_name is None:
            return "complete"
        try:
            self._rewalk_parent()
            identity = self._stage_identity()
            if identity.links != 1:
                return "unverified"
            reopened = self._reopen_stage()
            try:
                os.unlink(self.stage_name, dir_fd=self.parent_fd)
                held_after = self._stage_identity()
                reopened_after = _file_identity(reopened)
                if held_after != reopened_after or held_after.links != 0:
                    return "unverified"
            finally:
                os.close(reopened)
            self.stage_name = None
            try:
                os.fsync(self.parent_fd)
            except OSError:
                return "durability-unverified"
            return "complete"
        except FileNotFoundError:
            return "unverified"
        except (OSError, CommandFailure):
            return "unverified"

    def close(self) -> None:
        if self.stage_fd is not None:
            os.close(self.stage_fd)
            self.stage_fd = None
        if self.parent_fd >= 0:
            os.close(self.parent_fd)
            self.parent_fd = -1
        if self.anchor_fd >= 0:
            os.close(self.anchor_fd)
            self.anchor_fd = -1


def _common_payload(args: argparse.Namespace, command: str) -> dict[str, Any]:
    return {
        "command": command,
        "url": args.url,
        "auth_profile": args.auth_profile,
        "max_redirects": args.max_redirects,
        "connect_timeout": args.connect_timeout,
        "read_timeout": args.read_timeout,
        "max_body_bytes": args.max_body_bytes,
    }


def _print_metadata(result: dict[str, Any]) -> None:
    ordered = (
        "source_url",
        "final_url",
        "query_redacted",
        "artifact_identity",
        "status",
        "auth_profile",
        "auth",
        "redirects",
        "content_type",
        "content_length",
        "wire_bytes",
        "entity_bytes",
        "persisted_bytes",
        "representation",
        "input_lines",
        "output_lines",
        "output_chars",
        "truncated",
        "sha256",
        "output",
        "publication",
        "durability",
        "cleanup",
        "classification",
    )
    for key in ordered:
        if key in result and result[key] is not None and result[key] != "":
            value = result[key]
            if isinstance(value, bool):
                value = str(value).lower()
            print(f"{key}={_safe_detail(value)}")


def _execute_probe(args: argparse.Namespace, deadline: float) -> dict[str, Any]:
    payload = _common_payload(args, "probe-url")
    payload.update(
        {
            "method": args.method,
            "sniff_bytes": args.sniff_bytes,
            "encoding": args.encoding,
        }
    )
    return _run_worker(payload, deadline=deadline)


def _execute_show(args: argparse.Namespace, deadline: float) -> dict[str, Any]:
    mode = (
        "grep"
        if args.grep is not None
        else "head"
        if args.head
        else "tail"
        if args.tail
        else "default"
    )
    count = args.head or args.tail or args.max_output_lines
    payload = _common_payload(args, "show-url")
    payload.update(
        {
            "selection_mode": mode,
            "selection_count": count,
            "grep": args.grep,
            "ignore_case": args.ignore_case,
            "context": args.context,
            "encoding": args.encoding,
            "max_input_line_bytes": args.max_input_line_bytes,
            "max_input_lines": args.max_input_lines,
            "max_output_lines": args.max_output_lines,
            "max_output_chars": args.max_output_chars,
        }
    )
    return _run_worker(payload, deadline=deadline)


def _execute_fetch(
    args: argparse.Namespace, deadline: float
) -> tuple[dict[str, Any], PublicationOutcome]:
    transaction = OutputTransaction(args.output)
    try:
        assert transaction.stage_fd is not None
        payload = _common_payload(args, "fetch-url")
        payload["stage_fd"] = transaction.stage_fd
        result = _run_worker(
            payload,
            deadline=deadline,
            pass_fds=(transaction.stage_fd,),
        )
        expected_size = int(result["persisted_bytes"])
        expected_digest = str(result["sha256"])
        transaction.verify_content(expected_size, expected_digest)
        outcome = transaction.publish(expected_size, expected_digest)
        result.update(
            {
                "output": str(transaction.output),
                "publication": outcome.publication,
                "durability": outcome.durability,
                "cleanup": outcome.cleanup,
                "classification": outcome.classification,
            }
        )
        return result, outcome
    except BaseException as error:
        cleanup = transaction.abort()
        if isinstance(error, CommandFailure):
            if error.cleanup is None:
                error.cleanup = cleanup
            else:
                error.metadata["producer_cleanup"] = error.cleanup
                error.metadata["staging_cleanup"] = cleanup
            raise
        raise CommandFailure(
            "publication-failed",
            type(error).__name__,
            exit_code=EXIT_PUBLICATION,
            cleanup=cleanup,
        ) from error
    finally:
        transaction.close()


def cmd_probe_url(args: argparse.Namespace) -> int:
    deadline = time.monotonic() + args.timeout
    result = _execute_probe(args, deadline)
    _print_metadata(result)
    if result.get("preview"):
        print("--- body preview ---")
        print(_terminal_safe(str(result["preview"])))
    return 0


def cmd_show_url(args: argparse.Namespace) -> int:
    if args.context and args.grep is None:
        raise UsageFailure(
            "argument-rejected",
            "--context requires --grep",
        )
    deadline = time.monotonic() + args.timeout
    result = _execute_show(args, deadline)
    lines = result.pop("lines")
    _print_metadata(result)
    print("--- selected text ---")
    for line_number, line in lines:
        if args.line_numbers:
            print(f"{line_number}:{line}")
        else:
            print(line)
    return 0


def cmd_fetch_url(args: argparse.Namespace) -> int:
    deadline = time.monotonic() + args.timeout
    result, outcome = _execute_fetch(args, deadline)
    _print_metadata(result)
    return 0 if outcome.classification == "published" else EXIT_PUBLICATION


class BoundedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        print("classification=argument-rejected", file=sys.stderr)
        print(f"detail={_safe_detail(message)}", file=sys.stderr)
        raise SystemExit(EXIT_USAGE)


def _add_remote_limits(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--auth-profile",
        choices=sorted(AUTH_PROFILES),
    )
    parser.add_argument(
        "--max-redirects",
        type=_positive_bounded_int("--max-redirects", HARD_MAX_REDIRECTS),
        default=DEFAULT_MAX_REDIRECTS,
    )
    parser.add_argument(
        "--connect-timeout",
        type=_positive_bounded_float(
            "--connect-timeout",
            HARD_MAX_CONNECT_TIMEOUT_SECONDS,
        ),
        default=DEFAULT_CONNECT_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--read-timeout",
        type=_positive_bounded_float(
            "--read-timeout",
            HARD_MAX_READ_TIMEOUT_SECONDS,
        ),
        default=DEFAULT_READ_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--timeout",
        type=_positive_bounded_float(
            "--timeout",
            HARD_MAX_TOTAL_TIMEOUT_SECONDS,
        ),
        default=DEFAULT_TOTAL_TIMEOUT_SECONDS,
        help="Hard producer wall-clock deadline in seconds.",
    )
    parser.add_argument(
        "--max-body-bytes",
        type=_positive_bounded_int(
            "--max-body-bytes",
            HARD_MAX_BODY_BYTES,
        ),
        default=DEFAULT_MAX_BODY_BYTES,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = BoundedArgumentParser(
        description=(
            "Fetch Cisco Jenkins build evidence with redirect-safe authentication, "
            "bounded streaming, and atomic no-clobber publication."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    probe = subparsers.add_parser("probe-url")
    probe.add_argument("url")
    probe.add_argument("--method", choices=("HEAD", "GET"), default="HEAD")
    probe.add_argument(
        "--sniff-bytes",
        type=_positive_bounded_int(
            "--sniff-bytes",
            HARD_MAX_PROBE_SNIFF_BYTES,
        ),
        default=DEFAULT_PROBE_SNIFF_BYTES,
    )
    probe.add_argument("--encoding", type=_encoding_name, default="utf-8")
    _add_remote_limits(probe)
    probe.set_defaults(func=cmd_probe_url)

    show = subparsers.add_parser("show-url")
    show.add_argument("url")
    selection = show.add_mutually_exclusive_group()
    selection.add_argument(
        "--head",
        type=_positive_bounded_int("--head", HARD_MAX_OUTPUT_LINES),
        default=0,
    )
    selection.add_argument(
        "--tail",
        type=_positive_bounded_int("--tail", HARD_MAX_OUTPUT_LINES),
        default=0,
    )
    selection.add_argument("--grep", type=_grep_pattern)
    show.add_argument("--ignore-case", action="store_true")
    show.add_argument("--context", type=_nonnegative_int, default=0)
    show.add_argument("--encoding", type=_encoding_name, default="utf-8")
    show.add_argument("--line-numbers", action="store_true")
    show.add_argument(
        "--max-input-line-bytes",
        type=_positive_bounded_int(
            "--max-input-line-bytes",
            HARD_MAX_INPUT_LINE_BYTES,
        ),
        default=DEFAULT_MAX_INPUT_LINE_BYTES,
    )
    show.add_argument(
        "--max-input-lines",
        type=_positive_bounded_int(
            "--max-input-lines",
            HARD_MAX_INPUT_LINES,
        ),
        default=DEFAULT_MAX_INPUT_LINES,
    )
    show.add_argument(
        "--max-output-lines",
        type=_positive_bounded_int(
            "--max-output-lines",
            HARD_MAX_OUTPUT_LINES,
        ),
        default=DEFAULT_MAX_OUTPUT_LINES,
    )
    show.add_argument(
        "--max-output-chars",
        type=_positive_bounded_int(
            "--max-output-chars",
            HARD_MAX_OUTPUT_CHARS,
        ),
        default=DEFAULT_MAX_OUTPUT_CHARS,
    )
    _add_remote_limits(show)
    show.set_defaults(func=cmd_show_url)

    fetch = subparsers.add_parser("fetch-url")
    fetch.add_argument("url")
    fetch.add_argument("--output", required=True)
    _add_remote_limits(fetch)
    fetch.set_defaults(func=cmd_fetch_url)
    return parser


def _emit_failure(error: CommandFailure) -> None:
    print(f"classification={error.classification}", file=sys.stderr)
    print(f"detail={error.detail}", file=sys.stderr)
    if error.cleanup is not None:
        print(f"cleanup={error.cleanup}", file=sys.stderr)
    for key in sorted(error.metadata):
        value = error.metadata[key]
        if isinstance(value, (str, int, float, bool)) or value is None:
            print(f"{key}={_safe_detail(value)}", file=sys.stderr)


def main() -> int:
    if sys.argv[1:] == [WORKER_ARG]:
        return _worker_main()
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except CommandFailure as error:
        _emit_failure(error)
        return error.exit_code
    except (OSError, ValueError) as error:
        failure = CommandFailure(
            "local-operation-failed",
            type(error).__name__,
            exit_code=EXIT_PUBLICATION,
        )
        _emit_failure(failure)
        return failure.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
