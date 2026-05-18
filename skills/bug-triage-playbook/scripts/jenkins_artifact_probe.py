#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import collections
import io
import os
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Iterator

DEFAULT_ALLOWED_HOSTS = frozenset({"jenkins.example.com"})
AUTH_PROFILES = {
    "default": (
        "JENKINS_ARTIFACT_USER",
        "JENKINS_ARTIFACT_TOKEN",
    ),
}


def _allowed_hosts() -> frozenset[str]:
    raw_hosts = os.getenv("JENKINS_ARTIFACT_ALLOWED_HOSTS")
    if not raw_hosts:
        return DEFAULT_ALLOWED_HOSTS
    hosts = frozenset(host.strip() for host in raw_hosts.split(",") if host.strip())
    return hosts or DEFAULT_ALLOWED_HOSTS


def _compile_pattern(pattern: str, ignore_case: bool = False) -> re.Pattern[str]:
    flags = re.IGNORECASE if ignore_case else 0
    return re.compile(pattern, flags)


def _ensure_allowed_url(url: str) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("only https URLs are allowed")
    if parsed.hostname is None:
        raise ValueError("URL must include a host")
    if parsed.hostname not in _allowed_hosts():
        raise ValueError(f"host not allowed: {parsed.hostname}")
    if parsed.username or parsed.password:
        raise ValueError("inline URL credentials are not allowed")
    return parsed


def _resolve_output_path(output: str) -> pathlib.Path:
    raw_path = pathlib.Path(output).expanduser()
    candidate = (pathlib.Path.cwd() / raw_path) if not raw_path.is_absolute() else raw_path
    resolved = candidate.resolve()
    workspace_root = pathlib.Path.cwd().resolve()
    tmp_root = pathlib.Path("/tmp").resolve()
    if resolved.is_relative_to(workspace_root) or resolved.is_relative_to(tmp_root):
        return resolved
    raise ValueError(
        f"output path must stay under {workspace_root} or {tmp_root}"
    )


def _add_basic_auth(
    request: urllib.request.Request,
    auth_profile: str | None,
) -> str:
    if not auth_profile:
        return "absent"

    try:
        user_env, token_env = AUTH_PROFILES[auth_profile]
    except KeyError as exc:
        raise ValueError(f"unknown auth profile: {auth_profile}") from exc

    user = os.getenv(user_env)
    token = os.getenv(token_env)
    if not user or not token:
        raise ValueError(
            f"missing auth env for profile {auth_profile}: expected {user_env} and {token_env}"
        )

    raw = f"{user}:{token}".encode("utf-8")
    header = base64.b64encode(raw).decode("ascii")
    request.add_header("Authorization", f"Basic {header}")
    return "present"


def _build_remote_request(
    url: str,
    *,
    method: str,
    auth_profile: str | None,
) -> tuple[urllib.request.Request, str]:
    _ensure_allowed_url(url)
    request = urllib.request.Request(url, method=method)
    auth_state = _add_basic_auth(request, auth_profile)
    return request, auth_state


def _report_usage_error(url: str, error: ValueError) -> int:
    print(f"url={url}", file=sys.stderr)
    print(f"error={error}", file=sys.stderr)
    return 2


def _read_zip_text(zip_path: pathlib.Path, member: str, encoding: str) -> list[str]:
    with zipfile.ZipFile(zip_path) as archive:
        raw = archive.read(member)
    return raw.decode(encoding, errors="replace").splitlines()


def _find_members(
    archive: zipfile.ZipFile,
    needle: str,
    use_regex: bool,
    ignore_case: bool,
) -> list[str]:
    names = [info.filename for info in archive.infolist()]
    if use_regex:
        pattern = _compile_pattern(needle, ignore_case)
        return [name for name in names if pattern.search(name)]

    compare = needle.lower() if ignore_case else needle
    matches = []
    for name in names:
        candidate = name.lower() if ignore_case else name
        if candidate == compare:
            matches.append(name)
    return matches


def _iter_context_lines(
    lines: list[str],
    pattern: re.Pattern[str],
    context: int,
) -> list[tuple[int, str]]:
    keep: set[int] = set()
    for idx, line in enumerate(lines):
        if pattern.search(line):
            start = max(0, idx - context)
            end = min(len(lines), idx + context + 1)
            keep.update(range(start, end))
    return [(idx + 1, lines[idx]) for idx in sorted(keep)]


def _iter_text_lines(stream: io.BufferedIOBase, encoding: str) -> Iterator[str]:
    wrapper = io.TextIOWrapper(stream, encoding=encoding, errors="replace")
    try:
        for raw_line in wrapper:
            yield raw_line.rstrip("\r\n")
    finally:
        wrapper.detach()


def _select_lines(
    lines: list[str],
    grep: str | None,
    ignore_case: bool,
    context: int,
    head: int,
    tail: int,
) -> list[tuple[int, str]]:
    if grep:
        pattern = _compile_pattern(grep, ignore_case)
        return _iter_context_lines(lines, pattern, context)
    if head:
        return [(idx + 1, line) for idx, line in enumerate(lines[:head])]
    if tail:
        start = max(0, len(lines) - tail)
        return [(idx + 1, lines[idx]) for idx in range(start, len(lines))]
    return [(idx + 1, line) for idx, line in enumerate(lines)]


def _select_stream_lines(
    stream: io.BufferedIOBase,
    encoding: str,
    head: int,
    tail: int,
) -> list[tuple[int, str]]:
    if head > 0:
        output_lines: list[tuple[int, str]] = []
        for idx, line in enumerate(_iter_text_lines(stream, encoding), start=1):
            output_lines.append((idx, line))
            if idx >= head:
                break
        return output_lines

    if tail > 0:
        output_lines: collections.deque[tuple[int, str]] = collections.deque(
            maxlen=tail
        )
        for idx, line in enumerate(_iter_text_lines(stream, encoding), start=1):
            output_lines.append((idx, line))
        return list(output_lines)

    return [(idx, line) for idx, line in enumerate(_iter_text_lines(stream, encoding), start=1)]


def cmd_probe_url(args: argparse.Namespace) -> int:
    try:
        request, auth_state = _build_remote_request(
            args.url,
            method=args.method,
            auth_profile=args.auth_profile,
        )
    except ValueError as error:
        return _report_usage_error(args.url, error)
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:
            body = response.read(args.sniff_bytes) if args.sniff_bytes else b""
            print(f"url={args.url}")
            print(f"status={response.status}")
            print(f"auth={auth_state}")
            content_type = response.headers.get("Content-Type", "")
            content_length = response.headers.get("Content-Length", "")
            if content_type:
                print(f"content_type={content_type}")
            if content_length:
                print(f"content_length={content_length}")
            if body:
                text = body.decode(args.encoding, errors="replace")
                print("--- body preview ---")
                print(text.rstrip())
            return 0
    except urllib.error.HTTPError as error:
        print(f"url={args.url}")
        print(f"status={error.code}")
        print(f"auth={auth_state}")
        print(f"error={error.reason}")
        return 1
    except urllib.error.URLError as error:
        print(f"url={args.url}")
        print(f"auth={auth_state}")
        print(f"error={error.reason}")
        return 1


def cmd_show_url(args: argparse.Namespace) -> int:
    try:
        request, auth_state = _build_remote_request(
            args.url,
            method="GET",
            auth_profile=args.auth_profile,
        )
    except ValueError as error:
        return _report_usage_error(args.url, error)
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:
            if (
                not args.grep
                and args.head >= 0
                and args.tail >= 0
                and (args.head > 0 or args.tail > 0)
            ):
                output_lines = _select_stream_lines(
                    response,
                    args.encoding,
                    args.head,
                    args.tail,
                )
            else:
                lines = list(_iter_text_lines(response, args.encoding))
                output_lines = _select_lines(
                    lines,
                    args.grep,
                    args.ignore_case,
                    args.context,
                    args.head,
                    args.tail,
                )
    except urllib.error.HTTPError as error:
        print(f"url={args.url}", file=sys.stderr)
        print(f"auth={auth_state}", file=sys.stderr)
        print(f"status={error.code}", file=sys.stderr)
        print(f"error={error.reason}", file=sys.stderr)
        return 1
    except urllib.error.URLError as error:
        print(f"url={args.url}", file=sys.stderr)
        print(f"auth={auth_state}", file=sys.stderr)
        print(f"error={error.reason}", file=sys.stderr)
        return 1

    for line_number, line in output_lines:
        if args.line_numbers:
            print(f"{line_number}:{line}")
        else:
            print(line)
    return 0


def cmd_fetch_url(args: argparse.Namespace) -> int:
    try:
        request, auth_state = _build_remote_request(
            args.url,
            method="GET",
            auth_profile=args.auth_profile,
        )
        output = _resolve_output_path(args.output)
    except ValueError as error:
        return _report_usage_error(args.url, error)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:
            data = response.read()
        output.write_bytes(data)
        print(f"url={args.url}")
        print(f"output={output}")
        print(f"bytes={len(data)}")
        print(f"auth={auth_state}")
        return 0
    except urllib.error.HTTPError as error:
        print(f"url={args.url}")
        print(f"status={error.code}")
        print(f"auth={auth_state}")
        print(f"error={error.reason}")
        return 1
    except urllib.error.URLError as error:
        print(f"url={args.url}")
        print(f"auth={auth_state}")
        print(f"error={error.reason}")
        return 1


def cmd_zip_list(args: argparse.Namespace) -> int:
    zip_path = pathlib.Path(args.zip_path)
    pattern = _compile_pattern(args.match, args.ignore_case) if args.match else None
    with zipfile.ZipFile(zip_path) as archive:
        matched = 0
        for info in archive.infolist():
            if pattern and not pattern.search(info.filename):
                continue
            matched += 1
            print(f"{info.file_size}\t{info.compress_size}\t{info.filename}")
            if args.limit and matched >= args.limit:
                break
    return 0


def cmd_zip_show(args: argparse.Namespace) -> int:
    zip_path = pathlib.Path(args.zip_path)
    with zipfile.ZipFile(zip_path) as archive:
        matches = _find_members(archive, args.member, args.regex, args.ignore_case)
    if not matches:
        print("error=no matching members", file=sys.stderr)
        return 1
    if len(matches) > 1 and not args.all:
        print("error=multiple matching members", file=sys.stderr)
        for match in matches:
            print(match, file=sys.stderr)
        return 1

    grep_pattern = (
        _compile_pattern(args.grep, args.ignore_case) if args.grep else None
    )
    selected = matches if args.all else matches[:1]
    for index, member in enumerate(selected):
        if index:
            print()
        print(f"== {member} ==")
        lines = _read_zip_text(zip_path, member, args.encoding)
        if grep_pattern:
            output_lines = _iter_context_lines(lines, grep_pattern, args.context)
        else:
            output_lines = _select_lines(
                lines,
                None,
                args.ignore_case,
                args.context,
                args.head,
                args.tail,
            )

        for line_number, line in output_lines:
            if args.line_numbers:
                print(f"{line_number}:{line}")
            else:
                print(line)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Probe Jenkins-style URLs and inspect archive members without ad hoc shell chains."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    probe = subparsers.add_parser("probe-url", help="Probe a remote URL with optional basic auth.")
    probe.add_argument("url")
    probe.add_argument("--method", default="HEAD", choices=["HEAD", "GET"])
    probe.add_argument("--auth-profile", choices=sorted(AUTH_PROFILES))
    probe.add_argument("--timeout", type=int, default=20)
    probe.add_argument("--sniff-bytes", type=int, default=0)
    probe.add_argument("--encoding", default="utf-8")
    probe.set_defaults(func=cmd_probe_url)

    show = subparsers.add_parser(
        "show-url",
        help="Fetch a text URL and print filtered lines to stdout.",
    )
    show.add_argument("url")
    show.add_argument("--auth-profile", choices=sorted(AUTH_PROFILES))
    show.add_argument("--timeout", type=int, default=60)
    show.add_argument("--grep")
    show.add_argument("--ignore-case", action="store_true")
    show.add_argument("--context", type=int, default=0)
    show.add_argument("--head", type=int, default=0)
    show.add_argument("--tail", type=int, default=0)
    show.add_argument("--encoding", default="utf-8")
    show.add_argument("--line-numbers", action="store_true")
    show.set_defaults(func=cmd_show_url)

    fetch = subparsers.add_parser("fetch-url", help="Fetch a remote URL to a local file.")
    fetch.add_argument("url")
    fetch.add_argument(
        "--output",
        required=True,
        help="Output path must resolve under the current workspace or /tmp.",
    )
    fetch.add_argument("--auth-profile", choices=sorted(AUTH_PROFILES))
    fetch.add_argument("--timeout", type=int, default=60)
    fetch.set_defaults(func=cmd_fetch_url)

    zip_list = subparsers.add_parser("zip-list", help="List members in a zip archive.")
    zip_list.add_argument("zip_path")
    zip_list.add_argument("--match")
    zip_list.add_argument("--ignore-case", action="store_true")
    zip_list.add_argument("--limit", type=int, default=0)
    zip_list.set_defaults(func=cmd_zip_list)

    zip_show = subparsers.add_parser(
        "zip-show",
        help="Show a zip member, optionally selected by regex and filtered by grep/context.",
    )
    zip_show.add_argument("zip_path")
    zip_show.add_argument("member")
    zip_show.add_argument("--regex", action="store_true")
    zip_show.add_argument("--all", action="store_true")
    zip_show.add_argument("--grep")
    zip_show.add_argument("--ignore-case", action="store_true")
    zip_show.add_argument("--context", type=int, default=0)
    zip_show.add_argument("--head", type=int, default=0)
    zip_show.add_argument("--tail", type=int, default=0)
    zip_show.add_argument("--encoding", default="utf-8")
    zip_show.add_argument("--line-numbers", action="store_true")
    zip_show.set_defaults(func=cmd_zip_show)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
