from __future__ import annotations

import argparse
import base64
import contextlib
import errno
import importlib.util
import io
import os
import pathlib
import random
import re
import signal
import stat
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import warnings
import zipfile
import zlib
from contextlib import redirect_stderr, redirect_stdout
from typing import Dict, List, Optional, Tuple, Union
from unittest import mock


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "skills/bug-triage-playbook/scripts/jenkins_artifact_probe.py"
SPEC = importlib.util.spec_from_file_location("jenkins_artifact_probe", SCRIPT_PATH)
assert SPEC is not None
assert SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
REQUIRED_CALL_TRIGGER = """on:
  workflow_call:

permissions:"""
CHECKOUT_REPOSITORY = "Joey-Tools/codex-debug-triage"
REPOSITORY_GUARD = """- name: Reject unexpected repository
        if: ${{ github.repository != 'Joey-Tools/codex-debug-triage' }}
        run: exit 1"""
CHECKOUT_BINDING = """- uses: actions/checkout@v4
        with:
          repository: Joey-Tools/codex-debug-triage
          ref: ${{ github.sha }}
          persist-credentials: false"""


def workflow_steps(workflow: str) -> List[str]:
    lines = workflow.splitlines()
    steps: List[str] = []
    for index, line in enumerate(lines):
        if not line.startswith("      - "):
            continue
        indent = len(line) - len(line.lstrip())
        end = index + 1
        while end < len(lines):
            candidate = lines[end]
            candidate_indent = len(candidate) - len(candidate.lstrip())
            if candidate.strip() and (
                candidate_indent < indent
                or (candidate_indent == indent and candidate.lstrip().startswith("- "))
            ):
                break
            end += 1
        steps.append("\n".join(lines[index:end]))
    return steps


def checkout_steps(workflow: str) -> List[str]:
    return [
        step
        for step in workflow_steps(workflow)
        if step.lstrip().startswith("- uses: actions/checkout@")
    ]


class FakeHTTPResponse(io.BytesIO):
    def __init__(
        self,
        payload: bytes,
        *,
        status: int = 200,
        headers: Optional[Dict[str, str]] = None,
        final_url: str = "https://jenkins.example.com/final",
    ) -> None:
        super().__init__(payload)
        self.status = status
        self.headers = headers or {}
        self.final_url = final_url
        self.read_sizes: List[int] = []

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return super().read(size)

    def geturl(self) -> str:
        return self.final_url


class FakeOpener:
    def __init__(self, response: FakeHTTPResponse) -> None:
        self.response = response
        self.requests: List[urllib.request.Request] = []

    def open(self, request: urllib.request.Request, timeout: float) -> FakeHTTPResponse:
        self.requests.append(request)
        return self.response


def _sleep_worker(args: argparse.Namespace) -> int:
    time.sleep(args.sleep_seconds)
    return 0


def _failure_worker(_: argparse.Namespace) -> int:
    return 1


def _blocking_read_worker(args: argparse.Namespace) -> int:
    os.read(args.blocking_fd, 1)
    return 0


def _regex_worker(args: argparse.Namespace) -> int:
    re.search(r"(a+)+$", "a" * args.regex_length + "!")
    return 0


def _decompression_worker(args: argparse.Namespace) -> int:
    while True:
        zlib.decompress(args.compressed_payload)


def _stalled_publish_worker(args: argparse.Namespace) -> int:
    publisher = MODULE.AtomicPublisher.prepare(args.output, args._receipt_fd)
    try:
        with publisher.file() as output:
            output.write(b"partial")
            output.flush()
        pathlib.Path(args.milestone).write_text("prepared", encoding="utf-8")
        time.sleep(args.sleep_seconds)
    finally:
        publisher.abort()
        publisher.close()
    return 0


def _published_stall_worker(args: argparse.Namespace) -> int:
    publisher = MODULE.AtomicPublisher.prepare(args.output, args._receipt_fd)
    try:
        with publisher.file() as output:
            output.write(b"complete")
            output.flush()
        publisher.publish(8)
        pathlib.Path(args.milestone).write_text("published", encoding="utf-8")
        time.sleep(args.sleep_seconds)
    finally:
        publisher.close()
    return 0


def _delayed_receipt_worker(args: argparse.Namespace) -> int:
    def delayed_receipt(self: object, receipt_fd: int) -> None:
        pathlib.Path(args.milestone).write_text("temp-created", encoding="utf-8")
        time.sleep(args.receipt_delay)

    MODULE.AtomicPublisher._send_receipt = delayed_receipt
    MODULE.AtomicPublisher.prepare(args.output, args._receipt_fd)
    return 0


def _signaled_prepared_worker(args: argparse.Namespace) -> int:
    MODULE.AtomicPublisher.prepare(args.output, args._receipt_fd)
    pathlib.Path(args.milestone).write_text("prepared", encoding="utf-8")
    os.kill(os.getpid(), signal.SIGKILL)
    return 0


def _signaled_published_worker(args: argparse.Namespace) -> int:
    publisher = MODULE.AtomicPublisher.prepare(args.output, args._receipt_fd)
    with publisher.file() as output:
        output.write(b"complete")
    publisher.publish(8)
    pathlib.Path(args.milestone).write_text("published", encoding="utf-8")
    os.kill(os.getpid(), signal.SIGKILL)
    return 0


def _nonzero_published_worker(args: argparse.Namespace) -> int:
    publisher = MODULE.AtomicPublisher.prepare(args.output, args._receipt_fd)
    with publisher.file() as output:
        output.write(b"complete")
    publisher.publish(8)
    publisher.close()
    return 1


def _nonzero_without_receipt_worker(args: argparse.Namespace) -> int:
    if args.truncated_receipt:
        os.write(args._receipt_fd, b"{")
    return 1


def _interruptible_prepared_worker(args: argparse.Namespace) -> int:
    MODULE.AtomicPublisher.prepare(args.output, args._receipt_fd)
    pathlib.Path(args.milestone).write_text("prepared", encoding="utf-8")
    os.read(args.blocking_fd, 1)
    return 0


class JenkinsArtifactProbeTests(unittest.TestCase):
    def _show_args(self, **changes: object) -> argparse.Namespace:
        values: Dict[str, object] = {
            "url": "https://jenkins.example.com/job/example/consoleText",
            "auth_profile": None,
            "socket_timeout": 5.0,
            "max_redirects": 2,
            "grep": None,
            "ignore_case": False,
            "context": 0,
            "head": 0,
            "tail": 0,
            "encoding": "utf-8",
            "line_numbers": False,
            "max_bytes": 1024,
            "max_scan_lines": 100,
            "max_line_bytes": 100,
            "max_emit_lines": 20,
            "max_emit_bytes": 1024,
        }
        values.update(changes)
        return argparse.Namespace(**values)

    def _fetch_args(self, output: pathlib.Path, **changes: object) -> argparse.Namespace:
        values: Dict[str, object] = {
            "url": "https://jenkins.example.com/job/example/artifact.zip",
            "output": str(output),
            "auth_profile": None,
            "socket_timeout": 5.0,
            "max_redirects": 2,
            "max_bytes": 1024,
        }
        values.update(changes)
        return argparse.Namespace(**values)

    def _zip_args(self, zip_path: pathlib.Path, **changes: object) -> argparse.Namespace:
        values: Dict[str, object] = {
            "zip_path": str(zip_path),
            "max_archive_bytes": 1024 * 1024,
            "max_central_directory_bytes": 1024 * 1024,
            "max_members": 100,
            "max_member_name_bytes": 200,
            "max_member_compressed_bytes": 1024 * 1024,
            "max_member_uncompressed_bytes": 1024 * 1024,
            "max_total_compressed_bytes": 1024 * 1024,
            "max_total_uncompressed_bytes": 1024 * 1024,
            "max_ratio": 200.0,
            "max_selected_members": 10,
        }
        values.update(changes)
        return argparse.Namespace(**values)

    def _zip_show_args(self, zip_path: pathlib.Path, **changes: object) -> argparse.Namespace:
        values = vars(self._zip_args(zip_path)).copy()
        values.update(
            {
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
                "max_bytes": 1024 * 1024,
                "max_scan_lines": 100,
                "max_line_bytes": 1024,
                "max_emit_lines": 20,
                "max_emit_bytes": 4096,
            }
        )
        values.update(changes)
        return argparse.Namespace(**values)

    def _write_zip(
        self,
        path: pathlib.Path,
        entries: List[Tuple[Union[str, zipfile.ZipInfo], bytes]],
        compression: int = zipfile.ZIP_DEFLATED,
    ) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path, "w", compression=compression) as archive:
                for name, payload in entries:
                    archive.writestr(name, payload)

    def _rewrite_deflate_as_declared_prefix(
        self,
        path: pathlib.Path,
        *,
        member: str,
        declared_prefix: bytes,
        hidden_suffix: bytes,
    ) -> None:
        self._write_zip(
            path,
            [(member, declared_prefix + hidden_suffix)],
            compression=zipfile.ZIP_DEFLATED,
        )
        raw = bytearray(path.read_bytes())
        local = raw.find(b"PK\x03\x04")
        central = raw.find(b"PK\x01\x02")
        self.assertGreaterEqual(local, 0)
        self.assertGreaterEqual(central, 0)
        declared_crc = zlib.crc32(declared_prefix) & 0xFFFFFFFF
        raw[local + 14 : local + 18] = declared_crc.to_bytes(4, "little")
        raw[local + 22 : local + 26] = len(declared_prefix).to_bytes(4, "little")
        raw[central + 16 : central + 20] = declared_crc.to_bytes(4, "little")
        raw[central + 24 : central + 28] = len(declared_prefix).to_bytes(
            4, "little"
        )
        path.write_bytes(raw)

    def _append_deflate_stream_inside_declared_compressed_span(
        self,
        path: pathlib.Path,
        *,
        member: str,
        payload: bytes,
        trailing_payload: bytes,
    ) -> None:
        self._write_zip(
            path,
            [(member, payload)],
            compression=zipfile.ZIP_DEFLATED,
        )
        raw = bytearray(path.read_bytes())
        local = raw.find(b"PK\x03\x04")
        central = raw.find(b"PK\x01\x02")
        self.assertGreaterEqual(local, 0)
        self.assertGreaterEqual(central, 0)
        name_length = int.from_bytes(raw[local + 26 : local + 28], "little")
        extra_length = int.from_bytes(raw[local + 28 : local + 30], "little")
        compressed_size = int.from_bytes(raw[local + 18 : local + 22], "little")
        payload_end = local + 30 + name_length + extra_length + compressed_size
        compressor = zlib.compressobj(wbits=-15)
        trailing = compressor.compress(trailing_payload) + compressor.flush()
        raw[payload_end:payload_end] = trailing
        central += len(trailing)
        new_compressed_size = compressed_size + len(trailing)
        raw[local + 18 : local + 22] = new_compressed_size.to_bytes(4, "little")
        raw[central + 20 : central + 24] = new_compressed_size.to_bytes(4, "little")
        eocd = raw.rfind(b"PK\x05\x06")
        self.assertGreaterEqual(eocd, 0)
        central_offset = int.from_bytes(raw[eocd + 16 : eocd + 20], "little")
        raw[eocd + 16 : eocd + 20] = (
            central_offset + len(trailing)
        ).to_bytes(4, "little")
        path.write_bytes(raw)

    @contextlib.contextmanager
    def _remote(self, response: FakeHTTPResponse):
        yield response

    def test_request_uses_fixed_auth_profile(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"JENKINS_ARTIFACT_USER": "user", "JENKINS_ARTIFACT_TOKEN": "token"},
            clear=False,
        ):
            request, state = MODULE._build_remote_request(
                "https://jenkins.example.com/api/json",
                method="GET",
                auth_profile="default",
            )
        self.assertEqual(state, "present")
        expected = base64.b64encode(b"user:token").decode("ascii")
        self.assertEqual(request.get_header("Authorization"), "Basic " + expected)

    def test_invalid_utf8_auth_value_is_rejected_without_value_disclosure(self) -> None:
        args = argparse.Namespace(
            url="https://jenkins.example.com/api/json",
            method="HEAD",
            auth_profile="default",
        )
        with mock.patch.dict(
            os.environ,
            {
                "JENKINS_ARTIFACT_USER": "user",
                "JENKINS_ARTIFACT_TOKEN": "\udcffsecret-marker",
            },
            clear=False,
        ):
            errors = io.StringIO()
            with redirect_stderr(errors):
                result = MODULE.cmd_probe_url(args)
        self.assertEqual(result, 2)
        self.assertIn("valid UTF-8", errors.getvalue())
        self.assertNotIn("secret-marker", errors.getvalue())
        self.assertNotIn("udcff", errors.getvalue())

    def test_allowed_host_cannot_be_widened_by_environment(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"JENKINS_ARTIFACT_ALLOWED_HOSTS": "evil.example"},
            clear=False,
        ):
            with self.assertRaisesRegex(ValueError, "host not allowed"):
                MODULE._ensure_allowed_url("https://evil.example/artifact")

    def test_url_policy_rejects_non_https_inline_credentials_fragment_and_host(self) -> None:
        rejected = (
            "http://jenkins.example.com/a",
            "https://user:token@jenkins.example.com/a",
            "https://jenkins.example.com/a#fragment",
            "https://jenkins.example.com/a#",
            "https://jenkins.example.com/a path",
            "https://jenkins.example.com/a\tpath",
            "https://jenkins.example.com/caf\u00e9",
            "https://example.com/a",
        )
        for url in rejected:
            with self.subTest(url=url), self.assertRaises(ValueError):
                MODULE._ensure_allowed_url(url)

    def test_url_policy_rejects_non_default_port_before_auth(self) -> None:
        with mock.patch.object(MODULE, "_add_basic_auth") as add_basic_auth:
            with self.assertRaisesRegex(ValueError, "port"):
                MODULE._build_remote_request(
                    "https://jenkins.example.com:8443/artifact",
                    method="GET",
                    auth_profile="default",
                )
        add_basic_auth.assert_not_called()

    def test_same_origin_redirect_preserves_authorization(self) -> None:
        request = urllib.request.Request("https://jenkins.example.com/start")
        request.add_header("Authorization", "Basic test")
        request.add_header("Proxy-Authorization", "Basic proxy-secret")
        request.add_header("X-Unrelated", "drop-me")
        handler = MODULE.SameOriginRedirectHandler(request.full_url, 2)
        redirected = handler.redirect_request(
            request, io.BytesIO(), 302, "Found", {}, "/next"
        )
        assert redirected is not None
        self.assertEqual(redirected.full_url, "https://jenkins.example.com/next")
        self.assertEqual(redirected.get_header("Authorization"), "Basic test")
        self.assertIsNone(redirected.get_header("Proxy-Authorization"))
        self.assertIsNone(redirected.get_header("X-Unrelated"))

    def test_opener_and_main_wire_the_policy_and_deadline_layers(self) -> None:
        opener = MODULE._build_opener("https://jenkins.example.com/start", 2)
        self.assertTrue(
            any(
                isinstance(handler, MODULE.SameOriginRedirectHandler)
                for handler in opener.handlers
            )
        )

        with mock.patch.object(
            MODULE, "_run_with_hard_deadline", return_value=17
        ) as run_deadline:
            result = MODULE.main(
                ["probe-url", "https://jenkins.example.com/start"]
            )
        self.assertEqual(result, 17)
        parsed_args = run_deadline.call_args.args[0]
        self.assertIs(parsed_args.func, MODULE.cmd_probe_url)
        self.assertEqual(parsed_args.deadline_seconds, MODULE.HARD_DEADLINE_SECONDS)

    def test_redirect_preserves_head_for_302_and_308(self) -> None:
        for code in (302, 308):
            with self.subTest(code=code):
                request = urllib.request.Request(
                    "https://jenkins.example.com/start", method="HEAD"
                )
                handler = MODULE.SameOriginRedirectHandler(request.full_url, 2)
                redirected = handler.redirect_request(
                    request, io.BytesIO(), code, "Redirect", {}, "/next"
                )
                assert redirected is not None
                self.assertEqual(redirected.get_method(), "HEAD")

    def test_redirect_handler_closes_without_unbounded_body_drain(self) -> None:
        for code in (301, 302, 303, 307, 308):
            with self.subTest(code=code):
                request = urllib.request.Request(
                    "https://jenkins.example.com/start", method="HEAD"
                )
                request.timeout = 1.0
                response = FakeHTTPResponse(b"redirect-body")
                handler = MODULE.SameOriginRedirectHandler(request.full_url, 2)
                handler.parent = mock.Mock()
                handler.parent.open.return_value = "redirected-response"
                callback = getattr(handler, "http_error_{}".format(code))
                result = callback(
                    request,
                    response,
                    code,
                    "Redirect",
                    {"Location": "/next"},
                )
                self.assertEqual(result, "redirected-response")
                self.assertTrue(response.closed)
                self.assertEqual(response.read_sizes, [])
                redirected = handler.parent.open.call_args.args[0]
                self.assertEqual(redirected.get_method(), "HEAD")

    def test_redirect_rejects_cross_host_cross_port_and_downgrade(self) -> None:
        initial = "https://jenkins.example.com/start"
        targets = (
            "https://example.com/next",
            "https://jenkins.example.com:444/next",
            "https://jenkins.example.com:0/next",
            "http://jenkins.example.com/next",
            "/next#",
        )
        for target in targets:
            with self.subTest(target=target):
                request = urllib.request.Request(initial)
                request.add_header("Authorization", "Basic secret")
                handler = MODULE.SameOriginRedirectHandler(initial, 2)
                with self.assertRaises(MODULE.UnsafeRedirectError):
                    handler.redirect_request(
                        request, io.BytesIO(), 302, "Found", {}, target
                    )

    def test_redirect_hop_limit_is_enforced(self) -> None:
        request = urllib.request.Request("https://jenkins.example.com/start")
        handler = MODULE.SameOriginRedirectHandler(request.full_url, 1)
        redirected = handler.redirect_request(
            request, io.BytesIO(), 302, "Found", {}, "/one"
        )
        assert redirected is not None
        with self.assertRaisesRegex(MODULE.UnsafeRedirectError, "hop limit"):
            handler.redirect_request(
                redirected, io.BytesIO(), 302, "Found", {}, "/two"
            )

    def test_final_response_origin_is_revalidated(self) -> None:
        request = urllib.request.Request("https://jenkins.example.com/start")
        response = FakeHTTPResponse(b"", final_url="https://example.com/final")
        with mock.patch.object(
            MODULE, "_build_opener", return_value=FakeOpener(response)
        ):
            with self.assertRaises(ValueError):
                with MODULE._open_remote(
                    request, socket_timeout=1.0, max_redirects=1
                ):
                    pass

    def test_chunk_reader_uses_bounded_reads_and_detects_overflow(self) -> None:
        stream = FakeHTTPResponse(b"abcd")
        self.assertEqual(b"".join(MODULE._iter_limited_chunks(stream, 4)), b"abcd")
        self.assertTrue(stream.read_sizes)
        self.assertNotIn(-1, stream.read_sizes)
        self.assertLessEqual(max(stream.read_sizes), 5)

        overflowing = FakeHTTPResponse(b"abcde")
        with self.assertRaises(MODULE.LimitExceeded):
            b"".join(MODULE._iter_limited_chunks(overflowing, 4))

    def test_bounded_seekable_snapshot_translates_negative_reads(self) -> None:
        underlying = FakeHTTPResponse(b"snapshot")
        bounded = MODULE._BoundedSeekableFile(underlying, 8)
        self.assertEqual(bounded.read(), b"snapshot")
        self.assertEqual(underlying.read_sizes, [8])
        with self.assertRaises(MODULE.ArtifactError):
            bounded.seek(9)

    def test_probe_uses_fake_transport_and_bounds_preview(self) -> None:
        response = FakeHTTPResponse(
            b"preview-secret",
            status=200,
            headers={"Content-Type": "text/plain", "Content-Length": "14"},
        )
        observed: List[urllib.request.Request] = []

        @contextlib.contextmanager
        def capture_remote(request: urllib.request.Request, **kwargs: object):
            observed.append(request)
            yield response

        args = argparse.Namespace(
            url="https://jenkins.example.com/api/json?token=query-secret",
            method="GET",
            auth_profile=None,
            socket_timeout=1.0,
            max_redirects=1,
            sniff_bytes=7,
            encoding="utf-8",
        )
        output = io.StringIO()
        with mock.patch.object(MODULE, "_open_remote", new=capture_remote):
            with redirect_stdout(output):
                result = MODULE.cmd_probe_url(args)
        self.assertEqual(result, 0)
        self.assertEqual(observed[0].get_method(), "GET")
        self.assertIn("status=200", output.getvalue())
        self.assertIn("preview", output.getvalue())
        self.assertNotIn("query-secret", output.getvalue())
        self.assertNotIn(-1, response.read_sizes)

    def test_rejected_inline_credentials_are_never_echoed(self) -> None:
        args = argparse.Namespace(
            url="https://user:token-secret@jenkins.example.com/path?key=query-secret",
            method="HEAD",
            auth_profile=None,
        )
        errors = io.StringIO()
        with redirect_stderr(errors):
            result = MODULE.cmd_probe_url(args)
        self.assertEqual(result, 2)
        self.assertIn("https://jenkins.example.com/path", errors.getvalue())
        self.assertNotIn("user", errors.getvalue())
        self.assertNotIn("token-secret", errors.getvalue())
        self.assertNotIn("query-secret", errors.getvalue())

        args.url = "https://jenkins.example.com/path?key=query-secret value"
        errors = io.StringIO()
        with redirect_stderr(errors):
            result = MODULE.cmd_probe_url(args)
        self.assertEqual(result, 2)
        self.assertNotIn("query-secret", errors.getvalue())

    def test_response_framing_rejects_duplicate_length_and_te_cl(self) -> None:
        headers = mock.Mock()
        headers.get_all.side_effect = lambda name: {
            "Content-Length": ["4", "4"],
            "Transfer-Encoding": [],
        }[name]
        with self.assertRaisesRegex(MODULE.ArtifactError, "duplicate"):
            MODULE._response_content_length(headers)

        headers.get_all.side_effect = lambda name: {
            "Content-Length": ["4"],
            "Transfer-Encoding": ["chunked"],
        }[name]
        with self.assertRaisesRegex(MODULE.ArtifactError, "cannot coexist"):
            MODULE._response_content_length(headers)

    def test_probe_rejects_multiline_metadata_and_excess_preview_lines(self) -> None:
        args = argparse.Namespace(
            url="https://jenkins.example.com/api/json",
            method="GET",
            auth_profile=None,
            socket_timeout=1.0,
            max_redirects=1,
            sniff_bytes=2048,
            encoding="utf-8",
        )
        cases = (
            FakeHTTPResponse(
                b"body", headers={"Content-Type": "text/plain\r\nfake=1"}
            ),
            FakeHTTPResponse(b"\n" * (MODULE.HARD_EMIT_LINES + 1)),
        )
        for response in cases:
            with self.subTest(headers=response.headers):
                output = io.StringIO()
                errors = io.StringIO()
                with mock.patch.object(
                    MODULE, "_open_remote", return_value=self._remote(response)
                ), redirect_stdout(output), redirect_stderr(errors):
                    result = MODULE.cmd_probe_url(args)
                self.assertEqual(result, 1)
                self.assertEqual(output.getvalue(), "")
                self.assertIn("error=", errors.getvalue())

    def test_collector_escapes_controls_and_emits_fixed_utf8_bytes(self) -> None:
        collector = MODULE.OutputCollector(max_lines=2, max_bytes=100)
        collector.add("caf\u00e9\x1b\u202e")

        class BinaryStdout:
            def __init__(self) -> None:
                self.buffer = io.BytesIO()

            def write(self, value: str) -> int:
                raise AssertionError("text encoding path must not be used")

        output = BinaryStdout()
        with mock.patch.object(MODULE.sys, "stdout", output):
            collector.emit()
        self.assertEqual(
            output.buffer.getvalue(),
            "caf\u00e9\\x1b\\u202e\n".encode("utf-8"),
        )

    def test_show_url_tail_and_grep_context_are_streamed_and_bounded(self) -> None:
        tail_response = FakeHTTPResponse(b"one\ntwo\nthree\n")
        output = io.StringIO()
        with mock.patch.object(
            MODULE, "_open_remote", return_value=self._remote(tail_response)
        ), redirect_stdout(output):
            result = MODULE.cmd_show_url(self._show_args(tail=2))
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue().splitlines(), ["two", "three"])

        grep_response = FakeHTTPResponse(b"one\ntwo\nERROR\nfour\nfive\n")
        output = io.StringIO()
        with mock.patch.object(
            MODULE, "_open_remote", return_value=self._remote(grep_response)
        ), redirect_stdout(output):
            result = MODULE.cmd_show_url(
                self._show_args(
                    grep="error", ignore_case=True, context=1, line_numbers=True
                )
            )
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue().splitlines(), ["2:two", "3:ERROR", "4:four"])

    def test_show_url_tail_applies_emit_bytes_to_final_window(self) -> None:
        response = FakeHTTPResponse(b"discard-this-line\nok\n")
        output = io.StringIO()
        with mock.patch.object(
            MODULE, "_open_remote", return_value=self._remote(response)
        ), redirect_stdout(output):
            result = MODULE.cmd_show_url(
                self._show_args(tail=1, max_emit_bytes=3)
            )
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), "ok\n")

    def test_show_url_tail_rejects_oversized_final_window(self) -> None:
        response = FakeHTTPResponse(b"ok\nfinal-too-long\n")
        output = io.StringIO()
        errors = io.StringIO()
        with mock.patch.object(
            MODULE, "_open_remote", return_value=self._remote(response)
        ), redirect_stdout(output), redirect_stderr(errors):
            result = MODULE.cmd_show_url(
                self._show_args(tail=1, max_emit_bytes=3)
            )
        self.assertEqual(result, 1)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("emitted byte limit", errors.getvalue())

    def test_show_url_head_stops_before_later_scan_limits(self) -> None:
        response = FakeHTTPResponse(b"one\ntwo\n")
        output = io.StringIO()
        with mock.patch.object(
            MODULE, "_open_remote", return_value=self._remote(response)
        ), redirect_stdout(output):
            result = MODULE.cmd_show_url(
                self._show_args(head=1, max_scan_lines=1)
            )
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue().splitlines(), ["one"])

    def test_show_url_head_allows_declared_body_larger_than_scan_limit(self) -> None:
        response = FakeHTTPResponse(
            b"one\ntwo\nextra", headers={"Content-Length": "999"}
        )
        output = io.StringIO()
        with mock.patch.object(
            MODULE, "_open_remote", return_value=self._remote(response)
        ), redirect_stdout(output):
            result = MODULE.cmd_show_url(self._show_args(head=1, max_bytes=4))
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue().splitlines(), ["one"])
        self.assertEqual(response.read_sizes, [4])

    def test_show_url_rejects_content_length_before_body_read(self) -> None:
        response = FakeHTTPResponse(b"small", headers={"Content-Length": "999"})
        errors = io.StringIO()
        with mock.patch.object(
            MODULE, "_open_remote", return_value=self._remote(response)
        ), redirect_stderr(errors):
            result = MODULE.cmd_show_url(self._show_args(max_bytes=4))
        self.assertEqual(result, 1)
        self.assertEqual(response.read_sizes, [])
        self.assertIn("Content-Length", errors.getvalue())

    def test_show_url_rejects_early_eof_against_content_length(self) -> None:
        response = FakeHTTPResponse(b"abc", headers={"Content-Length": "4"})
        errors = io.StringIO()
        with mock.patch.object(
            MODULE, "_open_remote", return_value=self._remote(response)
        ), redirect_stderr(errors):
            result = MODULE.cmd_show_url(self._show_args())
        self.assertEqual(result, 1)
        self.assertIn("declared length", errors.getvalue())

    def test_show_url_rejects_unknown_length_line_scan_line_and_emission_overflow(self) -> None:
        cases = (
            (b"abcde", {"max_bytes": 4}, "byte limit"),
            (b"a\nb\n", {"max_scan_lines": 1}, "line scan limit"),
            (b"abcde\n", {"max_line_bytes": 4}, "line byte limit"),
            (b"a\nb\n", {"max_emit_lines": 1}, "emitted line limit"),
            (b"abcd\n", {"max_emit_bytes": 4}, "emitted byte limit"),
        )
        for payload, changes, expected in cases:
            with self.subTest(expected=expected):
                response = FakeHTTPResponse(payload)
                errors = io.StringIO()
                with mock.patch.object(
                    MODULE, "_open_remote", return_value=self._remote(response)
                ), redirect_stderr(errors):
                    result = MODULE.cmd_show_url(self._show_args(**changes))
                self.assertEqual(result, 1)
                self.assertIn(expected, errors.getvalue())

    def test_fetch_refuses_existing_output_before_remote_open(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            output = pathlib.Path(directory) / "artifact"
            output.write_bytes(b"keep")
            with mock.patch.object(
                MODULE, "_open_remote"
            ) as open_remote, redirect_stderr(io.StringIO()):
                result = MODULE.cmd_fetch_url(self._fetch_args(output))
            self.assertEqual(result, 2)
            open_remote.assert_not_called()
            self.assertEqual(output.read_bytes(), b"keep")

    def test_fetch_streams_to_new_mode_0600_file(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            output = pathlib.Path(directory) / "artifact"
            response = FakeHTTPResponse(b"payload")
            with mock.patch.object(
                MODULE, "_open_remote", return_value=self._remote(response)
            ), redirect_stdout(io.StringIO()):
                result = MODULE.cmd_fetch_url(self._fetch_args(output))
            self.assertEqual(result, 0)
            self.assertEqual(output.read_bytes(), b"payload")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertNotIn(-1, response.read_sizes)

    def test_fetch_overflow_leaves_no_final_or_temp_file(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            parent = pathlib.Path(directory)
            output = parent / "artifact"
            response = FakeHTTPResponse(b"abcde")
            with mock.patch.object(
                MODULE, "_open_remote", return_value=self._remote(response)
            ), redirect_stderr(io.StringIO()):
                result = MODULE.cmd_fetch_url(self._fetch_args(output, max_bytes=4))
            self.assertEqual(result, 1)
            self.assertFalse(output.exists())
            self.assertEqual(list(parent.glob(".*.artifact-*.tmp")), [])

    def test_fetch_declared_length_mismatch_leaves_no_final(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            parent = pathlib.Path(directory)
            output = parent / "artifact"
            response = FakeHTTPResponse(b"abc", headers={"Content-Length": "4"})
            with mock.patch.object(
                MODULE, "_open_remote", return_value=self._remote(response)
            ), redirect_stderr(io.StringIO()):
                result = MODULE.cmd_fetch_url(self._fetch_args(output))
            self.assertEqual(result, 1)
            self.assertFalse(output.exists())
            self.assertEqual(list(parent.glob(".*.artifact-*.tmp")), [])

    def test_fetch_reports_publish_fsync_failure_as_local_io(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            parent = pathlib.Path(directory)
            output = parent / "artifact"
            response = FakeHTTPResponse(b"payload")
            errors = io.StringIO()
            with mock.patch.object(
                MODULE, "_open_remote", return_value=self._remote(response)
            ), mock.patch.object(
                MODULE.os,
                "fsync",
                side_effect=OSError(errno.ENOSPC, "No space left on device"),
            ), redirect_stderr(errors):
                result = MODULE.cmd_fetch_url(self._fetch_args(output))
            self.assertEqual(result, 1)
            self.assertIn("local I/O failure", errors.getvalue())
            self.assertNotIn("remote I/O failure", errors.getvalue())
            self.assertFalse(output.exists())
            self.assertEqual(list(parent.glob(".*.artifact-*.tmp")), [])

    def test_output_parent_must_preexist_and_nested_symlinks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = pathlib.Path(directory)
            with self.assertRaisesRegex(MODULE.ArtifactError, "must already exist"):
                MODULE.AtomicPublisher.prepare(str(root / "missing" / "out"))

            target = root / "target"
            target.mkdir()
            link = root / "link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(OSError):
                MODULE.AtomicPublisher.prepare(str(link / "out"))

    def test_output_rejects_non_sticky_group_or_other_writable_parent(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            parent = pathlib.Path(directory)
            original_mode = stat.S_IMODE(parent.stat().st_mode)
            try:
                parent.chmod(0o777)
                with self.assertRaisesRegex(MODULE.ArtifactError, "unsafe"):
                    MODULE.AtomicPublisher.prepare(str(parent / "out"))
            finally:
                parent.chmod(original_mode)

    def test_output_rejects_untrusted_directory_owner_even_when_not_writable(self) -> None:
        info = mock.Mock(
            st_mode=stat.S_IFDIR | 0o755,
            st_uid=1 if os.geteuid() == 0 else os.geteuid() + 1,
        )
        with self.assertRaisesRegex(MODULE.ArtifactError, "untrusted"):
            MODULE._ensure_safe_directory_policy(info)

    def test_atomic_publish_tolerates_sibling_churn(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            parent = pathlib.Path(directory)
            output = parent / "artifact"
            publisher = MODULE.AtomicPublisher.prepare(str(output))
            try:
                (parent / "unrelated").write_text("churn", encoding="utf-8")
                with publisher.file() as file_object:
                    file_object.write(b"payload")
                publisher.publish(7)
            finally:
                publisher.abort()
                publisher.close()
            self.assertEqual(output.read_bytes(), b"payload")

    def test_atomic_publish_rejects_destination_race_without_clobbering(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            parent = pathlib.Path(directory)
            output = parent / "artifact"
            publisher = MODULE.AtomicPublisher.prepare(str(output))
            try:
                with publisher.file() as file_object:
                    file_object.write(b"ours")
                output.write_bytes(b"theirs")
                with self.assertRaisesRegex(MODULE.ArtifactError, "appeared"):
                    publisher.publish(4)
            finally:
                publisher.abort()
                publisher.close()
            self.assertEqual(output.read_bytes(), b"theirs")

    def test_atomic_publish_rejects_parent_access_policy_change(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            parent = pathlib.Path(directory)
            output = parent / "artifact"
            publisher = MODULE.AtomicPublisher.prepare(str(output))
            original_mode = stat.S_IMODE(parent.stat().st_mode)
            try:
                with publisher.file() as file_object:
                    file_object.write(b"payload")
                parent.chmod(0o700 if original_mode != 0o700 else 0o755)
                with self.assertRaisesRegex(MODULE.ArtifactError, "access policy"):
                    publisher.publish(7)
            finally:
                parent.chmod(original_mode)
                publisher.abort()
                publisher.close()
            self.assertFalse(output.exists())

    def test_atomic_publish_rejects_parent_identity_replacement(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = pathlib.Path(directory)
            parent = root / "parent"
            parent.mkdir()
            output = parent / "artifact"
            publisher = MODULE.AtomicPublisher.prepare(str(output))
            displaced = root / "displaced"
            try:
                with publisher.file() as file_object:
                    file_object.write(b"payload")
                parent.rename(displaced)
                parent.mkdir()
                with self.assertRaisesRegex(MODULE.ArtifactError, "identity"):
                    publisher.publish(7)
            finally:
                publisher.abort()
                publisher.close()
            self.assertFalse(output.exists())
            self.assertEqual(list(displaced.glob(".*.artifact-*.tmp")), [])

    def test_atomic_publish_revalidates_parent_after_link_and_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            parent = pathlib.Path(directory)
            output = parent / "artifact"
            publisher = MODULE.AtomicPublisher.prepare(str(output))
            original_mode = stat.S_IMODE(parent.stat().st_mode)
            changed_mode = 0o755 if original_mode != 0o755 else 0o700
            real_link = os.link

            def link_then_change_parent(*args: object, **kwargs: object) -> None:
                real_link(*args, **kwargs)
                parent.chmod(changed_mode)

            try:
                with publisher.file() as file_object:
                    file_object.write(b"payload")
                with mock.patch.object(
                    MODULE.os, "link", side_effect=link_then_change_parent
                ), self.assertRaisesRegex(MODULE.ArtifactError, "access policy"):
                    publisher.publish(7)
                self.assertFalse(output.exists())
            finally:
                parent.chmod(original_mode)
                publisher.abort()
                publisher.close()
            self.assertFalse(output.exists())
            self.assertEqual(list(parent.glob(".*.artifact-*.tmp")), [])

    def test_atomic_publish_rejects_same_inode_length_change(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            output = pathlib.Path(directory) / "artifact"
            publisher = MODULE.AtomicPublisher.prepare(str(output))
            try:
                with publisher.file() as file_object:
                    file_object.write(b"payload")
                os.ftruncate(publisher.temp_fd, 1)
                with self.assertRaisesRegex(MODULE.ArtifactError, "length"):
                    publisher.publish(7)
            finally:
                publisher.abort()
                publisher.close()
            self.assertFalse(output.exists())

    def test_cleanup_refuses_parent_access_policy_change(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            parent = pathlib.Path(directory)
            output = parent / "artifact"
            publisher = MODULE.AtomicPublisher.prepare(str(output))
            receipt = MODULE.TempReceipt(
                parent_path=publisher.parent_path,
                parent_device=publisher.parent_snapshot.device,
                parent_inode=publisher.parent_snapshot.inode,
                parent_mode=publisher.parent_snapshot.mode,
                parent_uid=publisher.parent_snapshot.uid,
                parent_gid=publisher.parent_snapshot.gid,
                final_name=publisher.final_name,
                temp_name=publisher.temp_name,
                temp_device=publisher.temp_device,
                temp_inode=publisher.temp_inode,
            )
            original_mode = stat.S_IMODE(parent.stat().st_mode)
            try:
                parent.chmod(0o777)
                self.assertEqual(MODULE._cleanup_receipt(receipt), "inconclusive")
                self.assertTrue((parent / publisher.temp_name).exists())
            finally:
                parent.chmod(original_mode)
                self.assertEqual(MODULE._cleanup_receipt(receipt), "complete")
                publisher.close()

    def test_cleanup_removes_exact_temp_while_preserving_foreign_final(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            parent = pathlib.Path(directory)
            parent.chmod(0o1777)
            output = parent / "artifact"
            publisher = MODULE.AtomicPublisher.prepare(str(output))
            receipt = MODULE.TempReceipt(
                parent_path=publisher.parent_path,
                parent_device=publisher.parent_snapshot.device,
                parent_inode=publisher.parent_snapshot.inode,
                parent_mode=publisher.parent_snapshot.mode,
                parent_uid=publisher.parent_snapshot.uid,
                parent_gid=publisher.parent_snapshot.gid,
                final_name=publisher.final_name,
                temp_name=publisher.temp_name,
                temp_device=publisher.temp_device,
                temp_inode=publisher.temp_inode,
            )
            output.write_bytes(b"foreign")
            try:
                self.assertEqual(MODULE._cleanup_receipt(receipt), "inconclusive")
                self.assertEqual(output.read_bytes(), b"foreign")
                self.assertFalse((parent / publisher.temp_name).exists())
            finally:
                output.unlink()
                publisher.close()

    def test_full_wall_deadline_stops_sleep_blocked_read_regex_and_decompression(self) -> None:
        read_fd, write_fd = os.pipe()
        compressed = zlib.compress(b"x" * 1024 * 1024)
        cases = (
            argparse.Namespace(
                func=_sleep_worker, deadline_seconds=0.2, sleep_seconds=5.0
            ),
            argparse.Namespace(
                func=_blocking_read_worker,
                deadline_seconds=0.2,
                blocking_fd=read_fd,
            ),
            argparse.Namespace(
                func=_regex_worker,
                deadline_seconds=0.2,
                regex_length=50_000,
            ),
            argparse.Namespace(
                func=_decompression_worker,
                deadline_seconds=0.2,
                compressed_payload=compressed,
            ),
        )
        try:
            for args in cases:
                with self.subTest(worker=args.func.__name__), redirect_stderr(io.StringIO()):
                    started = time.monotonic()
                    result = MODULE._run_with_hard_deadline(args)
                    elapsed = time.monotonic() - started
                self.assertEqual(result, 124)
                self.assertLess(elapsed, 2.0)
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_deadline_cleans_exact_unpublished_temp(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            parent = pathlib.Path(directory)
            output = parent / "artifact"
            milestone = parent / "prepared.milestone"
            args = argparse.Namespace(
                func=_stalled_publish_worker,
                deadline_seconds=1.0,
                sleep_seconds=5.0,
                output=str(output),
                milestone=str(milestone),
            )
            errors = io.StringIO()
            with redirect_stderr(errors):
                result = MODULE._run_with_hard_deadline(args)
            self.assertEqual(result, 124)
            self.assertEqual(milestone.read_text(encoding="utf-8"), "prepared")
            self.assertIn("cleanup=complete", errors.getvalue())
            self.assertFalse(output.exists())
            self.assertEqual(list(parent.glob(".*.artifact-*.tmp")), [])

    def test_deadline_rolls_back_exact_published_file_before_worker_success(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            parent = pathlib.Path(directory)
            output = parent / "artifact"
            milestone = parent / "published.milestone"
            args = argparse.Namespace(
                func=_published_stall_worker,
                deadline_seconds=1.0,
                sleep_seconds=5.0,
                output=str(output),
                milestone=str(milestone),
            )
            errors = io.StringIO()
            with redirect_stderr(errors):
                result = MODULE._run_with_hard_deadline(args)
            self.assertEqual(result, 124)
            self.assertEqual(milestone.read_text(encoding="utf-8"), "published")
            self.assertIn("cleanup=complete", errors.getvalue())
            self.assertFalse(output.exists())
            self.assertEqual(list(parent.glob(".*.artifact-*.tmp")), [])

    def test_deadline_during_real_temp_to_receipt_window_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            parent = pathlib.Path(directory)
            milestone = parent / "temp-created.milestone"
            args = argparse.Namespace(
                func=_delayed_receipt_worker,
                deadline_seconds=1.0,
                receipt_delay=5.0,
                output=str(parent / "artifact"),
                milestone=str(milestone),
            )
            errors = io.StringIO()
            with redirect_stderr(errors):
                result = MODULE._run_with_hard_deadline(args)
            self.assertEqual(result, 124)
            self.assertEqual(milestone.read_text(encoding="utf-8"), "temp-created")
            self.assertIn("cleanup=inconclusive", errors.getvalue())
            self.assertEqual(len(list(parent.glob(".*.artifact-*.tmp"))), 1)

    def test_parent_observation_at_or_after_deadline_is_not_accepted(self) -> None:
        args = argparse.Namespace(
            func=_sleep_worker,
            deadline_seconds=0.5,
            sleep_seconds=0.0,
        )
        with mock.patch.object(MODULE.time, "monotonic", side_effect=(10.0, 10.6)):
            with mock.patch.object(MODULE.os, "fork", return_value=12345):
                with mock.patch.object(
                    MODULE.os, "waitpid", return_value=(12345, 0)
                ):
                    with mock.patch.object(MODULE.os, "kill") as kill:
                        with redirect_stderr(io.StringIO()):
                            result = MODULE._run_with_hard_deadline(args)
        self.assertEqual(result, 124)
        kill.assert_not_called()

    def test_parent_interrupt_during_post_fork_setup_kills_and_reaps_worker(
        self,
    ) -> None:
        args = argparse.Namespace(
            func=_sleep_worker,
            deadline_seconds=0.5,
            sleep_seconds=0.0,
        )
        signal_mask_calls = 0

        def interrupt_first_restore(_: int, __: object) -> frozenset:
            nonlocal signal_mask_calls
            signal_mask_calls += 1
            if signal_mask_calls == 2:
                raise KeyboardInterrupt
            return frozenset()

        with mock.patch.object(MODULE.os, "fork", return_value=12345):
            with mock.patch.object(
                MODULE.signal,
                "pthread_sigmask",
                side_effect=interrupt_first_restore,
            ):
                with mock.patch.object(
                    MODULE.os, "waitpid", return_value=(12345, 0)
                ) as waitpid:
                    with mock.patch.object(MODULE.os, "kill") as kill:
                        with redirect_stderr(io.StringIO()):
                            with self.assertRaises(KeyboardInterrupt):
                                MODULE._run_with_hard_deadline(args)
        kill.assert_called_once_with(12345, signal.SIGKILL)
        waitpid.assert_called_once_with(12345, 0)

    def test_interrupt_after_waitpid_reap_does_not_signal_reused_pid(self) -> None:
        args = argparse.Namespace(
            func=_sleep_worker,
            deadline_seconds=0.5,
            sleep_seconds=0.0,
        )
        signal_mask_calls = 0

        def interrupt_reap_restore(_: int, __: object) -> frozenset:
            nonlocal signal_mask_calls
            signal_mask_calls += 1
            if signal_mask_calls == 4:
                raise KeyboardInterrupt
            return frozenset()

        with mock.patch.object(
            MODULE.time, "monotonic", side_effect=(10.0, 10.1, 10.1)
        ):
            with mock.patch.object(MODULE.os, "fork", return_value=12345):
                with mock.patch.object(
                    MODULE.signal,
                    "pthread_sigmask",
                    side_effect=interrupt_reap_restore,
                ):
                    with mock.patch.object(
                        MODULE.os, "waitpid", return_value=(12345, 0)
                    ) as waitpid:
                        with mock.patch.object(MODULE.os, "kill") as kill:
                            with redirect_stderr(io.StringIO()):
                                with self.assertRaises(KeyboardInterrupt):
                                    MODULE._run_with_hard_deadline(args)
        kill.assert_not_called()
        waitpid.assert_called_once_with(12345, os.WNOHANG)

    @unittest.skipUnless(
        hasattr(os, "fork")
        and hasattr(signal, "pthread_sigmask")
        and hasattr(signal, "SIGCHLD"),
        "requires POSIX child-signal handling",
    )
    def test_inherited_sigchld_ignore_preserves_worker_exit_status(self) -> None:
        previous = signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        try:
            for worker, expected in ((_sleep_worker, 0), (_failure_worker, 1)):
                with self.subTest(worker=worker.__name__):
                    args = argparse.Namespace(
                        func=worker,
                        deadline_seconds=0.5,
                        sleep_seconds=0.0,
                    )
                    with redirect_stderr(io.StringIO()):
                        result = MODULE._run_with_hard_deadline(args)
                    self.assertEqual(result, expected)
                    self.assertEqual(
                        signal.getsignal(signal.SIGCHLD), signal.SIG_IGN
                    )
        finally:
            signal.signal(signal.SIGCHLD, previous)

    def test_signal_failure_cleans_receipted_temp_and_published_output(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            parent = pathlib.Path(directory)
            for worker, state in (
                (_signaled_prepared_worker, "prepared"),
                (_signaled_published_worker, "published"),
            ):
                with self.subTest(state=state):
                    output = parent / (state + ".artifact")
                    milestone = parent / (state + ".milestone")
                    args = argparse.Namespace(
                        func=worker,
                        deadline_seconds=2.0,
                        output=str(output),
                        milestone=str(milestone),
                    )
                    errors = io.StringIO()
                    with redirect_stderr(errors):
                        result = MODULE._run_with_hard_deadline(args)
                    self.assertEqual(result, 1)
                    self.assertEqual(
                        milestone.read_text(encoding="utf-8"), state
                    )
                    self.assertIn("cleanup=complete", errors.getvalue())
                    self.assertFalse(output.exists())

    def test_nonzero_exit_rolls_back_receipted_published_output(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            output = pathlib.Path(directory) / "artifact"
            args = argparse.Namespace(
                func=_nonzero_published_worker,
                deadline_seconds=2.0,
                output=str(output),
            )
            errors = io.StringIO()
            with redirect_stderr(errors):
                result = MODULE._run_with_hard_deadline(args)
            self.assertEqual(result, 1)
            self.assertIn("cleanup=complete", errors.getvalue())
            self.assertFalse(output.exists())

    def test_nonzero_output_worker_reports_missing_or_truncated_receipt(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            for truncated_receipt in (False, True):
                with self.subTest(truncated_receipt=truncated_receipt):
                    args = argparse.Namespace(
                        func=_nonzero_without_receipt_worker,
                        deadline_seconds=2.0,
                        output=str(pathlib.Path(directory) / "artifact"),
                        truncated_receipt=truncated_receipt,
                    )
                    errors = io.StringIO()
                    with redirect_stderr(errors):
                        result = MODULE._run_with_hard_deadline(args)
                    self.assertEqual(result, 1)
                    self.assertIn("cleanup=inconclusive", errors.getvalue())

    def test_parent_interrupt_cleans_receipted_temp_before_reraising(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            parent = pathlib.Path(directory)
            output = parent / "artifact"
            milestone = parent / "prepared.milestone"
            read_fd, write_fd = os.pipe()
            args = argparse.Namespace(
                func=_interruptible_prepared_worker,
                deadline_seconds=5.0,
                output=str(output),
                milestone=str(milestone),
                blocking_fd=read_fd,
            )
            real_sleep = time.sleep

            def interrupt_after_prepare(_: float) -> None:
                deadline = time.monotonic() + 2.0
                while not milestone.exists() and time.monotonic() < deadline:
                    real_sleep(0.005)
                if not milestone.exists():
                    self.fail("worker did not prepare output before parent interrupt")
                raise KeyboardInterrupt

            errors = io.StringIO()
            try:
                with mock.patch.object(
                    MODULE.time, "sleep", side_effect=interrupt_after_prepare
                ):
                    with redirect_stderr(errors), self.assertRaises(KeyboardInterrupt):
                        MODULE._run_with_hard_deadline(args)
            finally:
                os.close(read_fd)
                os.close(write_fd)
            self.assertIn("cleanup=complete", errors.getvalue())
            self.assertFalse(output.exists())
            self.assertEqual(list(parent.glob(".*.artifact-*.tmp")), [])

    def test_post_reap_drain_interrupt_cleans_published_output(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            parent = pathlib.Path(directory)
            output = parent / "artifact"
            milestone = parent / "published.milestone"
            args = argparse.Namespace(
                func=_published_stall_worker,
                deadline_seconds=2.0,
                sleep_seconds=0.0,
                output=str(output),
                milestone=str(milestone),
            )
            state = {"reaped": False, "interrupted": False}
            real_waitpid_tracked = MODULE._waitpid_tracked
            real_read = MODULE.os.read

            def track_reap(
                worker: object, options: int, blocked_signals: frozenset
            ) -> int:
                result = real_waitpid_tracked(worker, options, blocked_signals)
                state["reaped"] = bool(worker.reaped)
                return result

            def interrupt_first_post_reap_read(fd: int, size: int) -> bytes:
                if state["reaped"] and not state["interrupted"]:
                    state["interrupted"] = True
                    raise KeyboardInterrupt
                return real_read(fd, size)

            errors = io.StringIO()
            with mock.patch.object(
                MODULE, "_waitpid_tracked", side_effect=track_reap
            ), mock.patch.object(
                MODULE.os, "read", side_effect=interrupt_first_post_reap_read
            ), redirect_stderr(errors), self.assertRaises(KeyboardInterrupt):
                MODULE._run_with_hard_deadline(args)
            self.assertTrue(state["interrupted"])
            self.assertIn("cleanup=complete", errors.getvalue())
            self.assertFalse(output.exists())
            self.assertEqual(list(parent.glob(".*.artifact-*.tmp")), [])

    def test_post_reap_receipt_parse_interrupt_cleans_published_output(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            parent = pathlib.Path(directory)
            output = parent / "artifact"
            milestone = parent / "published.milestone"
            args = argparse.Namespace(
                func=_published_stall_worker,
                deadline_seconds=2.0,
                sleep_seconds=0.0,
                output=str(output),
                milestone=str(milestone),
            )
            real_parse_receipt = MODULE._parse_receipt
            parse_calls = 0

            def interrupt_first_parse(raw: bytes) -> Optional[object]:
                nonlocal parse_calls
                parse_calls += 1
                if parse_calls == 1:
                    raise KeyboardInterrupt
                return real_parse_receipt(raw)

            errors = io.StringIO()
            with mock.patch.object(
                MODULE, "_parse_receipt", side_effect=interrupt_first_parse
            ), redirect_stderr(errors), self.assertRaises(KeyboardInterrupt):
                MODULE._run_with_hard_deadline(args)
            self.assertEqual(parse_calls, 2)
            self.assertIn("cleanup=complete", errors.getvalue())
            self.assertFalse(output.exists())
            self.assertEqual(list(parent.glob(".*.artifact-*.tmp")), [])

    def test_cli_limit_flags_can_only_tighten_hard_ceilings(self) -> None:
        parser = MODULE.build_parser()
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "fetch-url",
                    "https://jenkins.example.com/a",
                    "--output",
                    "/tmp/out",
                    "--max-bytes",
                    str(MODULE.HARD_REMOTE_BYTES + 1),
                ]
            )
        for argv in (
            ["zip-list", "/tmp/archive.zip", "--max-selected-members", "1"],
            [
                "zip-extract",
                "/tmp/archive.zip",
                "payload",
                "--output",
                "/tmp/output",
                "--max-selected-members",
                "1",
            ],
        ):
            with self.subTest(argv=argv), redirect_stderr(
                io.StringIO()
            ), self.assertRaises(SystemExit):
                parser.parse_args(argv)
        parsed = parser.parse_args(
            [
                "zip-show",
                "/tmp/archive.zip",
                "payload",
                "--max-selected-members",
                "1",
            ]
        )
        self.assertEqual(parsed.max_selected_members, 1)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "probe-url",
                    "https://jenkins.example.com/a",
                    "--deadline-seconds",
                    str(MODULE.HARD_DEADLINE_SECONDS + 1),
                ]
            )

    def test_text_selection_modes_are_mutually_exclusive(self) -> None:
        parser = MODULE.build_parser()
        for argv in (
            [
                "show-url",
                "https://jenkins.example.com/consoleText",
                "--head",
                "1",
                "--tail",
                "1",
            ],
            [
                "show-url",
                "https://jenkins.example.com/consoleText",
                "--grep",
                "ERROR",
                "--head",
                "1",
            ],
            [
                "show-url",
                "https://jenkins.example.com/consoleText",
                "--grep",
                "ERROR",
                "--tail",
                "1",
            ],
            [
                "zip-show",
                "/tmp/archive.zip",
                "payload",
                "--head",
                "1",
                "--tail",
                "1",
            ],
            [
                "zip-show",
                "/tmp/archive.zip",
                "payload",
                "--grep",
                "ERROR",
                "--head",
                "1",
            ],
            [
                "zip-show",
                "/tmp/archive.zip",
                "payload",
                "--grep",
                "ERROR",
                "--tail",
                "1",
            ],
        ):
            with self.subTest(argv=argv), redirect_stderr(
                io.StringIO()
            ), self.assertRaises(SystemExit):
                parser.parse_args(argv)

    def test_text_selection_rejects_explicit_zero_head_and_tail(self) -> None:
        parser = MODULE.build_parser()
        for argv in (
            [
                "show-url",
                "https://jenkins.example.com/consoleText",
                "--head",
                "0",
            ],
            [
                "show-url",
                "https://jenkins.example.com/consoleText",
                "--tail",
                "0",
            ],
            ["zip-show", "/tmp/archive.zip", "payload", "--head", "0"],
            ["zip-show", "/tmp/archive.zip", "payload", "--tail", "0"],
        ):
            with self.subTest(argv=argv), redirect_stderr(
                io.StringIO()
            ), self.assertRaises(SystemExit):
                parser.parse_args(argv)

    def test_zip_list_rejects_explicit_zero_limit(self) -> None:
        parser = MODULE.build_parser()
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(["zip-list", "/tmp/archive.zip", "--limit", "0"])

    def test_parser_escapes_control_characters_from_raw_argv_errors(self) -> None:
        errors = io.StringIO()
        with redirect_stderr(errors), self.assertRaises(SystemExit):
            MODULE.main(
                [
                    "zip-list",
                    "/tmp/archive.zip",
                    "--bad\ninjected=1\x1b",
                ]
            )
        rendered = errors.getvalue()
        self.assertEqual(len(rendered.splitlines()), 1)
        self.assertIn("\\x0a", rendered)
        self.assertIn("\\x1b", rendered)
        self.assertNotIn("\ninjected=1", rendered)

    def test_zip_inventory_rejects_traversal_absolute_backslash_and_drive_paths(self) -> None:
        unsafe_names = (
            "../evil",
            "/absolute",
            "dir\\evil",
            "C:/evil",
            "a//b",
            "a//",
            "logs/trailing.",
            "logs/trailing ",
        )
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            for index, name in enumerate(unsafe_names):
                with self.subTest(name=name):
                    path = pathlib.Path(directory) / "unsafe-{}.zip".format(index)
                    self._write_zip(path, [(name, b"payload")])
                    with self.assertRaises(MODULE.ArtifactError):
                        with MODULE._open_validated_zip(
                            str(path), MODULE._zip_limits(self._zip_args(path))
                        ):
                            pass

    def test_zip_inventory_rejects_non_printable_member_names(self) -> None:
        unsafe_names = (
            "logs/del\x7f.txt",
            "logs/c1\u0085.txt",
            "logs/line\u2028break.txt",
            "logs/bidi\u202etxt",
        )
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            for index, name in enumerate(unsafe_names):
                with self.subTest(name=repr(name)):
                    path = pathlib.Path(directory) / "control-{}.zip".format(index)
                    self._write_zip(path, [(name, b"payload")])
                    with self.assertRaisesRegex(
                        MODULE.ArtifactError, "non-printable"
                    ):
                        with MODULE._open_validated_zip(
                            str(path), MODULE._zip_limits(self._zip_args(path))
                        ):
                            pass

    def test_zip_inventory_rejects_exact_casefold_and_unicode_duplicates(self) -> None:
        duplicate_sets = (
            (("same", b"one"), ("same", b"two")),
            (("A.txt", b"one"), ("a.txt", b"two")),
            (("caf\u00e9.txt", b"one"), ("cafe\u0301.txt", b"two")),
        )
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            for index, entries in enumerate(duplicate_sets):
                path = pathlib.Path(directory) / "duplicate-{}.zip".format(index)
                self._write_zip(path, list(entries))
                with self.subTest(entries=entries), self.assertRaisesRegex(
                    MODULE.ArtifactError, "duplicate portable"
                ):
                    with MODULE._open_validated_zip(
                        str(path), MODULE._zip_limits(self._zip_args(path))
                    ):
                        pass

    def test_zip_inventory_rejects_symlink_special_and_encrypted_members(self) -> None:
        entries = []
        for name, mode, flags in (
            ("link", stat.S_IFLNK | 0o777, 0),
            ("fifo", stat.S_IFIFO | 0o600, 0),
            ("secret", stat.S_IFREG | 0o600, 1),
        ):
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = mode << 16
            info.flag_bits = flags
            entries.append(info)
        with self.assertRaisesRegex(MODULE.ArtifactError, "symbolic-link"):
            MODULE._validate_member_type(entries[0])
        with self.assertRaisesRegex(MODULE.ArtifactError, "special-file"):
            MODULE._validate_member_type(entries[1])
        with self.assertRaisesRegex(MODULE.ArtifactError, "encrypted"):
            MODULE._validate_member_type(entries[2])

    def test_zip_inventory_rejects_directory_type_name_disagreement(self) -> None:
        directory = zipfile.ZipInfo("not-marked-as-directory")
        directory.create_system = 3
        directory.external_attr = (stat.S_IFDIR | 0o700) << 16
        with self.assertRaisesRegex(MODULE.ArtifactError, "type and member name"):
            MODULE._validate_member_type(directory)

        regular = zipfile.ZipInfo("marked-as-directory/")
        regular.create_system = 3
        regular.external_attr = (stat.S_IFREG | 0o600) << 16
        with self.assertRaisesRegex(MODULE.ArtifactError, "type and member name"):
            MODULE._validate_member_type(regular)

        dos_volume = zipfile.ZipInfo("volume")
        dos_volume.create_system = 0
        dos_volume.external_attr = 0x08
        with self.assertRaisesRegex(MODULE.ArtifactError, "volume-label"):
            MODULE._validate_member_type(dos_volume)

        dos_directory = zipfile.ZipInfo("not-a-directory")
        dos_directory.create_system = 0
        dos_directory.external_attr = 0x10
        with self.assertRaisesRegex(MODULE.ArtifactError, "DOS type"):
            MODULE._validate_member_type(dos_directory)

        unsupported = zipfile.ZipInfo("payload")
        unsupported.create_system = 7
        with self.assertRaisesRegex(MODULE.ArtifactError, "origin system"):
            MODULE._validate_member_type(unsupported)

    def test_zip_inventory_rejects_nul_truncated_original_name(self) -> None:
        info = zipfile.ZipInfo("safe\x00../hidden")
        self.assertNotEqual(info.orig_filename, info.filename)
        fake_archive = mock.Mock()
        fake_archive.infolist.return_value = [info]
        limits = MODULE._zip_limits(
            self._zip_args(pathlib.Path("/tmp/not-opened.zip"))
        )
        with self.assertRaisesRegex(MODULE.ArtifactError, "truncated or is ambiguous"):
            MODULE._validate_zip_inventory(fake_archive, limits)

    def test_zip_inventory_rejects_unbounded_decompressor_methods(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            for index, compression in enumerate(
                (zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA)
            ):
                archive = pathlib.Path(directory) / "method-{}.zip".format(index)
                self._write_zip(archive, [("payload", b"x" * 1024)], compression)
                limits = MODULE._zip_limits(self._zip_args(archive))
                with self.subTest(compression=compression), self.assertRaisesRegex(
                    MODULE.ArtifactError, "compression method"
                ):
                    with MODULE._open_validated_zip(str(archive), limits):
                        pass

    def test_zip_open_converts_unsupported_version_to_artifact_error(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            archive = pathlib.Path(directory) / "unsupported-version.zip"
            self._write_zip(
                archive,
                [("payload", b"content")],
                compression=zipfile.ZIP_STORED,
            )
            raw = bytearray(archive.read_bytes())
            local = raw.find(b"PK\x03\x04")
            central = raw.find(b"PK\x01\x02")
            self.assertGreaterEqual(local, 0)
            self.assertGreaterEqual(central, 0)
            unsupported = (zipfile.MAX_EXTRACT_VERSION + 1).to_bytes(2, "little")
            raw[local + 4 : local + 6] = unsupported
            raw[central + 6 : central + 8] = unsupported
            archive.write_bytes(raw)

            with self.assertRaisesRegex(
                MODULE.ArtifactError, "unsupported ZIP feature version"
            ):
                with MODULE._open_validated_zip(
                    str(archive), MODULE._zip_limits(self._zip_args(archive))
                ):
                    pass

    def test_zip_open_rejects_unsupported_local_version(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            archive = pathlib.Path(directory) / "unsupported-local-version.zip"
            self._write_zip(
                archive,
                [("payload", b"content")],
                compression=zipfile.ZIP_STORED,
            )
            raw = bytearray(archive.read_bytes())
            local = raw.find(b"PK\x03\x04")
            central = raw.find(b"PK\x01\x02")
            self.assertGreaterEqual(local, 0)
            self.assertGreaterEqual(central, 0)
            central_version = bytes(raw[central + 6 : central + 8])
            raw[local + 4 : local + 6] = (
                zipfile.MAX_EXTRACT_VERSION + 1
            ).to_bytes(2, "little")
            archive.write_bytes(raw)
            self.assertEqual(
                archive.read_bytes()[central + 6 : central + 8], central_version
            )

            with self.assertRaisesRegex(
                MODULE.ArtifactError, "unsupported ZIP feature version"
            ):
                with MODULE._open_validated_zip(
                    str(archive), MODULE._zip_limits(self._zip_args(archive))
                ):
                    pass

    def test_zip_open_rejects_unsupported_central_version(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            archive = pathlib.Path(directory) / "unsupported-central-version.zip"
            self._write_zip(
                archive,
                [("payload", b"content")],
                compression=zipfile.ZIP_STORED,
            )
            raw = bytearray(archive.read_bytes())
            local = raw.find(b"PK\x03\x04")
            central = raw.find(b"PK\x01\x02")
            self.assertGreaterEqual(local, 0)
            self.assertGreaterEqual(central, 0)
            local_version = bytes(raw[local + 4 : local + 6])
            raw[central + 6 : central + 8] = (
                zipfile.MAX_EXTRACT_VERSION + 1
            ).to_bytes(2, "little")
            archive.write_bytes(raw)
            self.assertEqual(
                archive.read_bytes()[local + 4 : local + 6], local_version
            )

            with self.assertRaisesRegex(
                MODULE.ArtifactError, "unsupported ZIP feature version"
            ):
                with MODULE._open_validated_zip(
                    str(archive), MODULE._zip_limits(self._zip_args(archive))
                ):
                    pass

    def test_zip_open_rejects_local_and_central_version_mismatch(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            archive = pathlib.Path(directory) / "mismatched-versions.zip"
            self._write_zip(
                archive,
                [("payload", b"content")],
                compression=zipfile.ZIP_STORED,
            )
            raw = bytearray(archive.read_bytes())
            local = raw.find(b"PK\x03\x04")
            central = raw.find(b"PK\x01\x02")
            self.assertGreaterEqual(local, 0)
            self.assertGreaterEqual(central, 0)
            central_version = int.from_bytes(
                raw[central + 6 : central + 8], "little"
            )
            different_supported_version = (
                central_version + 1
                if central_version < zipfile.MAX_EXTRACT_VERSION
                else central_version - 1
            )
            raw[local + 4 : local + 6] = different_supported_version.to_bytes(
                2, "little"
            )
            archive.write_bytes(raw)

            with self.assertRaisesRegex(
                MODULE.ArtifactError, "extract versions disagree"
            ):
                with MODULE._open_validated_zip(
                    str(archive), MODULE._zip_limits(self._zip_args(archive))
                ):
                    pass

    def test_zip_inventory_rejects_stored_size_disagreement(self) -> None:
        info = zipfile.ZipInfo("payload")
        info.compress_type = zipfile.ZIP_STORED
        info.compress_size = 1
        info.file_size = 2
        fake_archive = mock.Mock()
        fake_archive.infolist.return_value = [info]
        limits = MODULE._zip_limits(
            self._zip_args(pathlib.Path("/tmp/not-opened.zip"))
        )
        with self.assertRaisesRegex(MODULE.ArtifactError, "sizes do not match"):
            MODULE._validate_zip_inventory(fake_archive, limits)

    def test_zip_inventory_enforces_archive_member_name_size_aggregate_and_ratio_caps(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = pathlib.Path(directory)
            archive = root / "artifact.zip"
            self._write_zip(
                archive,
                [("one.txt", b"a" * 100), ("two.txt", b"b" * 100)],
            )
            cases = (
                {"max_archive_bytes": 10},
                {"max_central_directory_bytes": 10},
                {"max_members": 1},
                {"max_member_name_bytes": 3},
                {"max_member_compressed_bytes": 2},
                {"max_member_uncompressed_bytes": 50},
                {"max_total_compressed_bytes": 2},
                {"max_total_uncompressed_bytes": 150},
                {"max_ratio": 2.0},
            )
            for changes in cases:
                args = self._zip_args(archive, **changes)
                with self.subTest(changes=changes), self.assertRaises(
                    MODULE.LimitExceeded
                ):
                    with MODULE._open_validated_zip(
                        str(archive), MODULE._zip_limits(args)
                    ):
                        pass

    def test_zip_member_count_is_preflighted_before_zipfile_construction(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            archive = pathlib.Path(directory) / "artifact.zip"
            self._write_zip(archive, [])
            raw = bytearray(archive.read_bytes())
            eocd = raw.rfind(b"PK\x05\x06")
            self.assertGreaterEqual(eocd, 0)
            raw[eocd + 8 : eocd + 10] = (101).to_bytes(2, "little")
            raw[eocd + 10 : eocd + 12] = (101).to_bytes(2, "little")
            archive.write_bytes(raw)
            limits = MODULE._zip_limits(self._zip_args(archive, max_members=100))
            with self.assertRaisesRegex(MODULE.LimitExceeded, "member limit"):
                with MODULE._open_validated_zip(str(archive), limits):
                    pass

    def test_zip_preflight_rejects_a_lied_low_member_count(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            archive = pathlib.Path(directory) / "artifact.zip"
            self._write_zip(archive, [("one", b"1"), ("two", b"2")])
            raw = bytearray(archive.read_bytes())
            eocd = raw.rfind(b"PK\x05\x06")
            self.assertGreaterEqual(eocd, 0)
            raw[eocd + 8 : eocd + 10] = (1).to_bytes(2, "little")
            raw[eocd + 10 : eocd + 12] = (1).to_bytes(2, "little")
            archive.write_bytes(raw)
            limits = MODULE._zip_limits(self._zip_args(archive))
            with self.assertRaisesRegex(zipfile.BadZipFile, "count"):
                with MODULE._open_validated_zip(str(archive), limits):
                    pass

    def test_zip_preflight_does_not_fall_back_from_last_false_signature(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            archive = pathlib.Path(directory) / "artifact.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("payload", b"data")
                output.comment = b"comment-with-false-PK\x05\x06-tail"
            limits = MODULE._zip_limits(self._zip_args(archive))
            with self.assertRaisesRegex(zipfile.BadZipFile, r"end[ -]record"):
                with MODULE._open_validated_zip(str(archive), limits):
                    pass

    def test_zip_preflight_rejects_locator_with_non_sentinel_classic_eocd(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            archive = pathlib.Path(directory) / "artifact.zip"
            self._write_zip(archive, [("payload", b"data")])
            raw = bytearray(archive.read_bytes())
            eocd = raw.rfind(b"PK\x05\x06")
            self.assertGreaterEqual(eocd, 0)
            locator = b"PK\x06\x07" + b"\x00" * 16
            archive.write_bytes(raw[:eocd] + locator + raw[eocd:])
            limits = MODULE._zip_limits(self._zip_args(archive))
            with self.assertRaisesRegex(MODULE.ArtifactError, "ZIP64"):
                with MODULE._open_validated_zip(str(archive), limits):
                    pass

    def test_zip_preflight_and_inventory_reject_member_disk_numbers(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            archive = pathlib.Path(directory) / "artifact.zip"
            self._write_zip(archive, [("payload", b"data")])
            raw = bytearray(archive.read_bytes())
            central = raw.find(b"PK\x01\x02")
            self.assertGreaterEqual(central, 0)
            raw[central + 34 : central + 36] = (1).to_bytes(2, "little")
            archive.write_bytes(raw)
            limits = MODULE._zip_limits(self._zip_args(archive))
            with self.assertRaisesRegex(MODULE.ArtifactError, "multi-disk"):
                with MODULE._open_validated_zip(str(archive), limits):
                    pass

            info = zipfile.ZipInfo("payload")
            info.volume = 1
            fake_archive = mock.Mock()
            fake_archive.infolist.return_value = [info]
            with self.assertRaisesRegex(MODULE.ArtifactError, "multi-disk"):
                MODULE._validate_zip_inventory(fake_archive, limits)

    def test_zip_preflight_rejects_per_member_and_local_header_zip64(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = pathlib.Path(directory)
            central_zip64 = root / "central-zip64.zip"
            self._write_zip(central_zip64, [("payload", b"data")])
            raw = bytearray(central_zip64.read_bytes())
            central = raw.find(b"PK\x01\x02")
            self.assertGreaterEqual(central, 0)
            compressed_size = int.from_bytes(raw[central + 20 : central + 24], "little")
            uncompressed_size = int.from_bytes(raw[central + 24 : central + 28], "little")
            name_length = int.from_bytes(raw[central + 28 : central + 30], "little")
            extra_length = int.from_bytes(raw[central + 30 : central + 32], "little")
            zip64_extra = (
                b"\x01\x00\x10\x00"
                + uncompressed_size.to_bytes(8, "little")
                + compressed_size.to_bytes(8, "little")
            )
            insert_at = central + 46 + name_length + extra_length
            raw[central + 20 : central + 24] = (0xFFFFFFFF).to_bytes(4, "little")
            raw[central + 24 : central + 28] = (0xFFFFFFFF).to_bytes(4, "little")
            raw[central + 30 : central + 32] = (
                extra_length + len(zip64_extra)
            ).to_bytes(2, "little")
            raw[insert_at:insert_at] = zip64_extra
            eocd = raw.rfind(b"PK\x05\x06")
            central_size = int.from_bytes(raw[eocd + 12 : eocd + 16], "little")
            raw[eocd + 12 : eocd + 16] = (
                central_size + len(zip64_extra)
            ).to_bytes(4, "little")
            central_zip64.write_bytes(raw)
            limits = MODULE._zip_limits(self._zip_args(central_zip64))
            with self.assertRaisesRegex(MODULE.ArtifactError, "ZIP64"):
                with MODULE._open_validated_zip(str(central_zip64), limits):
                    pass

            local_zip64 = root / "local-zip64.zip"
            with zipfile.ZipFile(local_zip64, "w") as archive:
                with archive.open("payload", "w", force_zip64=True) as member:
                    member.write(b"data")
            limits = MODULE._zip_limits(self._zip_args(local_zip64))
            with self.assertRaisesRegex(MODULE.ArtifactError, "ZIP64"):
                with MODULE._open_validated_zip(str(local_zip64), limits):
                    pass

    def test_zip_preflight_rejects_local_header_metadata_disagreement(self) -> None:
        mutations = (
            ("magic", 0, b"BAD!", "local-file header"),
            ("encryption", 6, (1).to_bytes(2, "little"), "encrypted"),
            ("method", 8, (99).to_bytes(2, "little"), "flags or methods"),
        )
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            for index, (label, offset, replacement, message) in enumerate(mutations):
                with self.subTest(label=label):
                    archive = pathlib.Path(directory) / "local-{}.zip".format(index)
                    self._write_zip(archive, [("payload", b"data")])
                    raw = bytearray(archive.read_bytes())
                    local = raw.find(b"PK\x03\x04")
                    self.assertGreaterEqual(local, 0)
                    raw[local + offset : local + offset + len(replacement)] = replacement
                    archive.write_bytes(raw)
                    limits = MODULE._zip_limits(self._zip_args(archive))
                    with self.assertRaisesRegex(Exception, message):
                        with MODULE._open_validated_zip(str(archive), limits):
                            pass

    def test_zip_preflight_validates_data_descriptors_and_flag_allowlist(self) -> None:
        class UnseekableBuffer(io.BytesIO):
            def seekable(self) -> bool:
                return False

            def seek(self, *args: object, **kwargs: object) -> int:
                raise io.UnsupportedOperation("unseekable")

        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = pathlib.Path(directory)
            stream = UnseekableBuffer()
            with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as output:
                output.writestr("payload", b"data")
            raw = stream.getvalue()
            descriptor = raw.find(b"PK\x07\x08")
            self.assertGreaterEqual(descriptor, 0)

            valid = root / "descriptor.zip"
            valid.write_bytes(raw)
            limits = MODULE._zip_limits(self._zip_args(valid))
            with MODULE._open_validated_zip(
                str(valid), limits
            ) as (archive, inventory):
                MODULE._verify_member_payload(
                    archive,
                    inventory["payload"],
                    limits.max_member_uncompressed_bytes,
                )

            invalid_descriptor = root / "bad-descriptor.zip"
            mutated = bytearray(raw)
            mutated[descriptor + 4] ^= 0x01
            invalid_descriptor.write_bytes(mutated)
            limits = MODULE._zip_limits(self._zip_args(invalid_descriptor))
            with self.assertRaisesRegex(MODULE.ArtifactError, "descriptor"):
                with MODULE._open_validated_zip(str(invalid_descriptor), limits):
                    pass

            invalid_flags = root / "bad-flags.zip"
            mutated = bytearray(raw)
            local = mutated.find(b"PK\x03\x04")
            central = mutated.find(b"PK\x01\x02")
            local_flags = int.from_bytes(mutated[local + 6 : local + 8], "little")
            central_flags = int.from_bytes(
                mutated[central + 8 : central + 10], "little"
            )
            mutated[local + 6 : local + 8] = (local_flags | 0x20).to_bytes(
                2, "little"
            )
            mutated[central + 8 : central + 10] = (
                central_flags | 0x20
            ).to_bytes(2, "little")
            invalid_flags.write_bytes(mutated)
            limits = MODULE._zip_limits(self._zip_args(invalid_flags))
            with self.assertRaisesRegex(MODULE.ArtifactError, "flags"):
                with MODULE._open_validated_zip(str(invalid_flags), limits):
                    pass

    def test_zip_commands_reject_declared_size_over_cli_limit_before_payload_reads(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = pathlib.Path(directory)
            archive = root / "artifact.zip"
            output = root / "payload"
            self._write_zip(
                archive,
                [("logs/console.txt", b"long member payload")],
                compression=zipfile.ZIP_STORED,
            )
            with mock.patch.object(
                MODULE,
                "_iter_member_compressed_chunks",
                side_effect=AssertionError("payload span must not be read"),
            ) as payload_reads, redirect_stderr(
                io.StringIO()
            ), redirect_stdout(
                io.StringIO()
            ):
                show_result = MODULE.cmd_zip_show(
                    self._zip_show_args(archive, max_bytes=1)
                )
                values = vars(self._zip_args(archive)).copy()
                values.update(
                    {
                        "member": "logs/console.txt",
                        "output": str(output),
                        "max_bytes": 1,
                    }
                )
                extract_result = MODULE.cmd_zip_extract(
                    argparse.Namespace(**values)
                )
            self.assertEqual(show_result, 1)
            self.assertEqual(extract_result, 1)
            payload_reads.assert_not_called()
            self.assertFalse(output.exists())
            self.assertEqual(list(root.glob(".*.artifact-*.tmp")), [])

    def test_zip_show_fully_reads_member_so_crc_failure_is_not_hidden_by_head(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            archive = pathlib.Path(directory) / "artifact.zip"
            payload = b"unique-payload-for-crc\nsecond\n"
            self._write_zip(
                archive,
                [("logs/console.txt", payload)],
                compression=zipfile.ZIP_STORED,
            )
            raw = bytearray(archive.read_bytes())
            offset = raw.find(payload)
            self.assertGreaterEqual(offset, 0)
            raw[offset] ^= 0x01
            archive.write_bytes(raw)
            errors = io.StringIO()
            with redirect_stderr(errors), redirect_stdout(io.StringIO()):
                result = MODULE.cmd_zip_show(
                    self._zip_show_args(archive, head=1)
                )
            self.assertEqual(result, 1)
            self.assertIn("CRC", errors.getvalue())

    def test_zip_show_reports_malformed_deflate_payload(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            archive = pathlib.Path(directory) / "artifact.zip"
            self._write_zip(
                archive,
                [("logs/console.txt", b"payload" * 100)],
                compression=zipfile.ZIP_DEFLATED,
            )
            with zipfile.ZipFile(archive) as opened:
                info = opened.getinfo("logs/console.txt")
            raw = bytearray(archive.read_bytes())
            local = info.header_offset
            name_length = int.from_bytes(raw[local + 26 : local + 28], "little")
            extra_length = int.from_bytes(raw[local + 28 : local + 30], "little")
            payload_start = local + 30 + name_length + extra_length
            raw[payload_start : payload_start + info.compress_size] = (
                b"\xff" * info.compress_size
            )
            archive.write_bytes(raw)
            errors = io.StringIO()
            with redirect_stderr(errors), redirect_stdout(io.StringIO()):
                result = MODULE.cmd_zip_show(self._zip_show_args(archive))
            self.assertEqual(result, 1)
            self.assertIn("malformed DEFLATE", errors.getvalue())

    def test_zip_show_and_extract_reject_deflate_output_past_declared_length(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = pathlib.Path(directory)
            archive = root / "overlong.zip"
            output = root / "console.txt"
            self._rewrite_deflate_as_declared_prefix(
                archive,
                member="logs/console.txt",
                declared_prefix=b"safe prefix\n",
                hidden_suffix=b"hidden output that must not be ignored\n",
            )

            show_errors = io.StringIO()
            with redirect_stderr(show_errors), redirect_stdout(io.StringIO()):
                show_result = MODULE.cmd_zip_show(self._zip_show_args(archive))
            self.assertEqual(show_result, 1)
            self.assertIn("declared length", show_errors.getvalue())

            values = vars(self._zip_args(archive)).copy()
            values.update(
                {
                    "member": "logs/console.txt",
                    "output": str(output),
                    "max_bytes": 1024,
                }
            )
            extract_errors = io.StringIO()
            with redirect_stderr(extract_errors), redirect_stdout(io.StringIO()):
                extract_result = MODULE.cmd_zip_extract(
                    argparse.Namespace(**values)
                )
            self.assertEqual(extract_result, 1)
            self.assertIn("declared length", extract_errors.getvalue())
            self.assertFalse(output.exists())
            self.assertEqual(list(root.glob(".*.artifact-*.tmp")), [])

    def test_zip_show_rejects_a_second_stream_inside_the_compressed_span(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = pathlib.Path(directory)
            archive = root / "trailing-stream.zip"
            output = root / "console.txt"
            self._append_deflate_stream_inside_declared_compressed_span(
                archive,
                member="logs/console.txt",
                payload=b"visible payload\n",
                trailing_payload=b"unclaimed second stream\n",
            )
            errors = io.StringIO()
            with redirect_stderr(errors), redirect_stdout(io.StringIO()):
                result = MODULE.cmd_zip_show(self._zip_show_args(archive))
            self.assertEqual(result, 1)
            self.assertIn("trailing compressed data", errors.getvalue())

            values = vars(self._zip_args(archive)).copy()
            values.update(
                {
                    "member": "logs/console.txt",
                    "output": str(output),
                    "max_bytes": 1024,
                }
            )
            errors = io.StringIO()
            with redirect_stderr(errors), redirect_stdout(io.StringIO()):
                result = MODULE.cmd_zip_extract(argparse.Namespace(**values))
            self.assertEqual(result, 1)
            self.assertIn("trailing compressed data", errors.getvalue())
            self.assertFalse(output.exists())
            self.assertEqual(list(root.glob(".*.artifact-*.tmp")), [])

    def test_raw_payload_verifier_accepts_stored_and_deflated_members(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = pathlib.Path(directory)
            for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                with self.subTest(compression=compression):
                    archive = root / "valid-{}.zip".format(compression)
                    self._write_zip(
                        archive,
                        [("logs/console.txt", b"valid payload\n")],
                        compression=compression,
                    )
                    limits = MODULE._zip_limits(self._zip_args(archive))
                    with MODULE._open_validated_zip(
                        str(archive), limits
                    ) as (opened, inventory):
                        MODULE._verify_member_payload(
                            opened,
                            inventory["logs/console.txt"],
                            limits.max_member_uncompressed_bytes,
                        )

    def test_raw_payload_verifier_drains_buffered_deflate_output(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            archive = pathlib.Path(directory) / "buffered-output.zip"
            payload = random.Random(16384).randbytes(16384) + b"A" * (
                MODULE.CHUNK_BYTES + 1 - 16384
            )
            self._write_zip(
                archive,
                [("logs/console.txt", payload)],
                compression=zipfile.ZIP_DEFLATED,
            )
            limits = MODULE._zip_limits(self._zip_args(archive))
            with MODULE._open_validated_zip(
                str(archive), limits
            ) as (opened, inventory):
                MODULE._verify_member_payload(
                    opened,
                    inventory["logs/console.txt"],
                    len(payload),
                )

    def test_zip_list_validates_metadata_without_claiming_payload_crc(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            archive = pathlib.Path(directory) / "artifact.zip"
            payload = b"unique-list-payload"
            self._write_zip(
                archive,
                [("logs/console.txt", payload)],
                compression=zipfile.ZIP_STORED,
            )
            raw = bytearray(archive.read_bytes())
            raw[raw.find(payload)] ^= 0x01
            archive.write_bytes(raw)
            values = vars(self._zip_args(archive)).copy()
            values.update(
                {
                    "match": None,
                    "ignore_case": False,
                    "limit": 0,
                    "max_emit_lines": 10,
                    "max_emit_bytes": 1024,
                }
            )
            output = io.StringIO()
            with redirect_stdout(output):
                result = MODULE.cmd_zip_list(argparse.Namespace(**values))
            self.assertEqual(result, 0)
            self.assertIn("uncompressed=", output.getvalue())
            self.assertIn("logs/console.txt", output.getvalue())

    def test_zip_show_rejects_truncated_archive(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            archive = pathlib.Path(directory) / "artifact.zip"
            self._write_zip(archive, [("logs/console.txt", b"payload")])
            archive.write_bytes(archive.read_bytes()[:-8])
            with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                result = MODULE.cmd_zip_show(self._zip_show_args(archive))
            self.assertEqual(result, 1)

    def test_zip_input_is_revalidated_even_when_the_operation_fails(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            archive = pathlib.Path(directory) / "artifact.zip"
            self._write_zip(archive, [("logs/console.txt", b"payload")])
            real_fstat = os.fstat
            calls = 0

            def changed_fstat(file_descriptor: int):
                nonlocal calls
                info = real_fstat(file_descriptor)
                calls += 1
                if calls != 4:
                    return info
                values = list(info)
                values[6] = info.st_size + 1
                return os.stat_result(values)

            limits = MODULE._zip_limits(self._zip_args(archive))
            with mock.patch.object(MODULE.os, "fstat", side_effect=changed_fstat):
                with self.assertRaisesRegex(
                    MODULE.ArtifactError, "operation also failed"
                ):
                    with MODULE._open_validated_zip(str(archive), limits):
                        raise RuntimeError("synthetic operation failure")

    def test_zip_source_acquisition_detects_change_and_fstat_failure(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            archive = pathlib.Path(directory) / "artifact.zip"
            self._write_zip(archive, [("logs/console.txt", b"payload")])
            real_fstat = os.fstat
            limits = MODULE._zip_limits(self._zip_args(archive))

            for failure in ("changed", "fstat"):
                calls = 0

                def source_fstat(file_descriptor: int):
                    nonlocal calls
                    info = real_fstat(file_descriptor)
                    calls += 1
                    if calls != 2:
                        return info
                    if failure == "fstat":
                        raise OSError("synthetic source fstat failure")
                    values = list(info)
                    values[6] = info.st_size + 1
                    return os.stat_result(values)

                expected = (
                    "source revalidation failed"
                    if failure == "fstat"
                    else "content-stability signal"
                )
                with self.subTest(failure=failure), mock.patch.object(
                    MODULE.os, "fstat", side_effect=source_fstat
                ), self.assertRaisesRegex(MODULE.ArtifactError, expected):
                    with MODULE._open_validated_zip(str(archive), limits):
                        pass

    def test_zip_source_change_remains_visible_after_acquisition_error(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            archive = pathlib.Path(directory) / "artifact.zip"
            self._write_zip(archive, [("logs/console.txt", b"payload")])
            real_fstat = os.fstat
            calls = 0

            def changed_fstat(file_descriptor: int):
                nonlocal calls
                info = real_fstat(file_descriptor)
                calls += 1
                if calls == 2:
                    values = list(info)
                    values[6] = info.st_size + 1
                    return os.stat_result(values)
                return info

            limits = MODULE._zip_limits(
                self._zip_args(archive, max_archive_bytes=1)
            )
            with mock.patch.object(
                MODULE.os, "fstat", side_effect=changed_fstat
            ), self.assertRaisesRegex(
                MODULE.ArtifactError, "acquisition also failed"
            ):
                with MODULE._open_validated_zip(str(archive), limits):
                    pass

    def test_zip_show_caps_selected_members_and_emission(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            archive = pathlib.Path(directory) / "artifact.zip"
            self._write_zip(
                archive,
                [("one.log", b"one\n"), ("two.log", b"two\n")],
            )
            args = self._zip_show_args(
                archive,
                member=r".*\.log",
                regex=True,
                all=True,
                max_selected_members=1,
            )
            with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                self.assertEqual(MODULE.cmd_zip_show(args), 1)

            args = self._zip_show_args(
                archive,
                member="one.log",
                max_emit_lines=1,
            )
            with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                self.assertEqual(MODULE.cmd_zip_show(args), 1)

    def test_zip_extract_publishes_one_exact_member_atomically(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = pathlib.Path(directory)
            archive = root / "artifact.zip"
            output = root / "console.txt"
            self._write_zip(archive, [("logs/console.txt", b"payload")])
            values = vars(self._zip_args(archive)).copy()
            values.update(
                {
                    "member": "logs/console.txt",
                    "output": str(output),
                    "max_bytes": 1024,
                }
            )
            with redirect_stdout(io.StringIO()):
                result = MODULE.cmd_zip_extract(argparse.Namespace(**values))
            self.assertEqual(result, 0)
            self.assertEqual(output.read_bytes(), b"payload")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_zip_extract_crc_failure_leaves_no_partial_final(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = pathlib.Path(directory)
            archive = root / "artifact.zip"
            output = root / "console.txt"
            payload = b"unique-extract-payload"
            self._write_zip(
                archive,
                [("logs/console.txt", payload)],
                compression=zipfile.ZIP_STORED,
            )
            raw = bytearray(archive.read_bytes())
            raw[raw.find(payload)] ^= 0x01
            archive.write_bytes(raw)
            values = vars(self._zip_args(archive)).copy()
            values.update(
                {
                    "member": "logs/console.txt",
                    "output": str(output),
                    "max_bytes": 1024,
                }
            )
            with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                result = MODULE.cmd_zip_extract(argparse.Namespace(**values))
            self.assertEqual(result, 1)
            self.assertFalse(output.exists())
            self.assertEqual(list(root.glob(".*.artifact-*.tmp")), [])

    def test_zip_extract_rejects_actual_length_shorter_than_declared(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = pathlib.Path(directory)
            archive = root / "artifact.zip"
            output = root / "payload"
            self._write_zip(
                archive,
                [("payload", b"x")],
                compression=zipfile.ZIP_DEFLATED,
            )
            raw = bytearray(archive.read_bytes())
            central = raw.find(b"PK\x01\x02")
            self.assertGreaterEqual(central, 0)
            raw[central + 24 : central + 28] = (100).to_bytes(4, "little")
            archive.write_bytes(raw)
            values = vars(self._zip_args(archive)).copy()
            values.update(
                {"member": "payload", "output": str(output), "max_bytes": 1024}
            )
            with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                result = MODULE.cmd_zip_extract(argparse.Namespace(**values))
            self.assertEqual(result, 1)
            self.assertFalse(output.exists())

    def test_skill_is_optional_and_scoped_to_artifact_transport(self) -> None:
        skill_root = REPO_ROOT / "skills/bug-triage-playbook"
        skill = (skill_root / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("optional", skill.lower())
        self.assertIn("artifact transport", skill.lower())
        self.assertNotIn("Build a small hypothesis set", skill)

        distributed_markdown = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(skill_root.rglob("*.md"))
        )
        self.assertFalse((skill_root / "references/triage-report.md").exists())
        self.assertNotIn("# Bug Triage Report", distributed_markdown)
        self.assertNotIn("## Hypotheses", distributed_markdown)

        recipe = (
            skill_root / "references/jenkins-artifact-recipes.md"
        ).read_text(encoding="utf-8")
        self.assertNotIn("printenv JENKINS_ARTIFACT", recipe)

    def test_ci_covers_python_39_and_latest(self) -> None:
        workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('python-version: ["3.9", "3.x"]', workflow)
        self.assertIn("timeout-minutes: 10", workflow)
        self.assertIn("uses: actions/setup-python@v5", workflow)
        self.assertIn("python-version: ${{ matrix.python-version }}", workflow)
        self.assertIn(
            "python3 -m unittest tests.test_jenkins_artifact_probe", workflow
        )

    def test_required_ci_wraps_the_matrix_and_aggregate(self) -> None:
        workflow = (REPO_ROOT / ".github/workflows/required-ci.yml").read_text(
            encoding="utf-8"
        )
        job_ids = []
        in_jobs = False
        for line in workflow.splitlines():
            if line == "jobs:":
                in_jobs = True
                continue
            if in_jobs and line and not line.startswith(" "):
                break
            if (
                in_jobs
                and line.startswith("  ")
                and not line.startswith("    ")
                and line.endswith(":")
            ):
                job_ids.append(line[2:-1])

        self.assertIn(REQUIRED_CALL_TRIGGER, workflow)
        self.assertNotIn("workflow_call:\n    inputs:", workflow)
        steps = workflow_steps(workflow)
        checkout_indexes = [
            index
            for index, step in enumerate(steps)
            if step.lstrip().startswith("- uses: actions/checkout@")
        ]
        checkout = checkout_steps(workflow)
        self.assertGreater(len(checkout), 0)
        self.assertTrue(all(CHECKOUT_BINDING in step for step in checkout))
        for step in checkout:
            self.assertEqual(
                [
                    line.strip()
                    for line in step.splitlines()
                    if line.strip().startswith("repository:")
                ],
                [f"repository: {CHECKOUT_REPOSITORY}"],
            )
            self.assertEqual(
                [
                    line.strip()
                    for line in step.splitlines()
                    if line.strip().startswith("ref:")
                ],
                ["ref: ${{ github.sha }}"],
            )
            self.assertEqual(
                [
                    line.strip()
                    for line in step.splitlines()
                    if line.strip().startswith("persist-credentials:")
                ],
                ["persist-credentials: false"],
            )
        guard_indexes = [
            index
            for index, step in enumerate(steps)
            if step.lstrip().startswith("- name: Reject unexpected repository")
        ]
        self.assertEqual(guard_indexes, [index - 1 for index in checkout_indexes])
        self.assertEqual(
            [steps[index].strip() for index in guard_indexes],
            [REPOSITORY_GUARD] * len(checkout),
        )
        self.assertEqual(
            workflow.count(f"repository: {CHECKOUT_REPOSITORY}"), len(checkout)
        )
        self.assertNotIn("repository: ${{ github.repository }}", workflow)
        self.assertEqual(workflow.count("ref: ${{ github.sha }}"), len(checkout))
        self.assertEqual(workflow.count("persist-credentials: false"), len(checkout))
        self.assertIn("permissions:\n  contents: read\n", workflow)
        self.assertEqual(job_ids, ["test-matrix", "test"])
        self.assertIn('python-version: ["3.9", "3.x"]', workflow)
        self.assertIn("needs: test-matrix", workflow)
        self.assertIn("if: ${{ always() }}", workflow)
        self.assertIn(
            "python3 -m unittest tests.test_jenkins_artifact_probe", workflow
        )
        self.assertIn('run: test "$MATRIX_RESULT" = "success"', workflow)
        for forbidden in (
            "pull_request:",
            "pull_request_target:",
            "push:",
            "secrets.",
            "contents: write",
            "id-token: write",
            "statuses: write",
        ):
            self.assertNotIn(forbidden, workflow)


if __name__ == "__main__":
    unittest.main()
