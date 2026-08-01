from __future__ import annotations

import errno
import hashlib
import importlib.util
import io
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from unittest import mock


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT_PATH = (
    REPO_ROOT / "skills/cisco-build-artifacts/scripts/cisco_build_artifacts.py"
)
SPEC = importlib.util.spec_from_file_location("cisco_build_artifacts", SCRIPT_PATH)
assert SPEC is not None
assert SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class FakeHeaders:
    def __init__(self, values: dict[str, str | list[str]] | None = None) -> None:
        self.values = {key.lower(): value for key, value in (values or {}).items()}

    def get(self, name: str, default=None):
        value = self.values.get(name.lower(), default)
        if isinstance(value, list):
            return value[0] if value else default
        return value

    def get_all(self, name: str):
        value = self.values.get(name.lower())
        if value is None:
            return None
        return value if isinstance(value, list) else [value]


class FakeResponse:
    def __init__(
        self,
        payload: bytes = b"",
        *,
        status: int = 200,
        headers: dict[str, str | list[str]] | None = None,
    ) -> None:
        self.payload = payload
        self.offset = 0
        self.status = status
        self.headers = FakeHeaders(headers)
        self.closed = False
        self.read_calls = 0

    def read(self, count: int) -> bytes:
        self.read_calls += 1
        chunk = self.payload[self.offset : self.offset + count]
        self.offset += len(chunk)
        return chunk

    def getheader(self, name: str):
        return self.headers.get(name)

    def close(self) -> None:
        self.closed = True


class FakeSocket:
    def __init__(self) -> None:
        self.timeouts: list[float] = []

    def settimeout(self, timeout: float) -> None:
        self.timeouts.append(timeout)


class FakeConnection:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        self.sock = FakeSocket()
        self.closed = False

    def request(self, method: str, target: str, *, headers: dict[str, str]) -> None:
        self.requests.append((method, target, dict(headers)))

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


def base_payload(**overrides):
    payload = {
        "command": "show-url",
        "url": "https://jenkins.example.com/job/example/1/consoleText",
        "auth_profile": None,
        "max_redirects": MODULE.DEFAULT_MAX_REDIRECTS,
        "connect_timeout": MODULE.DEFAULT_CONNECT_TIMEOUT_SECONDS,
        "read_timeout": MODULE.DEFAULT_READ_TIMEOUT_SECONDS,
        "max_body_bytes": MODULE.DEFAULT_MAX_BODY_BYTES,
        "selection_mode": "default",
        "selection_count": MODULE.DEFAULT_MAX_OUTPUT_LINES,
        "grep": None,
        "ignore_case": False,
        "context": 0,
        "encoding": "utf-8",
        "max_input_line_bytes": MODULE.DEFAULT_MAX_INPUT_LINE_BYTES,
        "max_input_lines": MODULE.DEFAULT_MAX_INPUT_LINES,
        "max_output_lines": MODULE.DEFAULT_MAX_OUTPUT_LINES,
        "max_output_chars": MODULE.DEFAULT_MAX_OUTPUT_CHARS,
    }
    payload.update(overrides)
    return payload


@contextmanager
def workspace_directory():
    original = pathlib.Path.cwd()
    with tempfile.TemporaryDirectory(dir=REPO_ROOT) as directory:
        os.chmod(directory, 0o700)
        os.chdir(directory)
        try:
            yield pathlib.Path(directory)
        finally:
            os.chdir(original)


class UrlAndAuthenticationPolicyTests(unittest.TestCase):
    def test_rejects_non_https_before_connection(self) -> None:
        with mock.patch.object(MODULE, "_make_https_connection") as connection:
            with self.assertRaisesRegex(MODULE.UsageFailure, "only HTTPS"):
                MODULE._open_final_response(
                    "http://jenkins.example.com/job/example",
                    method="GET",
                    auth_profile=None,
                    max_redirects=5,
                    connect_timeout=1,
                    read_timeout=1,
                    deadline=time.monotonic() + 5,
                )
        connection.assert_not_called()

    def test_rejects_inline_credentials_before_connection(self) -> None:
        with mock.patch.object(MODULE, "_make_https_connection") as connection:
            with self.assertRaisesRegex(MODULE.UsageFailure, "inline URL credentials"):
                MODULE._open_final_response(
                    "https://user:token@jenkins.example.com/job/example",
                    method="GET",
                    auth_profile=None,
                    max_redirects=5,
                    connect_timeout=1,
                    read_timeout=1,
                    deadline=time.monotonic() + 5,
                )
        connection.assert_not_called()

    def test_rejects_disallowed_host_before_connection(self) -> None:
        with mock.patch.object(MODULE, "_make_https_connection") as connection:
            with self.assertRaisesRegex(MODULE.UsageFailure, "not allowlisted"):
                MODULE._open_final_response(
                    "https://evil.example.com/job/example",
                    method="GET",
                    auth_profile=None,
                    max_redirects=5,
                    connect_timeout=1,
                    read_timeout=1,
                    deadline=time.monotonic() + 5,
                )
        connection.assert_not_called()

    def test_rejects_nondefault_https_port(self) -> None:
        with self.assertRaisesRegex(MODULE.UsageFailure, "port 443"):
            MODULE._validate_url("https://jenkins.example.com:8443/job/example")

    def test_query_values_are_redacted(self) -> None:
        validated = MODULE._validate_url(
            "https://jenkins.example.com/job/example?token=secret&tree=result"
        )
        self.assertNotIn("secret", validated.safe)
        self.assertEqual(
            validated.safe,
            "https://jenkins.example.com/job/example?redacted",
        )
        self.assertTrue(validated.query_redacted)

    def test_profile_origin_is_authorized_before_credential_read(self) -> None:
        observed: list[str] = []

        def getenv(name: str):
            observed.append(name)
            if name == "CISCO_BUILD_ARTIFACT_DEFAULT_HOSTS":
                return "jenkins.example.com"
            if name in ("JENKINS_ARTIFACT_USER", "JENKINS_ARTIFACT_TOKEN"):
                self.fail("credential material was read before origin authorization")
            return None

        with mock.patch.object(MODULE.os, "getenv", side_effect=getenv):
            with self.assertRaisesRegex(MODULE.UsageFailure, "does not authorize"):
                MODULE._authorization_value(
                    "default",
                    ("artifacts.example.com", 443),
                )
        self.assertEqual(observed, ["CISCO_BUILD_ARTIFACT_DEFAULT_HOSTS"])

    def test_missing_profile_credentials_fail_before_producer_launch(self) -> None:
        payload = base_payload(auth_profile="default")
        with mock.patch.dict(
            os.environ,
            {
                "CISCO_BUILD_ARTIFACT_DEFAULT_HOSTS": "jenkins.example.com",
            },
            clear=True,
        ):
            with mock.patch.object(MODULE.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(MODULE.UsageFailure, "missing credentials"):
                    MODULE._run_worker(
                        payload,
                        deadline=time.monotonic() + 5,
                    )
        popen.assert_not_called()

    def test_unknown_profile_is_rejected(self) -> None:
        with self.assertRaisesRegex(MODULE.UsageFailure, "unknown authentication"):
            MODULE._profile("unknown")


class RedirectPolicyTests(unittest.TestCase):
    def _open_with_connections(
        self,
        connections: list[FakeConnection],
        *,
        auth_profile: str | None = None,
        max_redirects: int = 5,
    ):
        with mock.patch.object(
            MODULE,
            "_make_https_connection",
            side_effect=connections,
        ):
            with mock.patch.object(MODULE.ssl, "create_default_context"):
                return MODULE._open_final_response(
                    "https://jenkins.example.com/job/example",
                    method="GET",
                    auth_profile=auth_profile,
                    max_redirects=max_redirects,
                    connect_timeout=1,
                    read_timeout=1,
                    deadline=time.monotonic() + 5,
                )

    def test_same_profile_cross_host_redirect_rebuilds_auth(self) -> None:
        first = FakeConnection(
            FakeResponse(
                status=302,
                headers={"Location": "https://artifacts.example.com/file.zip"},
            )
        )
        second = FakeConnection(FakeResponse(b"ok"))
        with mock.patch.dict(
            os.environ,
            {
                "CISCO_BUILD_ARTIFACT_ALLOWED_HOSTS": (
                    "jenkins.example.com,artifacts.example.com"
                ),
                "CISCO_BUILD_ARTIFACT_DEFAULT_HOSTS": (
                    "jenkins.example.com,artifacts.example.com"
                ),
                "JENKINS_ARTIFACT_USER": "user",
                "JENKINS_ARTIFACT_TOKEN": "token",
            },
            clear=True,
        ):
            response, connection, final, redirects, auth = self._open_with_connections(
                [first, second],
                auth_profile="default",
            )
        self.assertIs(response, second.response)
        self.assertIs(connection, second)
        self.assertEqual(final.host, "artifacts.example.com")
        self.assertEqual(redirects, 1)
        self.assertEqual(auth, "present")
        first_headers = first.requests[0][2]
        second_headers = second.requests[0][2]
        self.assertIn("Authorization", first_headers)
        self.assertEqual(
            second_headers["Authorization"],
            first_headers["Authorization"],
        )
        self.assertIsNot(first_headers, second_headers)
        self.assertNotIn("Cookie", second_headers)
        self.assertNotIn("Proxy-Authorization", second_headers)

    def test_cross_host_redirect_rejects_profile_before_second_request(self) -> None:
        first = FakeConnection(
            FakeResponse(
                status=302,
                headers={"Location": "https://artifacts.example.com/file.zip"},
            )
        )
        second = FakeConnection(FakeResponse(b"should not run"))
        with mock.patch.dict(
            os.environ,
            {
                "CISCO_BUILD_ARTIFACT_ALLOWED_HOSTS": (
                    "jenkins.example.com,artifacts.example.com"
                ),
                "CISCO_BUILD_ARTIFACT_DEFAULT_HOSTS": "jenkins.example.com",
                "JENKINS_ARTIFACT_USER": "user",
                "JENKINS_ARTIFACT_TOKEN": "token",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(MODULE.UsageFailure, "does not authorize"):
                self._open_with_connections(
                    [first, second],
                    auth_profile="default",
                )
        self.assertEqual(len(first.requests), 1)
        self.assertEqual(second.requests, [])

    def test_redirect_downgrade_is_rejected(self) -> None:
        first = FakeConnection(
            FakeResponse(
                status=302,
                headers={"Location": "http://jenkins.example.com/file.zip"},
            )
        )
        with self.assertRaisesRegex(MODULE.UsageFailure, "only HTTPS"):
            self._open_with_connections([first])

    def test_redirect_loop_is_rejected(self) -> None:
        first = FakeConnection(
            FakeResponse(
                status=302,
                headers={"Location": "/job/example"},
            )
        )
        with self.assertRaisesRegex(MODULE.CommandFailure, "redirect loop"):
            self._open_with_connections([first])

    def test_redirect_count_is_capped(self) -> None:
        first = FakeConnection(
            FakeResponse(
                status=302,
                headers={"Location": "/job/other"},
            )
        )
        with self.assertRaisesRegex(MODULE.CommandFailure, "redirect count"):
            self._open_with_connections([first], max_redirects=0)

    def test_redirect_without_location_is_rejected(self) -> None:
        first = FakeConnection(FakeResponse(status=302))
        with self.assertRaisesRegex(MODULE.CommandFailure, "omitted Location"):
            self._open_with_connections([first])

    def test_default_tls_context_is_mandatory(self) -> None:
        connection = FakeConnection(FakeResponse(b"ok"))
        with mock.patch.object(
            MODULE,
            "_make_https_connection",
            return_value=connection,
        ):
            with mock.patch.object(
                MODULE.ssl,
                "create_default_context",
                return_value=mock.sentinel.context,
            ) as create_context:
                response, opened, _, _, _ = MODULE._open_final_response(
                    "https://jenkins.example.com/job/example",
                    method="GET",
                    auth_profile=None,
                    max_redirects=5,
                    connect_timeout=1,
                    read_timeout=1,
                    deadline=time.monotonic() + 5,
                )
        create_context.assert_called_once_with()
        self.assertIs(response, connection.response)
        self.assertIs(opened, connection)


class StreamingBudgetTests(unittest.TestCase):
    def _show(self, response: FakeResponse, **overrides):
        payload = base_payload(**overrides)
        connection = FakeConnection(response)
        initial = MODULE._validate_url(payload["url"])
        with mock.patch.object(
            MODULE,
            "_open_final_response",
            return_value=(response, connection, initial, 0, "absent"),
        ):
            return MODULE._worker_show(payload, time.monotonic() + 5)

    def test_head_stops_early_and_marks_truncated(self) -> None:
        response = FakeResponse(b"one\ntwo\nthree\n")
        result = self._show(
            response,
            selection_mode="head",
            selection_count=2,
            max_output_lines=2,
        )
        self.assertEqual(result["lines"], [(1, "one"), (2, "two")])
        self.assertTrue(result["truncated"])
        self.assertLess(result["wire_bytes"], len(response.payload) + 1)

    def test_tail_uses_bounded_deque(self) -> None:
        result = self._show(
            FakeResponse(b"one\ntwo\nthree\n"),
            selection_mode="tail",
            selection_count=2,
        )
        self.assertEqual(result["lines"], [(2, "two"), (3, "three")])

    def test_grep_context_is_bounded(self) -> None:
        result = self._show(
            FakeResponse(b"one\ntwo\nERROR\nthree\nfour\n"),
            selection_mode="grep",
            selection_count=200,
            grep="error",
            ignore_case=True,
            context=1,
        )
        self.assertEqual(
            result["lines"],
            [(2, "two"), (3, "ERROR"), (4, "three")],
        )

    def test_long_line_is_truncated_without_unbounded_retention(self) -> None:
        result = self._show(
            FakeResponse((b"x" * 100) + b"\n"),
            max_input_line_bytes=16,
            max_output_chars=32,
        )
        self.assertTrue(result["truncated"])
        self.assertLessEqual(result["output_chars"], 32)

    def test_input_line_count_is_capped(self) -> None:
        result = self._show(
            FakeResponse(b"one\ntwo\nthree\n"),
            max_input_lines=2,
        )
        self.assertTrue(result["truncated"])
        self.assertEqual(result["input_lines"], 3)

    def test_output_line_and_character_caps_are_independent(self) -> None:
        result = self._show(
            FakeResponse(b"12345\n67890\nabcde\n"),
            max_output_lines=2,
            max_output_chars=8,
        )
        self.assertTrue(result["truncated"])
        self.assertLessEqual(result["output_lines"], 2)
        self.assertLessEqual(result["output_chars"], 8)

    def test_false_content_length_cannot_bypass_fetch_cap(self) -> None:
        response = FakeResponse(
            b"0123456789",
            headers={"Content-Length": "2"},
        )
        connection = FakeConnection(response)
        initial = MODULE._validate_url(
            "https://jenkins.example.com/job/example/artifact/file.zip"
        )
        fd, path = tempfile.mkstemp()
        try:
            os.fchmod(fd, 0o600)
            payload = base_payload(
                command="fetch-url",
                stage_fd=fd,
                max_body_bytes=4,
            )
            with mock.patch.object(
                MODULE,
                "_open_final_response",
                return_value=(response, connection, initial, 0, "absent"),
            ):
                with self.assertRaisesRegex(MODULE.CommandFailure, "byte cap"):
                    MODULE._worker_fetch(payload, time.monotonic() + 5)
            self.assertEqual(os.fstat(fd).st_size, 4)
        finally:
            os.close(fd)
            os.unlink(path)

    def test_oversized_declared_length_fails_before_fetch_read(self) -> None:
        response = FakeResponse(
            b"never read",
            headers={"Content-Length": "100"},
        )
        connection = FakeConnection(response)
        initial = MODULE._validate_url(
            "https://jenkins.example.com/job/example/artifact/file.zip"
        )
        fd, path = tempfile.mkstemp()
        try:
            os.fchmod(fd, 0o600)
            payload = base_payload(
                command="fetch-url",
                stage_fd=fd,
                max_body_bytes=8,
            )
            with mock.patch.object(
                MODULE,
                "_open_final_response",
                return_value=(response, connection, initial, 0, "absent"),
            ):
                with self.assertRaisesRegex(MODULE.CommandFailure, "declared"):
                    MODULE._worker_fetch(payload, time.monotonic() + 5)
            self.assertEqual(response.read_calls, 0)
        finally:
            os.close(fd)
            os.unlink(path)

    def test_fetch_streams_and_reports_exact_digest(self) -> None:
        payload_bytes = b"archive bytes"
        response = FakeResponse(payload_bytes)
        connection = FakeConnection(response)
        initial = MODULE._validate_url(
            "https://jenkins.example.com/job/example/artifact/file.zip"
        )
        fd, path = tempfile.mkstemp()
        try:
            os.fchmod(fd, 0o600)
            payload = base_payload(
                command="fetch-url",
                stage_fd=fd,
                max_body_bytes=1024,
            )
            with mock.patch.object(
                MODULE,
                "_open_final_response",
                return_value=(response, connection, initial, 0, "absent"),
            ):
                result = MODULE._worker_fetch(payload, time.monotonic() + 5)
            self.assertEqual(result["persisted_bytes"], len(payload_bytes))
            self.assertEqual(
                result["sha256"],
                hashlib.sha256(payload_bytes).hexdigest(),
            )
            self.assertEqual(result["representation"], "identity-http-entity")
        finally:
            os.close(fd)
            os.unlink(path)

    def test_nonidentity_content_encoding_is_rejected(self) -> None:
        with self.assertRaisesRegex(MODULE.CommandFailure, "identity"):
            MODULE._validate_content_encoding(FakeHeaders({"Content-Encoding": "gzip"}))

    def test_conflicting_content_lengths_are_rejected(self) -> None:
        with self.assertRaisesRegex(MODULE.CommandFailure, "conflicting"):
            MODULE._content_length(FakeHeaders({"Content-Length": ["1", "2"]}))

    def test_http_auth_failure_reports_secret_free_context(self) -> None:
        response = FakeResponse(status=403)
        connection = FakeConnection(response)
        initial = MODULE._validate_url(
            "https://jenkins.example.com/job/example?token=secret"
        )
        payload = base_payload(url=initial.canonical)
        with mock.patch.object(
            MODULE,
            "_open_final_response",
            return_value=(response, connection, initial, 0, "present"),
        ):
            with self.assertRaises(MODULE.CommandFailure) as raised:
                MODULE._worker_show(payload, time.monotonic() + 5)
        error = raised.exception
        self.assertEqual(error.classification, "remote-authentication-failed")
        self.assertEqual(error.metadata["status"], 403)
        self.assertEqual(error.metadata["auth"], "present")
        self.assertNotIn("secret", error.metadata["source_url"])

    def test_nonredirect_three_hundred_status_is_not_success(self) -> None:
        response = FakeResponse(status=304)
        connection = FakeConnection(response)
        initial = MODULE._validate_url(
            "https://jenkins.example.com/job/example/consoleText"
        )
        payload = base_payload(url=initial.canonical)
        with mock.patch.object(
            MODULE,
            "_open_final_response",
            return_value=(response, connection, initial, 0, "absent"),
        ):
            with self.assertRaises(MODULE.CommandFailure) as raised:
                MODULE._worker_show(payload, time.monotonic() + 5)
        self.assertEqual(raised.exception.classification, "remote-http-error")
        self.assertEqual(raised.exception.metadata["status"], 304)

    def test_probe_sniff_is_bounded_and_truncated(self) -> None:
        response = FakeResponse(b"0123456789")
        connection = FakeConnection(response)
        initial = MODULE._validate_url("https://jenkins.example.com/job/example")
        payload = base_payload(
            command="probe-url",
            method="GET",
            sniff_bytes=4,
            encoding="utf-8",
            max_body_bytes=8,
        )
        with mock.patch.object(
            MODULE,
            "_open_final_response",
            return_value=(response, connection, initial, 0, "absent"),
        ):
            result = MODULE._worker_probe(payload, time.monotonic() + 5)
        self.assertEqual(result["wire_bytes"], 4)
        self.assertEqual(result["preview"], "0123")
        self.assertTrue(result["truncated"])


class ProducerSupervisionTests(unittest.TestCase):
    def _producer(self, source: str) -> subprocess.Popen[bytes]:
        return subprocess.Popen(
            [sys.executable, "-I", "-B", "-S", "-c", source],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
        )

    def test_timeout_terminates_and_reaps_direct_producer(self) -> None:
        process = self._producer("import time; time.sleep(10)")
        with self.assertRaises(MODULE.ProducerFailure) as raised:
            MODULE._bounded_worker_exchange(
                process,
                b"{}",
                deadline=time.monotonic() + 0.05,
            )
        self.assertEqual(raised.exception.classification, "producer-timeout")
        self.assertEqual(raised.exception.cleanup, "term-reaped")
        self.assertIsNotNone(process.returncode)

    def test_stdout_and_stderr_caps_stop_producer_while_running(self) -> None:
        cases = (
            (
                "stdout",
                "import sys; sys.stdout.buffer.write(b'x' * 1024); "
                "sys.stdout.buffer.flush()",
                "producer-output-overflow",
            ),
            (
                "stderr",
                "import sys; sys.stderr.buffer.write(b'x' * 1024); "
                "sys.stderr.buffer.flush()",
                "producer-error-overflow",
            ),
        )
        for label, source, classification in cases:
            with self.subTest(stream=label):
                process = self._producer(source)
                with self.assertRaises(MODULE.ProducerFailure) as raised:
                    MODULE._bounded_worker_exchange(
                        process,
                        b"{}",
                        deadline=time.monotonic() + 5,
                        stdout_cap=32,
                        stderr_cap=32,
                    )
                self.assertEqual(raised.exception.classification, classification)
                self.assertIsNotNone(process.returncode)

    def test_nonzero_worker_exit_is_distinct_from_timeout(self) -> None:
        process = mock.Mock()
        process.pid = 12345
        process.returncode = 7
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch.object(MODULE.subprocess, "Popen", return_value=process):
                with mock.patch.object(
                    MODULE,
                    "_bounded_worker_exchange",
                    return_value=(b"", b"bounded error"),
                ):
                    with self.assertRaises(MODULE.ProducerFailure) as raised:
                        MODULE._run_worker(
                            base_payload(),
                            deadline=time.monotonic() + 5,
                        )
        self.assertEqual(raised.exception.classification, "producer-failed")
        self.assertEqual(raised.exception.cleanup, "reaped")

    def test_malformed_worker_result_is_protocol_error(self) -> None:
        process = mock.Mock()
        process.pid = 12345
        process.returncode = 0
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch.object(MODULE.subprocess, "Popen", return_value=process):
                with mock.patch.object(
                    MODULE,
                    "_bounded_worker_exchange",
                    return_value=(b"not json", b""),
                ):
                    with self.assertRaises(MODULE.ProducerFailure) as raised:
                        MODULE._run_worker(
                            base_payload(),
                            deadline=time.monotonic() + 5,
                        )
        self.assertEqual(
            raised.exception.classification,
            "producer-protocol-error",
        )

    def test_worker_environment_excludes_unrelated_secrets(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "CISCO_BUILD_ARTIFACT_DEFAULT_HOSTS": "jenkins.example.com",
                "JENKINS_ARTIFACT_USER": "user",
                "JENKINS_ARTIFACT_TOKEN": "token",
                "UNRELATED_SECRET": "must-not-pass",
            },
            clear=True,
        ):
            environment = MODULE._worker_environment(
                "default",
                ("jenkins.example.com", 443),
            )
        self.assertNotIn("UNRELATED_SECRET", environment)
        self.assertEqual(environment["JENKINS_ARTIFACT_USER"], "user")
        self.assertEqual(environment["JENKINS_ARTIFACT_TOKEN"], "token")

    def test_signed_query_is_stdin_only_not_process_argv(self) -> None:
        process = mock.Mock()
        process.pid = 12345
        process.returncode = 0
        payload = base_payload(
            url="https://jenkins.example.com/job/example?token=secret"
        )
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch.object(
                MODULE.subprocess,
                "Popen",
                return_value=process,
            ) as popen:
                with mock.patch.object(
                    MODULE,
                    "_bounded_worker_exchange",
                    return_value=(b'{"auth":"absent","ok":true}', b""),
                ) as exchange:
                    MODULE._run_worker(payload, deadline=time.monotonic() + 5)
        argv = popen.call_args.args[0]
        self.assertNotIn("secret", " ".join(argv))
        request = exchange.call_args.args[1]
        self.assertIn(b"secret", request)


class AtomicPublicationTests(unittest.TestCase):
    def _write_stage(self, transaction, payload: bytes) -> str:
        assert transaction.stage_fd is not None
        os.write(transaction.stage_fd, payload)
        return hashlib.sha256(payload).hexdigest()

    def test_output_outside_workspace_and_task_temp_is_rejected(self) -> None:
        with workspace_directory():
            with self.assertRaisesRegex(MODULE.UsageFailure, "must stay under"):
                MODULE.OutputTransaction("/var/tmp/cisco-output.bin")

    def test_temp_output_requires_owner_private_task_directory(self) -> None:
        path = MODULE.TEMP_ROOT / "not-task-scoped" / "artifact.zip"
        with self.assertRaisesRegex(MODULE.UsageFailure, "task directory"):
            MODULE.OutputTransaction(str(path))

    def test_existing_destination_is_no_clobber_before_stage(self) -> None:
        with workspace_directory() as workspace:
            destination = workspace / "artifact.zip"
            destination.write_bytes(b"original")
            with self.assertRaisesRegex(MODULE.UsageFailure, "no-clobber"):
                MODULE.OutputTransaction("artifact.zip")
            self.assertEqual(destination.read_bytes(), b"original")

    def test_destination_symlink_is_rejected(self) -> None:
        with workspace_directory() as workspace:
            target = workspace / "target"
            target.write_bytes(b"original")
            (workspace / "artifact.zip").symlink_to(target)
            with self.assertRaisesRegex(MODULE.UsageFailure, "symlink"):
                MODULE.OutputTransaction("artifact.zip")
            self.assertEqual(target.read_bytes(), b"original")

    def test_successful_publication_is_atomic_and_durable(self) -> None:
        with workspace_directory() as workspace:
            transaction = MODULE.OutputTransaction("artifact.zip")
            try:
                payload = b"bounded artifact"
                digest = self._write_stage(transaction, payload)
                outcome = transaction.publish(len(payload), digest)
                self.assertEqual(outcome.classification, "published")
                self.assertEqual(outcome.durability, "verified")
                self.assertEqual((workspace / "artifact.zip").read_bytes(), payload)
                self.assertIsNone(transaction.stage_name)
            finally:
                transaction.abort()
                transaction.close()

    def test_destination_creation_race_cannot_clobber(self) -> None:
        with workspace_directory() as workspace:
            transaction = MODULE.OutputTransaction("artifact.zip")
            original_rename = MODULE._rename_noreplace

            def racing_rename(*args, **kwargs):
                (workspace / "artifact.zip").write_bytes(b"racer")
                return original_rename(*args, **kwargs)

            try:
                payload = b"bounded artifact"
                digest = self._write_stage(transaction, payload)
                with mock.patch.object(
                    MODULE,
                    "_rename_noreplace",
                    side_effect=racing_rename,
                ):
                    with self.assertRaisesRegex(
                        MODULE.CommandFailure,
                        "existing destination",
                    ):
                        transaction.publish(len(payload), digest)
                self.assertEqual((workspace / "artifact.zip").read_bytes(), b"racer")
            finally:
                transaction.abort()
                transaction.close()

    def test_stage_name_replacement_is_not_deleted(self) -> None:
        with workspace_directory() as workspace:
            transaction = MODULE.OutputTransaction("artifact.zip")
            assert transaction.stage_name is not None
            stage_path = workspace / transaction.stage_name
            retained_stage = workspace / "retained-stage"
            try:
                payload = b"bounded artifact"
                digest = self._write_stage(transaction, payload)
                os.link(stage_path, retained_stage)
                stage_path.unlink()
                stage_path.write_bytes(b"attacker replacement")
                os.chmod(stage_path, 0o600)
                with self.assertRaisesRegex(
                    MODULE.CommandFailure,
                    "pathname no longer names",
                ):
                    transaction.publish(len(payload), digest)
                self.assertEqual(transaction.abort(), "unverified")
                self.assertEqual(stage_path.read_bytes(), b"attacker replacement")
            finally:
                transaction.close()
                stage_path.unlink(missing_ok=True)
                retained_stage.unlink(missing_ok=True)

    def test_missing_stage_entry_is_distinct_from_identity_mismatch(self) -> None:
        with workspace_directory() as workspace:
            transaction = MODULE.OutputTransaction("artifact.zip")
            assert transaction.stage_name is not None
            stage_path = workspace / transaction.stage_name
            retained_stage = workspace / "retained-stage"
            try:
                payload = b"bounded artifact"
                digest = self._write_stage(transaction, payload)
                os.link(stage_path, retained_stage)
                stage_path.unlink()
                with self.assertRaises(MODULE.CommandFailure) as raised:
                    transaction.publish(len(payload), digest)
                self.assertEqual(
                    raised.exception.classification,
                    "staging-entry-missing",
                )
                self.assertEqual(transaction.abort(), "unverified")
                self.assertEqual(retained_stage.read_bytes(), payload)
            finally:
                transaction.close()
                retained_stage.unlink(missing_ok=True)

    def test_unreadable_parent_revalidation_has_distinct_classification(self) -> None:
        with workspace_directory():
            transaction = MODULE.OutputTransaction("artifact.zip")
            try:
                payload = b"bounded artifact"
                digest = self._write_stage(transaction, payload)
                with mock.patch.object(
                    transaction,
                    "_rewalk_parent",
                    side_effect=PermissionError(errno.EACCES, "denied"),
                ):
                    with self.assertRaises(MODULE.CommandFailure) as raised:
                        transaction.publish(len(payload), digest)
                self.assertEqual(
                    raised.exception.classification,
                    "output-revalidation-unreadable",
                )
            finally:
                transaction.abort()
                transaction.close()

    def test_parent_identity_mismatch_blocks_publication(self) -> None:
        with workspace_directory():
            transaction = MODULE.OutputTransaction("artifact.zip")
            try:
                payload = b"bounded artifact"
                digest = self._write_stage(transaction, payload)
                transaction.anchor_identity = MODULE.DirectoryIdentity(
                    device=-1,
                    inode=-1,
                    owner=os.geteuid(),
                    mode=0o700,
                    access_policy=("test", 0, "mismatch"),
                )
                with self.assertRaisesRegex(
                    MODULE.CommandFailure,
                    "root identity or access policy changed",
                ):
                    transaction.publish(len(payload), digest)
            finally:
                transaction.abort()
                transaction.close()

    def test_access_policy_drift_blocks_publication(self) -> None:
        with workspace_directory() as workspace:
            transaction = MODULE.OutputTransaction("artifact.zip")
            assert transaction.stage_fd is not None
            assert transaction.stage_name is not None
            initial = os.fstat(transaction.stage_fd)
            original_binding = MODULE._access_policy_binding

            def drift_stage_policy(descriptor: int):
                metadata = os.fstat(descriptor)
                if (
                    metadata.st_dev == initial.st_dev
                    and metadata.st_ino == initial.st_ino
                ):
                    return ("changed-policy", 1, "different")
                return original_binding(descriptor)

            try:
                payload = b"bounded artifact"
                digest = self._write_stage(transaction, payload)
                with mock.patch.object(
                    MODULE,
                    "_access_policy_binding",
                    side_effect=drift_stage_policy,
                ):
                    with self.assertRaisesRegex(
                        MODULE.CommandFailure,
                        "access policy changed",
                    ):
                        transaction.publish(len(payload), digest)
                    self.assertEqual(transaction.abort(), "unverified")
                    self.assertTrue((workspace / transaction.stage_name).exists())
            finally:
                transaction.abort()
                transaction.close()

    def test_stage_fsync_failure_never_publishes_destination(self) -> None:
        with workspace_directory() as workspace:
            transaction = MODULE.OutputTransaction("artifact.zip")
            assert transaction.stage_fd is not None
            try:
                payload = b"bounded artifact"
                digest = self._write_stage(transaction, payload)
                with mock.patch.object(
                    MODULE.os,
                    "fsync",
                    side_effect=OSError(errno.EIO, "fsync failed"),
                ):
                    with self.assertRaisesRegex(
                        MODULE.CommandFailure,
                        "staging file fsync",
                    ):
                        transaction.publish(len(payload), digest)
                self.assertFalse((workspace / "artifact.zip").exists())
            finally:
                transaction.abort()
                transaction.close()

    def test_directory_fsync_failure_keeps_visible_destination(self) -> None:
        with workspace_directory() as workspace:
            transaction = MODULE.OutputTransaction("artifact.zip")
            assert transaction.stage_fd is not None
            stage_fd = transaction.stage_fd
            parent_fd = transaction.parent_fd
            original_fsync = os.fsync

            def selective_fsync(descriptor: int):
                if descriptor == parent_fd:
                    raise OSError(errno.EIO, "directory fsync failed")
                return original_fsync(descriptor)

            try:
                payload = b"bounded artifact"
                digest = self._write_stage(transaction, payload)
                with mock.patch.object(
                    MODULE.os,
                    "fsync",
                    side_effect=selective_fsync,
                ):
                    outcome = transaction.publish(len(payload), digest)
                self.assertEqual(outcome.publication, "published")
                self.assertEqual(outcome.durability, "unverified")
                self.assertEqual(outcome.classification, "durability-unverified")
                self.assertEqual((workspace / "artifact.zip").read_bytes(), payload)
                self.assertNotEqual(stage_fd, parent_fd)
            finally:
                transaction.abort()
                transaction.close()

    def test_postpublication_identity_failure_reports_visible_destination(self) -> None:
        with workspace_directory() as workspace:
            transaction = MODULE.OutputTransaction("artifact.zip")
            original_stage_identity = transaction._stage_identity

            def fail_after_publication():
                if transaction.published:
                    raise MODULE.CommandFailure(
                        "staging-identity-mismatch",
                        "postpublication identity failure",
                        exit_code=MODULE.EXIT_PUBLICATION,
                    )
                return original_stage_identity()

            try:
                payload = b"bounded artifact"
                digest = self._write_stage(transaction, payload)
                with mock.patch.object(
                    transaction,
                    "_stage_identity",
                    side_effect=fail_after_publication,
                ):
                    outcome = transaction.publish(len(payload), digest)
                self.assertEqual(outcome.publication, "published")
                self.assertEqual(outcome.durability, "unverified")
                self.assertEqual(
                    outcome.classification,
                    "published-identity-unverified",
                )
                self.assertEqual((workspace / "artifact.zip").read_bytes(), payload)
            finally:
                transaction.abort()
                transaction.close()

    def test_postrename_content_drift_never_reports_verified_publication(self) -> None:
        with workspace_directory() as workspace:
            transaction = MODULE.OutputTransaction("artifact.zip")
            assert transaction.stage_name is not None
            stage_path = workspace / transaction.stage_name
            attacker_fd = os.open(stage_path, os.O_RDWR)
            original_rename = MODULE._rename_noreplace

            def mutate_then_rename(*args, **kwargs):
                os.pwrite(attacker_fd, b"X", 0)
                return original_rename(*args, **kwargs)

            try:
                payload = b"bounded artifact"
                digest = self._write_stage(transaction, payload)
                with mock.patch.object(
                    MODULE,
                    "_rename_noreplace",
                    side_effect=mutate_then_rename,
                ):
                    outcome = transaction.publish(len(payload), digest)
                self.assertEqual(outcome.publication, "published")
                self.assertEqual(outcome.durability, "unverified")
                self.assertEqual(outcome.cleanup, "complete")
                self.assertEqual(
                    outcome.classification,
                    "published-content-unverified",
                )
                self.assertNotEqual((workspace / "artifact.zip").read_bytes(), payload)
            finally:
                os.close(attacker_fd)
                transaction.abort()
                transaction.close()

    def test_postrename_source_replacement_never_reports_verified_publication(
        self,
    ) -> None:
        with workspace_directory() as workspace:
            transaction = MODULE.OutputTransaction("artifact.zip")
            assert transaction.stage_name is not None
            stage_path = workspace / transaction.stage_name
            original_rename = MODULE._rename_noreplace

            def replace_then_rename(*args, **kwargs):
                stage_path.unlink()
                stage_path.write_bytes(b"replacement")
                os.chmod(stage_path, 0o400)
                return original_rename(*args, **kwargs)

            try:
                payload = b"bounded artifact"
                digest = self._write_stage(transaction, payload)
                with mock.patch.object(
                    MODULE,
                    "_rename_noreplace",
                    side_effect=replace_then_rename,
                ):
                    outcome = transaction.publish(len(payload), digest)
                self.assertEqual(outcome.publication, "published")
                self.assertEqual(
                    outcome.classification,
                    "published-identity-unverified",
                )
                self.assertEqual(
                    (workspace / "artifact.zip").read_bytes(),
                    b"replacement",
                )
            finally:
                transaction.abort()
                transaction.close()

    def test_content_digest_mismatch_blocks_publication(self) -> None:
        with workspace_directory() as workspace:
            transaction = MODULE.OutputTransaction("artifact.zip")
            try:
                payload = b"bounded artifact"
                self._write_stage(transaction, payload)
                with self.assertRaisesRegex(MODULE.CommandFailure, "digest differs"):
                    transaction.publish(len(payload), "0" * 64)
                self.assertFalse((workspace / "artifact.zip").exists())
            finally:
                transaction.abort()
                transaction.close()

    def test_attacker_writable_parent_is_rejected(self) -> None:
        with workspace_directory() as workspace:
            unsafe = workspace / "unsafe"
            unsafe.mkdir(mode=0o777)
            os.chmod(unsafe, 0o777)
            with self.assertRaisesRegex(
                MODULE.UsageFailure,
                "writable by an untrusted principal",
            ):
                MODULE.OutputTransaction("unsafe/artifact.zip")

    def test_owner_private_fixed_temp_task_directory_is_allowed(self) -> None:
        task_directory = pathlib.Path(
            tempfile.mkdtemp(
                prefix=MODULE.TEMP_DIRECTORY_PREFIX,
                dir=MODULE.TEMP_ROOT,
            )
        )
        os.chmod(task_directory, 0o700)
        transaction = None
        try:
            transaction = MODULE.OutputTransaction(str(task_directory / "artifact.zip"))
            payload = b"bounded artifact"
            digest = self._write_stage(transaction, payload)
            outcome = transaction.publish(len(payload), digest)
            self.assertEqual(outcome.classification, "published")
            self.assertEqual(
                (task_directory / "artifact.zip").read_bytes(),
                payload,
            )
        finally:
            if transaction is not None:
                transaction.abort()
                transaction.close()
            artifact = task_directory / "artifact.zip"
            artifact.unlink(missing_ok=True)
            task_directory.rmdir()

    def test_existing_destination_prevents_network_launch(self) -> None:
        with workspace_directory() as workspace:
            (workspace / "artifact.zip").write_bytes(b"original")
            args = MODULE.build_parser().parse_args(
                [
                    "fetch-url",
                    "https://jenkins.example.com/file.zip",
                    "--output",
                    "artifact.zip",
                ]
            )
            with mock.patch.object(MODULE, "_run_worker") as worker:
                with self.assertRaises(MODULE.UsageFailure):
                    MODULE._execute_fetch(args, time.monotonic() + 5)
            worker.assert_not_called()

    def test_failed_producer_and_stage_cleanup_remain_independent(self) -> None:
        with workspace_directory() as workspace:
            args = MODULE.build_parser().parse_args(
                [
                    "fetch-url",
                    "https://jenkins.example.com/file.zip",
                    "--output",
                    "artifact.zip",
                ]
            )
            failure = MODULE.ProducerFailure(
                "producer-timeout",
                "deadline",
                cleanup="term-reaped",
            )
            with mock.patch.object(MODULE, "_run_worker", side_effect=failure):
                with self.assertRaises(MODULE.ProducerFailure) as raised:
                    MODULE._execute_fetch(args, time.monotonic() + 5)
            error = raised.exception
            self.assertEqual(error.cleanup, "term-reaped")
            self.assertEqual(error.metadata["producer_cleanup"], "term-reaped")
            self.assertEqual(error.metadata["staging_cleanup"], "complete")
            self.assertFalse((workspace / "artifact.zip").exists())
            self.assertEqual(
                list(workspace.glob(".cisco-build-artifacts.*.tmp")),
                [],
            )


class ArgumentAndReportingTests(unittest.TestCase):
    def test_success_metadata_escapes_terminal_control_characters(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            MODULE._print_metadata({"content_type": "text/plain\x1b[31m\nforged=value"})
        rendered = stdout.getvalue()
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\nforged=value", rendered)
        self.assertIn(r"\u001b", rendered)
        self.assertIn(r"\u000a", rendered)

    def test_nonfinite_timeouts_are_usage_errors(self) -> None:
        parser = MODULE.build_parser()
        for value in ("nan", "inf", "-inf"):
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as raised:
                    parser.parse_args(
                        [
                            "probe-url",
                            "https://jenkins.example.com/job/example",
                            "--timeout",
                            value,
                        ]
                    )
            self.assertEqual(raised.exception.code, MODULE.EXIT_USAGE)

    def test_empty_and_invalid_grep_patterns_are_usage_errors(self) -> None:
        parser = MODULE.build_parser()
        for value in ("", "("):
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as raised:
                    parser.parse_args(
                        [
                            "show-url",
                            "https://jenkins.example.com/job/example/consoleText",
                            "--grep",
                            value,
                        ]
                    )
            self.assertEqual(raised.exception.code, MODULE.EXIT_USAGE)

    def test_zero_and_above_hard_max_are_usage_errors(self) -> None:
        parser = MODULE.build_parser()
        for value in ("0", str(MODULE.HARD_MAX_BODY_BYTES + 1)):
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as raised:
                    parser.parse_args(
                        [
                            "fetch-url",
                            "https://jenkins.example.com/file.zip",
                            "--output",
                            "artifact.zip",
                            "--max-body-bytes",
                            value,
                        ]
                    )
            self.assertEqual(raised.exception.code, MODULE.EXIT_USAGE)
            self.assertIn("classification=argument-rejected", stderr.getvalue())

    def test_defaults_are_finite_and_not_disable_flags(self) -> None:
        args = MODULE.build_parser().parse_args(
            [
                "fetch-url",
                "https://jenkins.example.com/file.zip",
                "--output",
                "artifact.zip",
            ]
        )
        self.assertGreater(args.timeout, 0)
        self.assertGreater(args.max_body_bytes, 0)
        self.assertGreater(args.max_redirects, 0)
        self.assertLessEqual(args.timeout, MODULE.HARD_MAX_TOTAL_TIMEOUT_SECONDS)
        self.assertLessEqual(args.max_body_bytes, MODULE.HARD_MAX_BODY_BYTES)

    def test_error_reporting_does_not_echo_signed_query(self) -> None:
        error = MODULE.CommandFailure(
            "remote-http-error",
            "remote HTTP status 500",
            exit_code=MODULE.EXIT_REMOTE,
        )
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            MODULE._emit_failure(error)
        self.assertNotIn("token", stderr.getvalue())
        self.assertEqual(
            stderr.getvalue().splitlines(),
            [
                "classification=remote-http-error",
                "detail=remote HTTP status 500",
            ],
        )

    def test_metadata_reports_redaction_and_representation(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            MODULE._print_metadata(
                {
                    "source_url": "https://jenkins.example.com/file?redacted",
                    "query_redacted": True,
                    "wire_bytes": 12,
                    "entity_bytes": 12,
                    "persisted_bytes": 12,
                    "representation": "identity-http-entity",
                }
            )
        lines = stdout.getvalue().splitlines()
        self.assertIn("query_redacted=true", lines)
        self.assertIn("wire_bytes=12", lines)
        self.assertIn("entity_bytes=12", lines)
        self.assertIn("persisted_bytes=12", lines)


class PackagingTests(unittest.TestCase):
    def test_cisco_skill_owns_both_helpers(self) -> None:
        skill = REPO_ROOT / "skills/cisco-build-artifacts"
        self.assertTrue((skill / "SKILL.md").is_file())
        self.assertTrue((skill / "agents/openai.yaml").is_file())
        self.assertTrue((skill / "scripts/cisco_build_artifacts.py").is_file())
        self.assertTrue((skill / "scripts/archive_triage.py").is_file())
        self.assertTrue((skill / "references/remote-artifact-recipes.md").is_file())
        self.assertTrue((skill / "references/local-artifact-recipes.md").is_file())

    def test_bug_triage_no_longer_owns_remote_helpers(self) -> None:
        old = REPO_ROOT / "skills/bug-triage-playbook"
        self.assertFalse((old / "scripts/jenkins_artifact_probe.py").exists())
        self.assertFalse((old / "scripts/archive_triage.py").exists())
        self.assertFalse((old / "references/jenkins-artifact-recipes.md").exists())
        self.assertFalse((old / "references/local-artifact-recipes.md").exists())


if __name__ == "__main__":
    unittest.main()
