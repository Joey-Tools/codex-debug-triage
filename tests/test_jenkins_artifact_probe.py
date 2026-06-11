from __future__ import annotations

import argparse
import base64
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock
import urllib.error


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = (
    REPO_ROOT
    / "skills/bug-triage-playbook/scripts/jenkins_artifact_probe.py"
)
SPEC = importlib.util.spec_from_file_location("jenkins_artifact_probe", SCRIPT_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class FakeHTTPResponse(io.BytesIO):
    def __init__(
        self,
        payload: bytes,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(payload)
        self.status = status
        self.headers = headers or {}

    def __enter__(self) -> "FakeHTTPResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.close()
        return False


class JenkinsArtifactProbeTests(unittest.TestCase):
    def test_show_url_tail_outputs_last_lines(self) -> None:
        args = argparse.Namespace(
            url="https://jenkins.example.com/jenkins/job/example/consoleText",
            auth_profile=None,
            timeout=5,
            grep=None,
            ignore_case=False,
            context=0,
            head=0,
            tail=2,
            encoding="utf-8",
            line_numbers=False,
        )
        buffer = io.StringIO()
        with mock.patch(
            "urllib.request.urlopen",
            return_value=FakeHTTPResponse(b"line1\nline2\nline3\n"),
        ):
            with redirect_stdout(buffer):
                rc = MODULE.cmd_show_url(args)
        self.assertEqual(rc, 0)
        self.assertEqual(buffer.getvalue().splitlines(), ["line2", "line3"])

    def test_show_url_grep_with_context_and_line_numbers(self) -> None:
        args = argparse.Namespace(
            url="https://jenkins.example.com/jenkins/job/example/consoleText",
            auth_profile=None,
            timeout=5,
            grep="error",
            ignore_case=True,
            context=1,
            head=0,
            tail=0,
            encoding="utf-8",
            line_numbers=True,
        )
        buffer = io.StringIO()
        with mock.patch(
            "urllib.request.urlopen",
            return_value=FakeHTTPResponse(b"alpha\nbeta\nERROR boom\ngamma\ndelta\n"),
        ):
            with redirect_stdout(buffer):
                rc = MODULE.cmd_show_url(args)
        self.assertEqual(rc, 0)
        self.assertEqual(
            buffer.getvalue().splitlines(),
            ["2:beta", "3:ERROR boom", "4:gamma"],
        )

    def test_build_remote_request_adds_auth_header_from_profile(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "JENKINS_ARTIFACT_USER": "user",
                "JENKINS_ARTIFACT_TOKEN": "token",
            },
            clear=False,
        ):
            request, auth_state = MODULE._build_remote_request(
                "https://jenkins.example.com/jenkins/job/example/api/json",
                method="GET",
                auth_profile="default",
            )

        self.assertEqual(auth_state, "present")
        self.assertEqual(
            request.get_header("Authorization"),
            f"Basic {base64.b64encode(b'user:token').decode('ascii')}",
        )

    def test_build_remote_request_rejects_disallowed_host(self) -> None:
        with self.assertRaisesRegex(ValueError, "host not allowed: example.com"):
            MODULE._build_remote_request(
                "https://example.com/jenkins/job/example/api/json",
                method="GET",
                auth_profile=None,
            )

    def test_build_remote_request_rejects_non_https_urls(self) -> None:
        with self.assertRaisesRegex(ValueError, "only https URLs are allowed"):
            MODULE._build_remote_request(
                "http://jenkins.example.com/jenkins/job/example/api/json",
                method="GET",
                auth_profile=None,
            )

    def test_build_remote_request_rejects_inline_url_credentials(self) -> None:
        with self.assertRaisesRegex(
            ValueError,
            "inline URL credentials are not allowed",
        ):
            MODULE._build_remote_request(
                "https://user:token@jenkins.example.com/jenkins/job/example/api/json",
                method="GET",
                auth_profile=None,
            )

    def test_resolve_output_path_allows_workspace_relative_path(self) -> None:
        original_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir) / "workspace"
            workspace.mkdir()
            os.chdir(workspace)
            try:
                resolved = MODULE._resolve_output_path(".codex-tmp/run.consoleText")
            finally:
                os.chdir(original_cwd)

        self.assertEqual(
            resolved,
            (workspace / ".codex-tmp/run.consoleText").resolve(),
        )

    def test_resolve_output_path_allows_tmp_path(self) -> None:
        resolved = MODULE._resolve_output_path("/tmp/jenkins-artifact/run.consoleText")
        self.assertEqual(
            resolved,
            Path("/tmp/jenkins-artifact/run.consoleText").resolve(),
        )

    def test_resolve_output_path_rejects_outside_workspace_and_tmp(self) -> None:
        original_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir) / "workspace"
            workspace.mkdir()
            outside = Path("/var/tmp/codex-debug-triage-outside/run.consoleText")
            os.chdir(workspace)
            try:
                with self.assertRaisesRegex(
                    ValueError,
                    "output path must stay under",
                ):
                    MODULE._resolve_output_path(str(outside))
            finally:
                os.chdir(original_cwd)

    def test_select_lines_respects_head_before_full_output(self) -> None:
        lines = ["a", "b", "c"]
        self.assertEqual(
            MODULE._select_lines(
                lines,
                grep=None,
                ignore_case=False,
                context=0,
                head=2,
                tail=0,
            ),
            [(1, "a"), (2, "b")],
        )

    def test_select_stream_lines_tails_without_materializing_all_lines(self) -> None:
        stream = io.BytesIO(b"line1\nline2\nline3\n")
        self.assertEqual(
            MODULE._select_stream_lines(stream, "utf-8", head=0, tail=2),
            [(2, "line2"), (3, "line3")],
        )

    def test_select_stream_lines_respects_head(self) -> None:
        stream = io.BytesIO(b"line1\nline2\nline3\n")
        self.assertEqual(
            MODULE._select_stream_lines(stream, "utf-8", head=2, tail=0),
            [(1, "line1"), (2, "line2")],
        )

    def test_show_url_reports_auth_state_on_http_error(self) -> None:
        args = argparse.Namespace(
            url="https://jenkins.example.com/jenkins/job/example/consoleText",
            auth_profile="default",
            timeout=5,
            grep=None,
            ignore_case=False,
            context=0,
            head=0,
            tail=20,
            encoding="utf-8",
            line_numbers=False,
        )
        error = urllib.error.HTTPError(
            args.url,
            403,
            "Forbidden",
            hdrs=None,
            fp=None,
        )
        stderr = io.StringIO()
        with mock.patch.dict(
            os.environ,
            {
                "JENKINS_ARTIFACT_USER": "user",
                "JENKINS_ARTIFACT_TOKEN": "token",
            },
            clear=False,
        ):
            with mock.patch("urllib.request.urlopen", side_effect=error):
                with redirect_stdout(io.StringIO()):
                    with unittest.mock.patch("sys.stderr", stderr):
                        rc = MODULE.cmd_show_url(args)

        self.assertEqual(rc, 1)
        self.assertEqual(
            stderr.getvalue().splitlines(),
            [
                f"url={args.url}",
                "auth=present",
                "status=403",
                "error=Forbidden",
            ],
        )

    def test_probe_url_reports_missing_auth_env_before_network(self) -> None:
        args = argparse.Namespace(
            url="https://jenkins.example.com/jenkins/job/example/consoleText",
            auth_profile="default",
            method="HEAD",
            timeout=5,
            sniff_bytes=0,
            encoding="utf-8",
        )
        stderr = io.StringIO()
        with mock.patch("urllib.request.urlopen") as urlopen:
            with mock.patch.dict(os.environ, {}, clear=True):
                with unittest.mock.patch("sys.stderr", stderr):
                    rc = MODULE.cmd_probe_url(args)

        self.assertEqual(rc, 2)
        urlopen.assert_not_called()
        self.assertEqual(
            stderr.getvalue().splitlines(),
            [
                f"url={args.url}",
                "error=missing auth env for profile default: expected "
                "JENKINS_ARTIFACT_USER and JENKINS_ARTIFACT_TOKEN",
            ],
        )

    def test_probe_url_reports_disallowed_host_before_network(self) -> None:
        args = argparse.Namespace(
            url="https://example.com/jenkins/job/example/consoleText",
            auth_profile=None,
            method="HEAD",
            timeout=5,
            sniff_bytes=0,
            encoding="utf-8",
        )
        stderr = io.StringIO()
        with mock.patch("urllib.request.urlopen") as urlopen:
            with unittest.mock.patch("sys.stderr", stderr):
                rc = MODULE.cmd_probe_url(args)

        self.assertEqual(rc, 2)
        urlopen.assert_not_called()
        self.assertEqual(
            stderr.getvalue().splitlines(),
            [
                f"url={args.url}",
                "error=host not allowed: example.com",
            ],
        )

    def test_fetch_url_reports_disallowed_output_path_before_network(self) -> None:
        args = argparse.Namespace(
            url="https://jenkins.example.com/jenkins/job/example/consoleText",
            output="/var/tmp/run.consoleText",
            auth_profile=None,
            timeout=5,
        )
        stderr = io.StringIO()
        with mock.patch("urllib.request.urlopen") as urlopen:
            with unittest.mock.patch("sys.stderr", stderr):
                rc = MODULE.cmd_fetch_url(args)

        self.assertEqual(rc, 2)
        urlopen.assert_not_called()
        self.assertEqual(
            stderr.getvalue().splitlines(),
            [
                f"url={args.url}",
                "error=output path must stay under "
                f"{Path.cwd().resolve()} or {Path('/tmp').resolve()}",
            ],
        )

    def test_show_url_uses_stream_fast_path_for_positive_tail(self) -> None:
        args = argparse.Namespace(
            url="https://jenkins.example.com/jenkins/job/example/consoleText",
            auth_profile=None,
            timeout=5,
            grep=None,
            ignore_case=False,
            context=0,
            head=0,
            tail=2,
            encoding="utf-8",
            line_numbers=False,
        )
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = None
        stdout = io.StringIO()
        with mock.patch("urllib.request.urlopen", return_value=response):
            with mock.patch.object(
                MODULE,
                "_select_stream_lines",
                return_value=[(9, "tail-line")],
            ) as stream_select:
                with mock.patch.object(MODULE, "_select_lines") as slow_select:
                    with redirect_stdout(stdout):
                        rc = MODULE.cmd_show_url(args)

        self.assertEqual(rc, 0)
        stream_select.assert_called_once_with(response, "utf-8", 0, 2)
        slow_select.assert_not_called()
        self.assertEqual(stdout.getvalue().splitlines(), ["tail-line"])

    def test_show_url_negative_tail_keeps_legacy_empty_output(self) -> None:
        args = argparse.Namespace(
            url="https://jenkins.example.com/jenkins/job/example/consoleText",
            auth_profile=None,
            timeout=5,
            grep=None,
            ignore_case=False,
            context=0,
            head=0,
            tail=-1,
            encoding="utf-8",
            line_numbers=False,
        )
        buffer = io.StringIO()
        with mock.patch(
            "urllib.request.urlopen",
            return_value=FakeHTTPResponse(b"line1\nline2\n"),
        ):
            with redirect_stdout(buffer):
                rc = MODULE.cmd_show_url(args)

        self.assertEqual(rc, 0)
        self.assertEqual(buffer.getvalue(), "")

    def test_show_url_mixed_sign_counts_fall_back_to_legacy_behavior(self) -> None:
        args = argparse.Namespace(
            url="https://jenkins.example.com/jenkins/job/example/consoleText",
            auth_profile=None,
            timeout=5,
            grep=None,
            ignore_case=False,
            context=0,
            head=-1,
            tail=2,
            encoding="utf-8",
            line_numbers=False,
        )
        buffer = io.StringIO()
        with mock.patch(
            "urllib.request.urlopen",
            return_value=FakeHTTPResponse(b"line1\nline2\nline3\n"),
        ):
            with redirect_stdout(buffer):
                rc = MODULE.cmd_show_url(args)

        self.assertEqual(rc, 0)
        self.assertEqual(buffer.getvalue().splitlines(), ["line1", "line2"])


class BugTriageDocumentationTests(unittest.TestCase):
    def test_skill_warns_against_wide_local_artifact_reads(self) -> None:
        skill = (
            REPO_ROOT / "skills/bug-triage-playbook/SKILL.md"
        ).read_text(encoding="utf-8")

        self.assertIn("Do not run raw `rg -n` across `.codex-tmp`", skill)
        self.assertIn("release API responses or HTML/manual pages", skill)
        self.assertIn("`rg -l`, `rg --count`, or selected JSON keys", skill)

    def test_jenkins_recipe_budgets_local_artifact_reads(self) -> None:
        recipe = (
            REPO_ROOT
            / "skills/bug-triage-playbook/references/jenkins-artifact-recipes.md"
        ).read_text(encoding="utf-8")

        self.assertIn("## 3. Budget Local Artifact Reads", recipe)
        self.assertIn("Do not run raw `rg -n` across `.codex-tmp`", recipe)
        self.assertIn("Use `rg -l` / `rg --count` first", recipe)
        self.assertIn("fetch to disk and extract selected fields", recipe)


if __name__ == "__main__":
    unittest.main()
