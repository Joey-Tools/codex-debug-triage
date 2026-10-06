from __future__ import annotations

from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = REPO_ROOT / ".github/workflows/codex-review-gate-controller.yml"


class ReviewGateControllerTests(unittest.TestCase):
    def test_auto_request_is_opt_in_and_begins_review_at_run_head(self) -> None:
        workflow = CONTROLLER.read_text(encoding="utf-8")

        for contract in (
            "  workflow_run:\n    workflows: [Codex Review Gate Verifier]\n    types: [completed]",
            "vars.CODEX_REVIEW_GATE_AUTO_REQUEST == 'true'",
            "github.event.workflow_run.event == 'pull_request'",
            "github.event.workflow_run.run_attempt == 1",
            "github.event.workflow_run.conclusion == 'failure'",
            "github.event.workflow_run.pull_requests[0].number",
            "!github.event.workflow_run.pull_requests[1]",
            "CODEX_REVIEW_GATE_AUTO_REQUEST: ${{ vars.CODEX_REVIEW_GATE_AUTO_REQUEST }}",
            "github.event.workflow_run.head_sha",
            "github.event.workflow_run.pull_requests[0].number || '0'",
            "operation: ${{ github.event_name == 'workflow_run' && vars.CODEX_REVIEW_GATE_AUTO_REQUEST == 'true' && github.event.workflow_run.run_attempt == 1 && github.event.workflow_run.conclusion == 'failure' && github.event.workflow_run.pull_requests[0].number && !github.event.workflow_run.pull_requests[1] && 'begin-review'",
            "&& 'begin-review' || github.event_name == 'workflow_run' && 'report-completion'",
            "request_review: ${{ github.event_name == 'workflow_run' && vars.CODEX_REVIEW_GATE_AUTO_REQUEST == 'true' && github.event.workflow_run.run_attempt == 1 && github.event.workflow_run.conclusion == 'failure' && github.event.workflow_run.pull_requests[0].number && !github.event.workflow_run.pull_requests[1] || github.event_name == 'workflow_dispatch' && inputs.request_review || false }}",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, workflow)

    def test_completion_admission_accepts_only_exact_or_pull_request_merge_path(self) -> None:
        workflow = CONTROLLER.read_text(encoding="utf-8")
        guard = workflow.split("    if: >-\n", 1)[1].split("    runs-on:", 1)[0]
        exact_paths = re.findall(r"github\.event\.workflow_run\.path == '([^']+)'", guard)
        path_prefixes = re.findall(
            r"startsWith\(github\.event\.workflow_run\.path, '([^']+)'\)", guard
        )

        self.assertEqual(exact_paths, [".github/workflows/codex-review-gate.yml"])
        self.assertEqual(
            path_prefixes,
            [".github/workflows/codex-review-gate.yml@refs/pull/"],
        )
        self.assertIn("endsWith(github.event.workflow_run.path, '/merge')", guard)
        self.assertIn("github.event.workflow_run.event == 'pull_request'", guard)
        self.assertNotIn("github.event.workflow_run.run_attempt", guard)
        self.assertNotIn("github.event.workflow_run.conclusion", guard)

        def admitted(path: str) -> bool:
            return path in exact_paths or any(
                path.startswith(prefix) and path.endswith("/merge")
                for prefix in path_prefixes
            )

        self.assertTrue(admitted(".github/workflows/codex-review-gate.yml"))
        self.assertTrue(
            admitted(".github/workflows/codex-review-gate.yml@refs/pull/123/merge")
        )
        self.assertFalse(admitted(".github/workflows/codex-review-gate.yml.backup"))
        self.assertFalse(
            admitted(".github/workflows/codex-review-gate.yml@refs/heads/main")
        )
        self.assertFalse(
            admitted(".github/workflows/codex-review-gate.yml@refs/pull/123/head")
        )

    def test_unassociated_runs_get_distinct_concurrency_fallback(self) -> None:
        workflow = CONTROLLER.read_text(encoding="utf-8")
        concurrency_group = next(
            line.strip() for line in workflow.splitlines() if line.startswith("  group: ")
        )

        self.assertIn(
            "github.event.workflow_run.pull_requests[0].number || "
            "github.event.issue.number || inputs.pr_number || "
            "github.event.workflow_run.id || github.run_id",
            concurrency_group,
        )


if __name__ == "__main__":
    unittest.main()
