---
id: 20260727-638eec
title: Cisco Cutover Admission Hardening
status: blocked
created: 2026-07-27
updated: 2026-07-27
branch: codex/retire-active-generic-triage
pr: https://github.com/Joey-Tools/codex-debug-triage/pull/5
supersedes: []
superseded_by:
---

# Cisco Cutover Admission Hardening

## Summary

- PR #5 hardens the Cisco cutover enforcement doctor and bounded archive triage.
- Static admission remains intentionally blocked until a trusted live pointer authority is configured.

## Current State

- Directory mode-restoration failures make cleanup proof inconclusive even when all later removals succeed; retained-object evidence reflects only objects still locatable after cleanup.
- Workflow ID and SHA Actions variables must match both the administrator-pinned inputs and the selected native workflow metadata.
- Root-only DAC bypass and non-reaping PID 1 behavior no longer make the related tests host-dependent.
- Regex-worker teardown enters a retryable deadline-owned cleanup state before signal-support inspection, captures the true original mask with exactly one blocking call, masks repeating command-level `SIGALRM` across TERM/KILL/reap and pipe closure, restores only that captured mask, rethrows recorded deadline evidence, and retains the authoritative process handle plus PID/PGID recovery evidence when reap cannot be proven.

## Next Steps

- Configure the trusted live pointer authority and collect fresh live evidence before attempting cutover admission.
- Preserve the exact workflow, ruleset, run-attempt, and candidate-head bindings when refreshing evidence.

## Evidence

- PR: https://github.com/Joey-Tools/codex-debug-triage/pull/5
- Exact-bot reviewed head: `638eec5283ec1cf86b4cf33bbafd6d6286b66f32`
- Fresh Codex review range: `b6af1cf257deb1cdee04fbd49f72cabf2697ac5c..c742210b33c9ad7058e853766f9bedde896886b1`.
- Follow-up fresh Codex review range: `b6af1cf257deb1cdee04fbd49f72cabf2697ac5c..ce2e60cdb0251dbede38230e713ea7c1764155fe`.
- Review-fix regression selection: cleanup mode proof, workflow input identity, root DAC replacement, external regex-worker group termination, command deadline during regex teardown, pre-mask handshake interruption and retry, exact original-mask restoration, live-worker recovery identity, and unreaped-worker handle retention.
- Python 3.13.0 full suite: 223 tests passed.
- System Python 3.9.6 full suite: 223 tests passed.
- Python 3.13.0 and system Python 3.9.6 compilation passed for all CI-listed helpers and tests.
- Ruff passed for all CI-listed Python helpers and tests.
- Official skill validation was unavailable because PyYAML is not installed; the equivalent Ruby/Psych frontmatter fallback passed and its task-scoped files were removed.
