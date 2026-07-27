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

## Next Steps

- Configure the trusted live pointer authority and collect fresh live evidence before attempting cutover admission.
- Preserve the exact workflow, ruleset, run-attempt, and candidate-head bindings when refreshing evidence.

## Evidence

- PR: https://github.com/Joey-Tools/codex-debug-triage/pull/5
- Exact-bot reviewed head: `638eec5283ec1cf86b4cf33bbafd6d6286b66f32`
- Review-fix regression selection: cleanup mode proof, workflow input identity, root DAC replacement, and external regex-worker group termination tests.
- Python 3.13.0 full suite: 219 tests passed.
- System Python 3.9.6 full suite: 219 tests passed.
