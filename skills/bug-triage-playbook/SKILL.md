---
name: bug-triage-playbook
description: Optional, explicitly invoked framework for manually triaging provided local logs, crash reports, test output, and downloaded archives into ranked root-cause hypotheses and the next discriminating check. Use only when the user explicitly invokes $bug-triage-playbook or asks to apply this public playbook; do not use for remote artifact acquisition, provider-specific CI or check triage, tracker lookup, or a repository's stronger debugging workflow.
---

# Bug Triage Playbook

## Overview

Use this optional skill when debugging starts from symptoms and the relevant
evidence is already available locally. Turn logs, traces, failing tests, or
behavioral regressions into a small ranked hypothesis set, the strongest
evidence, and the next discriminating action.

## Respect Provider Boundaries

- For provider-specific CI or check failures, leave this skill and use the
  provider owner's workflow. In environments with the GitHub plugin, GitHub
  Actions belongs to that plugin rather than this generic playbook.
- For an authenticated/private build system, use a provider-specific retrieval
  skill or tool. That owner must define its host policy, credential interface,
  authentication preflight, and download controls. Return here only after the
  requested artifact is available locally.
- For tracker metadata, use the tracker owner's lookup workflow before
  treating linked logs or archives as triage evidence.
- If a repository supplies a stronger debugging playbook, follow it instead.

## Workflow

1. Normalize the problem first.
- Capture the exact symptom, observed behavior, expected behavior, repro conditions, and first known bad point in time if available.
- Separate user claims from confirmed evidence.
- If the report spans multiple processes, threads, machines, or timestamps, build a short timeline before editing code.

2. Establish artifact authority.
- If the user points to a specific remote log, archive, crash report, or build URL, treat that artifact as the primary evidence.
- Verify the local artifact's identity and provenance before mining similar files,
  older runs, or nearby code.
- Keep acquisition failures distinct from inconclusive evidence. If the
  provider-specific path is blocked, report the exact blocker instead of
  substituting stale local material.
- Treat prior sessions or nearby artifacts as secondary context unless the user
  explicitly accepts them as substitutes.
- Use a task-scoped temporary directory for downloaded or extracted data, and
  clean it up before finishing unless the user asks to keep it.
- Start large local reads with file sizes, line counts, candidate filenames,
  match counts, or selected structured fields. Then inspect one exact file,
  archive member, or small line window.
- Use `scripts/archive_triage.py` only for local ZIP listing and text-member
  inspection. It performs no network access and has no credential interface.
- Read `references/local-artifact-recipes.md` when the artifact needs repeated
  bounded local inspection.

3. Build a small hypothesis set.
- Start with one to three plausible root-cause hypotheses.
- Rank by likelihood and blast radius, not by convenience.
- Keep at least one hypothesis that challenges the current narrative when the failure is high impact.

4. Map evidence to the implementation.
- Use stable tokens from logs, error strings, metric names, file paths, state names, and feature flags to find code entry points.
- Trace state transitions, retries, queue handoffs, thread hops, and ownership boundaries before proposing a fix.
- Prefer the narrowest files and functions that can explain the symptom.

5. Choose the smallest discriminating next step.
- Prefer one step that can eliminate a major hypothesis: a targeted search, a focused repro, a tighter log point, a minimal test, or a scoped diff inspection.
- Do not ask for broad extra data if a smaller check can separate the leading hypotheses.
- If the issue is already clear enough, move directly to the fix and list the evidence that justified skipping more investigation.

6. Close with a triage report, not just scattered observations.
- State the most likely root cause.
- List the strongest evidence and the most credible alternative explanation.
- Recommend the next validation step or the smallest safe fix.
- Use `references/triage-report.md` when a reusable output structure helps.

## Guardrails

- Do not jump to code changes before the symptom and hypothesis set are coherent.
- Do not treat the first matching log string as proof of causality.
- Do not substitute a similar local artifact for the requested remote artifact unless the user explicitly accepts that fallback.
- Keep the hypothesis set small; too many branches usually means the evidence was not normalized first.
- When the evidence is inconclusive, say what remains uncertain and what single check would reduce uncertainty fastest.
- Do not invent private host allowlists, credential names, authentication
  profiles, or remote-fetch commands inside this generic skill.
- Do not let local artifact mining become the new wide read: avoid path-wide
  line-producing searches, full structured payload dumps, and broad log
  windows.
- Separate "could not access the requested artifact" from "artifact inspected and evidence was inconclusive"; these are different outcomes.
- Do not leave large downloaded archives, extracted members, or temporary worktrees behind silently; either remove them before finishing or report the residual paths.

## References

- Use `references/triage-report.md` for a compact structure covering symptoms, hypotheses, evidence, and next steps.
- Use `references/local-artifact-recipes.md` for bounded inspection of local logs and ZIP archives.
