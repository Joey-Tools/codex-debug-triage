---
name: bug-triage-playbook
description: Optional structured hypothesis reference for maintainers who explicitly invoke it while diagnosing local logs, regressions, flaky behavior, or failing tests. Ordinary diagnosis stays with the base model; this skill does not own remote artifact acquisition, Cisco/Jenkins evidence, or GitHub Actions.
---

# Bug Triage Playbook

## Overview

Use this optional reference only when the caller explicitly asks for its
structured symptom-to-hypothesis workflow. Ordinary debugging and diagnosis
fall through to the base model without loading this skill.

Cisco Jenkins builds, console output, remote artifact URLs, and fetched
archives belong to `$cisco-build-artifacts`. GitHub Actions and pull-request
checks belong to the GitHub provider workflow.

## Workflow

1. Normalize the exact symptom, observed behavior, expected behavior, repro
   conditions, and first known bad point.
2. Separate user claims from confirmed local evidence. Build a short timeline
   when multiple processes, threads, or timestamps are involved.
3. Form one to three plausible root-cause hypotheses. Rank them by likelihood
   and blast radius, and retain one credible alternative.
4. Map stable error strings, state names, paths, and flags to the narrowest
   implementation entrypoints that can explain the symptom.
5. Choose the smallest discriminating next step: a targeted search, focused
   repro, tighter log point, minimal test, or scoped diff.
6. Close with the most likely root cause, strongest evidence, credible
   alternative, remaining uncertainty, and the next validation step.

Use [triage-report.md](references/triage-report.md) when a compact reusable
report shape helps.

## Guardrails

- Do not auto-trigger this optional asset for ordinary diagnosis.
- Do not jump to code changes before the symptom and hypothesis set are
  coherent.
- Do not treat the first matching log string as causality.
- Do not absorb remote provider access, authentication, or archive acquisition.
- Do not build a custom GitHub Actions fetch path; use the GitHub provider.
- If another repository has stronger local debugging guidance, follow it.
