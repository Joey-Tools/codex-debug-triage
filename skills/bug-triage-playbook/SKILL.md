---
name: bug-triage-playbook
description: Investigate logs, regressions, flaky behavior, Jenkins or other remote build artifacts, and root-cause hypotheses across repos. Use when the user asks to find the most likely cause of a failure, inspect a Jenkins/build URL, fetch authoritative console or archive evidence, map log evidence to code paths, compare competing hypotheses, or propose the smallest validating experiment or test.
---

# Bug Triage Playbook

## Overview

Use this skill for cross-repo debugging work that starts from symptoms instead of a known fix.
The goal is to turn logs, traces, failing tests, or behavioral regressions into a ranked hypothesis set, the strongest evidence, and the next discriminating action.

## Workflow

1. Normalize the problem first.
- Capture the exact symptom, observed behavior, expected behavior, repro conditions, and first known bad point in time if available.
- Separate user claims from confirmed evidence.
- If the report spans multiple processes, threads, machines, or timestamps, build a short timeline before editing code.

2. Secure the authoritative artifact first.
- If the user points to a specific remote log, archive, crash report, or build URL, treat that artifact as the primary evidence.
- Verify access, authentication, and exact artifact identity before mining similar local files, older runs, or nearby code.
- Do a narrow access preflight first: confirm the exact fetch command, required env vars or credentials, and whether the command will need sandbox approval or network access.
- If the task starts from tracker issue metadata or forge PR/commit metadata rather than from the artifact itself, fetch that tracker metadata first with a tracker-specific lookup skill, then return here once the evidence source becomes logs, builds, archives, or code paths.
- Keep local env checks direct and approval-free with `printenv`, then default Jenkins or other repeated HTTP artifact probes/fetches to `python3 "$HOME/.codex/skills/bug-triage-playbook/scripts/jenkins_artifact_probe.py"` using `probe-url`, `show-url`, or `fetch-url`.
- Treat that helper as intentionally narrow: remote URL subcommands only allow `https://jenkins.example.com/...`, auth goes through a fixed `--auth-profile` instead of arbitrary env-var names, and `fetch-url` may only write under the current workspace or `/tmp`.
- Interpret helper auth failures literally: `status=403` with `auth=absent` means the expected env vars or approval path are still missing, while `status=401` with `auth=present` usually means the chosen `--auth-profile` is wrong for that endpoint or job family.
- Once one Jenkins auth profile succeeds for the target job family, reuse that same `--auth-profile` for nearby console, API, and artifact reads before trying another profile.
- When the target URL contains shell metacharacters such as Jenkins `*view*`, `?`, `&`, or `[]`, pass it as one quoted argument or use a direct argv tool call instead of a shell wrapper. Do not let `zsh` expand the URL before the helper sees it.
- Once auth env presence and approval status are known, switch to the helper immediately for the first real artifact read. Do not detour into ad hoc `curl`, local session mining, or repo-history spelunking before either reading the requested artifact or explicitly concluding it is blocked.
- If the user also provides a prior session ID or local history clue, treat it as secondary context. Use it only after the requested remote artifact is accessible or after you have reported the precise blocker preventing access.
- When the first escalated helper call is needed, request a stable recurring `prefix_rule` for the exact helper subcommand, expanding the current user's home first, such as `["python3", "<expanded-home>/.codex/skills/bug-triage-playbook/scripts/jenkins_artifact_probe.py", "probe-url"]`, so later turns do not keep re-approving ad hoc remote fetch shapes. Do not widen that approval back to generic `curl` or arbitrary Python wrappers.
- If pipes, redirects, or post-processing are truly needed, split the remote helper fetch from local inspection steps instead of hiding the whole flow inside `bash -lc`; request approval for a wrapper form only when the helper genuinely cannot express the remote step.
- Raw `curl` is a fallback only when the helper cannot express the needed HTTP behavior, such as custom headers or cookies, TLS or redirect debugging, or another protocol detail the helper does not cover yet. If you fall back to `curl`, say exactly why the helper was insufficient.
- When the same Jenkins or remote archive inspection pattern starts repeating, keep approval-sensitive remote steps on the helper path and use `references/jenkins-artifact-recipes.md` plus `scripts/jenkins_artifact_probe.py` for the repetitive local archive-inspection part instead of rebuilding the same shell chain each turn.
- When local inspection needs large fetched artifacts or extracted files, prefer a task-scoped temp directory instead of fixed `/tmp/run.*` paths, and clean it up before finishing unless the user asked to keep it.
- When inspecting large fetched logs, API payloads, release metadata, manuals, or `.codex-tmp` artifact trees, keep the first local pass bounded: get file sizes, line counts, `rg -l`, `rg --count`, or selected JSON keys before printing matching lines. Then inspect one exact file, member, or small line window.
- For GitHub Actions triage through `gh`, use typed checks or selected JSON fields first, such as `gh pr checks`, `gh run list --json ... --jq ...`, or `gh api ... --jq ...`. If a full Actions log or jobs log is needed, write it to a task-scoped file before inspection, then print only `wc`, targeted `rg`, a short `sed` window, or a short tail; do not stream `gh run view --log`, `gh run view --log-failed`, or `gh api .../logs` directly into broad chat-visible output.
- For remote runner diagnostics, especially macOS `launchctl print gui/<uid>`, broad `pgrep -fl`, `ps`, `log show`, `xcodebuild`, build, or test commands, capture verbose output to a task-scoped log on the remote host or in the workspace and surface only decisive lines. Avoid dumping entire launchd trees, process inventories, or build streams when a scoped predicate, count, or tail can establish the hypothesis.
- Do not run raw `rg -n` across `.codex-tmp`, unpacked archive trees, or broad log/source trees, and do not print full release API responses or HTML/manual pages when selected fields, `--head`, `--tail`, `--grep`, or a small exact `sed` window would answer the question.
- If the artifact path is blocked by missing approval, auth, or environment variables, surface that exact blocker early instead of half-switching to local guesses.
- If access fails, report that explicitly and request the smallest missing credential, export, or approval instead of speculating from stale evidence.

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
- Do not default to raw `curl` for repeated Jenkins text or JSON fetches when the helper already covers the remote step.
- Do not let local artifact mining become the new wide read: avoid path-wide `rg -n`, full API/manual dumps, and broad log windows over fetched Jenkins artifacts.
- Do not absorb tracker metadata lookup into this skill when `cisco-trackers-lookup` already covers that read-only tracker step.
- If the repository already has a stronger debugging playbook, follow the repo over this skill.
- Separate "could not access the requested artifact" from "artifact inspected and evidence was inconclusive"; these are different outcomes.
- Do not leave large downloaded archives, extracted members, or temporary worktrees behind silently; either remove them before finishing or report the residual paths.

## References

- Use `references/triage-report.md` for a compact structure covering symptoms, hypotheses, evidence, and next steps.
- Use `references/jenkins-artifact-recipes.md` when Jenkins or archive triage needs a repeatable preflight, fetch, list, extract, and filter workflow.
