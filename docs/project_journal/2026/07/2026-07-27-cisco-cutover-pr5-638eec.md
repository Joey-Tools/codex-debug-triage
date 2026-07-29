---
id: 20260727-638eec
title: Cisco Cutover Admission Hardening
status: blocked
created: 2026-07-27
updated: 2026-07-29
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
- Regex-worker startup now holds that same true-original-mask property from before `Popen` through matcher-handle and `ExitStack` cleanup publication; failed publication restores only after proven reap, otherwise it retains a permanent signal fence and recovery handle.
- Timer-backed diagnostic writes now require both regex-worker state machines to be `IDLE`; an unproven cleanup or retained startup signal fence uses the bounded nonblocking timerless path, so a full diagnostic pipe cannot leave error publication unbounded after the command budget.
- The GitHub collector now holds one termination-signal transaction from before the first credential read through initialization, request gaps, parsing, revalidation, child publication, and verified close; cleanup precedes handler/mask restoration and original-signal forwarding, while failed cleanup retains the exact private runtime/object recovery identity.
- GitHub REST reads now use a fixed root-owned curl transport with a fixed `https://api.github.com` origin, no proxy, no redirect following, and a private descriptor-bound authorization-header file; every 3xx response is terminal and cannot forward authentication to another origin.
- Authentication preflight preserves API failure semantics: only local `gh auth token` acquisition failure and HTTP 401 are authentication failures; curl transport errors, permission/rate-limit responses, not-found responses, and service errors retain their ordinary classifications.
- Fixed curl exit 28 now maps precisely to `api-timeout` when curl's own timer wins the race with the outer supervisor; local `gh auth token` exit 28 remains an authentication failure and all other curl exit-code semantics are unchanged.
- The client lifecycle signal transaction also covers endpoint/query validation, the call-limit gap, curl postvalidation, response-trailer parsing, HTTP classification, and JSON parsing after a child exits.
- Check lineage now fully paginates every suite for the frozen head and `pull_request_target` base with `filter=all` and no app filter, then fully paginates every run in every suite with `filter=all`; stable totals, explicit empty terminal pages, aggregate capacity limits, globally unique IDs, and exact suite/head linkage are required, including beyond the commit check-run endpoint's 1,000-suite window.
- Snapshot identity and access policy remain per-use checks. Exact content receipts are reused only while descriptor/path size, `mtime_ns`, and `ctime_ns` generations stay unchanged; generation drift forces bounded digest revalidation, avoiding 16,384 repeated full executable/config reads without allowing source or snapshot drift.
- Executable snapshot initialization now hashes the read-only snapshot descriptor between pre/post identity, path, access-policy, and content-generation validation before caching its receipt; a same-inode, same-size rewrite with restored owner permissions is rejected before any credential subprocess can run.
- The absolute collection deadline starts immediately after signal supervision and before runtime/config path or credential reads, then covers configuration double reads, private snapshot creation, executable copy and `fsync`, revalidation, child execution, and parsing without reset. Uninterruptible filesystem calls still require an outer terminate/reap supervisor for a hard return, with descriptor-bound cleanup recovery identity retained on inconclusive cleanup.
- ZIP reread admission binds `ZipInfo` back to the preflight central-directory name, flags, extract version, compression method, CRC, compressed/uncompressed sizes, and local-header offset, so an equal-length central-directory rewrite cannot redirect later inspection.
- Actions Variables pagination uses the endpoint's documented 30-item ceiling rather than the generic 100-item GitHub page size, and receipts record the effective bound for every page.
- Archive inspection ignores ambient `TMPDIR`, creates a random `0700` root and `0600` file under the fixed system temporary parent, validates descriptor/path identity and Darwin ACL or Linux mode-mask policy before the first archive byte, then unlinks the file and removes the root. Parsing uses only the resulting zero-link descriptor, after complete source content and access-policy revalidation.

## Next Steps

- Configure the trusted live pointer authority and collect fresh live evidence before attempting cutover admission.
- Preserve the exact workflow, ruleset, run-attempt, and candidate-head bindings when refreshing evidence.

## Evidence

- PR: https://github.com/Joey-Tools/codex-debug-triage/pull/5
- Exact-bot reviewed head: `638eec5283ec1cf86b4cf33bbafd6d6286b66f32`
- Fresh Codex review range: `b6af1cf257deb1cdee04fbd49f72cabf2697ac5c..c742210b33c9ad7058e853766f9bedde896886b1`.
- Follow-up fresh Codex review range: `b6af1cf257deb1cdee04fbd49f72cabf2697ac5c..ce2e60cdb0251dbede38230e713ea7c1764155fe`.
- Review-fix regression selection: cleanup mode proof, workflow input identity, root DAC replacement, external regex-worker group termination, command deadline during regex teardown, pre-mask handshake interruption and retry, exact original-mask restoration, `Popen`-return deadline deferral, matcher/`ExitStack` publication, permanent signal fencing, full-pipe fenced diagnostic publication, managed GitHub process registry publication, whole-client credential lifecycle signals, initialization/request-gap/JSON/revalidation/finish-window injection, signal cleanup recovery identity, absolute-deadline exhaustion before spawn, total-call-ceiling receipt reuse, credential snapshot cleanup, live-worker recovery identity, and unreaped-worker handle retention.
- Python 3.13.0 full suite: 238 tests passed.
- System Python 3.9.6 full suite: 238 tests passed.
- Fresh-review repair suite on Python 3.13.0: 245 tests passed, including fixed-transport redirect refusal, authentication-preflight failure classification, post-child signal injection, and equal-length ZIP metadata rewrites.
- Current fresh-review repair suite on Python 3.13.0 and system Python 3.9.6: 261 tests passed, including complete `filter=all` suite/run lineage, suite-first enumeration beyond 1,000 suites, duplicate/cap/pagination refusal, owner-private anonymous archive snapshots, initialization-deadline cleanup, curl exit-28 classification, executable-snapshot readback mutation refusal, and bounded fenced diagnostics on a full pipe.
- Darwin repair selection on Python 3.13.0: 10 tests passed, including inherited snapshot ACL refusal before copy, existing descriptor-ACL integration, initialization deadlines, and suite-first lineage.
- Python 3.13.0 and system Python 3.9.6 compilation passed for all CI-listed helpers and tests.
- Ruff passed for all CI-listed Python helpers and tests.
- The installed OpenAI skill validator passed for `bug-triage-playbook`.
- Bundled project-journal validation passed.
- Direct Claude review was waived by Joey through 2026-08-01 00:00 Asia/Shanghai; the lane was not run and is not classified as completed.
