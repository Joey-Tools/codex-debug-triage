---
id: 20260727-638eec
title: Cisco Cutover Admission Hardening
status: blocked
created: 2026-07-27
updated: 2026-08-01
branch: codex/retire-active-generic-triage
pr: https://github.com/Joey-Tools/codex-debug-triage/pull/5
supersedes: []
superseded_by:
---

# Cisco Cutover Admission Hardening

## Summary

- PR #5 now contains the canonical `cisco-build-artifacts` provider,
  redirect-safe bounded acquisition, the intact validated ZIP parser, and the
  retirement of remote-provider ownership from `bug-triage-playbook`.
- Canonical completion is source history only. Private overlay catalog,
  `removed_links`, release publication, installed-pointer, pointer-authority,
  and base-change-enforcement admission remain external blockers.

## Current State

- `skills/cisco-build-artifacts` owns Cisco Jenkins build, console, API,
  artifact-viewer, fetch, and bounded ZIP inspection interfaces. The network
  producer has a hard wall deadline with TERM/KILL/reap classification; fetch
  publication is dirfd-bound, no-follow, same-directory, atomic no-replace,
  default no-clobber, and reports durability separately.
- `bug-triage-playbook` is an explicitly invoked optional hypothesis
  reference with implicit invocation disabled. It owns no Jenkins, Cisco,
  remote-artifact, or GitHub Actions route; ordinary diagnosis falls through
  to the base model and GitHub Actions stays with the GitHub provider.
- This repository does not claim the provider is installed. The candidate PR
  remains open and cutover admission remains blocked.
- Directory mode-restoration failures make cleanup proof inconclusive even when all later removals succeed; retained-object evidence reflects only objects still locatable after cleanup.
- Workflow ID and SHA Actions variables must match both the administrator-pinned inputs and the selected native workflow metadata.
- Root-only DAC bypass and non-reaping PID 1 behavior no longer make the related tests host-dependent.
- Regex-worker teardown enters a retryable deadline-owned cleanup state before signal-support inspection, captures the true original mask with exactly one blocking call, masks repeating command-level `SIGALRM` across TERM/KILL/reap and pipe closure, restores only that captured mask, rethrows recorded deadline evidence, and retains the authoritative process handle plus PID/PGID recovery evidence when reap cannot be proven.
- Regex-worker startup now holds that same true-original-mask property from before `Popen` through matcher-handle and `ExitStack` cleanup publication; failed publication restores only after proven reap, otherwise it retains a permanent signal fence and recovery handle.
- Timer-backed diagnostic writes now require both regex-worker state machines to be `IDLE`; an unproven cleanup or retained startup signal fence uses the bounded nonblocking timerless path, so a full diagnostic pipe cannot leave error publication unbounded after the command budget.
- The GitHub collector now holds one termination-signal transaction from before the first credential read through initialization, request gaps, parsing, revalidation, child publication, and verified close; cleanup precedes handler/mask restoration and original-signal forwarding, while failed cleanup retains the exact private runtime/object recovery identity.
- GitHub REST reads now use a fixed root-owned curl transport with a fixed `https://api.github.com` origin, no proxy, no redirect following, and a private descriptor-bound authorization-header file; every 3xx response is terminal and cannot forward authentication to another origin.
- The fixed curl transport now binds `/`, `/usr`, `/usr/bin`, and `/usr/bin/curl` by descriptor-relative, no-follow traversal. Exact object identities, root ownership, non-writable modes, and descriptor ACL policies are retained across the launch window and revalidated before `Popen`, immediately after `Popen`, and after the request. On Darwin, only `ENOENT` proves absence of an extended ACL; unsupported, unreadable, inherited, or allowing ACL state fails closed.
- The minimal GitHub subprocess environment now supplies only the fixed system helper path `/usr/bin:/bin:/usr/sbin:/sbin`, preserving standard macOS Keychain lookup while excluding a malicious ambient `PATH`.
- The selected check lineage now binds its REST workflow-run node ID, database ID, event, and current rerun attempt to GitHub GraphQL's provider-authored `WorkflowRun.file`; the executed repository, path, and exact `blob/<ruleset SHA>/...` URL are protected across both snapshots, so an older workflow definition cannot satisfy the pinned rule.
- Authentication preflight preserves API failure semantics: only local `gh auth token` acquisition failure and HTTP 401 are authentication failures; curl transport errors, permission/rate-limit responses, not-found responses, and service errors retain their ordinary classifications.
- Fixed curl exit 28 now maps precisely to `api-timeout` when curl's own timer wins the race with the outer supervisor; local `gh auth token` exit 28 remains an authentication failure and all other curl exit-code semantics are unchanged.
- The client lifecycle signal transaction also covers endpoint/query validation, the call-limit gap, curl postvalidation, response-trailer parsing, HTTP classification, and JSON parsing after a child exits.
- Check lineage now fully paginates every suite for the frozen head and `pull_request_target` base with `filter=all` and no app filter, then fully paginates every run in every suite with `filter=all`; stable totals, explicit empty terminal pages, aggregate capacity limits, globally unique IDs, and exact suite/head linkage are required, including beyond the commit check-run endpoint's 1,000-suite window.
- Snapshot identity and access policy remain per-use checks. Exact content receipts are reused only while descriptor/path size, `mtime_ns`, and `ctime_ns` generations stay unchanged; generation drift forces bounded digest revalidation, avoiding 16,384 repeated full executable/config reads without allowing source or snapshot drift.
- Executable snapshot initialization now hashes the read-only snapshot descriptor between pre/post identity, path, access-policy, and content-generation validation before caching its receipt; a same-inode, same-size rewrite with restored owner permissions is rejected before any credential subprocess can run.
- The absolute collection deadline starts immediately after signal supervision and before runtime/config path or credential reads, then covers configuration double reads, private snapshot creation, executable copy and `fsync`, revalidation, child execution, and parsing without reset. Uninterruptible filesystem calls still require an outer terminate/reap supervisor for a hard return, with descriptor-bound cleanup recovery identity retained on inconclusive cleanup.
- ZIP reread admission binds `ZipInfo` back to the preflight central-directory name, flags, extract version, compression method, CRC, compressed/uncompressed sizes, and local-header offset, so an equal-length central-directory rewrite cannot redirect later inspection.
- Actions Variables pagination uses the endpoint's documented 30-item ceiling rather than the generic 100-item GitHub page size, and receipts record the effective bound for every page.
- Archive inspection keeps the private snapshot's no-grant ACL predicate separate from the source archive's exact descriptor ACL binding. Darwin hashes the bounded external ACL representation; Linux hashes the bounded raw `system.posix_acl_access` value alongside the separately bound mode mask. Source policy is sampled before snapshot creation, immediately before copy, after copy, and after the final digest, so named or extended ACL drift under an unchanged mode is rejected while unsupported and unreadable ACL queries retain their distinct failure classification.
- A private child directory that fails descriptor, mode, or ACL validation is removed only while its retained descriptor, parent-relative name, object identity, and parent access policy still match; replacement or unproved cleanup remains `collector-inconclusive` instead of deleting an unbound object.
- Successful private directory and regular-file creation now retains the original descriptor through the pathname rebind and compares the original descriptor, rebound descriptor, and parent-relative path. Regular files additionally bind the exact generated payload digest, so a same-EUID replacement or same-inode content rewrite cannot become the object later consumed by `gh` or `curl`.
- The required-workflow selector is explicitly neutral when all three administrator selector variables are absent, while partial, malformed, or placeholder configuration remains blocked. This prevents unrelated PRs from being held by an intentionally unconfigured cutover without weakening the selected target binding.
- The schema-3 private-overlay receipt validator and schema-4 live-enforcement doctor remain distinct contract profiles. Passing the enforcement contract to the receipt validator now returns a profile-routing error that names the correct doctor instead of a generic schema mismatch.
- The cutover protected identity is now the exact frozen `{pull-request number, head SHA, base SHA}` range. The selector compares the administrator-pinned base against provider event evidence; the schema-3 receipt and active merge lease carry the same base; and the schema-4 doctor compares its independent `--expected-base-sha` input against the repository variable and both provider API snapshots before accepting run/job/check lineage. A dispatched run rejects a base-only retarget or stale receipt, but the organization required-workflow rule does not guarantee that dispatch because its default activity set excludes `edited`.
- The workflow now declares `edited` as ordinary dispatch defense-in-depth. Both machine-readable contracts record `base_change_enforcement` as unavailable with reason `ruleset-workflow-default-activities-exclude-edited`, event `pull_request_target`, required activity `edited`, and exact ruleset dispatch activities `[opened,synchronize,reopened]`; workflow, local receipt validator, and doctor return an ordered admission-blocker list after static equivalence so the independent pointer-proof blocker remains visible. Activation cannot proceed until a merge queue or independent provider guarantees base-change reevaluation.
- Doctor output schema 6 names the administrator-pinned expected base and provider-observed base separately. The unpublished schema-3 receipt profile is intentionally tightened in place while pointer authority remains unavailable; the external `codex-private-workflows` release producer must emit both new base fields before cutover variables can be configured.

## Next Steps

- Sync the canonical provider into one validated private-overlay release with
  matching routing, active catalog, and `removed_links` retirement state.
- Configure the trusted live pointer authority and collect fresh live evidence
  before attempting cutover admission.
- Supply and independently validate merge-queue or provider enforcement for
  the required `edited`-equivalent base-change reevaluation before
  activating the ruleset.
- Preserve the exact workflow, ruleset, run-attempt, and candidate head/base
  bindings when refreshing evidence.

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
- Latest fresh-review repair suite on Python 3.13.0 and system Python 3.9.6: 264 tests passed, including fixed Keychain-helper lookup with ambient-`PATH` exclusion, fixed GraphQL workflow-file collection, exact ruleset-SHA acceptance/stale-definition rejection, and rerun-attempt binding.
- Current-head GitHub-review repair suite on Python 3.13.0 and system Python 3.9.6: 269 tests passed, including descriptor-bound failed-directory cleanup, replacement-safe retained-object evidence, neutral unconfigured selectors, blocked partial selectors, and explicit schema-3/schema-4 profile routing.
- Latest fresh-single repair suite on Python 3.13.0 and system Python 3.9.6: 272 tests passed, including successful-path directory replacement, regular-file replacement, and same-inode equal-length content-mutation races across the creation-to-rebind boundary.
- Source-ACL repair suite on Python 3.13.0 and system Python 3.9.6: 282 tests passed, including pre-copy, post-copy, and post-digest source-policy drift, Linux same-mask named ACL changes, distinct ACL query errors, stable Darwin source allow ACLs, persistent Darwin ACL drift, and the exact generated journal-index ignore.
- Focused current-head repair selection: 11 tests passed; the hosted macOS ACL integration selection passed all 7 tests.
- Darwin repair selection on Python 3.13.0: 10 tests passed, including inherited snapshot ACL refusal before copy, existing descriptor-ACL integration, initialization deadlines, and suite-first lineage.
- Python 3.13.0 and system Python 3.9.6 compilation passed for all CI-listed helpers and tests.
- Ruff passed for all CI-listed Python helpers and tests.
- Exact-base binding focused selection: 18 tests passed, covering dispatched base-only event/API drift, stale receipt reuse, receipt/lease base binding, malformed or missing pins, schema contracts, and distinct pinned/provider doctor output.
- Base-change-enforcement focused selection: 12 tests passed, covering the `edited` source declaration, exact five-field preconditions, ordered independent blockers, contract drift, and refusal to admit when pointer proof is test-doubled available.
- Python 3.13.0 and system Python 3.9.6 full suites: 293 tests passed on each runtime.
- Python 3.13.0 and system Python 3.9.6 compilation passed for all CI-listed helpers and tests; Ruff lint passed for all CI-listed Python files, Ruff format passed for the three changed Python files, and `actionlint` passed for all three workflows.
- The installed OpenAI skill validator and bundled project-journal validator passed after the exact-base and base-change-enforcement updates.
- Fixed-curl ancestor and ACL repair: Python 3.13.0 and system Python 3.9.6 each passed all 283 archive-triage tests and all 22 Jenkins-artifact tests. The focused fixed-curl selection passed 7 tests on each runtime; dual-runtime compilation, Ruff lint/format, skill validation, project-journal validation, and `git diff --check` also passed.
- Archive-selection budget repair: the regex budget now starts only after archive preflight, selected-line and regex work stops immediately when bounded output fills, and the raw member stream is still drained for CRC, size, line, and source-stability validation. Python 3.13.0 and system Python 3.9.6 each passed all 285 archive-triage tests and all 22 Jenkins-artifact tests.
- Hosted Linux fixed-curl integration now independently classifies the actual `/usr/bin/curl` owner/type/mode chain before launch and requires exactly one outcome: an unsafe runner-owned chain must return `collector-unavailable` with zero transport launches, while a root-owned non-writable chain must exercise the successful request path.
- The hosted macOS ACL integration now runs the fixed-curl directory-ACL regression explicitly, and the CI-selection contract test requires that entry, so Darwin descriptor-ACL enforcement cannot disappear while the Linux owner/type/mode integration still passes.
- Claude lane temporarily waived by Joey before 2026-08-01 00:00 Asia/Shanghai; the lane was not run and is not classified as completed.
- Canonical-provider precommit suites on Python 3.13.0 and system Python 3.9.6 each passed all 350 tests: 285 retained archive/cutover tests plus 65 remote acquisition, supervision, publication, packaging, and routing tests. Dual-runtime compilation also passed for every CI-listed helper and test.
- A read-only implementation pre-audit found post-link receipt drift, name-based successful cleanup, post-exit-only pipe caps, direct-child/group overclaiming, and success-metadata terminal injection. The repair seals the stage read-only, closes the writable descriptor, uses Darwin `RENAME_EXCL` or Linux `RENAME_NOREPLACE`, revalidates destination identity and the complete receipt, drains both worker pipes under runtime byte caps, scopes reap labels to the direct producer, and escapes all metadata output.
- Ruff 0.13.2 lint and format checks, actionlint 1.7.12, `git diff --check`, the installed OpenAI skill validator for both skills, and the project-journal validator passed for the canonical-provider candidate.
