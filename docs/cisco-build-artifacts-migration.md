# Private `cisco-build-artifacts` Migration Contract

This document records the private functionality intentionally removed from the
public `bug-triage-playbook`. It is a handoff contract for a separately owned
private `cisco-build-artifacts` skill, not an implementation or an installation
instruction.

Keep actual Cisco hosts, job families, credential variable names, authentication
profiles, approval prefixes, and private examples in the private repository.

## Ownership Boundary

The private skill owns:

- Cisco build and Jenkins URL recognition
- exact HTTPS host allowlists
- named authentication profiles and their credential sources
- approval and network preflight
- build, console, API, and artifact identity resolution
- bounded remote reads and downloads
- authentication and HTTP failure classification
- private examples and job-family guidance

The public `bug-triage-playbook` owns only the downstream reasoning workflow
after an authoritative artifact is available locally. Its
`scripts/archive_triage.py` helper may inspect local ZIP members but performs no
network or authentication work. That local helper keeps its own conservative
size and count defaults as immutable hard ceilings. Its in-process
`ITIMER_REAL` budget is best effort: it covers central-directory validation,
decompression, the post-selection validation drain, bounded output publication,
and the underlying output flush when the operating system returns control to
Python, but it cannot guarantee interruption of NFS, FUSE, File Provider,
uninterruptible, or automatically restarted system calls. A private provider
that requires a hard return deadline must launch the local helper in a
terminate-able isolated process under an external wall-clock supervisor and
must preserve or tighten the helper's size and count ceilings.

GitHub Actions and pull-request checks bypass both skills and stay with the
GitHub provider workflow named in the generic skill's provider boundary.

## Aggregate Activation And Cutover Ordering

The canonical `Joey-Tools/codex-debug-triage` merge is source history only. It
does not mutate an installed skill link, an installed `AGENTS.md`, a private
catalog, or a per-host `current` pointer by itself. Do not treat that merge as
proof that the replacement provider exists on any machine.

The installed cutover belongs to the `Joey-Tools/codex-private-workflows`
aggregate. One candidate immutable private-overlay release must contain and
validate all of these changes together:

1. install the complete `personal_codex/skills/cisco-build-artifacts` source at
   `skills/cisco-build-artifacts`
2. update the release's private `AGENTS.md` routing to select that provider for
   Cisco/Jenkins build acquisition
3. update `personal_codex/private-sync-manifest.json` so the active catalog
   includes `skills/cisco-build-artifacts` and excludes
   `skills/bug-triage-playbook`
4. include the `removed_links` record that removes
   `skills/bug-triage-playbook` and names
   `skills/cisco-build-artifacts` as its replacement

Package validation must prove the provider files, routing policy, active
catalog, and removal record belong to that same release. The private overlay
verifier must pass before publication, and the host installer must verify the
staged aggregate before switching the installed `current` pointer. A source
checkout, merged private commit, open sync PR, or partially published asset is
not a trusted release.

Keep both the canonical bug-triage retirement PR and any consumer source-sync
step blocked until the replacement private release has passed those gates and
the installed pointer transition has been verified. If the aggregate cannot
machine-prove this atomic activation, retain a compatible
`bug-triage-playbook` route and omit its `removed_links` retirement; never point
installed guidance at a provider that the same trusted release does not
install.

The non-private cutover fixture at
`tests/fixtures/cisco-build-artifacts-migration.json` records only repository
names, aggregate paths, transaction members, trust gates, and fallback state.
It intentionally contains no Cisco host, credential, profile, job, or artifact
data.

## Exact Release And Pointer Receipt Admission

This repository cannot prove that a private overlay was published or that an
installed `current` pointer moved. It therefore stores no fabricated completion
receipt. The fixture's `receipt_admission.status_without_receipt` remains
`blocked_until_trusted`, so the canonical retirement PR and private consumer
source sync are not merge-admitted by this repository alone.

The local, no-network diagnostic at
`scripts/validate_cisco_cutover_receipt.py` gives maintainers a
machine-verifiable receipt-equivalence check without adding Cisco behavior to
the installed generic skill. Because a pull request can modify this script and
its tests, running it from a candidate checkout is never a merge or release
admission. The independently trusted base workflow described below embeds its
own verifier and must obtain the receipt through the authenticated
`Joey-Tools/codex-private-workflows/.github/workflows/release.yml` release
workflow and must supply seven expectations from an independent trusted source,
not copy them from the receipt:

- the exact canonical candidate commit
- the exact retirement pull-request number
- the exact private release commit
- the exact private release-manifest SHA-256
- the exact SHA-256 of the receipt bytes
- the exact base-owned workflow ID
- the exact base-owned workflow commit SHA

Invoke it only after those values are pinned:

```text
python3 scripts/validate_cisco_cutover_receipt.py \
  --contract tests/fixtures/cisco-build-artifacts-migration.json \
  --receipt <trusted-receipt.json> \
  --expected-canonical-commit <40-lowercase-hex> \
  --expected-pull-request-number <positive-decimal> \
  --expected-private-release-commit <40-lowercase-hex> \
  --expected-release-manifest-sha256 <64-lowercase-hex> \
  --expected-receipt-sha256 <64-lowercase-hex> \
  --expected-workflow-id <positive-decimal> \
  --expected-workflow-sha <40-lowercase-hex>
```

The validator opens both the contract and receipt with `O_NOFOLLOW` and
`O_NONBLOCK`, immediately rejects anything other than a regular file, and
checks a one-second monotonic budget before and after open, metadata, and each
bounded read. A FIFO without a writer therefore fails closed instead of
waiting. The strict UTF-8 contract is capped at 65,536 bytes and the receipt at
35,840 bytes. Both reject duplicate keys and floating-point values; each
limits integers to 64 digits, nesting to 64 containers, total containers to
1,024, and parsed structure to 4,096 nodes. The receipt ceiling keeps its
canonical Base64 value at 47,788 bytes or less, below GitHub's documented
[48 KB per-configuration-variable limit](https://docs.github.com/en/actions/reference/workflows-and-actions/variables#limits-for-configuration-variables).
The receipt plus the eight short identity/digest variables also stays below the
repository aggregate; an oversized producer receipt must fail before
publication. Schema comparisons require exact JSON scalar and container types,
so a Boolean never substitutes for an integer and an integer never substitutes
for a Boolean. The receipt must bind all of the following without extra or
missing fields:

1. schema version 2, the exact canonical/private repositories and commits, and
   the exact release-manifest digest
2. the exact target repository ID/name/default branch, retirement PR
   number/head/base, and base-owned workflow ID/repository/path/ref/SHA/event/
   check-name contract
3. the complete aggregate activation object from the public contract
4. every trust gate, in contract order, with `status=passed` and the same exact
   private release commit and manifest digest
5. `release_target=releases/<private-release-commit>`
6. an installed pointer named `current` whose target, resolved release commit,
   and manifest digest all equal that immutable release

Exit 0 with `classification=admitted` is the only machine admission. A missing
receipt, missing independent expectation, digest mismatch, partial gate set,
pointer mismatch, malformed JSON, or any schema difference exits 1 with
`classification=blocked_until_trusted`. The validator proves exact byte and
field agreement; it does not authenticate where the caller obtained the
receipt. Authenticated retrieval and the independent expectation values remain
owned by the private release workflow.

### Protected-Base Admission And Exact Unblocking Inputs

The job name `cisco-cutover-admission` is not an enforcement identity. A
candidate-controlled GitHub Actions workflow uses the same Actions App and can
emit a green check with that same name. Neither a branch-protection context nor
a ruleset `required_status_checks` entry becomes safe merely by adding the
GitHub Actions integration ID.

The trusted workflow still uses `pull_request_target`, performs no checkout,
invokes no action, downloads no artifact, and executes no candidate script,
test, import, or generated file. Its verifier is self-contained in base-owned
workflow bytes. That protects the workflow execution, but it is not sufficient
merge enforcement until GitHub itself requires that workflow by identity.

The base workflow first runs `cisco-cutover-selector` with only two
administrator-owned repository variables:
`CISCO_CUTOVER_TARGET_PR_NUMBER` and `CISCO_CUTOVER_TARGET_HEAD_SHA`. The
selector validates the exact target/event/head repository and `master` base
ref for the retirement PR. For the exact target PR number it fails if the head
repository or event head differs; only an exact repository/number/head match
enables `cisco-cutover-admission`. Every other PR, including a fork PR, routes
to `cisco-cutover-neutral`, returns
`classification=not_applicable`, and never receives or reads the receipt or any
target evidence variable. Missing, malformed, or placeholder selector state
fails closed.

This split matters because the organization required-workflow rule applies to
every PR targeting the default branch. A concurrent PR and a future PR after
cutover therefore complete the same required workflow through the explicit
neutral job rather than being blocked by evidence that belongs to the one
retirement PR. A target-head change fails instead of becoming neutral. The
doctor independently reads both selector variables twice and requires them to
equal its PR number and candidate-head arguments; changing the selector cannot
turn a neutral run into target evidence.

The target admission job binds the selector outputs, exact event PR
number/head, receipt cutover object, and workflow ID/SHA before validating the
private release and pointer. It exposes no secret or token to a candidate
process because there is no candidate process. Exit 0 with
`classification=admitted` is its only target green outcome.

The enforcement boundary is an active organization-level GitHub ruleset rule
with `source_type=Organization` and `type=workflows`, not a repository-level
ruleset or named status context. The exact rule must:

- bind organization ID `283943935` and login `Joey-Tools`
- use an exact `repository_id.repository_ids=[1242512092]` target condition
  plus `ref_name.include=["~DEFAULT_BRANCH"]`, with no exclusions; the workflow
  binding's `repository_id` is the source workflow repository and never
  substitutes for this target condition
- have no bypass actors and
  `parameters.do_not_enforce_on_create=false`
- contain exactly one required workflow entry
- bind source workflow repository ID `1242512092`, path
  `.github/workflows/cisco-cutover-admission.yml`,
  ref `refs/heads/master`, and the exact protected-base commit SHA containing
  the reviewed workflow
- resolve that source repository through authenticated repository and workflow
  metadata to the separately pinned workflow ID in state `active`

A branch ref without the exact `sha` is mutable and remains blocked. The SHA
does not silently follow later edits: an administrator must review a new
workflow version and deliberately update the ruleset and doctor expectation.
The machine-readable fixed contract is
`docs/cisco-cutover-enforcement-contract.json`.

The gate intentionally remains red until the authenticated private release
workflow has produced a real receipt and a repository administrator has pinned
these non-secret GitHub Actions repository variables independently. Configure
the two selector variables first, but do not activate the organization ruleset
until all target evidence variables are exact:

- `CISCO_CUTOVER_TARGET_PR_NUMBER`: frozen retirement PR number
- `CISCO_CUTOVER_TARGET_HEAD_SHA`: frozen retirement PR head
- `CISCO_CUTOVER_RECEIPT_BASE64`: exact Base64 of the producer-authored receipt
- `CISCO_CUTOVER_EXPECTED_CANONICAL_COMMIT`: final signed canonical candidate
  commit
- `CISCO_CUTOVER_EXPECTED_PRIVATE_RELEASE_COMMIT`: immutable private release
  commit
- `CISCO_CUTOVER_EXPECTED_RELEASE_MANIFEST_SHA256`: exact private release
  manifest digest
- `CISCO_CUTOVER_EXPECTED_RECEIPT_SHA256`: exact digest of the decoded receipt
  bytes
- `CISCO_CUTOVER_EXPECTED_WORKFLOW_ID`: exact base-owned workflow ID
- `CISCO_CUTOVER_EXPECTED_WORKFLOW_SHA`: exact base commit bound by the
  required-workflow rule

Do not derive any `EXPECTED_*` value from `CISCO_CUTOVER_RECEIPT_BASE64`.
The base verifier compares `CISCO_CUTOVER_EXPECTED_CANONICAL_COMMIT` against
the exact event head SHA, so a valid old receipt and stale repository variable
cannot admit a different candidate. Missing, empty, recognizable placeholder,
all-zero, malformed, stale, or mismatched values keep the trusted workflow red.

Before retirement, run `scripts/doctor_cisco_cutover_enforcement.py` in the
trusted administrator environment. It deliberately accepts no `--evidence`
file and does not trust caller-supplied pagination or completeness booleans.
The same process:

- runs `gh auth status --hostname github.com` without printing its output, then
  reads `/user` to prove the active authenticated API path
- reads the exact organization, target repository, selected PR, organization
  ruleset, both applicability-selector repository variables, source workflow
  repository, workflow metadata, and pinned source commit
- lists every effective target-repository ruleset with
  `includes_parents=true`, every check run for both the frozen PR head and the
  `pull_request_target` base commit with `filter=all`, every workflow run for
  each selected-PR same-name check-suite ID, and every job for every observed
  run attempt
- uses `per_page=100`, continues even after a short non-empty page, and stops
  only after requesting an explicit empty terminal page; object endpoints and
  page bounds are recorded in the receipt
- derives the native PR -> workflow run and attempt -> Actions job -> check-run
  link from PR objects, run/job IDs and URLs, `job.check_run_url`, check-suite
  ID, head repository ID, the exact PR head, and the base SHA used by
  `pull_request_target`
- binds the GitHub Actions provider app ID/slug, status, conclusion, workflow
  ID/path, ruleset ref/SHA, source workflow repository ID, and native API URLs;
  the receipt also preserves GitHub's corresponding HTML URLs
- collects and validates the protected snapshot twice; organization,
  repository, PR head/base, ruleset content/scope, workflow source, or
  same-name execution-lineage changes block admission, while timestamps alone
  are not treated as object replacement or content mutation

The doctor rejects pagination totals that do not match the fully collected
items, page/call/search caps that prevent proof of exhaustion, a missing or
mutable workflow binding, the wrong organization/repository/ruleset/workflow
identity, a disabled or evaluating ruleset, any bypass actor, wrong repository
or default-branch conditions, or any same-name `required_status_checks` rule.
It also rejects every current `cisco-cutover-admission` check whose native
run/job/provider lineage differs from the pinned workflow. Therefore a green
candidate-authored duplicate cannot compensate for a red or absent trusted
workflow run.

The live preflight is read-only. It invokes only `gh auth status` and fixed
GitHub REST `GET` endpoints; it does not create, update, evaluate, disable, or
delete a ruleset, rerun a workflow, post a comment, or mutate the PR. The active
credential needs read access to the repository, Actions, checks, and
organization ruleset metadata. Authentication, permission, pagination, and
API-limit failures remain `blocked_until_trusted`.

API failures retain only a fixed endpoint class, a parsed HTTP status when `gh`
provides one, and a stable reason code. `401` maps to
`blocked-authentication`; ordinary `403` (including the current organization
ruleset `admin:org` failure) maps to `blocked-permission`; `404` maps to
`not-found`; `429` and explicit rate-limit `403` map to `rate-limited`; `5xx`
and malformed responses map to `api-unavailable`; and bounded command expiry
maps to `api-timeout`. Response bodies, raw headers, command environments,
tokens, and raw `gh` stderr are never copied into the doctor receipt.

Invoke the doctor only with administrator-pinned identities and the exact
existing PR:

```text
python3 scripts/doctor_cisco_cutover_enforcement.py \
  --contract docs/cisco-cutover-enforcement-contract.json \
  --pull-request-number <existing-pr-number> \
  --expected-ruleset-id <numeric-ruleset-id> \
  --expected-workflow-id <numeric-workflow-id> \
  --expected-workflow-sha <protected-base-40-lowercase-hex> \
  --candidate-head-sha <retirement-head-40-lowercase-hex>
```

The admitted doctor receipt has exact fields for the schema/operation,
contract and collected-evidence SHA-256 digests, collection timestamps and
page bounds, authenticated account identity, organization/target repository,
PR number/head repository ID/head SHA, ruleset source/ID, source workflow
repository ID/name/path/ref/SHA, and the trusted run/attempt/job/check
IDs, URLs, provider, status, and conclusion. Blocked output includes the
available digests plus `reason_code` and `reason`. The receipt is an output of
the live collection transaction, not reusable evidence input, and no admitted
receipt is stored in this repository.

This workflow cannot protect the pull request that first introduces it:
`pull_request_target` loads workflow bytes from the current base. The minimum
ordinary PR-merge state machine is therefore:

1. Keep the old Jenkins skill route, helper, reference, and tests intact.
   Separately review and merge a compatibility/bootstrap PR that installs this
   workflow on `master`; a branch containing the workflow is not proof that the
   base owns it.
2. Confirm the workflow file is present on protected `master`; record that base
   commit SHA and authenticated workflow ID. Then create the separate
   retirement PR from that base, finish its implementation, and freeze the
   final signed PR number/head without merging it.
3. Ask the independently authorized private release workflow to publish and
   verify the real private overlay. Its producer-authored schema-2 receipt must
   bind the exact target repository ID/name/default branch, frozen PR
   number/head/base, and workflow ID/repository/path/ref/SHA/event/check name.
   Do not fabricate a receipt or derive independent expectations from it.
4. A repository administrator configures both selector variables plus the
   receipt and all six independent `EXPECTED_*` variables. Re-read every
   value and require the selector number/head, canonical commit, receipt
   cutover object, and expected workflow ID/SHA to agree.
5. Only after step 4, an organization owner creates or updates the active,
   bypass-free organization `workflows` ruleset with the exact target
   repository/default-branch conditions and source
   repository/path/ref/SHA binding, then records its numeric ruleset ID. Do not
   add a same-name status-only requirement.
6. With explicit Actions authorization, trigger a new target evaluation
   without changing the frozen head—for example, rerun the target workflow
   attempt or use one of the declared `pull_request_target` activity
   transitions—and observe selector, target admission, run, job, and check
   success. This document does not perform that mutation automatically.
7. Run the live read-only doctor against that exact retirement PR/head. Its
   fully paginated, twice-stable API snapshot must prove selector variables,
   the exact identity-bound rule, and the current successful target
   run/job/check lineage.
8. Immediately before merge, revalidate that the PR is still open, its
   base/head are unchanged, the selector/ruleset/workflow snapshots still match,
   the receipt expectations still name the same head, and the fresh doctor
   receipt is `admitted`. Any head, workflow SHA, selector, receipt, or ruleset
   change returns the state machine to step 2 or the earliest affected step.
9. Only then may an authorized maintainer merge the retirement PR and allow the
   private consumer source-sync step. No merge, rerun, variable write, ruleset
   write, or release publication is an automatic action of this bootstrap
   workstream.

### Post-Cutover Decommission Transaction

After the exact retirement PR has merged, future PRs remain safe while cleanup
is pending: their PR number differs from the frozen selector and the
base-owned workflow takes the explicit neutral path without consuming target
evidence. The required-workflow rule, selector, variables, and workflow are
nevertheless temporary cutover infrastructure and must be retired by a
separately authorized administrator transaction.

GitHub does not document conditional `If-Match` support for these unsafe
ruleset and variable update/delete endpoints. The transaction therefore uses
an application-level compare-and-swap discipline under an exclusive
create-if-absent repository-variable lease named
`CISCO_CUTOVER_DECOMMISSION_LEASE`; it must not claim server-enforced CAS:

1. Atomically create the absent lease with a transaction ID, actor, frozen
   target PR/head, ruleset ID plus canonical JSON SHA-256, all cutover variable
   name/value-SHA-256/`updated_at` observations, and workflow path/blob SHA.
   Read the lease back and stop if it differs. A pre-existing lease is a
   recovery blocker, not permission to overwrite it.
2. Revalidate the merged PR identity/head, the final admitted doctor receipt,
   the exact active ruleset content, every variable observation, and the
   base-owned workflow blob. Before every later mutation, re-read the object
   being changed and compare it to the frozen observation. Any concurrent
   drift aborts before the next mutation.
3. Disable the exact organization ruleset by numeric ID using the complete
   reviewed payload, then prove from both the organization detail and the
   target repository's fully paginated effective list that the rule is no
   longer effective. Never delete selector/evidence variables or remove the
   workflow while this proof is missing.
4. With the ruleset proved inactive, keep all nine cutover variables in place
   while removing the workflow in a separate reviewed PR. That cleanup PR must
   still complete the base-owned workflow through the neutral path. Verify the
   protected-base workflow blob is absent and the cutover ruleset remains
   ineffective before continuing.
5. Delete only the nine exact cutover variables after per-variable
   name/value-SHA-256/`updated_at` comparison. Keep the lease. A partial
   deletion is recoverable because the rule is already inactive and the
   workflow is absent. Revalidate and delete the exact inactive ruleset by
   numeric ID and frozen canonical content, then prove the rule, variables, and
   workflow are all absent before deleting the lease last.

Failure before the ruleset-inactive proof leaves the workflow and every
variable intact; recover by releasing only a verified owner lease and retrying
from a fresh snapshot. Failure after that proof keeps the rule inactive and
the lease in place; record the transaction ID and resume the remaining
variable/workflow cleanup rather than reactivating enforcement. Unknown lease
ownership, an unverifiable partial write, or any concurrent drift stops the
transaction for administrator recovery. This workstream defines and tests the
contract only—it does not acquire the lease or mutate live GitHub state.

This branch restores the Jenkins entrypoint so it can be used only as the
compatibility/bootstrap change. It cannot install a base-owned workflow or
configure its own identity-bound ruleset. If it remains described or treated
as the retirement PR, it must stay draft/blocked until the bootstrap merge and
the newly ordered target state machine have
completed in separate protected-base/admin operations. In the 2026-07-24
read-only preflight, the effective list exposed organization rulesets
`16590367` and `16585220` plus repository rulesets `16583544` and `16583553`.
The two readable repository details contain only status-check and merge rules.
The active credential lacks `admin:org`, so GitHub rejected both organization
detail reads and no exact organization target/workflow contract could be
proved. The sanitized doctor outcome for that endpoint class is
`reason_code=blocked-permission`, `http_status=403`, without the response body
or credential-bearing command context. An organization administrator must
provide the required read authority
and install or identify the exact contract-compliant rule; no OAuth scope or
live ruleset was changed during this audit. That unproved external
administrator state is the rollout blocker. Do not weaken or skip it to
collapse the merges into one.

## Private Command Interface To Preserve

Provide a private helper with these conceptual subcommands:

```text
probe-url <url> [--method HEAD|GET] [--auth-profile <name>] [--timeout <seconds>] [--sniff-bytes <n>]
show-url <url> [--auth-profile <name>] [--timeout <seconds>] [--head <n> | --tail <n> | --grep <pattern> [--context <n>]] [--max-body-bytes <n>]
fetch-url <url> --output <path> [--auth-profile <name>] [--timeout <seconds>] [--max-body-bytes <n>]
```

The private implementation should preserve these properties:

1. Reject non-HTTPS URLs, inline URL credentials, and hosts outside the exact
   private allowlist before network access.
2. Resolve only predefined private authentication profiles; do not accept
   arbitrary credential environment-variable names from command arguments.
   Authorize the selected profile for the initial exact origin before reading
   or attaching any credential material.
3. Fail before network access when a selected profile lacks required
   credentials.
4. Keep downloaded files under the current workspace or a task-scoped temporary
   directory.
5. Report stable, secret-free fields such as URL, HTTP status, authentication
   presence, output path, byte count, content type, and error classification.
6. Keep `show-url` output bounded through head, tail, or grep/context controls.
7. Distinguish usage or policy rejection from remote HTTP/authentication
   failure and local write failure with documented nonzero exits.
8. Quote or directly pass URLs containing shell metacharacters; do not require
   callers to hide the operation in a shell wrapper.

## Required Remote And Publication Safeguards

The migrated implementation must strengthen the retired public helper rather
than copy its unbounded `response.read()` and direct `write_bytes()` behavior.

### Redirect And Network Policy

- Validate the initial URL and every redirect target against the same HTTPS,
  inline-credential, port, and exact private host policy before following it.
- Treat an origin as scheme, normalized host, and effective port. Strip
  `Authorization`, `Proxy-Authorization`, and `Cookie` at every redirect; only
  rebuild authentication after the new origin passes policy and the selected
  profile explicitly authorizes that origin.
- Set a finite redirect count and reject downgrade, disallowed cross-host hops,
  redirect loops, and targets that cannot be normalized unambiguously.
- Apply explicit connect/read and total wall-clock deadlines. A timeout must
  stop the transfer rather than merely stop waiting for console output.
- Keep `probe-url` body sniffing separately capped; a probe must not become an
  implicit full download.
- Require normal TLS certificate-chain and hostname validation. Expose no
  insecure bypass. Normalize hostnames consistently, reject unapproved
  non-default ports, and never use suffix matching as a host allowlist.
- Never echo a raw URL that may contain a signed query. Drop fragments and
  redact query values by default; report only explicitly allowlisted,
  non-secret query fields plus a `query_redacted` signal.

### Streaming And Size Caps

- Stream response bodies in fixed-size chunks. Do not materialize a full
  console or artifact in memory before enforcing its limit.
- Enforce a hard downloaded-byte cap while streaming even when
  `Content-Length` is missing or false. Reject an oversized declared length
  before download, but never rely on that declaration alone.
- Give direct text output independent byte, line, and line-length caps.
  Implement head with early termination, tail with a bounded deque, and
  grep/context with bounded state.
- Cap archive/member counts, decompressed member bytes, and reported match
  output before handing a downloaded archive to downstream inspection.
- Define wire bytes, decoded HTTP entity bytes, decoded text characters, and
  persisted artifact bytes separately. Enforce wire and entity caps whenever
  content decoding is enabled, and report which representation is persisted.

Before activating the private skill, define exact `DEFAULT_*` and
`HARD_MAX_*` constants for redirects, connect/read/total timeouts, probe sniff
bytes, wire/entity body bytes, download bytes, output lines/characters, and
archive/member limits. Omitted values use the default; zero, negative, and
above-hard-max values are usage errors; no flag disables a cap. A bounded
`probe-url` or `show-url` response may succeed with `truncated=true`, while a
`fetch-url` body overflow, timeout, or integrity failure must fail without
publishing a destination.

### No-Clobber Atomic Publication

The protected properties are:

- **access policy**: every output remains under the validated workspace or
  task-scoped temporary root
- **object identity**: the caller's destination remains absent until one
  no-replace publication of the helper-created staged file
- **content stability**: published bytes are exactly the bounded stream written
  and verified through the staged file descriptor

To preserve them:

1. Open the trusted output root and allowed parent as directory file
   descriptors, walking components with no-follow semantics. Hold the parent
   `dirfd` through staging, publication, synchronization, and cleanup; reject
   missing, unreadable, replaced, or policy-invalid parents as distinct
   outcomes.
   Require the root, every ancestor, and the parent to remain controlled by a
   trusted principal and not renameable or writable by an untrusted principal
   for the whole transaction. Immediately before publication, re-walk from the
   held trusted-root descriptor and compare the reached parent's object identity
   with the held parent `dirfd`; block if the same allowed directory object
   cannot be proved.
2. Create a private same-directory staging file relative to that held `dirfd`,
   with exclusive creation, no-follow semantics, and restrictive permissions.
   Hold its descriptor throughout streaming, verification, flush, and `fsync`.
3. Track the staged object through descriptor identity. Do not treat unrelated
   directory-entry churn or timestamps alone as content mutation; require
   object replacement, content change, or access-policy change to classify a
   protected-property mismatch.
   Immediately before publication or cleanup, open the staged name relative to
   the held parent with no-follow semantics and compare its object identity to
   the held staged descriptor. Because a check followed by rename still races
   in an attacker-writable directory, require either the trusted-control
   precondition above or a platform primitive that publishes directly from the
   held staged object; otherwise block.
4. Publish relative to the same held `dirfd` with an operating-system
   no-replace atomic primitive. Do not use an `exists()` check followed by
   `os.replace()`, because that can overwrite a destination created in the race
   window.
5. Sync the held containing directory where the platform contract requires it.
   Remove only the helper-owned staging entry through that same `dirfd` after a
   failed publication, and never delete or overwrite the caller's existing
   destination.
6. Report unreadable or failed revalidation separately from destination
   missing, destination already present, content mismatch, and policy mismatch.
7. If no-replace publication succeeds but the containing-directory `fsync`
   fails, enter `published / durability-unverified`: report that the destination
   is visible but persistence is unknown, never delete it, and never retry
   automatically. Recovery must first verify destination identity and content,
   then retry only the directory durability step under explicit control.

## Handoff Back To Generic Triage

On a successful fetch, supply at least:

```text
source_url=<redaction-safe authoritative URL>
artifact_identity=<build/run/artifact identifier>
local_path=<validated local path>
bytes=<downloaded byte count>
auth_profile=<profile label, never credential material>
```

The caller can then explicitly invoke `$bug-triage-playbook` with the local path
and provenance. The generic skill should not infer or retry Cisco
authentication.

## Private Migration Tests

Move or recreate private tests covering:

- HTTPS, host-allowlist, and inline-credential rejection before network access
- redirect downgrade, disallowed cross-host hops, loops, and redirect-count caps
- credential/header stripping on redirects and profile-authorized rebuilds
- known and unknown authentication profiles
- initial exact-origin/profile authorization before credential access
- missing credentials before network access
- HTTP 401/403 and transport error classification without secret disclosure
- bounded streaming with missing, false, and oversized `Content-Length`
- bounded head, tail, grep, context, line-length, and body-sniff output
- download path containment, byte-count reporting, and failed-transfer cleanup
- existing-destination no-clobber behavior and destination-symlink rejection
- same-directory atomic no-replace publication, descriptor identity checks,
  flush/`fsync`, and revalidation outcome classification
- trusted-root re-walk, parent identity, staged-name identity, and
  attacker-writable-directory blocking
- post-publication directory-sync failure as
  `published / durability-unverified`, with no delete or automatic retry
- default, hard-max, zero, negative, above-max, truncation, and hard-failure cap
  semantics across wire/entity/persisted representations
- signed-query redaction, port/host normalization, and mandatory TLS validation
- shell-sensitive URL handling at the documented command boundary

Do not copy private fixtures, hosts, credentials, or job names into this public
repository.
