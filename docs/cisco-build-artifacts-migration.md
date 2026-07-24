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
workflow and must supply four expectations from an independent trusted source,
not copy them from the receipt:

- the exact canonical candidate commit
- the exact private release commit
- the exact private release-manifest SHA-256
- the exact SHA-256 of the receipt bytes

Invoke it only after those values are pinned:

```text
python3 scripts/validate_cisco_cutover_receipt.py \
  --contract tests/fixtures/cisco-build-artifacts-migration.json \
  --receipt <trusted-receipt.json> \
  --expected-canonical-commit <40-lowercase-hex> \
  --expected-private-release-commit <40-lowercase-hex> \
  --expected-release-manifest-sha256 <64-lowercase-hex> \
  --expected-receipt-sha256 <64-lowercase-hex>
```

The validator opens both the contract and receipt with `O_NOFOLLOW` and
`O_NONBLOCK`, immediately rejects anything other than a regular file, and
checks a one-second monotonic budget before and after open, metadata, and each
bounded read. A FIFO without a writer therefore fails closed instead of
waiting. Each strict UTF-8 JSON document is capped at 65,536 bytes, rejects
duplicate keys and floating-point values, limits integers to 64 digits, nesting
to 64 containers, total containers to 1,024, and parsed structure to 4,096
nodes. Schema comparisons require exact JSON scalar and container types, so a
Boolean never substitutes for an integer and an integer never substitutes for
a Boolean. The receipt must bind all of the following without extra or missing
fields:

1. schema version 1, the exact canonical/private repositories and commits, and
   the exact release-manifest digest
2. the complete aggregate activation object from the public contract
3. every trust gate, in contract order, with `status=passed` and the same exact
   private release commit and manifest digest
4. `release_target=releases/<private-release-commit>`
5. an installed pointer named `current` whose target, resolved release commit,
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

The base job binds the exact target/event/head repository, `master` base ref,
and service-authored pull-request head SHA before validating the receipt. It
exposes no secret or token to a candidate process because there is no candidate
process. Exit 0 with `classification=admitted` is its only green outcome.

The enforcement boundary is an active GitHub ruleset rule with
`type=workflows`, not a named status context. The exact rule must:

- target only the repository's default branch
- have no bypass actors and
  `parameters.do_not_enforce_on_create=false`
- contain exactly one required workflow entry
- bind repository ID `1242512092`, path
  `.github/workflows/cisco-cutover-admission.yml`,
  ref `refs/heads/master`, and the exact protected-base commit SHA containing
  the reviewed workflow
- resolve through authenticated workflow metadata to the separately pinned
  workflow ID in state `active`

A branch ref without the exact `sha` is mutable and remains blocked. The SHA
does not silently follow later edits: an administrator must review a new
workflow version and deliberately update the ruleset and doctor expectation.
The machine-readable fixed contract is
`docs/cisco-cutover-enforcement-contract.json`.

The gate intentionally remains red until the authenticated private release
workflow has produced a real receipt and a repository administrator has pinned
these non-secret GitHub Actions repository variables independently:

- `CISCO_CUTOVER_RECEIPT_BASE64`: exact Base64 of the producer-authored receipt
- `CISCO_CUTOVER_EXPECTED_CANONICAL_COMMIT`: final signed canonical candidate
  commit
- `CISCO_CUTOVER_EXPECTED_PRIVATE_RELEASE_COMMIT`: immutable private release
  commit
- `CISCO_CUTOVER_EXPECTED_RELEASE_MANIFEST_SHA256`: exact private release
  manifest digest
- `CISCO_CUTOVER_EXPECTED_RECEIPT_SHA256`: exact digest of the decoded receipt
  bytes

Do not derive any `EXPECTED_*` value from `CISCO_CUTOVER_RECEIPT_BASE64`.
The base verifier compares `CISCO_CUTOVER_EXPECTED_CANONICAL_COMMIT` against
the exact event head SHA, so a valid old receipt and stale repository variable
cannot admit a different candidate. Missing, empty, recognizable placeholder,
all-zero, malformed, stale, or mismatched values keep the trusted workflow red.

Before retirement, collect authenticated GitHub API evidence and normalize it
into the schema consumed by
`scripts/doctor_cisco_cutover_enforcement.py`. The evidence must contain:

- complete target repository metadata: numeric ID, exact full name, default
  branch, archived state, and disabled state
- every effective ruleset with its numeric ID, source, enforcement, target,
  conditions, bypass actors, and full rules
- exact workflow metadata: workflow ID, repository ID/full name, path, state,
  protected-base ref, and pinned source SHA
- the frozen candidate head and one exact trusted workflow run, including run
  ID/attempt, workflow identity, candidate head, event, status, and conclusion
- all check runs for that candidate head joined through authenticated
  Actions job/run metadata to workflow ID, repository ID, path, ref, and SHA
- all five collection-completeness flags from the machine contract

The doctor rejects incomplete pagination, a missing or mutable workflow
binding, the wrong repository/ruleset/workflow ID, a disabled or evaluating
ruleset, any bypass actor, or any same-name `required_status_checks` rule. It
also rejects any `cisco-cutover-admission` check whose joined workflow identity
differs from the pinned trusted workflow. Therefore a green candidate-authored
duplicate cannot compensate for a red or absent trusted workflow run.

Invoke the doctor only with administrator-pinned identities:

```text
python3 scripts/doctor_cisco_cutover_enforcement.py \
  --contract docs/cisco-cutover-enforcement-contract.json \
  --evidence <authenticated-complete-api-evidence.json> \
  --expected-ruleset-id <numeric-ruleset-id> \
  --expected-workflow-id <numeric-workflow-id> \
  --expected-workflow-sha <protected-base-40-lowercase-hex> \
  --candidate-head-sha <retirement-head-40-lowercase-hex>
```

The admitted doctor receipt has exact fields for the schema/operation,
contract and evidence SHA-256 digests, candidate head, repository identity,
ruleset ID, trusted workflow ID/repository ID/path/ref/SHA, trusted workflow run
ID, and trusted check-run ID. Blocked output includes the same available input
digests plus `reason_code` and `reason`. The doctor validates exact evidence
equivalence; it does not authenticate a locally supplied evidence file.
Collection must therefore come from authenticated GitHub APIs, and no admitted
receipt is stored in this repository.

This workflow cannot protect the pull request that first introduces it:
`pull_request_target` loads workflow bytes from the current base. The minimum
ordinary PR-merge sequence is therefore:

1. Keep the old Jenkins skill route, helper, reference, and tests intact.
   Separately review and merge a compatibility/bootstrap PR that installs this
   workflow on `master`; a branch containing the workflow is not proof that the
   base owns it.
2. Confirm the workflow file is present on protected `master`. Record that
   base commit SHA and the authenticated workflow ID. Create an active,
   bypass-free `workflows` ruleset with the exact repository/path/ref/SHA
   binding above, then record its numeric ruleset ID. Do not add a same-name
   status-only requirement.
3. Collect complete ruleset/workflow metadata and run the doctor against a
   real test candidate. Keep blocked until the exact identity-bound rule and
   successful trusted run are both proved.
4. Publish and verify the real private overlay, obtain its producer-authored
   receipt, and independently configure the receipt plus all four expectation
   variables. Do not add a fabricated receipt or derive expectations from it.
5. Create a separate retirement PR from the updated protected base, freeze its
   final head, bind the receipt and canonical expectation to that exact head,
   and require both the trusted workflow and the identity doctor to return
   `admitted`.
6. Only then merge the retirement PR and allow the private consumer source-sync
   step. Any head or trusted workflow SHA change requires new exact evidence
   and a new doctor receipt.

This branch restores the Jenkins entrypoint so it can be used only as the
compatibility/bootstrap change. It cannot install a base-owned workflow or
configure its own identity-bound ruleset. If it remains described or treated
as the retirement PR, it must stay draft/blocked until steps 1 through 3 have
completed in separate protected-base/admin operations. As of the 2026-07-24
audit, the live repository rulesets contain only status-check and merge rules;
no `workflows` rule exists. That external administrator action is the rollout
blocker. Do not weaken or skip it to collapse the merges into one.

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
