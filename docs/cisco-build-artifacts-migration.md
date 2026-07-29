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
- bounded archive validation, extraction, and evidence publication for fetched
  Cisco build artifacts
- authentication and HTTP failure classification
- private examples and job-family guidance

After cutover, ordinary local-log and local-artifact diagnosis returns directly
to the base model; it has no installed skill route or catalog dependency. The
public repository may retain `scripts/archive_triage.py`, references, and tests
as optional source assets, but the installed private overlay neither links nor
routes to `bug-triage-playbook`. When explicitly used from this source
repository, the optional local helper performs no network or authentication
work and keeps its own conservative size and count defaults as immutable hard
ceilings. Its in-process
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
   Cisco/Jenkins build acquisition and bounded archive inspection, while
   ordinary local diagnosis falls through to the base model without a skill
   route
3. update `personal_codex/private-sync-manifest.json` so the active catalog
   includes `skills/cisco-build-artifacts` and excludes
   `skills/bug-triage-playbook`
4. include the `removed_links` record that removes
   `skills/bug-triage-playbook` and names
   `skills/cisco-build-artifacts` as the replacement only for Cisco build fetch
   and archive handling

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
install. That compatibility fallback exists only before cutover admission; a
completed cutover has no active or installed `bug-triage-playbook` route.

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
machine-verifiable, static receipt-equivalence check without adding Cisco
behavior to the installed generic skill. Because a pull request can modify this
script and its tests, running it from a candidate checkout is never a merge or
release admission. The independently trusted base workflow described below
embeds its own static verifier. Both verifiers require ten expectations from an
independent trusted source, not copied from the receipt:

- the exact canonical candidate commit
- the exact retirement pull-request number
- the exact private release commit
- the exact private release-manifest SHA-256
- the exact SHA-256 of the receipt bytes
- the exact base-owned workflow ID
- the exact base-owned workflow commit SHA
- the exact installation-scope identifier
- the exact positive pointer generation
- the exact domain-separated pointer-state SHA-256

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
  --expected-workflow-sha <40-lowercase-hex> \
  --expected-installation-scope-id <canonical-ASCII-identifier> \
  --expected-pointer-generation <positive-decimal> \
  --expected-pointer-state-sha256 <64-lowercase-hex>
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
The receipt plus the eleven short identity/digest variables also stays below the
repository aggregate; an oversized producer receipt must fail before
publication. Schema comparisons require exact JSON scalar and container types,
so a Boolean never substitutes for an integer and an integer never substitutes
for a Boolean. The receipt must bind all of the following without extra or
missing fields:

1. schema version 3, the exact canonical/private repositories and commits, and
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
7. a canonical 1-128 character ASCII `installation_scope_id`, an exact positive
   signed-64-bit `generation`, and a `state_sha256` independently pinned by the
   caller
8. strict UTC `observed_at` and `expires_at` timestamps, with observation not
   in the future and expiration strictly after observation and current
   validation time
9. exact historical provider provenance:
   private repository ID/name, release workflow ID/path/ref/SHA, run
   ID/current attempt, GitHub Actions provider ID/slug, and proof-artifact
   ID/SHA-256
10. an active, unexpired merge lease whose exact lease ID, target repository
    ID, retirement PR number/head, installation scope, and pointer generation
    agree with the independently pinned receipt state

The pointer-state digest is exactly
`SHA256("cisco-installed-pointer-state-v1\0" || canonical_json(state))`.
`state` has only `generation`, `installation_scope_id`, `name`,
`release_manifest_sha256`, `resolved_release_commit`, and `target`;
`canonical_json` uses UTF-8, `ensure_ascii=true`, lexicographically sorted
keys, `(",", ":")` separators, and no trailing newline. The authority must
serialize pointer changes and maintain the generation as a monotonic
high-watermark: every switch increments it, including a rollback that points
back to an older release. A receipt-provided integer does not by itself prove
that monotonicity.

A missing receipt, missing independent expectation, digest mismatch, partial
gate set, pointer/lease mismatch, expired proof, malformed JSON, or any schema
difference exits 1 with `classification=blocked_until_trusted` and a
discriminating reason. After every static field succeeds, the checked-in
validator still exits 1 with
`validation_scope=static-equivalence-only,reason=pointer-proof-unavailable`.
Its `live_authority` object is historical provenance, not proof that `current`
still has that state. Only an independently configured live authority can
re-read the exact scoped current pointer and merge lease; the checked-in
contract explicitly records
`status=unavailable,reason=private-live-authority-not-configured` and contains
no placeholder private IDs.

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
turn a neutral run into target evidence. It also requires the workflow ID and
SHA variables to equal both the administrator-pinned doctor arguments and the
native workflow metadata and source commit returned by GitHub.

The target admission job binds the selector outputs, exact event PR
number/head, receipt cutover object, and workflow ID/SHA before validating the
private release and pointer. It exposes no secret or token to a candidate
process because there is no candidate process. It reports static mismatches
before the terminal authority decision. With the checked-in contract's live
authority unavailable, even complete static equivalence ends with
`classification=blocked_until_trusted,reason=pointer-proof-unavailable`; there
is no target green outcome. The live doctor follows the same ordering: it
finishes static collection, performs the final protected-snapshot
revalidation, and hashes the canonical evidence before asking for pointer
proof. A pointer-only blocker therefore includes
`static_equivalence=validated` and its non-null `evidence_sha256`; failures
before that boundary leave the static claim unset. These fields, together with
sanitized cleanup-failure evidence when applicable, define doctor receipt
schema 5.

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
- `CISCO_CUTOVER_EXPECTED_INSTALLATION_SCOPE_ID`: independently pinned
  canonical installation-scope identifier
- `CISCO_CUTOVER_EXPECTED_POINTER_GENERATION`: independently pinned positive
  monotonic generation
- `CISCO_CUTOVER_EXPECTED_POINTER_STATE_SHA256`: exact domain-separated digest
  of the six-field canonical pointer state

Do not derive any `EXPECTED_*` value from `CISCO_CUTOVER_RECEIPT_BASE64`.
The base verifier compares `CISCO_CUTOVER_EXPECTED_CANONICAL_COMMIT` against
the exact event head SHA, so a valid old receipt and stale repository variable
cannot admit a different candidate. Missing, empty, recognizable placeholder,
all-zero, malformed, stale, or mismatched values keep the trusted workflow red.
The doctor must read all twelve variables through fixed, no-redirect REST
`GET` requests to the exact `https://api.github.com` origin and require every
variable's `updated_at` to be strictly earlier than the selected workflow
attempt's `run_started_at`. Equality is not an ordering proof. The
administrator-pinned run ID and attempt remain exact inputs; do not select a
run, attempt, or proof artifact by name, recency, or a `latest` alias.

Before retirement, run `scripts/doctor_cisco_cutover_enforcement.py` in the
trusted administrator environment. It deliberately accepts no `--evidence`
file and does not trust caller-supplied pagination or completeness booleans.
The administrator must supply an absolute, non-symlink `gh` executable path,
its independently pinned SHA-256, and an explicit absolute owner-private
`GH_CONFIG_DIR`. That directory must be mode `0700`; `hosts.yml` and an
optional `config.yml` must be single-link, owner-only regular files. Every
component from `/` to the selected directory is opened with no-follow
semantics, retained by descriptor, and required to have an owner and write
policy that prevents another principal from renaming its child.

On Darwin, mode bits are not the complete access policy: an extended or
inherited ACL can grant another principal read, write, traversal, or
delete-child rights while `0700`, `0500`, or `0400` remains unchanged. The
doctor therefore queries `ACL_TYPE_EXTENDED` directly on each retained file or
directory descriptor through fixed `/usr/lib/libSystem.B.dylib`. It neither
resolves principals through directory services nor parses path-based `ls`
output. The kernel ACL is capped at 128 entries and its external representation
at 64 KiB. A non-inherited deny entry is only restrictive and remains valid
(including the ordinary home-directory `deny delete` ACL); every extended
allow and every inherited or inheritable entry is rejected. Rejecting all
extended allow entries is the bounded conservative superset of resolving which
allow qualifier denotes the owner. The complete external ACL representation is
size-checked while the retained access-policy binding is the monotone
no-allow/no-inheritance predicate, queried twice for stability and revalidated
with the descriptor/path identity chain before and after every `gh` invocation
and before final admission. Adding or changing a purely restrictive,
non-inherited deny entry is benign because it cannot weaken the selected
confidentiality or non-replacement property.

Every runtime child is created only below a parent whose ACL has already
passed. Its descriptor ACL is checked before any executable or token bytes are
written and again after the final owner-only `fchmod`, so a parent inheritance
rule cannot create a readable credential window. ACL query failure, an allow
grant, inheritance, or initial instability is `collector-unavailable`; drift
during or after an invocation is `collector-inconclusive`, and the command
output is discarded. This is a property-scoped access-policy check, not a
`ctime` proxy. As with the existing namespace binding, a process deliberately
acting under the same effective UID is the same filesystem principal and is
outside a separate-principal isolation claim.

Cleanup preserves two distinct properties. Access-policy stability is checked
once more before cleanup mutation; a mode or ACL expansion remains
`collector-inconclusive` even if deletion later succeeds, because deletion
cannot retroactively prove confidentiality. Object deletion is then bound to
the retained descriptors rather than to names alone. Each file name must still
resolve to the retained device/inode before `unlink`, and that exact descriptor
must report zero links afterward. Configuration, executable, and run
directories are removed leaf-to-root with retained parent/child descriptors,
pre-removal identity agreement, and post-removal name absence inside the
owner-private namespace. A bare `FileNotFoundError` is not proof that a
previously bound object was removed.

Failed `fchmod`, `unlink`, or `rmdir` operations are never discarded. The
doctor completes every safe cleanup attempt, returns
`reason_code=collector-inconclusive`, and records stable operation labels. If
the exact run directory is still present under the trusted runtime parent, the
blocked receipt adds `cleanup_failure.retained_runtime` with the verified
absolute path plus device and inode. No credential bytes, config payload, raw
error text, or environment data enter that locator. Still-linked bound
snapshots are listed separately in `cleanup_failure.retained_objects`. A
fixed last-known path is emitted as verified only after the retained descriptor
and that path agree on device, inode, and object type. A relocated object is
reported by exact device/inode with an explicitly unverified last-known path;
the potentially attacker-chosen current path is not serialized.

On Linux, the explicit `linux-posix-mode-mask-v1` path relies on POSIX access
ACL effective masks being reflected in the group mode bits already bound by
the doctor; new private objects are checked again after `fchmod`, preventing an
inherited default ACL from silently widening effective group/other access.
This does not claim Darwin/NFSv4 ACL semantics on Linux. Platforms other than
Darwin and Linux fail closed because no reviewed descriptor ACL profile exists.

The doctor ignores ambient `HOME` and `TMPDIR`. It derives the fixed runtime
parent `~/.codex/cisco-cutover-doctor` from the effective account database,
opens and retains every component with the same namespace checks, and creates
a unique `0700` run directory below it. It copies the digest-matched executable
into a dedicated private `bin` directory and changes that directory to `0500`
before any command. This protected namespace is the macOS-compatible
non-ABA execution binding: an untrusted principal cannot replace the executable
between validation and `exec`. Another process with the same effective UID is
the same filesystem security principal; deliberate same-UID interference is
still detected by the before/after identity and digest checks, but is not
claimed as a separate OS isolation boundary.

The source `hosts.yml` parser admits only the simple `github.com` authentication
mapping, retains only its active user, and excludes every other host and
credential. A fresh `config.yml` is generated with prompting disabled and an
empty `http_unix_socket`; source `http_unix_socket`, proxy, socket, API host,
base URL, endpoint, and transport overrides are rejected rather than copied.
The generated files are `0400` and their configuration directory becomes
`0500` before execution. Every invocation
uses only `LC_ALL=C`, `GH_PROMPT_DISABLED=1`,
`GH_NO_UPDATE_NOTIFIER=1`, and the generated snapshot `GH_CONFIG_DIR`; ambient
`PATH`, `HOME`, `TMPDIR`, token, loader, proxy, CA, and other `GH_*` variables
are absent. `gh` is not the HTTP transport. A token already present in the
admitted active `github.com` mapping is copied directly into an owner-private
`0400` header file; a keyring-only token is obtained with the sole fixed local
command `gh auth token --hostname github.com`. The token never enters the API
argv or environment.

Every REST read uses the fixed root-owned `/usr/bin/curl` OS trust root and an
exact URL built from `https://api.github.com` plus a validated relative
endpoint and typed query. The argv starts with `--disable`, disables proxy use,
admits only HTTPS, contains neither `--location` nor `--location-trusted`, and
sets `--max-redirs 0`. Therefore every `300` through `399` response is terminal:
the doctor neither parses nor follows `Location`, regardless of same-host,
cross-host, scheme, port, or multi-hop shape. The curl executable and each
root-owned, non-writable ancestor are rebound before and after the request;
the authorization-header file is included in the same descriptor-safe
pre/post revalidation and verified cleanup transaction as the generated
configuration.

The source executable/config and snapshot path/descriptor identities, sizes,
owners, groups, links, modes, and access-policy bindings are revalidated before
and after every invocation and once more before any admission. Each exact
content digest is cached only with a descriptor/path generation receipt bound
to size, `mtime_ns`, and `ctime_ns`. An unchanged generation avoids rereading a
large executable; a changed generation performs the same bounded content read
and exact digest comparison before the receipt can advance. Metadata churn is
therefore only a rehash signal, while replacement, access-policy expansion, or
content mutation still returns `collector-inconclusive` and discards command
output. The 16,384-call ceiling cannot amplify unchanged executable/config
hashing into 16,384 full reads.
Before the executable snapshot's first generation receipt is registered, its
read-only descriptor is hashed between matching pre/post descriptor identity,
path identity, access-policy, and content-generation checks. The retained
digest must equal both the copied source digest and the administrator-pinned
digest, so an initialization-window same-inode, same-size rewrite is rejected
even if owner permissions are restored.
The same process:

- resolves the active token locally when needed, then reads `/user` through
  the fixed no-redirect transport to prove both token validity and the exact
  authenticated account without printing credential output
- reads the exact organization, target repository, selected PR, organization
  ruleset, all twelve cutover-input repository variables, the exact selected
  run-attempt endpoint, source workflow repository, workflow metadata, and
  pinned source commit
- lists every effective target-repository ruleset with
  `includes_parents=true`; fully paginates every check suite for both the frozen
  PR head and the `pull_request_target` base commit with `filter=all` and no app
  filter; then fully paginates every check run for each discovered suite with
  `filter=all`, every workflow run for each selected-PR same-name check-suite
  ID, and every job for every observed run attempt
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
items, duplicate check-suite or check-run IDs, suite/head linkage drift,
page/call/suite/run/search caps that prevent proof of exhaustion, a missing or
mutable workflow binding, the wrong organization/repository/ruleset/workflow
identity, a disabled or evaluating ruleset, any bypass actor, wrong repository
or default-branch conditions, or any same-name `required_status_checks` rule.
It also rejects every collected `cisco-cutover-admission` check whose native
run/job/provider lineage differs from the pinned workflow. Therefore a green
candidate-authored duplicate cannot compensate for a red or absent trusted
workflow run. Multiple executions or rerun attempts on the same frozen head are
not ambiguous by themselves: the administrator must pin one exact run ID and
its current attempt number, every collected same-name lineage must still bind
to the trusted workflow identity, and only the pinned lineage's run, job, and
check must be complete and successful. A later attempt supersedes an older
attempt of the same run.

The live preflight is read-only. It invokes only the local `gh auth token`
credential lookup when the admitted config has no inline token and fixed
GitHub REST `GET` endpoints through the no-redirect curl profile; it does not
create, update, evaluate, disable, or delete a ruleset, rerun a workflow, post
a comment, or mutate the PR. The active credential needs read access to the
repository, Actions, checks, and organization ruleset metadata.
Authentication, permission, pagination, and API-limit failures remain
`blocked_until_trusted`.

API failures retain only a fixed endpoint class, the curl trailer's parsed
HTTP status, and a stable reason code. `401` maps to
`blocked-authentication`; ordinary `403` (including the current organization
ruleset `admin:org` failure) maps to `blocked-permission`; `404` maps to
`not-found`; `429` and explicit rate-limit `403` map to `rate-limited`; `5xx`
and malformed responses map to `api-unavailable`; and bounded command expiry
maps to `api-timeout`. Fixed curl exit 28 also maps to `api-timeout` when
curl's own connect or operation timer expires before the outer process
supervisor; other nonzero curl exits retain their prior meanings. A nonzero
local `gh auth token` result, including exit 28, remains an authentication
preflight failure. Response bodies, raw headers, command environments, tokens,
and raw subprocess stderr are never copied into the doctor receipt.

The termination boundary starts before the first source credential read and
remains one client-lifecycle transaction until verified deletion.
Initialization keeps ordinary catchable termination signals blocked while
configuration and executable snapshots are created; context entry then
restores delivery through request gaps, snapshot revalidation, response
parsing, and admission work. Before `Popen`, the same guard blocks delivery
again while spawning, constructing the managed-process handle, and publishing
it in the client registry, so no nested guard can restore a stale handler. A
signal deferred in any lifecycle phase first blocks further delivery, drives
bounded TERM/grace/KILL, drain, and reap when needed, closes the owner-private
credential and executable snapshot, restores the caller's handlers and signal
mask, and forwards the original signal to the caller's handler. The original
signal remains primary when child or snapshot cleanup also fails; retained
runtime/object locators carry the recovery identity. An unsafe handler/mask
restoration keeps the termination signals fenced instead of opening an
unowned interruption window.

One absolute monotonic collection deadline begins immediately after the
termination-signal guard is installed and before the first runtime/config path
or credential read. Directory and file binding, configuration double reads,
private credential/config creation, the bounded executable copy, each
`fchmod`/`fsync`, initialization and pre-execution snapshot revalidation, the
child, post-execution revalidation, and JSON parsing all consume that same
deadline; initialization never resets it. Revalidation checks the deadline
around each bounded read, recomputes remaining time afterward, and passes the
absolute deadline into process supervision; expiration before spawn prohibits
`Popen`.

These in-process monotonic checks do not claim to hard-interrupt NFS, FUSE,
File Provider, uninterruptible, or automatically restarted filesystem calls.
A caller that requires a hard return must launch the doctor as a separate
terminate-able process under an outer TERM/KILL/reap supervisor. Deadline
failure still runs the descriptor-bound cleanup transaction first; if cleanup
cannot be proved, the sanitized runtime/object locator and retained process or
descriptor identity remain the authoritative recovery evidence.

The direct process is registered before deadline, buffer, or selector
initialization. Every post-spawn error enters bounded TERM/grace/KILL with
interleaved pipe drain and a second hard reap deadline. Before the first
`poll()` or `wait()`, successful completion and error cleanup both seal the
process group while the unreaped leader still pins the numeric PID/PGID; after
reap they never signal or probe that number. This protects group identity
during signaling and prevents remaining members from continuing user-space
credential access without claiming numeric group absence after reap. On
Darwin, a zombie-only `EPERM` from the final group signal counts only when a
non-reaping `waitid` or `EVFILT_PROC` check proves the leader exited; every
unknown permission result remains inconclusive. Unexpected selector, stream,
wait, or resource errors map to structured `collector-inconclusive` evidence.
The client retries any unresolved registered process before credential
cleanup, but a retry whose leader was already reaped cannot touch the old PGID.
If quiescence is still unproven, it performs no snapshot `fchmod`, `unlink`, or
`rmdir`, retains the owner-private runtime, and returns sanitized
retained-object locators plus the unresolved process binding.

Invoke the doctor only with administrator-pinned identities and the exact
existing PR:

```text
python3 scripts/doctor_cisco_cutover_enforcement.py \
  --contract docs/cisco-cutover-enforcement-contract.json \
  --gh-executable <absolute-admin-pinned-gh-path> \
  --expected-gh-sha256 <64-lowercase-hex> \
  --gh-config-dir <absolute-explicit-gh-config-directory> \
  --pull-request-number <existing-pr-number> \
  --expected-ruleset-id <numeric-ruleset-id> \
  --expected-run-id <numeric-actions-run-id> \
  --expected-run-attempt <positive-decimal-attempt> \
  --expected-workflow-id <numeric-workflow-id> \
  --expected-workflow-sha <protected-base-40-lowercase-hex> \
  --candidate-head-sha <retirement-head-40-lowercase-hex>
```

The schema-5 admitted doctor receipt has exact fields for the schema/operation,
contract and collected-evidence SHA-256 digests, collection timestamps and
page bounds, authenticated account identity, organization/target repository,
PR number/head repository ID/head SHA, ruleset source/ID, source workflow
repository ID/name/path/ref/SHA, the administrator-pinned run ID/attempt, and
the trusted run/job/check IDs, URLs, provider, status, and conclusion. Blocked
output includes the
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
   verify the real private overlay. Its producer-authored schema-3 receipt must
   bind the exact target repository ID/name/default branch, frozen PR
   number/head/base, workflow ID/repository/path/ref/SHA/event/check name,
   non-replay pointer state, exact provider run/current attempt/artifact, and
   active PR/head/scope/generation merge lease.
   Do not fabricate a receipt or derive independent expectations from it.
4. A repository administrator configures both selector variables plus the
   receipt and all nine independent `EXPECTED_*` variables. Re-read all twelve
   values and require the selector number/head, canonical commit, receipt
   cutover object, workflow ID/SHA, scope, generation, and pointer-state digest
   to agree.
5. Only after step 4, an organization owner creates or updates the active,
   bypass-free organization `workflows` ruleset with the exact target
   repository/default-branch conditions and source
   repository/path/ref/SHA binding, then records its numeric ruleset ID. Do not
   add a same-name status-only requirement.
6. Configure and independently validate the live pointer authority before
   attempting a target evaluation. The checked-in contract deliberately has no
   private authority repository/workflow/artifact locator and therefore stops
   here with `pointer-proof-unavailable`; the Jenkins compatibility route
   remains installed. Do not insert placeholder IDs to advance the state
   machine.
7. After a separately reviewed contract/workflow version supplies real
   authority locators, use explicit Actions authorization to trigger a new target evaluation
   without changing the frozen head—for example, rerun the target workflow
   attempt or use one of the declared `pull_request_target` activity
   transitions—and observe selector, target admission, run, job, and check
   success. Record the exact successful Actions run ID and its current attempt
   number; this document does not perform that mutation automatically.
8. Run the live read-only doctor against that exact retirement PR/head. Its
   fully paginated, twice-stable API snapshot must prove selector variables,
   the exact identity-bound rule, and the current successful target
   run/job/check lineage selected by that exact run ID/attempt. It must fetch
   the proof by exact authority repository, workflow, run, current attempt, and
   artifact ID, verify the artifact digest and freshness, and read both the
   scoped current state and merge lease twice. Historical artifact provenance
   alone is replayable and cannot admit.
9. Immediately before merge, revalidate that the PR is still open, its
   base/head are unchanged, the selector/ruleset/workflow snapshots still match,
   the receipt expectations still name the same head, and the fresh doctor
   receipt is `admitted`. Any head, workflow SHA, selector, receipt, or ruleset
   change returns the state machine to step 2 or the earliest affected step.
10. Only then may an authorized maintainer merge the retirement PR and allow the
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
4. With the ruleset proved inactive, keep all twelve cutover variables in place
   while removing the workflow in a separate reviewed PR. That cleanup PR must
   still complete the base-owned workflow through the neutral path. Verify the
   protected-base workflow blob is absent and the cutover ruleset remains
   ineffective before continuing.
5. Delete only the twelve exact cutover variables, in the contract's declared
   order, after per-variable
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

## Handoff To Base-Model Diagnosis

On a successful fetch, supply at least:

```text
source_url=<redaction-safe authoritative URL>
artifact_identity=<build/run/artifact identifier>
local_path=<validated local path>
bytes=<downloaded byte count>
auth_profile=<profile label, never credential material>
```

The private `cisco-build-artifacts` provider owns any required bounded archive
inspection and then supplies the resulting local path or bounded excerpts plus
this provenance to ordinary base-model diagnosis. The caller must not invoke or
recreate an installed `$bug-triage-playbook` route. A maintainer may explicitly
use the public repository's helper as an optional source tool, but that choice
is not an active-catalog entry, installed link, receipt dependency, or generic
diagnosis router. Base-model diagnosis must not infer or retry Cisco
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
