# Codex Debug Triage

An optional public playbook for turning logs, crash reports, test output, and
build artifacts into ranked root-cause hypotheses.

This bootstrap release deliberately retains the existing Jenkins entrypoint,
reference, routing, and tests while adding the bounded local ZIP helper. The
Jenkins route cannot be retired until the independently trusted cutover
admission workflow is installed on the protected default branch.

After the admitted private cutover, `cisco-build-artifacts` owns Cisco fetch
and bounded archive handling, while ordinary local diagnosis falls through to
the base model without an installed skill route. This public repository and its
local ZIP helper may remain available as optional source assets, but
`bug-triage-playbook` is absent from the active private catalog and installed
links.

## Private Migration

The proposed authenticated Jenkins retirement and the contract for moving it to
a separate private `cisco-build-artifacts` skill are documented in
[`docs/cisco-build-artifacts-migration.md`](docs/cisco-build-artifacts-migration.md).
That private implementation is intentionally not part of this repository.
`.github/workflows/cisco-cutover-admission.yml` is a self-contained
`pull_request_target` gate with no candidate checkout or candidate code
execution. A copy added by a pull request does not protect that same pull
request: it becomes authoritative only after a separately reviewed bootstrap
merge places it on the protected base. Its job name is not an enforcement
identity: another GitHub Actions workflow can emit the same
`cisco-cutover-admission` context.

The checked-in enforcement contract is deliberately non-admitting. Its
`base_change_enforcement` precondition is
`status=unavailable,reason=ruleset-workflow-default-activities-exclude-edited,
event=pull_request_target,required_activity=edited,
ruleset_dispatch_activities=[opened,synchronize,reopened]`, and its
`pointer_authority` is
`status=unavailable,reason=private-live-authority-not-configured`; it contains
no invented private repository, workflow, run, artifact, or locator ID. The
workflow and local validator can verify a schema-3 receipt's exact static
equivalence—including its independently pinned installation scope, monotonic
pointer generation, domain-separated pointer-state digest, freshness window,
provider provenance, and active PR/head/base-bound merge lease—but they then return
`classification=blocked_until_trusted,
reason=admission-preconditions-unavailable` with an ordered `blockers` list
that preserves both unavailable preconditions.
Static receipt bytes and repository variables never establish that the private
authority still serves that pointer state.

Retirement additionally requires an active, bypass-free organization ruleset
(`source_type=Organization`, organization ID `283943935`) whose conditions
target only repository ID `1242512092` and `~DEFAULT_BRANCH`. Its `workflows`
rule binds the source workflow repository ID, exact workflow path,
`refs/heads/master`, and an administrator-pinned source commit SHA. The
workflow `repository_id` identifies the source workflow repository; it is not
the ruleset target condition. A `required_status_checks` rule with the same
context is explicitly insufficient.
GitHub's organization required-workflow enforcement uses its default
pull-request activities (`opened`, `synchronize`, and `reopened`) rather than
the workflow's declared `types`, so it does not guarantee a run for the
`edited` activity that carries a base-only retarget. The workflow declares
`edited` as ordinary dispatch defense-in-depth, but that source declaration
does not satisfy the missing enforcement precondition.

Because the organization rule applies to every default-branch PR, the workflow
uses administrator-owned exact PR-number/head/base-SHA selector variables. The
one frozen retirement PR range runs `cisco-cutover-admission`; concurrent and
future PRs run the explicit `cisco-cutover-neutral` path without receiving
target receipt evidence. When all three selector variables are absent, all PRs
are explicitly neutral; a partial selector configuration or target-head/base
change is rejected by any run that is dispatched. That comparison does not
prove that the ruleset dispatches a new run after a base-only retarget.
Activation therefore remains unavailable until a merge queue or independent
provider guarantees the required reevaluation. After that prerequisite exists,
the intended rollout order is:
merge the bootstrap workflow, create and freeze the retirement PR range,
publish a receipt bound to that repo/PR/head/base/workflow contract, configure variables and
the ruleset, observe the target run, obtain a fresh doctor admission, and only
then pass merge readiness. None of those live mutations is automatic.

`scripts/doctor_cisco_cutover_enforcement.py` accepts no caller-produced
evidence file. It performs an authenticated, read-only `github.com` preflight
with an absolute administrator-pinned `gh` executable and SHA-256, an explicit
absolute owner-private `GH_CONFIG_DIR`, owner-private executable and
configuration snapshots, and a minimal environment that inherits no ambient
`PATH`, `HOME`, `TMPDIR`, token, loader, proxy, or CA variables. The runtime
root is the fixed system-account path
`~/.codex/cisco-cutover-doctor`, not an environment-selected temporary
directory. Every path component is opened without following symlinks and kept
descriptor-bound; ancestors must not be renameable by another principal.
On Darwin, the same descriptors are queried through the fixed
`/usr/lib/libSystem.B.dylib` ACL API with explicit entry and byte ceilings.
Non-inherited deny entries remain valid, while every extended allow or
inherited/inheritable entry is rejected; the bounded ACL is rebound to that
no-expansion predicate around each command, so restrictive deny-only churn is
benign. Snapshot files are checked before credential bytes are written. On
Linux, the explicit profile instead binds the POSIX ACL effective mask through
the group mode bits and repeats that check after each owner-only `fchmod`;
other platforms fail closed rather than claiming Darwin ACL coverage.
Only the active `github.com` authentication entry enters the generated
configuration snapshot, whose global config contains no transport redirect.
Credential lookup receives only the fixed system helper path
`/usr/bin:/bin:/usr/sbin:/sbin`, so the macOS Keychain backend remains
available without inheriting an ambient executable directory.
Source and snapshot identities and access policy are revalidated before and
after each invocation and before admission. Content receipts bind the exact
SHA-256 to descriptor/path identity plus size, `mtime_ns`, and `ctime_ns`;
the executable snapshot is reopened read-only and hashed between matching
before/after identity, path, access-policy, and content-generation checks
before its first receipt is registered. Its digest must match both the copied
source and the administrator-pinned digest.
Unchanged generations reuse that receipt, while any generation change forces a
bounded reread and exact digest comparison. This avoids multiplying a large
executable hash by the 16,384-call ceiling without treating metadata churn
alone as a content violation or allowing source drift. The monotonic absolute
collection deadline starts immediately after termination-signal supervision,
before the first runtime/config path or credential read. Configuration double
reads, private snapshot creation, the bounded executable copy, every `fsync`,
pre/post revalidation, child execution, and response parsing all consume that
same deadline; it is not reset after initialization. Remaining child time is
computed only after preflight revalidation, and an exhausted budget cannot
reach `Popen`. Python deadline checks cannot hard-interrupt an uninterruptible
filesystem syscall; a caller requiring a hard return must run the doctor under
a terminate/reap-capable outer process supervisor and preserve any
descriptor-bound cleanup recovery identity. It collects every API page through
an explicit empty terminal page,
and revalidates the protected snapshot before admitting the selector, pinned
ruleset, workflow, PR head, administrator-pinned exact run ID/attempt, job, and
check run. Pointer admission additionally requires an exact authority
repository/workflow/run/current-attempt/artifact locator and twice-stable live
reads of the scoped current state and active merge lease; artifact name or
latest-run discovery is not an authority. For both the frozen PR head and its
`pull_request_target` base, it first fully paginates check suites with
`filter=all` and no app filter, then fully paginates the check runs of every
suite with `filter=all`, with aggregate suite/run capacities, unique IDs, exact
head/suite linkage, stable totals, and explicit empty terminal pages required
before same-name lineage is called complete. Older or additional same-name
lineage is allowed only when it comes from the same trusted workflow identity.
For the selected run, one fixed GraphQL query also binds the provider-authored
executed workflow repository, path, current attempt, and exact repository-file
URL at the ruleset-pinned workflow SHA.
Sanitized failures
retain a fixed endpoint class, HTTP status when available, and stable reason
code without raw response bodies, headers, environment, or tokens. Fixed curl
exit 28 is classified as `api-timeout`, including when curl's own timeout
precedes the outer process deadline; other nonzero curl exits retain their
existing classification, while any nonzero local `gh auth token` exit remains
an authentication failure. Until it returns
`classification=admitted`, retirement remains `blocked_until_trusted` and the
Jenkins entrypoint stays installed. With the checked-in
base-change-enforcement and pointer-authority policies both unavailable, that
compatibility route therefore remains mandatory.

Doctor receipt schema 6 adds distinct administrator-pinned
`expected_base_sha` and provider-observed `provider_observed_base_sha` fields
plus ordered admission `blockers` to the static-equivalence boundary, alongside
sanitized cleanup-failure evidence. Termination-signal supervision begins before the
first credential source read and remains the single outer transaction through
configuration/executable snapshot creation, every request gap and parse, final
revalidation, and verified cleanup. A deferred signal first blocks further
termination delivery, tears down any active process, deletes the bound private
snapshot, restores the original handlers and signal mask, and only then
forwards the original signal. Cleanup failure remains secondary and publishes
the retained runtime/object recovery identity. Every spawned `gh` process is
registered before
selector or deadline setup and is unregistered only after its direct child is
reaped, both pipes reach EOF, and its process group was sealed while the
unreaped leader still pinned the numeric PID/PGID. The protected property is
stable group identity for signaling and termination of user-space credential
access, not numeric group absence after reap: the doctor performs no
`poll()`/`wait()` before its final group action and never signals or probes that
PGID afterward. Darwin's zombie-only `EPERM` result is accepted only when a
non-reaping child-exit check proves the leader exited; an unknown permission
result stays inconclusive. Any post-spawn timeout, byte-limit, selector, stream,
or wait failure enters one bounded TERM/grace/KILL transaction with interleaved
drain and a separate hard reap deadline. Snapshot deletion begins only after
that transaction proves the group was sealed, the child was reaped, and the
pipes were drained. If a close-time retry still cannot prove it, the doctor
leaves the owner-private runtime intact and reports its verified locator plus
the unresolved PID/process-group binding.

Snapshot cleanup keeps the credential, executable, and directory descriptors
open while it removes their exact bound objects from leaf to root. Credential
creation registers a provisional descriptor before content is written, so a
binding failure before the normal snapshot member is published still retains
the exact object identity through cleanup. Credential source-file binding
likewise keeps a local descriptor until both bounded reads, object/policy
checks, and final parent revalidation succeed; every earlier exception closes
that local descriptor before it can escape.
File unlink proof requires the retained inode to reach zero links; directory
removal is issued relative to the retained owner-private parent only after
path/descriptor identity agrees. A pre-cleanup ACL or mode drift, or any failed
`fchmod`, `unlink`, or `rmdir`, is `collector-inconclusive` rather than a
silent best-effort cleanup. A failed directory owner-mode restoration remains
proof-affecting even if all later identity-bound removals succeed; in that
case `cleanup_proof` is inconclusive without claiming that a removed runtime
or snapshot is retained. When the run directory remains bound at its trusted
name, the blocked receipt includes a sanitized
`cleanup_failure.retained_runtime` locator with its absolute path, device,
inode, and verified path-binding state. Any still-linked bound or provisional
snapshot also appears in `retained_objects` with its exact device/inode. Its
fixed last-known path is marked verified only while it still resolves to that
object; a relocated object never publishes its new potentially
attacker-chosen path and retains an explicitly unverified last-known path
instead.
When static collection and its final snapshot revalidation succeeded before
the unavailable pointer gate, that same blocked receipt preserves
`static_equivalence=validated` and the canonical `evidence_sha256`.

## Test

```bash
python3 -m py_compile \
  skills/bug-triage-playbook/scripts/jenkins_artifact_probe.py \
  skills/bug-triage-playbook/scripts/archive_triage.py \
  scripts/doctor_cisco_cutover_enforcement.py \
  scripts/validate_cisco_cutover_receipt.py \
  tests/test_archive_triage.py \
  tests/test_jenkins_artifact_probe.py
python3 -m unittest \
  tests.test_archive_triage \
  tests.test_jenkins_artifact_probe
```
