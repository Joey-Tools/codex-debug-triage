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
`pointer_authority` is
`status=unavailable,reason=private-live-authority-not-configured`; it contains
no invented private repository, workflow, run, artifact, or locator ID. The
workflow and local validator can verify a schema-3 receipt's exact static
equivalence—including its independently pinned installation scope, monotonic
pointer generation, domain-separated pointer-state digest, freshness window,
provider provenance, and active PR/head-bound merge lease—but they then return
`classification=blocked_until_trusted,reason=pointer-proof-unavailable`.
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

Because the organization rule applies to every default-branch PR, the workflow
uses administrator-owned exact PR-number/head selector variables. The one
frozen retirement PR runs `cisco-cutover-admission`; concurrent and future PRs
run the explicit `cisco-cutover-neutral` path without receiving target receipt
evidence. A target-head change fails closed. The satisfiable rollout order is:
merge the bootstrap workflow, create and freeze the retirement PR, publish a
receipt bound to that repo/PR/head/workflow contract, configure variables and
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
Source and snapshot identities, access policy, and content are revalidated
before and after each invocation and before admission. It collects
every API page through an explicit empty terminal page,
and revalidates the protected snapshot before admitting the selector, pinned
ruleset, workflow, PR head, administrator-pinned exact run ID/attempt, job, and
check run. Pointer admission additionally requires an exact authority
repository/workflow/run/current-attempt/artifact locator and twice-stable live
reads of the scoped current state and active merge lease; artifact name or
latest-run discovery is not an authority. Older or additional same-name lineage
is allowed only when it comes from the same trusted workflow identity. Sanitized failures
retain a fixed endpoint class, HTTP status when available, and stable reason
code without raw response bodies, headers, environment, or tokens. Until it returns
`classification=admitted`, retirement remains `blocked_until_trusted` and the
Jenkins entrypoint stays installed. With the checked-in
`private-live-authority-not-configured` policy, that compatibility route
therefore remains mandatory.

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
