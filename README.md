# Codex Debug Triage

An optional public playbook for manually turning provided logs, crash reports,
test output, and downloaded archives into ranked root-cause hypotheses.

The bundled skill is explicit-invocation only. It does not own authenticated
artifact retrieval, provider-specific credentials, or private host policy.
Provider-specific CI triage stays with the corresponding provider workflow.
The local helper only inspects ZIP files that are already on disk.

## Private Migration

The retired authenticated Jenkins interface and the contract for moving it to
a separate private `cisco-build-artifacts` skill are documented in
[`docs/cisco-build-artifacts-migration.md`](docs/cisco-build-artifacts-migration.md).
That private implementation is intentionally not part of this repository.
The repository includes only a no-network receipt validator for a future
private release gate; without an independently trusted exact release/pointer
receipt, cutover remains `blocked_until_trusted`.
The CI gate is intentionally red until the authenticated private release
receipt and all four independently pinned expected identities are configured;
it contains no placeholder success path.

## Test

```bash
python3 -m py_compile \
  skills/bug-triage-playbook/scripts/archive_triage.py \
  scripts/run_cisco_cutover_ci_gate.py \
  scripts/validate_cisco_cutover_receipt.py \
  tests/test_archive_triage.py
python3 -m unittest tests.test_archive_triage
```
