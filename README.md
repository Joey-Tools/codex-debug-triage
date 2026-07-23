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

## Test

```bash
python3 -m py_compile skills/bug-triage-playbook/scripts/archive_triage.py tests/test_archive_triage.py
python3 -m unittest tests.test_archive_triage
```
