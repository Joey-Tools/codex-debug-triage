# Codex Debug Triage

An optional public playbook for turning logs, crash reports, test output, and
build artifacts into ranked root-cause hypotheses.

This bootstrap release deliberately retains the existing Jenkins entrypoint,
reference, routing, and tests while adding the bounded local ZIP helper. The
Jenkins route cannot be retired until the independently trusted cutover
admission workflow is installed on the protected default branch.

## Private Migration

The proposed authenticated Jenkins retirement and the contract for moving it to
a separate private `cisco-build-artifacts` skill are documented in
[`docs/cisco-build-artifacts-migration.md`](docs/cisco-build-artifacts-migration.md).
That private implementation is intentionally not part of this repository.
`.github/workflows/cisco-cutover-admission.yml` is a self-contained
`pull_request_target` gate with no candidate checkout or candidate code
execution. A copy added by a pull request does not protect that same pull
request: it becomes authoritative only after a separately reviewed bootstrap
merge places it on the protected base and the repository ruleset requires the
exact `cisco-cutover-admission` context. Until then, retirement remains
`blocked_until_trusted` and the Jenkins entrypoint stays installed.

## Test

```bash
python3 -m py_compile \
  skills/bug-triage-playbook/scripts/jenkins_artifact_probe.py \
  skills/bug-triage-playbook/scripts/archive_triage.py \
  scripts/validate_cisco_cutover_receipt.py \
  tests/test_archive_triage.py \
  tests/test_jenkins_artifact_probe.py
python3 -m unittest \
  tests.test_archive_triage \
  tests.test_jenkins_artifact_probe
```
