# Codex Debug Triage

This public repository provides an optional, bounded transport helper for allowlisted Jenkins-style HTTPS text and ZIP artifacts. Generic root-cause analysis and forge-, tracker-, runner-, or private-environment workflows stay in their dedicated skills.

The helper enforces same-origin authenticated redirects, a parent/worker monotonic wall deadline, streaming `limit + 1` reads, bounded text and output, complete ZIP inventory validation, and atomic mode-`0600` no-clobber publication. Runtime flags may tighten but never widen its compiled safety ceilings.

See [`skills/bug-triage-playbook/SKILL.md`](skills/bug-triage-playbook/SKILL.md) and [`jenkins-artifact-recipes.md`](skills/bug-triage-playbook/references/jenkins-artifact-recipes.md) for scope and usage.

## Test

The test suite is fully offline and runs on Python 3.9 and the latest Python available in CI.

```bash
python3 -m py_compile \
  skills/bug-triage-playbook/scripts/jenkins_artifact_probe.py \
  tests/test_jenkins_artifact_probe.py
python3 -m unittest tests.test_jenkins_artifact_probe
```
