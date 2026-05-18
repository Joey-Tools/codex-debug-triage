# Codex Debug Triage

Public log, build artifact, and archive triage helpers for Codex workflows.

## Test

```bash
python3 -m py_compile skills/bug-triage-playbook/scripts/jenkins_artifact_probe.py tests/test_jenkins_artifact_probe.py
python3 -m unittest tests.test_jenkins_artifact_probe
```
