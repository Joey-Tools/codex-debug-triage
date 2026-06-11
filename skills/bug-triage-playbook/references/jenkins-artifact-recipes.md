# Jenkins And Archive Recipes

Use these recipes when the repeated work is:

- verify auth and approval before touching the real artifact
- probe or fetch a Jenkins console, API payload, or archive without a shell wrapper
- list likely log members or local files before printing matches
- extract one member or inspect one local file and filter to the key lines

Prefer direct argv helper forms for approval-sensitive remote steps so prefix rules can match stable command families. Use the installed personal-skill path under the current user's `$HOME`, for example `$HOME/.codex/skills/bug-triage-playbook/scripts/jenkins_artifact_probe.py`, as the recurring target; the repo mirror under `personal_codex/` is for authoring and sync, not the default runtime command example.

Before fetching large local artifacts, allocate a task-scoped temp directory and clean it up when the task ends unless the user explicitly wants to keep the files:

```bash
tmp_dir="$(mktemp -d /tmp/jenkins-artifact.XXXXXX)"
trap 'rm -rf "$tmp_dir"' EXIT
```

## 1. Preflight The Gate

Check whether the expected auth env vars are present before attempting a remote fetch:

```bash
printenv JENKINS_ARTIFACT_USER JENKINS_ARTIFACT_TOKEN
```

Default remote probe when approval reuse matters:

```bash
python3 "$HOME/.codex/skills/bug-triage-playbook/scripts/jenkins_artifact_probe.py" probe-url \
  'https://jenkins.example.com/jenkins/wme/job/P3A0-WME-TA-LINUX-Daily/123/consoleText' \
  --auth-profile default
```

Interpret the first failure before retrying:

- `status=403` plus `auth=absent`: the expected env vars are still missing or you are not on the approved helper path yet.
- `status=401` plus `auth=present`: the helper reached the server, but the chosen `--auth-profile` is wrong for that endpoint. Change profile before falling back to raw `curl`.
- When one profile works for a Jenkins job family, reuse it for nearby `consoleText`, `api/json`, and artifact URLs unless the evidence says otherwise.

When this is the first escalated helper preflight in the session, request a recurring prefix such as:

```text
["python3", "<expanded-home>/.codex/skills/bug-triage-playbook/scripts/jenkins_artifact_probe.py", "probe-url"]
```

Fallback raw `curl` only when the helper cannot express the HTTP detail you need:

```bash
curl -fLI \
  -u "$JENKINS_ARTIFACT_USER:$JENKINS_ARTIFACT_TOKEN" \
  'https://jenkins.example.com/jenkins/wme/job/P3A0-WME-TA-LINUX-Daily/123/consoleText'
```

If this step fails, stop and report the precise blocker: missing env vars, approval, network, or remote auth.

The helper intentionally rejects:

- non-`https` URLs
- hosts outside `jenkins.example.com`
- arbitrary auth env names
- `fetch-url` output paths outside the current workspace or `/tmp`

## 2. Fetch The Requested Artifact

Show a text endpoint directly when you only need a modest text response or a bounded head/tail:

```bash
python3 "$HOME/.codex/skills/bug-triage-playbook/scripts/jenkins_artifact_probe.py" show-url \
  'https://jenkins.example.com/jenkins/wme/job/P3A0-WME-TA-LINUX-Daily/123/consoleText' \
  --auth-profile default \
  --tail 220
```

Keep shell-sensitive URLs quoted as one argument. Jenkins artifact viewer URLs such as `.../artifact/env.txt/*view*/` will be glob-expanded by `zsh` if you leave the `*view*` segment unquoted in a shell wrapper.

Show a small JSON payload directly:

```bash
python3 "$HOME/.codex/skills/bug-triage-playbook/scripts/jenkins_artifact_probe.py" show-url \
  'https://jenkins.example.com/jenkins/wme/job/P3A0-WME-TA-LINUX-Daily/123/api/json' \
  --auth-profile default
```

Fetch a console log to disk when the artifact is large or you need multiple local passes:

```bash
python3 "$HOME/.codex/skills/bug-triage-playbook/scripts/jenkins_artifact_probe.py" fetch-url \
  'https://jenkins.example.com/jenkins/wme/job/P3A0-WME-TA-LINUX-Daily/123/consoleText' \
  --output "$tmp_dir/run.consoleText" \
  --auth-profile default
```

Fetch a zip artifact:

```bash
python3 "$HOME/.codex/skills/bug-triage-playbook/scripts/jenkins_artifact_probe.py" fetch-url \
  'https://jenkins.example.com/path/to/artifact.zip' \
  --output "$tmp_dir/run.zip" \
  --auth-profile default
```

When this is the first escalated helper fetch in the session, request a recurring prefix such as:

```text
["python3", "<expanded-home>/.codex/skills/bug-triage-playbook/scripts/jenkins_artifact_probe.py", "fetch-url"]
```

Use the same pattern for `show-url` when you want direct stdout output:

```text
["python3", "<expanded-home>/.codex/skills/bug-triage-playbook/scripts/jenkins_artifact_probe.py", "show-url"]
```

Avoid embedding the whole flow inside `bash -lc` unless shell syntax is essential. Split remote helper fetches from local `tail`, `rg`, `python3`, or `jq` inspection.
If you need multiple local passes over a `*view*` URL or another shell-sensitive endpoint, prefer `fetch-url` first and then inspect the saved local file.

## 3. Budget Local Artifact Reads

Once the remote artifact or related archive has been fetched locally, do not switch to broad line-producing searches over the whole artifact tree. Start with cheap orientation:

```bash
find "$tmp_dir" -type f -print | sed -n '1,80p'
wc -l "$tmp_dir/run.consoleText"
rg -l -i 'ASSERT|ERROR|FAIL|Exception|Traceback|timeout' "$tmp_dir" | head -n 40
rg --count -i 'ASSERT|ERROR|FAIL|Exception|Traceback|timeout' "$tmp_dir" | head -n 40
```

Then print only one exact source at a time:

```bash
rg -n -i 'ASSERT|ERROR|FAIL|Exception|Traceback|timeout' "$tmp_dir/run.consoleText" | head -n 80
sed -n '420,470p' "$tmp_dir/run.consoleText"
```

Do not run raw `rg -n` across `.codex-tmp`, unpacked archives, `raw/` log trees, or broad source/documentation directories. Patterns such as `rg -n 'needle' .codex-tmp/av1-*` or `rg -n 'job|jenkins|create' .codex-tmp ...` can print tens of thousands of retained lines. Use `rg -l` / `rg --count` first, then read one exact file, member, symbol, or line window.

For large JSON, release metadata, or HTML/manual pages, avoid printing the full response. Prefer a helper `show-url` with `--head`, `--tail`, or `--grep`, or fetch to disk and extract selected fields with `jq` / a short parser before deciding whether a larger read is justified.

## 4. List Candidate Members

List all members:

```bash
python3 "$HOME/.codex/skills/bug-triage-playbook/scripts/jenkins_artifact_probe.py" zip-list "$tmp_dir/run.zip"
```

Narrow to likely files:

```bash
python3 "$HOME/.codex/skills/bug-triage-playbook/scripts/jenkins_artifact_probe.py" zip-list \
  "$tmp_dir/run.zip" \
  --match 'console|mqe|error|fail|log'
```

## 5. Extract And Filter The Key Lines

Show a known member:

```bash
python3 "$HOME/.codex/skills/bug-triage-playbook/scripts/jenkins_artifact_probe.py" zip-show \
  "$tmp_dir/run.zip" \
  'logs/console.txt' \
  --head 120
```

Search a member selected by regex, with context:

```bash
python3 "$HOME/.codex/skills/bug-triage-playbook/scripts/jenkins_artifact_probe.py" zip-show \
  "$tmp_dir/run.zip" \
  'fail8_share.*mqe.*\\.log' \
  --regex \
  --grep 'ASSERT|ERROR|FAIL|Exception|Traceback|timeout' \
  --ignore-case \
  --context 2
```

If the artifact is already a plain text file, keep filtering direct and narrow:

```bash
rg -n -i 'ASSERT|ERROR|FAIL|Exception|Traceback|timeout' "$tmp_dir/run.consoleText" | head -n 80
```

## 6. Report The Smallest Decisive Evidence

Do not paste the whole console or whole extracted file by default.
Prefer:

- the exact URL or artifact path inspected
- the member name inside the archive
- five to ten key lines with line numbers
- the smallest next step that separates the top hypotheses
