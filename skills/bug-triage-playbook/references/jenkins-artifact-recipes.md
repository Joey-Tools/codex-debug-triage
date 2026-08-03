# Bounded Jenkins-Style Artifact Recipes

These recipes use the optional public helper as the canonical transport boundary. The public host and job names are synthetic. Run the installed helper directly; avoid wrapping authenticated calls in a broad shell command.

```bash
helper="$HOME/.codex/skills/bug-triage-playbook/scripts/jenkins_artifact_probe.py"
artifact_dir="$(mktemp -d /tmp/artifact-probe.XXXXXX)"
```

The output parent must already exist, its path chain must not contain non-sticky group/other-writable directories, and each persistent destination must be absent. These checks cover traditional owner/mode/sticky semantics, not extended ACLs; choose a chain with no ACL grant to another principal. The standard sticky root-owned `/tmp` plus a private `mktemp` directory without such ACL grants satisfy this policy. Clean up the task-scoped directory when the task ends.

## Probe Access

Let the helper check whether the fixed auth variables are present. Do not run `printenv`, `env`, or another value-producing command for this preflight; the helper reports the missing variable names without exposing values.

```bash
python3 "$helper" probe-url \
  'https://jenkins.example.com/job/example/42/api/json' \
  --auth-profile default \
  --deadline-seconds 20
```

Interpret `auth=absent` and `auth=present` as transport state, not as proof that a credential is valid. HTTP, policy, and deadline errors remain distinct.

## Show Bounded Text

```bash
python3 "$helper" show-url \
  'https://jenkins.example.com/job/example/42/consoleText' \
  --auth-profile default \
  --grep 'ERROR|FAIL|Exception|timeout' \
  --ignore-case \
  --context 2 \
  --line-numbers \
  --max-bytes 8388608 \
  --max-emit-lines 80 \
  --deadline-seconds 30
```

`--head` and `--tail` are also bounded by the emitted-line and emitted-byte ceilings. A command-line limit can only tighten its compiled hard ceiling.

Text-oriented stdout is budgeted UTF-8 and escapes non-printable characters, so it is safe diagnostic rendering rather than a byte-for-byte copy. Use `fetch-url` or `zip-extract` when exact bytes are required.

## Fetch Without Overwrite

```bash
python3 "$helper" fetch-url \
  'https://jenkins.example.com/job/example/42/artifact/logs.zip' \
  --auth-profile default \
  --output "$artifact_dir/logs.zip" \
  --max-bytes 134217728 \
  --deadline-seconds 60
```

The helper checks destination absence before opening the remote response. It publishes a completed same-parent mode-`0600` file atomically and never overwrites an existing path. A reported worker failure or enforced deadline leaves no final partial file; an inconclusive timeout cleanup is reported explicitly. Abrupt parent termination that cannot execute receipt cleanup is outside this guarantee and can leave a private temporary file or a fully published final file.

Authenticated redirects are accepted only on the same effective HTTPS origin. Cross-host, cross-port, downgrade, inline-credential, loop, and excessive-hop redirects are rejected before another request is sent.

## Validate And List A ZIP

```bash
python3 "$helper" zip-list "$artifact_dir/logs.zip" \
  --match 'console|error|fail|\.log$' \
  --ignore-case \
  --limit 80 \
  --deadline-seconds 20
```

Listing validates the bounded central directory before allocating the complete inventory. Hard ceilings cover archive and central-directory bytes, member count, member-name bytes, per-member and aggregate compressed/uncompressed bytes, compression ratio, and selected members. Only stored and bounded-output DEFLATE members are accepted; unsafe paths, portable duplicate names, symlinks, special files, encryption, and other compression methods are rejected.

## Show One Or A Bounded Set Of Members

```bash
python3 "$helper" zip-show "$artifact_dir/logs.zip" \
  'logs/console.txt' \
  --grep 'ERROR|FAIL|Exception|timeout' \
  --ignore-case \
  --context 2 \
  --line-numbers \
  --max-emit-lines 80 \
  --deadline-seconds 20
```

Regex selection is available with `--regex`; multiple matches require `--all` and still obey `--max-selected-members`. Selected members are fully drained within their cap so CRC and truncation failures are not hidden by `--head`. `zip-list` validates metadata without decompressing payloads, so a successful list is not a payload-CRC claim.

## Extract One Exact Member

```bash
python3 "$helper" zip-extract "$artifact_dir/logs.zip" \
  'logs/console.txt' \
  --output "$artifact_dir/console.txt" \
  --max-bytes 33554432 \
  --deadline-seconds 20
```

Extraction accepts one exact regular-file member and never uses `extractall`. Publication has the same absent-destination, existing-parent, same-parent, mode-`0600`, atomic no-clobber contract as `fetch-url`.

## Finish

Report only the sanitized remote label or exact local path, member, five to ten decisive lines, and any explicit blocker. Remove the task-scoped directory when its artifacts are no longer needed:

Cleanup is destructive. Prefer recoverable cleanup tooling when it is available. Before using direct removal, confirm that the variable still names the exact task-scoped `/tmp/artifact-probe.*` directory and not a broader path:

```bash
rm -rf "$artifact_dir"
```
