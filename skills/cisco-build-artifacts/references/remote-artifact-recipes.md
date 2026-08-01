# Cisco Remote Artifact Recipes

Use these direct helper shapes for Cisco Jenkins build pages, `consoleText`,
API responses, artifact viewers, and archives. The private installed overlay
owns the exact host and authentication-profile configuration; this canonical
source intentionally contains only non-private placeholders.

## Contents

1. Validate the configured gate
2. Probe a URL
3. Show bounded text
4. Fetch with atomic no-clobber publication
5. Interpret classifications
6. Hand off evidence

## 1. Validate The Configured Gate

The helper has two independent exact-origin policies:

- `CISCO_BUILD_ARTIFACT_ALLOWED_HOSTS` is the global comma-separated
  host allowlist.
- `CISCO_BUILD_ARTIFACT_DEFAULT_HOSTS` is the host allowlist for the
  built-in `default` authentication profile.

Both accept only exact normalized `host` or `host:443` entries. They do
not accept wildcards, suffixes, schemes, paths, inline credentials, or
non-default ports. The canonical fallback is `jenkins.example.com` so a
private installation must configure its own exact hosts without changing the
command interface.

The `default` profile reads `JENKINS_ARTIFACT_USER` and
`JENKINS_ARTIFACT_TOKEN` only after the initial exact origin passes both
allowlists. Do not print or inspect the values. Let the helper report
`authentication-missing` before network access.

At a redirect, the helper validates the new HTTPS origin, verifies that the
same selected profile authorizes it, discards all sensitive request headers,
and only then rebuilds Basic authorization. A cross-host redirect never
inherits the previous header. Adding a host only to the global list is
insufficient to send profile credentials there.

## 2. Probe A URL

Resolve the script relative to the loaded skill:

```bash
python3 "<loaded-skill-dir>/scripts/cisco_build_artifacts.py" probe-url \
  'https://jenkins.example.com/job/example/123/' \
  --auth-profile default
```

Use `--method GET` only when a bounded body preview is needed. The probe
sniff default is 4 KiB and cannot exceed 64 KiB. Raw query values are never
reported; `source_url` and `final_url` use `?redacted` and set
`query_redacted=true`.

## 3. Show Bounded Text

Show the last 120 lines of a console:

```bash
python3 "<loaded-skill-dir>/scripts/cisco_build_artifacts.py" show-url \
  'https://jenkins.example.com/job/example/123/consoleText' \
  --auth-profile default \
  --tail 120 \
  --line-numbers
```

Select errors with context:

```bash
python3 "<loaded-skill-dir>/scripts/cisco_build_artifacts.py" show-url \
  'https://jenkins.example.com/job/example/123/consoleText' \
  --auth-profile default \
  --grep 'ASSERT|ERROR|FAIL|Exception|Traceback|timeout' \
  --ignore-case \
  --context 2 \
  --line-numbers
```

Head stops the producer early. Tail retains a character-bounded deque. Grep
keeps bounded previous/trailing context. All modes independently cap response
bytes, input lines, input-line bytes, output lines, and output characters.
`truncated=true` means the selected text is incomplete and must not be
presented as whole-console coverage.

## 4. Fetch With Atomic No-Clobber Publication

Create a fixed-root owner-private task directory:

```bash
case "$(uname -s)" in
  Darwin) artifact_root="/private/tmp" ;;
  *) artifact_root="/tmp" ;;
esac
artifact_dir="$(mktemp -d "$artifact_root/cisco-build-artifacts.XXXXXX")"
chmod 700 "$artifact_dir"
```

Fetch to an absent destination:

```bash
python3 "<loaded-skill-dir>/scripts/cisco_build_artifacts.py" fetch-url \
  'https://jenkins.example.com/job/example/123/artifact/build.zip' \
  --auth-profile default \
  --output "$artifact_dir/build.zip"
```

The other allowed output scope is an existing owner-controlled parent under
the current workspace. Intermediate symlinks, untrusted owners, group/other
writable directories, existing destinations, and destination symlinks fail
before network access.

Mode bits are not treated as the complete access policy. The helper reuses the
skill-relative archive policy runtime: Darwin rejects extended allow and every
inherited/inheritable ACL entry, while Linux binds the bounded raw
`system.posix_acl_access` value alongside the separately checked mode mask.
Unsupported or unreadable descriptor ACL queries fail closed. The initial
staged-file identity binds owner, mode, and that ACL value; publication and
cleanup refuse a later policy mismatch.

The parent creates a same-directory mode-`0600` staged file and passes only
its descriptor to the supervised network producer. It verifies the producer's
size/SHA-256 receipt, narrows the file to mode `0400`, calls file `fsync`,
reopens it read-only, re-walks the trusted root, and rebinds the parent and
staged name. It then consumes that staging name with the platform's
descriptor-relative atomic no-replace rename, revalidates destination identity
and the complete receipt, and calls directory `fsync`. There is no overwrite
option and no separate successful-path staging unlink.

Keep the task directory until local inspection completes, then remove it using
the task's normal cleanup mechanism. Do not delete a path reported with
`cleanup=unverified` until its object identity is independently established.

## 5. Interpret Classifications

The command exits use these independent layers:

| Exit | Layer | Examples |
| --- | --- | --- |
| 2 | local usage/policy | `url-policy-rejected`, `auth-origin-rejected`, `destination-present` |
| 1 | remote acquisition | `remote-authentication-failed`, `remote-http-error`, `body-limit-exceeded` |
| 4 | producer supervision | `producer-timeout`, `producer-protocol-error` |
| 3 | local publication/durability | `download-content-mismatch`, `atomic-no-replace-failed`, `durability-unverified` |

A producer timeout reports cleanup separately. `term-reaped` or
`kill-reaped` proves the direct producer reached a terminal state;
`unverified` requires recovery and must not be collapsed into timeout alone.
The supervisor drains both pipes while the producer runs and stops the process
at the first byte beyond the fixed 256 KiB stdout or 8 KiB stderr retained
ceiling. These labels do not claim that arbitrary worker-created descendants
were inventoried; the canonical worker creates none.

If publication succeeded but directory synchronization failed, output contains:

```text
publication=published
durability=unverified
classification=durability-unverified
```

The destination is visible. Do not delete it and do not rerun fetch
automatically. First verify its bound identity, size, and SHA-256, then perform
only an explicitly authorized durability recovery.

## 6. Hand Off Evidence

On success, preserve:

```text
source_url=<redaction-safe URL>
artifact_identity=<query-independent URL-path digest>
output=<validated local path>
persisted_bytes=<bounded byte count>
sha256=<verified staged content digest>
auth_profile=<profile label>
publication=published
durability=verified
```

After bounded archive inspection, pass that provenance and the selected member
or excerpt directly to base-model diagnosis. Do not call
`$bug-triage-playbook` as a second router.
