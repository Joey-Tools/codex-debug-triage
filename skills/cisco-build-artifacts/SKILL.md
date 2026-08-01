---
name: cisco-build-artifacts
description: Safely acquire and inspect Cisco Jenkins build evidence. Use when Codex receives a Cisco Jenkins build, consoleText, API, artifact-viewer, or archive URL and must authenticate, follow approved redirects, stream a bounded response, publish a no-clobber local artifact, or inspect selected ZIP members.
---

# Cisco Build Artifacts

## Overview

Own Cisco Jenkins URL recognition, authenticated acquisition, bounded archive
inspection, and evidence provenance. Hand the resulting bounded excerpts or
verified local path directly to ordinary base-model diagnosis.

Do not route Cisco evidence through `$bug-triage-playbook`. Keep GitHub Actions
and pull-request check inspection with the GitHub provider workflow.

## Workflow

1. Classify the supplied URL as a build page, `consoleText`, API response,
   artifact viewer, or archive.
2. Treat the exact supplied remote artifact as authoritative. Do not substitute
   an older local artifact before reporting a precise access blocker.
3. Resolve helper paths relative to this loaded skill directory:
   - `scripts/cisco_build_artifacts.py` for remote probe/show/fetch.
   - `scripts/archive_triage.py` for bounded local ZIP listing and selection.
4. Use a direct argv helper call. Keep shell-sensitive URLs as one argument;
   never put a signed query in a shell-expanded command or diagnostic.
5. Use `probe-url` for access metadata, `show-url` for bounded text, and
   `fetch-url` for an archive or repeated local passes.
6. For `fetch-url`, pre-create either an in-workspace owner-controlled parent
   or an owner-private mode-`0700` task directory named
   `cisco-build-artifacts.*` under the fixed system temp root. The destination
   must be absent.
7. Inspect fetched ZIPs with `archive_triage.py`. Preserve or narrow its
   immutable archive/member/output ceilings. When a hard syscall return
   deadline is required, launch that local helper through the
   `$bounded-command-output` process-group deadline helper; its own timer is
   intentionally best effort.
8. Report the redaction-safe source URL, artifact identity, auth profile label,
   local path or selected member, byte counts, truncation state, and five to
   ten decisive lines. Never report credential material or query values.
9. Clean task-scoped artifacts when they are no longer needed, or report the
   retained path and reason.

Read [remote-artifact-recipes.md](references/remote-artifact-recipes.md) before
the first remote command. Read
[local-artifact-recipes.md](references/local-artifact-recipes.md) before ZIP
inspection.

## Protected Properties

- **Authentication origin policy:** normalize each HTTPS origin to exact
  `{host, effective port}` and require both the global allowlist and selected
  profile allowlist before credential access. At every redirect, discard
  `Authorization`, `Proxy-Authorization`, and `Cookie`; rebuild authorization
  only after the new exact origin passes the same profile policy.
- **Destination object identity and no-clobber:** hold validated output-root,
  parent-directory, and staged-file descriptors; walk and re-walk components
  without following symlinks; require trusted ownership and non-writable
  policy; bind the staged object's initial owner, mode, and descriptor ACL;
  seal it read-only, then publish from that same-directory object with an
  atomic descriptor-relative no-replace rename.
  On Darwin reject extended allow and inherited/inheritable ACL entries; on
  Linux bind the bounded raw POSIX access ACL alongside the mode mask. An
  unsupported or unreadable ACL fails closed. Never overwrite or delete a
  caller-created destination, and never clean up a policy-mismatched stage.
- **Downloaded content and budget stability:** stream identity-encoded HTTP
  entity bytes in fixed chunks; enforce declared and observed byte ceilings;
  bind the staged size and SHA-256 to the producer receipt; rehash before
  publication; keep text input bytes/lines/line length and displayed
  lines/characters independently bounded.

Directory-entry or timestamp churn alone is not a protected-property mismatch.
Classify only a proved object replacement, content change, or access-policy
change as mismatch. Keep unreadable or failed revalidation separate from
missing, already-present, and mismatched outcomes.

## Failure Boundaries

- `argument-rejected`, `url-policy-rejected`, `auth-origin-rejected`, and
  `output-policy-rejected` are local pre-network policy failures.
- `remote-authentication-failed`, `remote-http-error`,
  `remote-transport-error`, and `body-limit-exceeded` are remote acquisition
  failures.
- `producer-timeout`, `producer-failed`, and producer output/protocol failures
  are hard-wall supervisor failures. Preserve the independent
  `cleanup=term-reaped|kill-reaped|unverified` result. The two reaped labels
  prove the direct producer's terminal state; group signaling is defense in
  depth, not a claim that arbitrary worker-created descendants were inventoried.
- Pre-publication staging, identity, content, or `fsync` failure publishes no
  destination and reports staging cleanup separately.
- `publication=published,durability=unverified` means the destination is
  visible but containing-directory persistence is unknown. Never delete or
  automatically retry it; verify identity/content before an explicit
  durability-only recovery.
- `published-identity-unverified` and `published-content-unverified` also leave
  the visible destination untouched and require manual evidence-led recovery.

## Limits

Omitted flags use finite defaults. Zero, negative, and above-hard-max values
are usage errors; no flag disables a cap. `probe-url` and `show-url` may return
bounded output with `truncated=true`. `fetch-url` byte overflow, timeout,
integrity failure, or publication failure returns nonzero and never publishes
an incomplete destination.

The parent drains worker stdout and stderr incrementally and terminates the
producer as soon as either fixed retained-byte cap is crossed; the 256 KiB
stdout and 8 KiB stderr limits are runtime ceilings, not post-exit checks.

The local ZIP helper retains its verified immutable ceilings: 256 MiB archive,
10,000 members, 64 MiB central directory, 20 selected members, 8 MiB per
decompressed member, 32 MiB aggregate decompression, 100,000 lines per member,
200 output lines, and 65,536 output characters.

## Guardrails

- Do not add an insecure TLS option, arbitrary credential environment names,
  suffix host matching, non-default port, unbounded redirect, uncapped body, or
  overwrite flag.
- Do not echo raw signed queries, response bodies on error, authorization
  headers, cookies, usernames, or tokens.
- Do not fall back to raw `curl` merely because authentication or approval is
  missing. Report the exact blocker.
- Do not extract an entire archive tree. List bounded members, then inspect only
  selected text members.
- Do not recreate provider acquisition or the validated ZIP parser in an
  ad-hoc script.
