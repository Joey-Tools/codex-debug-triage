# Private `cisco-build-artifacts` Migration Contract

This document records the private functionality intentionally removed from the
public `bug-triage-playbook`. It is a handoff contract for a separately owned
private `cisco-build-artifacts` skill, not an implementation or an installation
instruction.

Keep actual Cisco hosts, job families, credential variable names, authentication
profiles, approval prefixes, and private examples in the private repository.

## Ownership Boundary

The private skill owns:

- Cisco build and Jenkins URL recognition
- exact HTTPS host allowlists
- named authentication profiles and their credential sources
- approval and network preflight
- build, console, API, and artifact identity resolution
- bounded remote reads and downloads
- authentication and HTTP failure classification
- private examples and job-family guidance

The public `bug-triage-playbook` owns only the downstream reasoning workflow
after an authoritative artifact is available locally. Its
`scripts/archive_triage.py` helper may inspect local ZIP members but performs no
network or authentication work.

GitHub Actions and pull-request checks bypass both skills and stay with the
GitHub provider workflow named in the generic skill's provider boundary.

## Aggregate Activation And Cutover Ordering

The canonical `Joey-Tools/codex-debug-triage` merge is source history only. It
does not mutate an installed skill link, an installed `AGENTS.md`, a private
catalog, or a per-host `current` pointer by itself. Do not treat that merge as
proof that the replacement provider exists on any machine.

The installed cutover belongs to the `Joey-Tools/codex-private-workflows`
aggregate. One candidate immutable private-overlay release must contain and
validate all of these changes together:

1. install the complete `personal_codex/skills/cisco-build-artifacts` source at
   `skills/cisco-build-artifacts`
2. update the release's private `AGENTS.md` routing to select that provider for
   Cisco/Jenkins build acquisition
3. update `personal_codex/private-sync-manifest.json` so the active catalog
   includes `skills/cisco-build-artifacts` and excludes
   `skills/bug-triage-playbook`
4. include the `removed_links` record that removes
   `skills/bug-triage-playbook` and names
   `skills/cisco-build-artifacts` as its replacement

Package validation must prove the provider files, routing policy, active
catalog, and removal record belong to that same release. The private overlay
verifier must pass before publication, and the host installer must verify the
staged aggregate before switching the installed `current` pointer. A source
checkout, merged private commit, open sync PR, or partially published asset is
not a trusted release.

Keep both the canonical bug-triage retirement PR and any consumer source-sync
step blocked until the replacement private release has passed those gates and
the installed pointer transition has been verified. If the aggregate cannot
machine-prove this atomic activation, retain a compatible
`bug-triage-playbook` route and omit its `removed_links` retirement; never point
installed guidance at a provider that the same trusted release does not
install.

The non-private cutover fixture at
`tests/fixtures/cisco-build-artifacts-migration.json` records only repository
names, aggregate paths, transaction members, trust gates, and fallback state.
It intentionally contains no Cisco host, credential, profile, job, or artifact
data.

## Private Command Interface To Preserve

Provide a private helper with these conceptual subcommands:

```text
probe-url <url> [--method HEAD|GET] [--auth-profile <name>] [--timeout <seconds>] [--sniff-bytes <n>]
show-url <url> [--auth-profile <name>] [--timeout <seconds>] [--head <n> | --tail <n> | --grep <pattern> [--context <n>]] [--max-body-bytes <n>]
fetch-url <url> --output <path> [--auth-profile <name>] [--timeout <seconds>] [--max-body-bytes <n>]
```

The private implementation should preserve these properties:

1. Reject non-HTTPS URLs, inline URL credentials, and hosts outside the exact
   private allowlist before network access.
2. Resolve only predefined private authentication profiles; do not accept
   arbitrary credential environment-variable names from command arguments.
   Authorize the selected profile for the initial exact origin before reading
   or attaching any credential material.
3. Fail before network access when a selected profile lacks required
   credentials.
4. Keep downloaded files under the current workspace or a task-scoped temporary
   directory.
5. Report stable, secret-free fields such as URL, HTTP status, authentication
   presence, output path, byte count, content type, and error classification.
6. Keep `show-url` output bounded through head, tail, or grep/context controls.
7. Distinguish usage or policy rejection from remote HTTP/authentication
   failure and local write failure with documented nonzero exits.
8. Quote or directly pass URLs containing shell metacharacters; do not require
   callers to hide the operation in a shell wrapper.

## Required Remote And Publication Safeguards

The migrated implementation must strengthen the retired public helper rather
than copy its unbounded `response.read()` and direct `write_bytes()` behavior.

### Redirect And Network Policy

- Validate the initial URL and every redirect target against the same HTTPS,
  inline-credential, port, and exact private host policy before following it.
- Treat an origin as scheme, normalized host, and effective port. Strip
  `Authorization`, `Proxy-Authorization`, and `Cookie` at every redirect; only
  rebuild authentication after the new origin passes policy and the selected
  profile explicitly authorizes that origin.
- Set a finite redirect count and reject downgrade, disallowed cross-host hops,
  redirect loops, and targets that cannot be normalized unambiguously.
- Apply explicit connect/read and total wall-clock deadlines. A timeout must
  stop the transfer rather than merely stop waiting for console output.
- Keep `probe-url` body sniffing separately capped; a probe must not become an
  implicit full download.
- Require normal TLS certificate-chain and hostname validation. Expose no
  insecure bypass. Normalize hostnames consistently, reject unapproved
  non-default ports, and never use suffix matching as a host allowlist.
- Never echo a raw URL that may contain a signed query. Drop fragments and
  redact query values by default; report only explicitly allowlisted,
  non-secret query fields plus a `query_redacted` signal.

### Streaming And Size Caps

- Stream response bodies in fixed-size chunks. Do not materialize a full
  console or artifact in memory before enforcing its limit.
- Enforce a hard downloaded-byte cap while streaming even when
  `Content-Length` is missing or false. Reject an oversized declared length
  before download, but never rely on that declaration alone.
- Give direct text output independent byte, line, and line-length caps.
  Implement head with early termination, tail with a bounded deque, and
  grep/context with bounded state.
- Cap archive/member counts, decompressed member bytes, and reported match
  output before handing a downloaded archive to downstream inspection.
- Define wire bytes, decoded HTTP entity bytes, decoded text characters, and
  persisted artifact bytes separately. Enforce wire and entity caps whenever
  content decoding is enabled, and report which representation is persisted.

Before activating the private skill, define exact `DEFAULT_*` and
`HARD_MAX_*` constants for redirects, connect/read/total timeouts, probe sniff
bytes, wire/entity body bytes, download bytes, output lines/characters, and
archive/member limits. Omitted values use the default; zero, negative, and
above-hard-max values are usage errors; no flag disables a cap. A bounded
`probe-url` or `show-url` response may succeed with `truncated=true`, while a
`fetch-url` body overflow, timeout, or integrity failure must fail without
publishing a destination.

### No-Clobber Atomic Publication

The protected properties are:

- **access policy**: every output remains under the validated workspace or
  task-scoped temporary root
- **object identity**: the caller's destination remains absent until one
  no-replace publication of the helper-created staged file
- **content stability**: published bytes are exactly the bounded stream written
  and verified through the staged file descriptor

To preserve them:

1. Open the trusted output root and allowed parent as directory file
   descriptors, walking components with no-follow semantics. Hold the parent
   `dirfd` through staging, publication, synchronization, and cleanup; reject
   missing, unreadable, replaced, or policy-invalid parents as distinct
   outcomes.
   Require the root, every ancestor, and the parent to remain controlled by a
   trusted principal and not renameable or writable by an untrusted principal
   for the whole transaction. Immediately before publication, re-walk from the
   held trusted-root descriptor and compare the reached parent's object identity
   with the held parent `dirfd`; block if the same allowed directory object
   cannot be proved.
2. Create a private same-directory staging file relative to that held `dirfd`,
   with exclusive creation, no-follow semantics, and restrictive permissions.
   Hold its descriptor throughout streaming, verification, flush, and `fsync`.
3. Track the staged object through descriptor identity. Do not treat unrelated
   directory-entry churn or timestamps alone as content mutation; require
   object replacement, content change, or access-policy change to classify a
   protected-property mismatch.
   Immediately before publication or cleanup, open the staged name relative to
   the held parent with no-follow semantics and compare its object identity to
   the held staged descriptor. Because a check followed by rename still races
   in an attacker-writable directory, require either the trusted-control
   precondition above or a platform primitive that publishes directly from the
   held staged object; otherwise block.
4. Publish relative to the same held `dirfd` with an operating-system
   no-replace atomic primitive. Do not use an `exists()` check followed by
   `os.replace()`, because that can overwrite a destination created in the race
   window.
5. Sync the held containing directory where the platform contract requires it.
   Remove only the helper-owned staging entry through that same `dirfd` after a
   failed publication, and never delete or overwrite the caller's existing
   destination.
6. Report unreadable or failed revalidation separately from destination
   missing, destination already present, content mismatch, and policy mismatch.
7. If no-replace publication succeeds but the containing-directory `fsync`
   fails, enter `published / durability-unverified`: report that the destination
   is visible but persistence is unknown, never delete it, and never retry
   automatically. Recovery must first verify destination identity and content,
   then retry only the directory durability step under explicit control.

## Handoff Back To Generic Triage

On a successful fetch, supply at least:

```text
source_url=<redaction-safe authoritative URL>
artifact_identity=<build/run/artifact identifier>
local_path=<validated local path>
bytes=<downloaded byte count>
auth_profile=<profile label, never credential material>
```

The caller can then explicitly invoke `$bug-triage-playbook` with the local path
and provenance. The generic skill should not infer or retry Cisco
authentication.

## Private Migration Tests

Move or recreate private tests covering:

- HTTPS, host-allowlist, and inline-credential rejection before network access
- redirect downgrade, disallowed cross-host hops, loops, and redirect-count caps
- credential/header stripping on redirects and profile-authorized rebuilds
- known and unknown authentication profiles
- initial exact-origin/profile authorization before credential access
- missing credentials before network access
- HTTP 401/403 and transport error classification without secret disclosure
- bounded streaming with missing, false, and oversized `Content-Length`
- bounded head, tail, grep, context, line-length, and body-sniff output
- download path containment, byte-count reporting, and failed-transfer cleanup
- existing-destination no-clobber behavior and destination-symlink rejection
- same-directory atomic no-replace publication, descriptor identity checks,
  flush/`fsync`, and revalidation outcome classification
- trusted-root re-walk, parent identity, staged-name identity, and
  attacker-writable-directory blocking
- post-publication directory-sync failure as
  `published / durability-unverified`, with no delete or automatic retry
- default, hard-max, zero, negative, above-max, truncation, and hard-failure cap
  semantics across wire/entity/persisted representations
- signed-query redaction, port/host normalization, and mandatory TLS validation
- shell-sensitive URL handling at the documented command boundary

Do not copy private fixtures, hosts, credentials, or job names into this public
repository.
