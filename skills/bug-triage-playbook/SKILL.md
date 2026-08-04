---
name: bug-triage-playbook
description: Optionally transport and inspect allowlisted Jenkins-style HTTPS console, API, and ZIP artifacts with bounded authentication, redirects, output, extraction, and wall time. Use when a task has an exact remote artifact URL or a local ZIP and needs a public-safe probe, fetch, member listing, text view, or single-member extraction before diagnosis.
---

# Bounded Artifact Transport

## Scope

This optional public skill supplies one canonical artifact transport helper. It does not define a generic root-cause method, GitHub Actions triage, tracker lookup, remote process diagnosis, or private host policy. Use the relevant forge or tracker skill for those tasks, and use ordinary evidence-based reasoning after the requested artifact is available.

The helper is `scripts/jenkins_artifact_probe.py`. Its public configuration is deliberately synthetic and fail-closed. A private installation may specialize fixed source constants through its own release process; callers cannot widen hosts, auth profiles, deadlines, or resource ceilings at runtime.

## Workflow

1. Identify the exact URL or local ZIP and the smallest required operation.
2. For a remote artifact, check the named auth profile's documented environment variables without printing their values.
3. Use `probe-url` for access metadata, `show-url` for bounded text, or `fetch-url` for a new persistent file.
4. Use `zip-list` to validate and orient an archive, `zip-show` for bounded member text, or `zip-extract` to publish one exact member.
5. Report the sanitized URL label or local path, selected member, decisive bounded evidence, and any explicit auth, policy, deadline, or limit blocker.

See `references/jenkins-artifact-recipes.md` for command forms and the hard-safety contract.

## Safety Contract

- Remote URLs must use an allowlisted HTTPS host. Inline credentials and URL fragments are rejected.
- URL text must be printable ASCII. Percent-encode spaces, Unicode path/query data, and other non-ASCII bytes before invoking the helper.
- Every redirect is revalidated before the next request. Authenticated redirects may remain only on the same effective HTTPS origin, including port, and redirect hops are capped.
- One parent process enforces a monotonic wall deadline over the complete worker operation. Socket timeout is a secondary bound, not the deadline.
- Network, text, lines, emitted output, ZIP local/central metadata, compression, decompression, and selected members all have hard ceilings. CLI flags can only lower them. Successful stdout is emitted as budgeted UTF-8, with non-printable characters escaped; probe metadata must be bounded printable single-line ASCII.
- Streaming reads request at most the remaining budget plus one byte; no artifact command performs an unbounded `read()`.
- ZIP source acquisition streams into a capped private snapshot, and ZIP inventory validation runs through a size-bounded seek/read view before allocating members. Selected local/central metadata—flags, methods, names, CRC and sizes, data descriptors, disk numbers, and 32-bit format bounds—is cross-checked; ZIP64 is rejected. It allows only stored or bounded-output DEFLATE members and rejects absolute or traversing paths, portable duplicate or non-printable names, symlinks, special files, encryption, excessive size/count/ratio, and truncated metadata. Before display or publication, `zip-show` and `zip-extract` independently stream the exact declared compressed span, require its output length and CRC to match, and require DEFLATE to reach its one exact end without unused or unconsumed trailing data. `zip-list` validates metadata only and does not claim payload integrity. The helper never calls `extractall`.
- `fetch-url` and `zip-extract` require an existing safe parent chain and an absent destination under the current workspace or `/tmp`. They stream to a same-parent mode-`0600` temporary regular file, verify expected length, and publish with an atomic no-clobber link. Non-sticky group/other-writable path components are rejected.
- Parent directory child churn is benign. Parent replacement or access-policy change, destination appearance, temporary-entry replacement, content-limit failure, or failed revalidation prevents publication.
- Root and processes running as the helper's effective UID are trusted principals. Cleanup does not promise conditional-unlink safety against either.
- Output access checks cover traditional owner/mode/sticky semantics, not extended ACLs. Do not use a parent chain whose ACL grants another principal read, add, delete, or write access.

## Boundaries

- Do not replace the helper with raw authenticated `curl` merely for convenience. If a required HTTP feature is unsupported, stop and state the missing feature.
- Do not create output parents automatically and do not choose an existing output path.
- Do not pass secrets in URLs, arbitrary header flags, or arbitrary environment-variable names.
- Status output strips URL userinfo, queries, and fragments. Treat that output as a safe label, not a byte-for-byte artifact identifier.
- Do not treat a transport failure as artifact evidence. Distinguish policy rejection, missing auth, remote HTTP failure, deadline, resource limit, malformed archive, and successful inspection.
- The acquired private ZIP snapshot is stable and always treated as untrusted. Source size and modification time detect ordinary concurrent changes but cannot prove stability against a writer that mutates content and restores those metadata signals.
- Blockable signals are deferred across the fork handoff and each `waitpid` ownership transition, so Python-level parent interruption cannot skip child reap or signal a PID after the worker was reaped. Receipt cleanup is attempted after enforced deadlines, worker failures, and Python-level parent interruption; it reports `inconclusive` when no exact receipt is available. Abrupt parent termination that cannot execute cleanup, including unhandled `SIGTERM` or `SIGHUP`, `SIGKILL`, and power loss, is outside the guarantee and can leave a private temporary file or a fully published final file.
- Do not leave fetched or extracted artifacts silently. Remove task-scoped artifacts when safe or report retained paths.

## Reference

- `references/jenkins-artifact-recipes.md`: bounded probe, fetch, ZIP inspection, extraction, and cleanup recipes.
