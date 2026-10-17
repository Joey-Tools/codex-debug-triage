---
name: macos-icloud-eviction-repair
description: Diagnose and recover macOS iCloud Drive File Provider files that cannot be evicted despite being uploaded and unpinned. Use for NonEvictable -2008, EPERM or cannotSetMetadata eviction failures, hydration timeouts, and verified reconstruction with a new cloud object identity.
---

# macOS iCloud Eviction Repair

Recover eviction while preserving verified file content. A successful workaround does not establish the underlying filesystem or File Provider bug.

## Establish the current state

Start with metadata for an exact, user-scoped file list. Record file type, hard-link count, logical size, allocated blocks, device/inode, ownership, permissions, ACLs, resource forks, extended attributes, birth/modification times, flags, provider identifier, upload/download state, pinning, conflicts, and provider errors. Resolve the current user's identity and paths; do not reuse historical PIDs, identifiers, inodes, or helper allowlists.

- Use `fileproviderctl evaluate <path>` when available, with a deadline and byte cap. Its output and private diagnostics can vary by macOS version. Missing fields are inconclusive.
- Measure allocation separately from logical size; `st_blocks` uses 512-byte units. A large logical file can already be dataless.
- Uploaded, idle, unpinned, unshared, conflict-free state is a prerequisite for the reconstruction protocol. A reported upload error or unknown cloud state blocks it.
- The byte-copy protocol requires a regular file with exactly one hard link, and access policy and metadata that its stated checks can preserve. Reject additional hard links, extended ACLs, resource forks, Finder tags, and other non-provider or unclassified metadata before replacement unless a separately validated preservation procedure covers them. Mode bits do not reproduce an ACL; a new inode does not preserve hard-link aliases.
- Inspect error domains and nested errors. Do not equate exit code zero with a successful native eviction; inspect the returned error and resulting provider state.
- Reading a cold file can download its entire content. Start with metadata; treat cloud reads, eviction, moves, and reconstruction as real operations within the user's authorization.

Use the supported `NSFileManager` ubiquitous-item eviction API and verify the resulting state. Do not remove private provider xattrs, edit `com.apple.decmpfs`, or force flags to manufacture an empty placeholder. The observed `UF_TRACKED` flag and a decmpfs header were not proof of corruption.

## Choose a bounded recovery

1. Preserve the latest evidence before changing services or files. Use exact file/provider identifiers, short log windows, bounded process sampling, and scoped `lsof -nP` queries.
2. If a service restart is justified and authorized, target only the current user's relevant service, then compare before/after state. Do not repeat a restart that produced no change without new evidence. Debugger attachment may be denied for protected Apple processes even with sudo; do not weaken SIP or debugger security to continue this workflow.
3. If ordinary eviction still fails on a healthy uploaded object, read [the reconstruction protocol](references/reconstruction-protocol.md) before making a replacement. Explain that a new cloud identity can affect old links/history, and that deleting the old object is a separate irreversible operation. Reuse existing session authorization when it already covers those actions.
4. Work on one small representative file first. Scale only after a new object has survived a cold cloud read, complete SHA-256 verification, and a second eviction. Recheck space throughout; provider staging can exceed the visible copies.

The protocol requires a retained original, a verified raw backup in a private non-provider local directory, and a genuinely fresh cloud object copied from that backup. Fresh creation and every move must fail atomically if the destination exists, while preserving the recorded object identities. Before coordinated promotion, verify the original and fresh object's complete SHA-256/length against the baseline under effective write exclusion, maintained through the moves; still perform the full cold cloud roundtrip afterward. Deleting the last verified backup additionally requires effective write exclusion throughout the final hash, eviction, and cleanup; a clean `lsof` or stable size/mtime is insufficient. If that exclusion cannot be established, retain a verified independent local backup and report cleanup incomplete. Rewriting bytes while retaining the old cloud identity did not resolve the recorded incident. This skill contains a procedure, not a general-purpose destructive batch executor; any task-specific helper must implement and validate these checkpoints for its current scope.

## Handle materialization and retries

Keep object identity, content verification, and access policy separate. A hash proves the bytes read, not future stability against a writer that restores metadata. `NSFileCoordinator` coordinates cooperating clients; it does not exclude arbitrary POSIX or remote writes. Normal hydration can change flags, ctime, or the local inode; it does not prove content corruption or authorize accepting a replacement silently.

- For `itemContentVersionMismatch` or a timed-out read, retain the original and raw backup. Re-evaluate the current object. Admit a changed inode only after explicit revalidation of the expected cloud identity, device, owner/group, mode, size, and preserved dates; still repeat the full SHA-256 cloud read.
- A completed read can precede the provider's resident/idle state. Allow a bounded settling interval before treating it as a failed validation.
- Allow classified read-only provider handles; block writable, update, or unclassified handles before promotion/deletion.
- Tie progress to the current operation, source, and observation time. A heartbeat or stale byte count is not evidence that cloud bytes are arriving. Confirm child termination after interruption before retrying.
- Stop after a finite retry budget, on low space, unknown state, identity/content mismatch, or unverified cleanup. Preserve recovery locations and distinguish missing, inaccessible, failed revalidation, and mismatched objects.

Read [the anonymized incident](references/case-2026-10-17.md) when comparing this error family, large-file behavior, version mismatch, or space accounting. Its observations are historical evidence, not current host state or permission to mutate another file.

## Report completion precisely

Report cloud hash results, final provider state, residual allocated blocks, original paths, and retained/deleted recovery objects. Dataless plus uploaded/idle/no-error state proves eviction; small residual allocation may settle later, so measure it rather than assuming zero.

Keep file-allocation reduction separate from volume free-space change. Report `df` immediate free space and any macOS estimated capacity as different measurements, with timestamps. Snapshot count is not a reclaimable-byte estimate, and snapshot deletion needs its own scope authorization.
