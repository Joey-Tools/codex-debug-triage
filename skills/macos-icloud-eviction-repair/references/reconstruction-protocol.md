# iCloud Eviction Reconstruction Protocol

Use this protocol for a small, explicitly authorized set of iCloud Drive files that remain resident after an eviction failure. It describes a guarded reconstruction, not a general repair script. Treat cloud deletion, local deletion, and replacement of a canonical file as separate decisions. Do not automate cleanup by deleting data on a best-effort basis.

## 1. Establish the failure and scope

1. Record the macOS version/build, exact error domains/codes, relevant provider messages, and the selected file's current metadata in a scoped local audit. Anonymize paths, cloud identifiers, per-file hashes, process IDs, and raw logs before publishing a public case note.
2. Establish whether the object is uploaded, unpinned, conflict-free, and still resident. A metadata/eviction error is not proof that file contents are corrupt.
3. Define the protected properties for this operation:
   - **Object identity:** device and inode for a local object; provider cloud ID for its cloud object.
   - **Content stability:** complete SHA-256, byte length, and stable modification time. A hash is the content proof; size/time are useful change signals, not substitutes.
   - **Access policy:** owner, group, and mode. Preserve birth time and modification time when reconstructing.
4. Check existing session authorization for the exact file list, identity-changing reconstruction, and deletion of old cloud objects/backups. Explain the effect on links/history and request only missing scope; do not ask again when those operations are already approved. Authorization does not extend beyond the approved manifest or to unapproved deletion.

Do not interpret ctime, file flags, or directory child-entry changes as content mutation. In particular, do not manually remove provider xattrs or change flags to force eviction. Device/inode, content hash/size/mtime, and owner/access policy answer different questions and must not be conflated.

## 2. Preserve and construct a fresh provider object

1. Create a complete private raw backup and record its SHA-256 and byte length. Open sources without following symlinks, bind descriptor and pathname identity, and verify identity, length, and modification time before/after the read. Create destinations exclusively; never overwrite a pre-existing backup or staging name. Keep the backup until the canonical replacement passes the final checks.
2. Create a byte-for-byte copy under a fresh name in the same folder so the provider assigns a new cloud ID. Do not rename or rewrite the failed provider object to simulate a new object, and do not copy its provider-private metadata.
3. Restore the source's birth time, modification time, UID, GID, and mode on the fresh local file. Never hard-code a UID, path, or inode from another run.
4. Wait for the fresh cloud object to report uploaded, idle, unpinned, and error-free. Confirm it has a new cloud ID. Evict it and verify that it becomes dataless/cold.
5. If any state is ambiguous, preserve both copies and stop. A fresh name by itself does not establish a successful upload or safe replacement.

## 3. Replace the canonical name with a rollback point

1. Use `NSFileCoordinator` to move the old canonical object to a held name, then move the verified fresh object to the canonical name. Moving the fresh object preserves its new provider identity.
2. Roll back only if the canonical path is absent and the held object still matches the recorded identity and complete SHA-256. If either check fails, stop and preserve all available objects for manual recovery.
3. Confirm the new canonical object is dataless, then read the entire file from iCloud and compare its SHA-256 with the raw backup. Wait until the provider reports the downloaded object resident and idle; allow up to 120 seconds for provider settling, then stop if it remains unsettled.
4. Evict the canonical object again. Revalidate device/inode, cloud ID, byte length, modification time, birth time, UID/GID/mode, and open handles against the completed cloud-hash receipt. Do not re-read the canonical bytes after this final eviction merely to check the recorded digest: that would hydrate it again. A required new content read invalidates the final-cold checkpoint until hash verification and eviction are repeated. Open classified read-only descriptors are acceptable; writable/update or unknown descriptors block replacement or deletion.

## 4. Delete only after revalidation

Every deletion is fail-closed. Use native coordinated deletion and require the relevant authorization. Before deleting the held old object, recheck its recorded identity and complete SHA-256 inside the coordinated operation. Before deleting the raw backup, recheck its identity/hash and that the canonical object remains healthy, uploaded, evicted, and bound by unchanged metadata/cloud identity to the completed cloud-hash receipt. No extra canonical content read is needed at that checkpoint. Any read/revalidation error, missing path, identity mismatch, hash mismatch, or policy mismatch stops cleanup; do not collapse these outcomes into “missing” or retry deletion blindly.

Never run a script that automatically removes old provider objects or backups after a timeout or partial success. Preserve evidence and copies on interruption. Report which individual checks passed and which deletion, if any, was actually completed.

## 5. Bound retries, time, and storage

- A provider may replace a local inode while materializing the same cloud object. An `ETIMEDOUT` (`Errno 60`) or `itemContentVersionMismatch(expected, received)` followed by a new inode is not permission to accept it automatically. Retain the previous object and raw backup; explicitly revalidate the new device/inode, cloud ID, UID/GID/mode, size, birth time, and modification time, then rerun the full content hash. After a bounded retry, stop rather than loop indefinitely.
- A timeout is effective only while its parent supervisor remains alive. On interruption, send SIGINT as designed, terminate and reap the child process group, and verify no child remains before reporting the operation stopped.
- Account dynamically for raw backup, fresh copy, hydration, and provider temporary copies; their peak can exceed a simple two-copy estimate. Maintain a changing free-space reserve and stop before starting an operation that would cross it. Bind progress records to source identity, operation ID, and timestamp: a progress JSON emitted before the first blocking read may still describe the previous source.
- Distinguish filesystem free space from Foundation's `importantUsage` estimate, which may include reclaimable caches. A Time Machine “purgeable” count is observational only unless separate cleanup is authorized. File-allocation deltas do not equal volume-free-space deltas, and snapshot counts do not measure reclaimable bytes.

## 6. Evidence boundaries

Do not restart all iCloud/File Provider services as a default action, weaken SIP, or attempt privileged debugger attachment to Apple daemons. Prefer the minimum user-authorized action. A trace without a target file descriptor or command argument cannot attribute the failing operation to a particular file or request. Keep root cause marked unknown unless evidence establishes it.
