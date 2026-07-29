# Local Artifact Recipes

Use these recipes after the authoritative log or archive is already available
on disk. Remote access, authentication, and provider-specific artifact
selection stay with the provider owner.

Follow the provider boundaries in `SKILL.md`. Use the owning provider workflow
first, then pass the resulting local path plus provenance into this playbook.

## Contents

1. Create a task-scoped workspace
2. Orient before printing lines
3. List ZIP members
4. Show one ZIP member
5. Report decisive evidence

## 1. Create A Task-Scoped Workspace

Keep temporary material isolated and remove it when the task ends unless the
user explicitly wants it retained:

```bash
artifact_dir="$(mktemp -d /tmp/codex-artifact.XXXXXX)"
trap 'rm -rf "$artifact_dir"' EXIT
```

Copy or download artifacts into that directory through the provider-specific
workflow. Do not put credentials, authorization headers, or private host
policy into the generic inspection commands below.

## 2. Orient Before Printing Lines

Start with bounded metadata and candidate names:

```bash
find "$artifact_dir" -type f -print | sed -n '1,80p'
wc -c "$artifact_dir/run.log"
wc -l "$artifact_dir/run.log"
rg -l -i 'ASSERT|ERROR|FAIL|Exception|Traceback|timeout' "$artifact_dir" | head -n 40
rg --count -i 'ASSERT|ERROR|FAIL|Exception|Traceback|timeout' "$artifact_dir" | head -n 40
```

Then inspect one exact file and a small window:

```bash
rg -n -i 'ASSERT|ERROR|FAIL|Exception|Traceback|timeout' \
  "$artifact_dir/run.log" | head -n 80
sed -n '420,470p' "$artifact_dir/run.log"
```

Do not run a broad line-producing search across unpacked archives, generated
trees, or a whole workspace. Use filenames and counts first, then narrow to one
file, member, symbol, or line window.

For large JSON or HTML, extract selected fields with a structured parser before
deciding whether a larger read is justified.

## 3. List ZIP Members

List a bounded sample:

```bash
python3 "<path-to-skill>/scripts/archive_triage.py" zip-list \
  "$artifact_dir/run.zip" \
  --limit 80
```

Narrow to likely text evidence:

```bash
python3 "<path-to-skill>/scripts/archive_triage.py" zip-list \
  "$artifact_dir/run.zip" \
  --match 'console|error|fail|log' \
  --ignore-case \
  --limit 40
```

## 4. Show One ZIP Member

Show a known member:

```bash
python3 "<path-to-skill>/scripts/archive_triage.py" zip-show \
  "$artifact_dir/run.zip" \
  'logs/console.txt' \
  --head 120 \
  --line-numbers
```

Select a member by regular expression and show matching lines with context:

```bash
python3 "<path-to-skill>/scripts/archive_triage.py" zip-show \
  "$artifact_dir/run.zip" \
  'error.*\.log' \
  --regex \
  --grep 'ASSERT|ERROR|FAIL|Exception|Traceback|timeout' \
  --ignore-case \
  --context 2 \
  --line-numbers
```

The helper only reads local ZIP members. It does not fetch URLs, choose a
provider artifact, or handle credentials.

Its defaults reject archive files above 256 MiB, central directories above
64 MiB, or archives above 10,000 members; cap member listings at 200 entries;
cap `--all` selection at 20 members; cap each decompressed text member at 8 MiB
and 100,000 lines; cap an input line at 131,072 characters; cap selected members
at 32 MiB total; and cap displayed output at 200 lines and 65,536 characters.
These defaults are also immutable hard ceilings: budget flags may only narrow a
run and values above the hard ceiling fail before the archive is opened. One
30-second in-process `ITIMER_REAL` budget covers the complete command when the
operating system returns control to Python, including central-directory
validation, decompression, the validation drain that continues after selected
output has been truncated, bounded success-output publication, and the
underlying output-stream flush. This is a best-effort interruption mechanism,
not a hard syscall deadline: it cannot guarantee interruption of NFS, FUSE,
File Provider, uninterruptible, or automatically restarted system calls. A
caller that requires a hard return deadline must run the helper in a separate
terminate-able process under an external wall-clock supervisor with
process-group cleanup.

The helper fails closed when the platform cannot provide the required POSIX
timer/signal controls, when the main thread currently blocks `SIGALRM`, when an
alarm is already pending, or when the caller already owns the process timer; it
never silently replaces an existing timer. Shutdown first blocks `SIGALRM`,
stops the timer, drains its pending alarm, restores the prior handler, and only
then restores the caller's signal mask. Runtime and argument errors use one
terminal-safe line capped at 8,192 characters. After the deadline first expires,
the same process timer repeats at a short fixed interval until cleanup so an
ordinary interruptible diagnostic write can be interrupted. If timer setup,
close, pending-alarm drain, handler restoration, or signal-mask restoration
fails, the error path never trusts `_armed` alone and avoids ordinary stream
writes and flushes. It temporarily enables `O_NONBLOCK` only on a validated
FIFO, socket, or terminal descriptor, publishes at most one bounded line under
a monotonic 100-millisecond poll budget, and restores the caller's original
descriptor blocking state under a separate bounded cleanup budget. Interrupted
`fcntl` setup and restoration cannot retry indefinitely; when no safe
descriptor is available it returns without risking a blocking diagnostic.
The same timerless path applies whenever regex-worker cleanup or startup has
not returned to `IDLE`, including a retained startup signal fence: a blocked
`SIGALRM` can never authorize an ordinary diagnostic write or flush.
`--encoding` accepts at most 64 ASCII letters, digits, dots, underscores, plus
signs, or hyphens and must resolve through Python's codec registry.

The helper opens the source archive once and copies at most the accepted
256 MiB extent into an owner-private, descriptor-only temporary snapshot. It
does not consult ambient `TMPDIR`: it uses the fixed system temporary parent,
atomically creates a unique `0700` root plus a `0600` regular file, and binds
their descriptor/path identity, owner, mode, link count, size, and access
policy before writing the first archive byte. On Darwin, the fixed descriptor
ACL runtime rejects every extended allow and every inherited or inheritable
entry on the created root or file and binds the bounded external ACL
representation. The Darwin source profile binds that representation without
applying the private snapshot's no-grant predicate, so a stable legitimate
source ACL remains readable. On Linux, a fixed descriptor `fgetxattr` profile
binds the bounded raw `system.posix_acl_access` value in addition to the
separately bound mode mask, so named-ACL changes cannot hide behind unchanged
group mode bits. An absent access ACL is distinct from an unsupported or
unreadable ACL query, and unsupported platforms fail closed. The file is then
unlinked and the empty root removed, leaving a zero-link descriptor as the only
parser input. The helper binds the source descriptor's identity, ACL, link
count, mode, and size before snapshot creation; revalidates that metadata and
ACL immediately before the first copy read, after the bounded copy, and again
after re-reading the complete SHA-256 content before any parser consumes the
snapshot. ACL query failure remains distinct from a successfully observed
binding mismatch. The reader exposes the snapshot's initial size as the only
EOF and revalidates its metadata, descriptor ACL binding, and complete digest
before success. This freezes the exact bytes used by member selection and
reading: source-path replacement, growth, shrinkage, and
same-inode/same-size rewrites remain isolated from the parser; sampled ACL
drift after binding also fails closed.

Before constructing Python `ZipInfo` objects, it reads EOCD/ZIP64 metadata and
sequentially counts bounded central-directory records from that same descriptor.
It resolves and orders every local-header offset, binds each central record to
one matching local record, and requires those records to explain the complete
byte range from offset zero to the central directory without gaps or unreferenced
records. Data-descriptor width is derived from the local and central ZIP64
extra/version/size representation rather than only the local size fields. It
rejects prefixed or concatenated ZIP views and multi-disk member starts.
Before extracting a selected member, it rejects general-purpose flags other
than the implemented data-descriptor and UTF-8-name semantics plus DEFLATE's
standard `0x0002`/`0x0004` compression-option bits. The four DEFLATE option
combinations `0x0000`, `0x0002`, `0x0004`, and `0x0006` are hints only; stored
members still reject those method-specific bits, and encryption, patched-data,
strong-encryption, masked-header, and every other unsupported bit remain
blocked.
For extraction, it accepts only stored and DEFLATE members. Python's BZIP2 and
LZMA ZIP paths can allocate decompressor-internal output or dictionaries before
the helper can enforce its actual-byte budget, so the helper rejects those
methods before opening a decompressor. The accepted paths consume the complete
declared compressed span in bounded chunks, count actual decompressed bytes,
and verify stream termination, absence of trailing compressed data, file size,
CRC, local-header metadata, and any data descriptor before buffered output is
published.

User-provided member, listing, and line-filter regular expressions run only in
terminable isolated workers under per-match and command-wide deadlines. A
worker inherits the helper's process group; it must never call `setsid` or
start a new session. A caller that needs a hard external return bound should
start the helper in one dedicated process group and apply TERM/KILL to that
whole group, which then contains both the helper and any catastrophic-regex
worker. Internal timeout cleanup still terminates and reaps the individual
worker. Worker teardown masks `SIGALRM` across TERM/KILL/reap and pipe closure,
then restores the command deadline classification only after terminal reap is
confirmed. A retryable cleanup-state handshake starts before signal-support
inspection, so alarms at that boundary are recorded instead of escaping.
Cleanup performs exactly one blocking mask call, preserves that call's true
original mask, and restores only that exact mask after reap and pipe closure;
it never treats a retry's already-blocked state as the original. The timer
remains armed, and any command expiration recorded during the deferred cleanup
is rethrown after mask restoration instead of extending or erasing the
deadline. If terminal reap cannot be proven, cleanup retains the authoritative
process handle plus the observed PID/process-group recovery identity instead
of discarding the handle.

Worker startup uses the same property across a wider publication transaction:
one true original `SIGALRM` mask covers `Popen`, publication of the returned
handle on the matcher, worker initialization, and publication of its cleanup
callback in the owning `ExitStack`. The helper restores that mask only after
the callback is registered or after a failed startup has completed
terminate/reap and pipe closure. A deadline observed at signal-support or
first-mask boundaries is recorded and rethrown after safe publication; a
deadline at the `Popen` return boundary cannot strand the still-unpublished
handle. If neither cleanup publication nor terminal reap can be proved, the
helper retains both the handle and the blocked signal fence for explicit
recovery. Decoded member text escapes terminal control and non-printing
characters before output character accounting and publication.

## 5. Report Decisive Evidence

Prefer:

- the local artifact path and its provider-supplied provenance
- the member or file name inspected
- five to ten key lines with line numbers
- the leading hypothesis and strongest alternative
- the smallest next step that separates them
