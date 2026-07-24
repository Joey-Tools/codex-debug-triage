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
30-second process-timer deadline covers the complete command, including central
directory validation, decompression, and the validation drain that continues
after selected output has been truncated. The helper fails closed when the
platform cannot provide that process timer or when the caller already owns it;
it never silently replaces an existing timer.

The helper opens the archive once, records the initially accepted file size,
and holds that file descriptor through member selection and reading. Its
reader exposes that initial size as the only EOF and rejects later file-size
growth or shrinkage before seeks and reads. This protects archive object identity
against path replacement and preserves the accepted extent, but it does not
freeze same-size content changes to the underlying object.

Before constructing Python `ZipInfo` objects, it reads EOCD/ZIP64 metadata and
sequentially counts bounded central-directory records from that same descriptor.
It resolves and orders every local-header offset, binds each central record to
one matching local record, and requires those records to explain the complete
byte range from offset zero to the central directory without gaps or unreferenced
records. Data-descriptor width is derived from the local and central ZIP64
extra/version/size representation rather than only the local size fields. It
rejects prefixed or concatenated ZIP views and multi-disk member starts.
Before extracting a selected member, it rejects general-purpose flags other
than the implemented data-descriptor and UTF-8-name semantics.
For extraction, it accepts only stored and DEFLATE members. Python's BZIP2 and
LZMA ZIP paths can allocate decompressor-internal output or dictionaries before
the helper can enforce its actual-byte budget, so the helper rejects those
methods before opening a decompressor. The accepted paths consume the complete
declared compressed span in bounded chunks, count actual decompressed bytes,
and verify stream termination, absence of trailing compressed data, file size,
CRC, local-header metadata, and any data descriptor before buffered output is
published.

User-provided member, listing, and line-filter regular expressions run only in
terminable isolated workers under per-match and command-wide deadlines.
Decoded member text escapes terminal control and non-printing characters before
output character accounting and publication.

## 5. Report Decisive Evidence

Prefer:

- the local artifact path and its provider-supplied provenance
- the member or file name inspected
- five to ten key lines with line numbers
- the leading hypothesis and strongest alternative
- the smallest next step that separates them
