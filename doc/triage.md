# Batch triage

`capa triage` walks a directory and produces two reports for manual review:

- `triage.json`: one normalized document containing every sample, grouped by
  PE, ELF, or other file type.
- `triage.md`: a summary table plus a focused high-risk section. Samples with a
  high-risk rule match or a suspicious import table are marked in red.

By default the command is file-scoped. It parses PE/ELF headers and import
tables, extracts ASCII and UTF-16LE strings, and evaluates capa rules whose
static scope is `file`. It does not disassemble functions, so it stays
practical for large daily batches.

Use `--deep` when you also need function, basic-block, and instruction-scope
rules. Deep mode invokes the vivisect backend for PE/ELF files and is
considerably slower.

## Quick start

```bash
capa triage ./samples -o ./triage-output
```

This writes:

| File | Purpose |
|---|---|
| `triage.json` | Complete normalized results, including headers, imports, strings, and rule matches |
| `triage.md` | Human-readable per-type summary and high-risk list |
| `triage.log` | Progress, per-file retries, and error details |
| `.capa-triage-state.json` | File fingerprints and prior successful results for incremental runs |

When capa is installed as a package without embedded rules, provide a rule
directory explicitly:

```bash
capa triage ./samples -r ./capa-rules -o ./triage-output
```

If no embedded or explicit rules are available, triage logs a warning and
continues with header, import, and string extraction only.

Run the full rule set, including function and instruction scope:

```bash
capa triage ./samples -r ./capa-rules -o ./triage-output --deep
```

## Incremental runs

The state file records the size and modification time of every successfully
processed file. A later run only analyzes new or changed files and reuses the
previous results for unchanged files. The generated JSON and Markdown reports
remain cumulative, so earlier results are not dropped.

If a file changes and analysis fails, the old successful state entry is
discarded and the file is retried on the next run. Failed files are never
considered complete.

The state is invalidated automatically when:

- a rule file is added, removed, or modified;
- the string length or string limit changes;
- high-risk namespace settings change.

Use `--force` to ignore fingerprints and reprocess everything:

```bash
capa triage ./samples -o ./triage-output --force
```

Use a custom state path when keeping reports outside the sample directory:

```bash
capa triage ./samples -o ./triage-output --state ./triage-output/state.json
```

## Retries and failures

Each file gets `--retries` additional attempts after the first failure. The
default is two retries with a 0.2 second delay:

```bash
capa triage ./samples -o ./triage-output --retries 4 --retry-delay 0.5
```

Failures do not stop the batch. They are written to `triage.md`, included in
`triage.json`, and logged with the exception type and message. Add
`--fail-on-error` to return a non-zero exit code when at least one file fails.

## Risk markers

A sample is marked high risk when either condition is true:

- a matched rule indicates high risk through `meta.severity`, `meta.risk`,
  known high-risk namespaces, or ATT&CK technique IDs;
- an imported API appears in the curated suspicious-import table, such as
  process injection, credential access, anti-analysis, network, or
  cryptography APIs.

High-risk entries use `"risk": {"level": "high", "highlight": true,
"color": "red"}` in JSON. The Markdown report uses a red `HIGH` marker and adds
a detailed reason list.

Add custom high-risk namespace prefixes if your rule set uses a different
convention:

```bash
capa triage ./samples -o ./triage-output \
  --high-risk-namespace custom/high-risk \
  --high-risk-namespace malware/family
```

## Options

| Option | Description |
|---|---|
| `INPUT_DIR` | Directory containing samples |
| `-o, --output-dir` | Report directory, default `triage-output` |
| `-r, --rules` | Rule file or directory; repeatable, defaults to embedded rules |
| `--no-rules` | Skip rule matching; still parse headers, imports, and strings |
| `--no-recursive` | Only scan files directly under `INPUT_DIR` |
| `--retries N` | Additional attempts after the first failure, default `2` |
| `--retry-delay SECONDS` | Delay between retries, default `0.2` |
| `--string-min-length N` | Minimum string length, default `4` |
| `--max-strings N` | Strings stored per sample, default `250`; `0` means unlimited |
| `--state PATH` | Incremental state file |
| `--log PATH` | Log file |
| `--force` | Reprocess unchanged files |
| `--deep` | Run full static rule matching with vivisect; slower |
| `--high-risk-namespace PREFIX` | Additional high-risk namespace prefix |
| `--fail-on-error` | Exit non-zero if any sample fails |
| `--debug` | Debug logging and tracebacks |
| `-q, --quiet` | Suppress progress messages on stderr |

## JSON layout

The top-level document contains:

- `run`: discovered, processed, skipped, succeeded, failed, and retry counts;
- `risk_summary`: high-risk, clean, and failed totals;
- `rules`: loaded rule count, paths, signature, and analysis scope;
- `groups`: `pe`, `elf`, and `other`, each with samples and counters;
- `failures`: the same failed records for convenient filtering.

Each successful sample contains `header`, `sections`, `segments`, `imports`,
`exports`, `strings`, `rules`, and `risk`. Import tables are grouped by library
and also expose a flat `suspicious` list for alerting.

