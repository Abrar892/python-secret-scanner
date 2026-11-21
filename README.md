# SecretScan

A fast, zero-dependency CLI that scans a file or a source tree for leaked
secrets — API keys, tokens, private keys and credentials embedded in URLs —
before they reach a commit.

```bash
pip install -e .
secretscan scan .
```

## Why this exists

Secrets leak into repositories through copy-pasted config, debug prints and
`.env` files that were never meant to be committed. Once pushed, a key is
compromised even if it is deleted in the next commit — git history keeps it
forever. SecretScan is the cheap check you run in CI or as a pre-commit hook
so the leak never lands.

## How detection works

Two complementary detectors, applied line by line:

1. **Provider rules** — 17 curated patterns anchored to the real shape of
   each credential: AWS access/secret keys, GitHub PATs and OAuth tokens,
   Slack tokens and webhooks, Stripe live keys, SendGrid, Twilio, npm and
   PyPI tokens, Google API keys, JWTs, private-key blocks, hardcoded
   password / API-key assignments, and credentials embedded in URLs.
   Patterns are written to reject placeholders (`"your-api-key-here"`,
   `"changeme"`, env-var lookups) instead of crying wolf.
2. **Entropy detector** — quoted strings of 20+ characters with Shannon
   entropy ≥ 4.5 and a mixed alphabet are flagged as `high-entropy-string`
   (low severity). This catches tokens from providers with no known prefix.

Overlapping matches are deduplicated by span, so one secret is reported
once even when two rules could match it.

## Design decisions

- **Zero runtime dependencies.** The whole scanner is stdlib Python
  (`re`, `hashlib`, `concurrent.futures`), so it installs anywhere and
  never breaks on a dependency update.
- **Redaction by default.** Reports show only the first and last four
  characters of a secret (`AKIA***MPLE`). Pass `--show-secrets` only when
  you need the full value locally — CI logs should never contain a live key.
- **Baselines, not whack-a-mole.** Known findings can be recorded with
  `--update-baseline`; later runs suppress exactly those fingerprints
  (path + rule + value), while any *new* secret still fails the build.
- **Thread-pool scanning.** Files are scanned concurrently with a bounded
  worker pool; the default of 4 workers keeps large trees fast without
  thrashing small machines.
- **Inline suppression is explicit.** A line is skipped only with
  `# secretscan:ignore` (or `# secretscan:ignore-next-line` above it),
  so suppressions stay visible in code review.

## Usage

```bash
# Scan the current directory (exit 1 if any secret is found)
secretscan scan .

# Scan one file, machine-readable output
secretscan scan config.py --json

# Only fail the build on high-severity findings
secretscan scan . --fail-on high

# Ignore extra paths, tune the entropy detector, print full secrets
secretscan scan . --exclude "fixtures/*" --min-entropy 5.0 --show-secrets

# Record today's findings as known, then fail only on new ones
secretscan scan . --baseline baseline.json --update-baseline
secretscan scan . --baseline baseline.json

# List the built-in rules
secretscan rules
```

### Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | No findings at or above `--fail-on` |
| 1 | Findings at or above `--fail-on` |
| 2 | Usage error (missing path, bad baseline, bad flag) |

### Ignoring files

SecretScan skips binary files, files over 1 MiB (`--max-file-size`), and
common build/cache directories (`.git`, `node_modules`, `__pycache__`,
`dist`, `target`, …). Add project-specific ignores in a
`.secretscanignore` file at the scan root (gitignore-style globs, one per
line) or with repeatable `--exclude` flags.

## Example output

```
HIGH (1)
--------
src/config.py:12:11 [aws-access-key] AWS Access Key ID — AKIA***MPLE

scanned 42 file(s), skipped 3, 1 finding(s)
```

## Running tests

```bash
python -m pytest
```

68 tests cover every rule (positive examples and near-miss negatives),
the entropy maths, the scanner engine (ignores, baselines, redaction,
deduplication) and the CLI exit-code contract end to end.

## Tech stack

- Python 3.9+ (stdlib only)
- pytest for tests
