"""Scanner engine tests: files, trees, ignores, baselines, redaction."""

from pathlib import Path

import pytest

from secretscan.scanner import Finding, Scanner, load_baseline, save_baseline

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_" + "a" * 36


@pytest.fixture()
def scanner():
    return Scanner(workers=1)


def write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_detects_aws_key_in_file(tmp_path, scanner):
    path = write(tmp_path, "config.py", f'aws_key = "{AWS_KEY}"\n')
    findings = scanner.scan_file(path)
    assert len(findings) == 1
    assert findings[0].rule_id == "aws-access-key"
    assert findings[0].severity == "high"
    assert findings[0].line == 1
    assert findings[0].matched == AWS_KEY


def test_clean_file_has_no_findings(tmp_path, scanner):
    path = write(tmp_path, "clean.py", 'print("hello world")\n')
    assert scanner.scan_file(path) == []


def test_inline_ignore_suppresses_line(tmp_path, scanner):
    path = write(
        tmp_path, "app.py",
        f'key = "{AWS_KEY}"  # secretscan:ignore\n',
    )
    assert scanner.scan_file(path) == []


def test_ignore_next_line_marker(tmp_path, scanner):
    path = write(
        tmp_path, "app.py",
        f"# secretscan:ignore-next-line\nkey = \"{AWS_KEY}\"\n",
    )
    assert scanner.scan_file(path) == []


def test_binary_file_skipped(tmp_path, scanner):
    path = tmp_path / "blob.bin"
    path.write_bytes(b"\x00\x01\x02" + AWS_KEY.encode() + b"\x00")
    assert scanner.scan_file(path) == []


def test_overlapping_rules_deduplicated(tmp_path, scanner):
    # gho_ matches both the GitHub PAT and OAuth patterns; report it once.
    path = write(tmp_path, "token.txt", "gho_" + "b" * 36 + "\n")
    findings = scanner.scan_file(path)
    assert len(findings) == 1
    assert findings[0].rule_id in {"github-pat", "github-oauth"}


def test_entropy_finding_is_low_severity(tmp_path, scanner):
    path = write(tmp_path, "cfg.py", 'token = "Xk9mQ2vL8pR4tY6wN3bV7cD1fH5jK"\n')
    findings = scanner.scan_file(path)
    assert len(findings) == 1
    assert findings[0].rule_id == "high-entropy-string"
    assert findings[0].severity == "low"


def test_tree_scan_skips_git_and_node_modules(tmp_path, scanner):
    write(tmp_path, ".git/config", f'key = "{AWS_KEY}"\n')
    write(tmp_path, "node_modules/dep/index.js", f'key = "{AWS_KEY}"\n')
    write(tmp_path, "src/app.py", 'print("clean")\n')
    write(tmp_path, "src/keys.py", f'token = "{GITHUB_TOKEN}"\n')
    result = scanner.scan_path(tmp_path)
    assert result.files_scanned == 2
    assert result.files_skipped == 0  # ignored dirs are pruned, not counted
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "github-pat"


def test_secretscanignore_file(tmp_path, scanner):
    write(tmp_path, ".secretscanignore", "fixtures/*\n")
    write(tmp_path, "fixtures/dump.txt", f'key = "{AWS_KEY}"\n')
    write(tmp_path, "real.py", f'key = "{AWS_KEY}"\n')
    result = scanner.scan_path(tmp_path)
    assert len(result.findings) == 1
    assert result.findings[0].path == "real.py"


def test_exclude_glob(tmp_path):
    write(tmp_path, "legacy.py", f'key = "{AWS_KEY}"\n')
    write(tmp_path, "new.py", f'key = "{AWS_KEY}"\n')
    result = Scanner(exclude=["legacy.py"], workers=1).scan_path(tmp_path)
    assert len(result.findings) == 1
    assert result.findings[0].path == "new.py"


def test_oversize_file_skipped(tmp_path):
    write(tmp_path, "big.txt", f'key = "{AWS_KEY}"\n' + "x" * 100)
    result = Scanner(max_file_size=10, workers=1).scan_path(tmp_path)
    assert result.files_scanned == 0
    assert result.findings == []
    assert result.skipped_reasons.get("oversize") == 1


def test_redaction_masks_middle():
    finding = Finding("a.py", 1, 0, "aws-access-key", "AWS", "high", AWS_KEY)
    redacted = finding.redacted()
    assert redacted.startswith("AKIA")
    assert redacted.endswith("MPLE")
    assert AWS_KEY not in redacted
    assert finding.display_value(show_secrets=True) == AWS_KEY


def test_fingerprint_stable_and_distinct():
    a = Finding("a.py", 1, 0, "aws-access-key", "AWS", "high", AWS_KEY)
    b = Finding("a.py", 2, 0, "aws-access-key", "AWS", "high", AWS_KEY)
    c = Finding("a.py", 1, 0, "aws-access-key", "AWS", "high", "AKIAIOSFODNN7EXAMPLX")
    assert a.fingerprint == b.fingerprint  # line number is not part of identity
    assert a.fingerprint != c.fingerprint


def test_baseline_roundtrip(tmp_path, scanner):
    path = write(tmp_path, "keys.py", f'key = "{AWS_KEY}"\n')
    findings = scanner.scan_file(path)
    baseline_file = tmp_path / "baseline.json"
    save_baseline(baseline_file, findings)
    loaded = load_baseline(baseline_file)
    assert findings[0].fingerprint in loaded
    assert load_baseline(tmp_path / "missing.json") == set()


def test_private_key_block_detected(tmp_path, scanner):
    path = write(tmp_path, "key.pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n")
    findings = scanner.scan_file(path)
    assert len(findings) == 1
    assert findings[0].rule_id == "private-key"


def test_url_credentials_detected(tmp_path, scanner):
    path = write(tmp_path, "db.conf", "postgres://user:hunter2hunter@db.example.com/mydb\n")
    findings = scanner.scan_file(path)
    assert len(findings) == 1
    assert findings[0].rule_id == "basic-auth-url"
