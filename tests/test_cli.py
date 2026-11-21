"""CLI tests: exit codes, output formats, baseline flow."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_" + "a" * 36

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"


def run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    env = {"PYTHONPATH": str(SRC_DIR), "PATH": "/usr/bin:/bin"}
    return subprocess.run(
        [sys.executable, "-m", "secretscan.cli", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        env=env,
    )


@pytest.fixture()
def dirty_tree(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(f'aws_key = "{AWS_KEY}"\n', encoding="utf-8")
    (tmp_path / "clean.py").write_text('print("ok")\n', encoding="utf-8")
    return tmp_path


def test_scan_dirty_tree_exits_1(dirty_tree):
    result = run_cli("scan", ".", cwd=dirty_tree)
    assert result.returncode == 1
    assert "aws-access-key" in result.stdout
    assert AWS_KEY not in result.stdout  # redacted by default


def test_scan_clean_tree_exits_0(tmp_path):
    (tmp_path / "clean.py").write_text('print("ok")\n', encoding="utf-8")
    result = run_cli("scan", ".", cwd=tmp_path)
    assert result.returncode == 0
    assert "no secrets found" in result.stdout


def test_fail_on_threshold(tmp_path):
    # Only a low-severity entropy finding: --fail-on high must pass.
    (tmp_path / "cfg.py").write_text('token = "Xk9mQ2vL8pR4tY6wN3bV7cD1fH5jK"\n', encoding="utf-8")
    low = run_cli("scan", ".", "--fail-on", "low", cwd=tmp_path)
    assert low.returncode == 1
    high = run_cli("scan", ".", "--fail-on", "high", cwd=tmp_path)
    assert high.returncode == 0


def test_json_output_is_valid(dirty_tree):
    result = run_cli("scan", ".", "--json", cwd=dirty_tree)
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert len(payload) == 1
    assert payload[0]["rule_id"] == "aws-access-key"
    assert payload[0]["severity"] == "high"
    assert payload[0]["value"] != AWS_KEY  # redacted


def test_show_secrets_reveals_value(dirty_tree):
    result = run_cli("scan", ".", "--show-secrets", cwd=dirty_tree)
    assert AWS_KEY in result.stdout


def test_missing_path_exits_2(tmp_path):
    result = run_cli("scan", "does-not-exist", cwd=tmp_path)
    assert result.returncode == 2


def test_baseline_suppresses_known_findings(dirty_tree):
    baseline = dirty_tree / "baseline.json"
    update = run_cli("scan", ".", "--baseline", "baseline.json", "--update-baseline", cwd=dirty_tree)
    assert update.returncode == 0
    assert baseline.is_file()
    rerun = run_cli("scan", ".", "--baseline", "baseline.json", cwd=dirty_tree)
    assert rerun.returncode == 0
    assert "no secrets found" in rerun.stdout


def test_baseline_does_not_suppress_new_findings(dirty_tree):
    baseline = dirty_tree / "baseline.json"
    run_cli("scan", ".", "--baseline", "baseline.json", "--update-baseline", cwd=dirty_tree)
    (dirty_tree / "more.py").write_text(f'token = "{GITHUB_TOKEN}"\n', encoding="utf-8")
    result = run_cli("scan", ".", "--baseline", "baseline.json", cwd=dirty_tree)
    assert result.returncode == 1
    assert "github-pat" in result.stdout


def test_rules_command_lists_rules(tmp_path):
    result = run_cli("rules", cwd=tmp_path)
    assert result.returncode == 0
    assert "aws-access-key" in result.stdout
    assert "github-pat" in result.stdout


def test_rules_json_is_valid(tmp_path):
    result = run_cli("rules", "--json", cwd=tmp_path)
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert any(r["id"] == "aws-access-key" for r in payload)
