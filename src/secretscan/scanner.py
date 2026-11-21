"""Core scanning engine.

Walks a file or a directory tree, applies the built-in rules plus the
entropy detector to every text line, and returns structured findings.
Binary files, oversized files, ignored paths and inline-suppressed lines
are skipped and counted, never silently dropped: the caller reports them.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from . import entropy as entropy_mod
from .rules import Rule, builtin_rules

DEFAULT_IGNORE_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", ".tox",
        "node_modules", "dist", "build", "target", ".idea", ".vscode",
        ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages",
    }
)

# Extensions that are (almost) never worth scanning as text.
BINARY_EXTENSIONS = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".pdf", ".zip",
        ".tar", ".gz", ".xz", ".7z", ".rar", ".exe", ".dll", ".so",
        ".dylib", ".bin", ".dat", ".woff", ".woff2", ".ttf", ".otf",
        ".mp3", ".mp4", ".mov", ".avi", ".sqlite", ".db", ".pyc",
        ".pyo", ".class", ".jar", ".war", ".parquet", ".feather",
    }
)

INLINE_IGNORE_MARKERS = ("secretscan:ignore", "nosec", "noqa: secretscan")
NEXT_LINE_IGNORE = "secretscan:ignore-next-line"


@dataclass(frozen=True)
class Finding:
    """One detected secret."""

    path: str  # path as given on the command line, or relative to scan root
    line: int  # 1-based
    column: int  # 0-based, of the match start
    rule_id: str
    rule_name: str
    severity: str  # "high" | "medium" | "low"
    matched: str  # the raw secret (never printed unless --show-secrets)
    entropy: float | None = None

    @property
    def fingerprint(self) -> str:
        """Stable identity for baselines: path + rule + secret value."""
        digest = hashlib.sha256(
            f"{self.path}\0{self.rule_id}\0{self.matched}".encode("utf-8", "replace")
        ).hexdigest()
        return digest[:16]

    def redacted(self) -> str:
        """The secret with its middle masked: first 4 + *** + last 4."""
        value = self.matched
        if len(value) <= 8:
            return "*" * len(value)
        return f"{value[:4]}***{value[-4:]}"

    def display_value(self, show_secrets: bool = False) -> str:
        return self.matched if show_secrets else self.redacted()


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    skipped_reasons: dict[str, int] = field(default_factory=dict)

    @property
    def by_severity(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = {"high": [], "medium": [], "low": []}
        for finding in self.findings:
            grouped.setdefault(finding.severity, []).append(finding)
        return grouped

    def worst_severity(self) -> str | None:
        for severity in ("high", "medium", "low"):
            if self.by_severity.get(severity):
                return severity
        return None


def _is_binary(sample: bytes) -> bool:
    """NUL byte in the first 8 KiB is the classic binary sniff test."""
    return b"\x00" in sample[:8192]


def _line_is_suppressed(lines: list[str], index: int) -> bool:
    """True when line *index* carries an inline ignore marker, or the
    previous line carries an ignore-next-line marker."""
    line = lines[index]
    if any(marker in line for marker in INLINE_IGNORE_MARKERS):
        return True
    if index > 0 and NEXT_LINE_IGNORE in lines[index - 1]:
        return True
    return False


class Scanner:
    """Configurable scanner over files and directory trees."""

    def __init__(
        self,
        rules: list[Rule] | None = None,
        *,
        min_entropy: float = 4.5,
        max_file_size: int = 1_048_576,  # 1 MiB
        exclude: list[str] | None = None,
        workers: int = 4,
        follow_symlinks: bool = False,
    ) -> None:
        self.rules = rules if rules is not None else builtin_rules()
        self.min_entropy = min_entropy
        self.max_file_size = max_file_size
        self.exclude = list(exclude or [])
        self.workers = max(1, workers)
        self.follow_symlinks = follow_symlinks

    # -- ignore handling -------------------------------------------------

    def _load_ignore_file(self, root: Path) -> list[str]:
        patterns = list(self.exclude)
        ignore_file = root / ".secretscanignore"
        if ignore_file.is_file():
            for raw in ignore_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
        return patterns

    @staticmethod
    def _matches_any(patterns: list[str], rel_path: str) -> bool:
        for pattern in patterns:
            if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(
                rel_path, pattern.rstrip("/") + "/**"
            ):
                return True
            # Match any path segment, e.g. "*.min.js" or "vendor/*".
            if any(fnmatch.fnmatch(part, pattern) for part in rel_path.split("/")):
                return True
        return False

    # -- per-file scanning ----------------------------------------------

    def scan_file(self, path: Path, display_path: str | None = None) -> list[Finding]:
        """Scan one file; returns its findings (empty for clean files)."""
        display = display_path or str(path)
        try:
            raw = path.read_bytes()
        except OSError:
            return []
        if len(raw) > self.max_file_size:
            return []
        if _is_binary(raw):
            return []
        text = raw.decode("utf-8", errors="replace")
        lines = text.splitlines()
        findings: list[Finding] = []
        for index, line in enumerate(lines):
            if _line_is_suppressed(lines, index):
                continue
            findings.extend(self._scan_line(line, index + 1, display))
        return findings

    def _scan_line(self, line: str, line_no: int, display: str) -> list[Finding]:
        findings: list[Finding] = []
        covered: list[tuple[int, int]] = []  # spans already claimed by a rule

        def overlaps(start: int, end: int) -> bool:
            return any(start < c_end and end > c_start for c_start, c_end in covered)

        for rule in self.rules:
            for match in rule.pattern.finditer(line):
                start, end = match.span(1) if match.lastindex else match.span()
                if overlaps(start, end):
                    continue
                covered.append((start, end))
                secret = match.group(1) if match.lastindex else match.group(0)
                findings.append(
                    Finding(
                        path=display,
                        line=line_no,
                        column=start,
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        matched=secret,
                    )
                )

        # Generic entropy detector, skipping spans a rule already claimed.
        for column, value, score in entropy_mod.high_entropy_strings(line, self.min_entropy):
            start = column + 1  # skip the opening quote
            if overlaps(start, start + len(value)):
                continue
            covered.append((start, start + len(value)))
            findings.append(
                Finding(
                    path=display,
                    line=line_no,
                    column=start,
                    rule_id="high-entropy-string",
                    rule_name="High-Entropy String",
                    severity="low",
                    matched=value,
                    entropy=round(score, 2),
                )
            )
        return findings

    # -- tree scanning ----------------------------------------------------

    def scan_path(self, target: Path) -> ScanResult:
        """Scan a file or a whole directory tree rooted at *target*."""
        result = ScanResult()
        if target.is_file():
            result.files_scanned = 1
            result.findings = self.scan_file(target)
            return result

        patterns = self._load_ignore_file(target)
        candidates: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(target, followlinks=self.follow_symlinks):
            dirnames[:] = [d for d in dirnames if d not in DEFAULT_IGNORE_DIRS]
            root = Path(dirpath)
            for name in filenames:
                file_path = root / name
                rel = str(file_path.relative_to(target))
                if self._matches_any(patterns, rel):
                    result.files_skipped += 1
                    result.skipped_reasons["ignored"] = result.skipped_reasons.get("ignored", 0) + 1
                    continue
                if file_path.suffix.lower() in BINARY_EXTENSIONS:
                    result.files_skipped += 1
                    result.skipped_reasons["binary-extension"] = result.skipped_reasons.get("binary-extension", 0) + 1
                    continue
                candidates.append(file_path)

        def work(file_path: Path) -> tuple[Path, list[Finding], str | None]:
            try:
                size = file_path.stat().st_size
            except OSError:
                return file_path, [], "unreadable"
            if size > self.max_file_size:
                return file_path, [], "oversize"
            raw_head = file_path.read_bytes()[:8192] if size else b""
            if _is_binary(raw_head):
                return file_path, [], "binary-content"
            return file_path, self.scan_file(file_path, str(file_path.relative_to(target))), None

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            for file_path, findings, skip_reason in pool.map(work, candidates):
                if skip_reason is not None:
                    result.files_skipped += 1
                    result.skipped_reasons[skip_reason] = result.skipped_reasons.get(skip_reason, 0) + 1
                    continue
                result.files_scanned += 1
                result.findings.extend(findings)

        result.findings.sort(key=lambda f: (f.path, f.line, f.column))
        return result


# -- baselines ------------------------------------------------------------


def load_baseline(path: Path) -> set[str]:
    """Load a baseline file (JSON list of fingerprints); missing file = empty."""
    if not path.is_file():
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"baseline {path} must contain a JSON list of fingerprints")
    return set(data)


def save_baseline(path: Path, findings: list[Finding]) -> None:
    """Write fingerprints of *findings* as the new baseline."""
    fingerprints = sorted({f.fingerprint for f in findings})
    path.write_text(json.dumps(fingerprints, indent=2) + "\n", encoding="utf-8")
