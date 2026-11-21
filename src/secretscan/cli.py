"""Command-line interface for SecretScan.

Exit codes (CI-friendly):
    0  no findings at or above the failure threshold
    1  findings at or above the failure threshold
    2  usage error (bad path, unreadable baseline, bad flag value)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .report import findings_to_json, render_text
from .rules import builtin_rules
from .scanner import Scanner, load_baseline, save_baseline

SEVERITIES = ("low", "medium", "high")


def _severity_at_least(severity: str, threshold: str) -> bool:
    return SEVERITIES.index(severity) >= SEVERITIES.index(threshold)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secretscan",
        description="Scan a file or directory tree for leaked secrets.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a file or directory for secrets")
    scan.add_argument("path", type=Path, help="file or directory to scan")
    scan.add_argument("--json", action="store_true", help="emit JSON instead of text")
    scan.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default="low",
        help="lowest severity that fails the run (default: low)",
    )
    scan.add_argument(
        "--min-entropy",
        type=float,
        default=4.5,
        help="Shannon entropy threshold for the generic detector (default: 4.5)",
    )
    scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="additional ignore glob (repeatable); also read from .secretscanignore",
    )
    scan.add_argument(
        "--max-file-size",
        type=int,
        default=1,
        metavar="MB",
        help="skip files larger than this many MiB (default: 1)",
    )
    scan.add_argument(
        "--workers",
        type=int,
        default=4,
        help="parallel scan workers (default: 4)",
    )
    scan.add_argument(
        "--show-secrets",
        action="store_true",
        help="print matched secrets in full (default: redacted)",
    )
    scan.add_argument(
        "--baseline",
        type=Path,
        default=None,
        metavar="FILE",
        help="JSON baseline of known fingerprints to suppress",
    )
    scan.add_argument(
        "--update-baseline",
        action="store_true",
        help="write current findings as the baseline and exit 0",
    )
    scan.add_argument(
        "--quiet",
        action="store_true",
        help="only print the summary line (or nothing with --json)",
    )

    rules = sub.add_parser("rules", help="list the built-in detection rules")
    rules.add_argument("--json", action="store_true", help="emit JSON instead of text")
    return parser


def _cmd_scan(args: argparse.Namespace) -> int:
    if not args.path.exists():
        print(f"secretscan: no such file or directory: {args.path}", file=sys.stderr)
        return 2
    if not 0.0 <= args.min_entropy <= 8.0:
        print("secretscan: --min-entropy must be between 0 and 8", file=sys.stderr)
        return 2

    baseline: set[str] = set()
    if args.baseline is not None:
        try:
            baseline = load_baseline(args.baseline)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"secretscan: cannot read baseline: {exc}", file=sys.stderr)
            return 2

    scanner = Scanner(
        min_entropy=args.min_entropy,
        max_file_size=args.max_file_size * 1_048_576,
        exclude=args.exclude,
        workers=args.workers,
    )
    result = scanner.scan_path(args.path)

    new_findings = [f for f in result.findings if f.fingerprint not in baseline]

    if args.update_baseline:
        if args.baseline is None:
            print("secretscan: --update-baseline needs --baseline FILE", file=sys.stderr)
            return 2
        save_baseline(args.baseline, result.findings)
        if not args.quiet:
            print(f"baseline updated: {len(result.findings)} finding(s) recorded in {args.baseline}")
        return 0

    failing = [f for f in new_findings if _severity_at_least(f.severity, args.fail_on)]

    if args.json:
        print(findings_to_json(new_findings, show_secrets=args.show_secrets), end="")
    elif new_findings and not args.quiet:
        print(render_text(_result_with(new_findings, result), show_secrets=args.show_secrets), end="")
        print(
            f"scanned {result.files_scanned} file(s), "
            f"skipped {result.files_skipped}, "
            f"{len(new_findings)} finding(s)"
        )
    elif not args.quiet:
        print(
            f"no secrets found — scanned {result.files_scanned} file(s), "
            f"skipped {result.files_skipped}"
        )
    return 1 if failing else 0


def _result_with(findings: list, result) -> "ScanResult":
    from .scanner import ScanResult

    return ScanResult(
        findings=findings,
        files_scanned=result.files_scanned,
        files_skipped=result.files_skipped,
        skipped_reasons=result.skipped_reasons,
    )


def _cmd_rules(args: argparse.Namespace) -> int:
    rules = builtin_rules()
    if args.json:
        import json as _json

        payload = [
            {
                "id": r.id,
                "name": r.name,
                "severity": r.severity,
                "description": r.description,
            }
            for r in rules
        ]
        print(_json.dumps(payload, indent=2))
    else:
        for rule in rules:
            print(f"{rule.id:<22} {rule.severity:<6} {rule.name}")
            print(f"{'':<22} {rule.description}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "rules":
        return _cmd_rules(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
