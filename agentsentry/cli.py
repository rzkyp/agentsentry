"""Command line interface for AgentSentry."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .report import (
    render_json,
    render_markdown,
    render_rules_table,
    render_sarif,
    render_table,
    rule_to_dict,
)
from .rules import RULES, RULES_BY_ID, SEVERITY_ORDER
from .scanner import load_baseline, scan

FAIL_ON_LEVELS = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "none": None,
}


def _csv(value: str) -> list:
    return [item.strip() for item in value.split(",") if item.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentsentry",
        description="AgentSentry — security scanner for MCP servers and AI agent skills.",
    )
    parser.add_argument("--version", action="version", version=f"agentsentry {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan MCP configs and agent skills")
    p_scan.add_argument("path", nargs="?", default=".", help="file or directory to scan (default: cwd)")
    p_scan.add_argument(
        "-f", "--format",
        choices=["table", "json", "markdown", "sarif"],
        default="table",
        help="output format (sarif feeds GitHub code scanning)",
    )
    p_scan.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout")
    p_scan.add_argument(
        "--fail-on",
        choices=list(FAIL_ON_LEVELS),
        default="high",
        help="exit 1 when a finding at this severity or higher exists (default: high)",
    )
    p_scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="skip paths matching this fnmatch pattern (repeatable, e.g. --exclude '*/cache/*')",
    )
    p_scan.add_argument("--lang", choices=["en", "id"], default="en", help="language of the report summary")
    p_scan.add_argument("--rules", metavar="IDS", help="comma-separated rule ids to run (default: all)")
    p_scan.add_argument("--skip-rules", metavar="IDS", help="comma-separated rule ids to skip")
    p_scan.add_argument(
        "--baseline",
        metavar="FILE",
        help="JSON report or text list of known findings to acknowledge (rule_id path [line])",
    )
    p_scan.add_argument("--summary-only", action="store_true", help="omit per-finding details")
    p_scan.add_argument("--max-rows", type=int, default=0, metavar="N", help="table output limit (0 = all)")
    p_scan.add_argument("--no-color", action="store_true")
    p_scan.add_argument("--quiet", action="store_true", help="suppress report output (useful with --output)")

    p_rules = sub.add_parser("rules", help="list all detection rules")
    p_rules.add_argument("--json", action="store_true", help="output rules as JSON")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "rules":
        if args.json:
            print(json.dumps([rule_to_dict(rule) for rule in RULES], indent=2))
        else:
            print(render_rules_table())
        return 0

    root = Path(args.path).expanduser()
    if not root.exists():
        parser.error(f"path does not exist: {args.path}")

    selected = _csv(args.rules) if args.rules else None
    if selected:
        unknown = [r for r in selected if r not in RULES_BY_ID]
        if unknown:
            parser.error(f"unknown rule id(s): {', '.join(unknown)}")
    if args.skip_rules:
        skipped = set(_csv(args.skip_rules))
        unknown = [r for r in skipped if r not in RULES_BY_ID]
        if unknown:
            parser.error(f"unknown rule id(s): {', '.join(unknown)}")
        selected = selected or [rule.id for rule in RULES]
        selected = [r for r in selected if r not in skipped]

    baseline = None
    if args.baseline:
        try:
            baseline = load_baseline(Path(args.baseline).expanduser())
        except (OSError, ValueError) as exc:
            parser.error(f"cannot read baseline {args.baseline}: {exc}")

    result = scan(root, excludes=args.exclude, rules=selected, baseline=baseline)

    if args.format == "sarif":
        output = render_sarif(result)
    elif args.format == "json":
        output = render_json(result, lang=args.lang, summary_only=args.summary_only)
    elif args.format == "markdown":
        output = render_markdown(result, lang=args.lang, summary_only=args.summary_only)
    else:
        output = render_table(result, no_color=args.no_color, lang=args.lang, max_rows=args.max_rows)

    if args.output:
        out = Path(args.output).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(output + "\n", encoding="utf-8")
        if not args.quiet:
            print(f"Report written to {out} — {len(result.findings)} finding(s).", file=sys.stderr)
    elif not args.quiet:
        print(output)

    threshold = FAIL_ON_LEVELS[args.fail_on]
    if threshold is None:
        return 0
    for finding in result.findings:
        if SEVERITY_ORDER.get(finding.severity, 9) <= SEVERITY_ORDER[threshold]:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
