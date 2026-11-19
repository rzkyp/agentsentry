"""Command line interface for AgentSentry."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .report import render_json, render_markdown, render_rules_table, render_table, rule_to_dict
from .rules import RULES, SEVERITY_ORDER
from .scanner import scan

FAIL_ON_LEVELS = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "none": None,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentsentry",
        description="AgentSentry — security scanner for MCP servers and AI agent skills.",
    )
    parser.add_argument("--version", action="version", version=f"agentsentry {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan MCP configs and agent skills")
    p_scan.add_argument("path", nargs="?", default=".", help="file or directory to scan (default: cwd)")
    p_scan.add_argument("-f", "--format", choices=["table", "json", "markdown"], default="table")
    p_scan.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout")
    p_scan.add_argument(
        "--fail-on",
        choices=list(FAIL_ON_LEVELS),
        default="high",
        help="exit 1 when a finding at this severity or higher exists (default: high)",
    )
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

    result = scan(root)
    renderer = {"table": render_table, "json": render_json, "markdown": render_markdown}[args.format]
    output = renderer(result, no_color=args.no_color) if args.format == "table" else renderer(result)

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
