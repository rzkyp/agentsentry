"""Output formatters: terminal table, JSON and Markdown reports."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .rules import RULES, SEVERITY_ORDER

SCHEMA = "agentsentry/report/1"

ANSI = {
    "CRITICAL": "\033[1;91m",
    "HIGH": "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW": "\033[96m",
    "INFO": "\033[90m",
    "reset": "\033[0m",
}


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def summary_line(result) -> str:
    c = result.counts
    return (
        f"CRITICAL {c['CRITICAL']} | HIGH {c['HIGH']} | MEDIUM {c['MEDIUM']} | "
        f"LOW {c['LOW']} | INFO {c['INFO']}"
    )


# ------------------------------------------------------------------ summary

_SUMMARY = {
    "en": {
        "title": "## Summary",
        "scanned": "Scanned {files} file(s): {mcp} MCP config(s) and {skills} agent skill dir(s).",
        "found": "Found {total} issue(s): {line}.",
        "clean": "No findings. The target is clean for the patterns AgentSentry watches.",
        "top": "Most frequent rules: {rules}.",
        "priority": "Review CRITICAL and HIGH first; MEDIUM and LOW are hygiene items.",
        "fp": "Rules match text patterns, so documentation and prose can trigger them. "
              "Open the cited line before acting.",
    },
    "id": {
        "title": "## Ringkasan",
        "scanned": "Memindai {files} file: {mcp} MCP config dan {skills} dir agent skill.",
        "found": "Ditemukan {total} temuan: {line}.",
        "clean": "Tidak ada temuan. Target bersih untuk pola yang dipantau AgentSentry.",
        "top": "Aturan paling sering muncul: {rules}.",
        "priority": "Prioritaskan CRITICAL dan HIGH; MEDIUM dan LOW bersifat hygiene.",
        "fp": "Aturan berbasis pola teks, jadi dokumentasi/prose bisa ikut terdeteksi. "
              "Buka baris yang dikutip sebelum mengambil tindakan.",
    },
}


def summary_lines(result, lang: str = "en") -> list:
    t = _SUMMARY.get(lang, _SUMMARY["en"])
    c = result.counts
    total = len(result.findings)
    lines = [
        t["scanned"].format(files=result.files_scanned, mcp=result.mcp_configs, skills=result.skill_dirs),
    ]
    if total:
        lines.append(t["found"].format(total=total, line=summary_line(result)))
        top = ", ".join(f"`{rule_id}` ({hits})" for rule_id, hits in result.top_rules(3))
        lines.append(t["top"].format(rules=top))
        lines.append(t["priority"])
    else:
        lines.append(t["clean"])
    lines.append(t["fp"])
    return lines


# ------------------------------------------------------------------- JSON

def render_json(result, lang: str = "en") -> str:
    payload = {
        "schema": SCHEMA,
        "generated_at": _ts(),
        "target": result.root,
        "summary": {
            "files_scanned": result.files_scanned,
            "mcp_configs": result.mcp_configs,
            "skill_dirs": result.skill_dirs,
            "findings": len(result.findings),
            "by_severity": result.counts,
            "top_rules": [
                {"rule_id": rule_id, "hits": hits} for rule_id, hits in result.top_rules(5)
            ],
            "notes": summary_lines(result, lang),
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "title": f.title,
                "file": f.path,
                "line": f.line,
                "snippet": f.snippet,
                "message": f.message,
                "remediation": f.remediation,
            }
            for f in result.sorted_findings()
        ],
        "errors": result.errors,
    }
    return json.dumps(payload, indent=2)


# --------------------------------------------------------------- Markdown

def render_markdown(result, lang: str = "en") -> str:
    t = _SUMMARY.get(lang, _SUMMARY["en"])
    lines = [
        "# AgentSentry scan report",
        "",
        f"- **Target:** `{result.root}`",
        f"- **Generated:** {_ts()}Z",
        f"- **Files scanned:** {result.files_scanned} "
        f"({result.mcp_configs} MCP config(s), {result.skill_dirs} skill dir(s))",
        f"- **Findings:** {len(result.findings)} — {summary_line(result)}",
        "",
        t["title"],
        "",
    ]
    lines += [f"- {line}" for line in summary_lines(result, lang)]
    lines += [
        "",
        "## Findings by rule",
        "",
        "| Rule | Severity | Title | Hits |",
        "|---|---|---|---|",
    ]

    by_rule = {}
    for f in result.findings:
        entry = by_rule.setdefault(f.rule_id, {"severity": f.severity, "title": f.title, "hits": 0})
        entry["hits"] += 1
    for rule_id in sorted(by_rule, key=lambda r: (SEVERITY_ORDER.get(by_rule[r]["severity"], 9), r)):
        info = by_rule[rule_id]
        lines.append(f"| `{rule_id}` | {info['severity']} | {info['title']} | {info['hits']} |")

    lines += ["", "## Details", ""]
    if not result.findings:
        lines.append("_No findings._")
    current = None
    for f in result.sorted_findings():
        if f.path != current:
            current = f.path
            lines += [f"### `{current}`", ""]
        lines += [
            f"**[{f.severity}] `{f.rule_id}` — {f.title}** (line {f.line})",
            "",
            f"> {f.snippet}",
            "",
            f"- {f.message}",
            f"- **Fix:** {f.remediation}",
            "",
        ]

    if result.errors:
        lines += ["## Errors", ""]
        lines += [f"- `{e}`" for e in result.errors]

    return "\n".join(lines)


# ------------------------------------------------------------------ table

def render_table(result, no_color: bool = False, lang: str = "en") -> str:
    lines = [
        f"AgentSentry — {result.root}",
        f"Files: {result.files_scanned} | MCP configs: {result.mcp_configs} | Skill dirs: {result.skill_dirs}",
        f"Findings: {len(result.findings)}  ({summary_line(result)})",
        "",
    ]
    if not result.findings:
        lines.append("No findings.")
        return "\n".join(lines)

    header = f"{'RULE':<10} {'SEVERITY':<9} {'LOCATION':<42} SNIPPET"
    lines += [header, "-" * len(header)]
    for f in result.sorted_findings():
        severity = f"{f.severity:<9}"
        if not no_color:
            severity = ANSI.get(f.severity, "") + severity + ANSI["reset"]
        location = f"{f.path}:{f.line}"
        if len(location) > 40:
            location = "..." + location[-37:]
        snippet = f.snippet.replace("\n", " ")[:60]
        lines.append(f"{f.rule_id:<10} {severity} {location:<42} {snippet}")
    lines += ["", _SUMMARY.get(lang, _SUMMARY["en"])["fp"]]
    return "\n".join(lines)


def render_rules_table() -> str:
    lines = [f"{'RULE':<10} {'SEVERITY':<9} {'SCOPES':<12} TITLE", "-" * 70]
    for rule in RULES:
        scopes = ",".join(rule.scopes)
        lines.append(f"{rule.id:<10} {rule.severity:<9} {scopes:<12} {rule.title}")
    return "\n".join(lines)


def rule_to_dict(rule) -> dict:
    return {
        "id": rule.id,
        "title": rule.title,
        "severity": rule.severity,
        "scopes": list(rule.scopes),
        "description": rule.description,
        "remediation": rule.remediation,
        "pattern": rule.pattern.pattern,
    }
