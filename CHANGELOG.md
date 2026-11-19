# Changelog

## 0.3.0

**Reporting**

- `--format sarif` — SARIF 2.1.0 output, ready for GitHub code scanning
- `--summary-only` — header, summary and per-rule table without the per-finding details
- `--max-rows N` — cap terminal table output
- "Files with the most findings" added to the summary
- `--baseline FILE` — acknowledge known findings (JSON report or `RULE_ID path [line]` text);
  baselined findings are excluded from counts and from the exit code
- `--lang id` summary now also reports the acknowledged count

**Rules**

- `NET-001` ignores documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`),
  link-local, and version-looking strings such as `Chrome/124.0.0.0`
- `INJ-001` requires an action verb after `you must (always|now|instead)`, so task wording
  like "you must now upgrade" is no longer flagged
- `EXEC-003` ignores bare `eval()` / `exec()` written as prose

**Discovery**

- `--exclude PATTERN` (repeatable, fnmatch) to skip vendor trees and caches
- Vendor/cache directories are skipped by default (`.venv`, `node_modules`, `.gradle`, …)
- JSON files larger than 64 KB are treated as data dumps, not MCP configs

## 0.2.0

- `--exclude`, `--lang`, and a plain-language summary section in every report
- False-positive filters: loopback/RFC1918 addresses, JSON-schema pointers, placeholder
  secrets (`your-api-key`, `DEMO_KEY`), and prose that quotes injection phrasing
- Prose rules restricted to text files, so JSON schemas are no longer scanned as skill text

## 0.1.0

- Initial release: 23 detection rules, MCP config and agent-skill discovery,
  table/JSON/Markdown output, CI-friendly exit codes
