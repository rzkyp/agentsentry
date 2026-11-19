"""Filesystem discovery and the scanning engine for AgentSentry.

The scanner finds two kinds of targets:

* **MCP configuration files** — ``.mcp.json``, ``mcp.json``, ``claude_desktop_config.json``,
  ``cline_mcp_settings.json`` and any small ``*.json`` containing an ``mcpServers`` key.
* **Agent skill directories** — every directory that contains a ``SKILL.md`` file, plus the
  scripts that sit next to it (``.py``, ``.sh``, ``.ps1``, ``.js``, ``.ts``, ``.md`` ...).

Vendor trees, caches and editor installs are skipped so scanning a home directory does not
produce a firehose of matches from application installs.
"""

from __future__ import annotations

import fnmatch
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .rules import RULES, RULES_BY_ID, SCOPE_MCP, SCOPE_SKILL, SEVERITY_ORDER

MCP_CONFIG_NAMES = {
    ".mcp.json",
    "mcp.json",
    "mcp_config.json",
    "claude_desktop_config.json",
    "cline_mcp_settings.json",
    "goose.json",
    "cursor_mcp.json",
    "windsurf_mcp.json",
    "mcp_servers.json",
}

SKILL_FILE_NAMES = {"skill.md"}

#: JSON files larger than this are data/spec dumps, not MCP configs.
MCP_JSON_MAX_BYTES = 64 * 1024

SKIP_DIRS = {
    # VCS / metadata
    ".git", ".hg", ".svn",
    # JS / TS
    "node_modules", "bower_components", ".npm", ".yarn", ".pnpm-store", ".parcel-cache",
    ".next", ".nuxt", ".svelte-kit", ".angular", ".turbo",
    # Python
    ".venv", "venv", "env", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "__pycache__", ".cache", ".pip",
    # JVM / .NET / Go / Rust
    ".gradle", ".m2", ".nuget", ".cargo", ".rustup", ".dartServer", ".pub-cache",
    # Ruby / Terraform / misc
    ".gem", ".bundle", ".terraform", ".serverless",
    # Editors / build output
    ".idea", "dist", "build", "out", "coverage", ".vscode-test",
}

SKILL_FILE_SUFFIXES = {
    ".md",
    ".markdown",
    ".txt",
    ".py",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".json",
    ".yaml",
    ".yml",
}

MAX_SNIPPET = 160


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    path: str
    line: int
    snippet: str
    message: str
    remediation: str


@dataclass
class ScanResult:
    root: str
    files_scanned: int = 0
    mcp_configs: int = 0
    skill_dirs: int = 0
    findings: list = field(default_factory=list)
    acknowledged: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    rules_used: list = field(default_factory=list)
    _seen: set = field(default_factory=set, repr=False)

    def add(self, finding: Finding, baseline) -> None:
        """Add a finding, de-duplicating on (rule, path, line).

        Findings present in *baseline* are kept on the result but moved to
        ``acknowledged`` so they do not affect counts or the exit code.
        """
        key = (finding.rule_id, finding.path, finding.line)
        if key in self._seen:
            return
        self._seen.add(key)
        if _in_baseline(finding, baseline):
            self.acknowledged.append(finding)
        else:
            self.findings.append(finding)

    @property
    def counts(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def sorted_findings(self) -> list:
        return sorted(
            self.findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.path, f.line, f.rule_id),
        )

    def top_rules(self, limit: int = 3) -> list:
        """``[(rule_id, hits), ...]`` ordered by severity, then hit count."""
        by_rule = {}
        for finding in self.findings:
            entry = by_rule.setdefault(finding.rule_id, {"severity": finding.severity, "hits": 0})
            entry["hits"] += 1
        return [
            (rule_id, info["hits"])
            for rule_id, info in sorted(
                by_rule.items(),
                key=lambda kv: (SEVERITY_ORDER.get(kv[1]["severity"], 9), -kv[1]["hits"], kv[0]),
            )
        ][:limit]

    def top_files(self, limit: int = 5) -> list:
        """``[(path, hits), ...]`` for the files with the most findings."""
        counts = {}
        for finding in self.findings:
            counts[finding.path] = counts.get(finding.path, 0) + 1
        return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]


def scan(root, excludes=(), rules=None, baseline=None) -> ScanResult:
    """Scan *root* (file or directory) and return a :class:`ScanResult`.

    *rules* — optional iterable of rule ids to run (default: every rule).
    *baseline* — optional ``(pairs, triples)`` set from :func:`load_baseline`.
    """
    root = Path(root)
    result = ScanResult(root=str(root))

    selected = RULES
    if rules:
        unknown = [r for r in rules if r not in RULES_BY_ID]
        if unknown:
            raise ValueError(f"unknown rule id(s): {', '.join(unknown)}")
        selected = [RULES_BY_ID[r] for r in rules]
    result.rules_used = [rule.id for rule in selected]

    targets, skill_dirs = discover_targets(root, excludes)
    result.skill_dirs = len(skill_dirs)

    for path, scope in targets:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            result.errors.append(f"{path}: {exc}")
            continue

        result.files_scanned += 1
        if scope == SCOPE_MCP:
            result.mcp_configs += 1

        rel = _relative(path, root)
        suffix = path.suffix.lower()
        lines = text.splitlines()

        for rule in selected:
            if not rule.matches_scope(scope):
                continue
            if not rule.matches_suffix(suffix):
                continue
            for match in rule.pattern.finditer(text):
                if rule.ignore is not None and rule.ignore(match.group(0), text[: match.start()]):
                    continue
                line_no = text.count("\n", 0, match.start()) + 1
                if 0 < line_no <= len(lines):
                    snippet = lines[line_no - 1].strip()
                else:
                    snippet = match.group(0)
                result.add(
                    Finding(
                        rule_id=rule.id,
                        severity=rule.severity,
                        title=rule.title,
                        path=rel,
                        line=line_no,
                        snippet=snippet[:MAX_SNIPPET],
                        message=rule.description,
                        remediation=rule.remediation,
                    ),
                    baseline,
                )
    return result


def load_baseline(path):
    """Read a baseline file.

    Supported formats:

    * JSON in AgentSentry report shape (``{"findings": [{rule_id, file, line}, ...]}``)
      or a bare list of those objects.
    * Plain text, one entry per line: ``RULE_ID path [line]`` or ``RULE_ID:path:line``.

    Returns ``(pairs, triples)`` where pairs are ``(rule_id, path)`` and triples add the
    line number. Paths are normalised to forward slashes and matched against the scan-root
    relative path, so generate the baseline from the same directory you scan.
    """
    text = Path(path).read_text(encoding="utf-8", errors="replace").strip()
    pairs, triples = set(), set()

    def _add(rule_id, file_path, line=None):
        norm = _norm_path(file_path)
        pairs.add((rule_id, norm))
        if isinstance(line, int):
            triples.add((rule_id, norm, line))

    if text.startswith("{") or text.startswith("["):
        data = json.loads(text)
        items = data.get("findings", []) if isinstance(data, dict) else data
        for item in items:
            _add(item.get("rule_id") or item.get("ruleId"), item.get("file") or item.get("path"),
                 item.get("line"))
    else:
        for raw in text.splitlines():
            entry = raw.strip()
            if not entry or entry.startswith("#"):
                continue
            if ":" in entry and entry.split()[0].count(":") >= 1 and " " not in entry:
                rule_id, _, rest = entry.partition(":")
                parts = rest.split(":")
                line = int(parts[-1]) if len(parts) > 1 and parts[-1].isdigit() else None
                _add(rule_id, parts[0], line)
            else:
                parts = entry.split()
                line = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None
                _add(parts[0], parts[1], line)
    return pairs, triples


def _in_baseline(finding: Finding, baseline) -> bool:
    if not baseline:
        return False
    pairs, triples = baseline
    return (finding.rule_id, finding.path) in pairs or (finding.rule_id, finding.path, finding.line) in triples


def _norm_path(value) -> str:
    return str(value).replace("\\", "/")


def discover_targets(root, excludes=()):
    """Return ``([(path, scope), ...], {skill_dir, ...})`` for *root*.

    *excludes* is a list of :mod:`fnmatch` patterns matched against the path relative to
    *root* and against the file name. ``*`` crosses directory separators, so
    ``"*/cache/*"`` and ``"AppData/*"`` behave as expected.
    """
    root = Path(root)
    files = []
    if root.is_file():
        files = [root]
    elif root.is_dir():
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for name in sorted(filenames):
                files.append(Path(dirpath) / name)
    else:
        return [], set()

    if excludes:
        files = [f for f in files if not _excluded(f, root, excludes)]

    skill_dirs = {f.parent for f in files if f.name.lower() in SKILL_FILE_NAMES}

    targets = []
    for path in files:
        lowered = path.name.lower()
        if lowered in MCP_CONFIG_NAMES or lowered.endswith("_mcp_settings.json"):
            targets.append((path, SCOPE_MCP))
            continue
        if lowered in SKILL_FILE_NAMES:
            targets.append((path, SCOPE_SKILL))
            continue
        if path.suffix.lower() == ".json":
            try:
                if path.stat().st_size > MCP_JSON_MAX_BYTES:
                    continue
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                content = ""
            if '"mcpServers"' in content or '"mcp_servers"' in content:
                targets.append((path, SCOPE_MCP))
                continue
        if path.parent in skill_dirs and path.suffix.lower() in SKILL_FILE_SUFFIXES:
            targets.append((path, SCOPE_SKILL))
    return targets, skill_dirs


def _excluded(path: Path, root: Path, excludes) -> bool:
    rel = _relative(path, root)
    for pattern in excludes:
        pattern = pattern.rstrip("/")
        if (
            fnmatch.fnmatch(rel, pattern)
            or fnmatch.fnmatch(rel, f"{pattern}/*")
            or fnmatch.fnmatch(path.name, pattern)
        ):
            return True
    return False


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
