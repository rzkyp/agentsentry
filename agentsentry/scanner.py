"""Filesystem discovery and the scanning engine for AgentSentry.

The scanner finds two kinds of targets:

* **MCP configuration files** — ``.mcp.json``, ``mcp.json``, ``claude_desktop_config.json``,
  ``cline_mcp_settings.json`` and any ``*.json`` containing an ``mcpServers`` key.
* **Agent skill directories** — every directory that contains a ``SKILL.md`` file, plus the
  scripts that sit next to it (``.py``, ``.sh``, ``.ps1``, ``.js``, ``.ts``, ``.md`` ...).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .rules import RULES, SCOPE_MCP, SCOPE_SKILL, SEVERITY_ORDER

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

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "env",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".idea",
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
    errors: list = field(default_factory=list)
    _seen: set = field(default_factory=set, repr=False)

    def add(self, finding: Finding) -> None:
        """Add a finding, de-duplicating on (rule, path, line)."""
        key = (finding.rule_id, finding.path, finding.line)
        if key in self._seen:
            return
        self._seen.add(key)
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


def discover_targets(root):
    """Return ``([(path, scope), ...], {skill_dir, ...})`` for *root*."""
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
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                content = ""
            if '"mcpServers"' in content or '"mcp_servers"' in content:
                targets.append((path, SCOPE_MCP))
                continue
        if path.parent in skill_dirs and path.suffix.lower() in SKILL_FILE_SUFFIXES:
            targets.append((path, SCOPE_SKILL))
    return targets, skill_dirs


def scan(root) -> ScanResult:
    """Scan *root* (file or directory) and return a :class:`ScanResult`."""
    root = Path(root)
    result = ScanResult(root=str(root))
    targets, skill_dirs = discover_targets(root)
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
        lines = text.splitlines()

        for rule in RULES:
            if not rule.matches_scope(scope):
                continue
            for match in rule.pattern.finditer(text):
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
                    )
                )
    return result


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
