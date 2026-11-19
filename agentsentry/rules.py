"""Detection rules for AgentSentry.

Every rule is a compiled regex plus metadata. Patterns are matched against
MCP server configuration files and agent-skill files (SKILL.md and the
scripts that live next to it).

Scopes
------
``mcp``   -> only MCP configuration files (``.mcp.json``, ``claude_desktop_config.json``, ...)
``skill`` -> only agent skill files (``SKILL.md`` + siblings in the same directory)
``all``   -> both
"""

from __future__ import annotations

import re
from dataclasses import dataclass

CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}

SCOPE_MCP = "mcp"
SCOPE_SKILL = "skill"
SCOPE_ALL = "all"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    pattern: re.Pattern
    description: str
    remediation: str
    scopes: tuple

    def matches_scope(self, scope: str) -> bool:
        return SCOPE_ALL in self.scopes or scope in self.scopes


def _rule(rule_id, title, severity, pattern, description, remediation, scopes=(SCOPE_ALL,)):
    return Rule(
        id=rule_id,
        title=title,
        severity=severity,
        pattern=re.compile(pattern, re.IGNORECASE),
        description=description,
        remediation=remediation,
        scopes=tuple(scopes),
    )


RULES = [
    # ---------------------------------------------------------------- critical
    _rule(
        "EXF-001",
        "Exfiltration endpoint referenced",
        CRITICAL,
        r"(webhook\.site|requestbin\.com|pipedream\.net|ngrok\.io|"
        r"discord\.com/api/webhooks|hooks\.slack\.com/services|api\.telegram\.org/bot\d|"
        r"t\.me/|pastebin\.com/raw|0x0\.st|transfer\.sh|file\.io|termbin\.com)",
        "The file references a public webhook/paste/bin endpoint commonly used to receive stolen data.",
        "Remove the endpoint. A legitimate skill never ships data to a third-party collector.",
    ),
    _rule(
        "EXEC-001",
        "Remote script piped into a shell",
        CRITICAL,
        r"((?:curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod)[^\n|]{0,120}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"
        r"|(?:curl|wget)[^\n|]{0,120}\|\s*(?:python|python3|perl|ruby)\b)",
        "A remote script is executed straight through a shell interpreter without inspection.",
        "Download to a file, verify its checksum/signature, then execute it deliberately.",
    ),
    _rule(
        "EXEC-002",
        "Reverse shell or interactive shell spawn",
        CRITICAL,
        r"(nc\s+-[a-z]*e[a-z]*[\s/]|netcat\s+-[a-z]*e|ncat\s+-[a-z]*e|socat\s+exec:"
        r"|bash\s+-i\s*>\s*&?\s*/dev/tcp/|/dev/tcp/\d+\.\d+\.\d+\.\d+"
        r"|mkfifo\s+/tmp/[\w.]+[^\n]*\bnc\b"
        r"|iex\s*\(\s*(?:New-Object\s+Net\.WebClient|irm\b|iwr\b)"
        r"|Invoke-Expression\s+(?:New-Object\s+Net\.WebClient|irm\b|iwr\b))",
        "The code spawns an interactive/reverse shell or runs a downloaded payload via IEX.",
        "Remove the shell-out entirely and use a vetted library instead of spawning a shell.",
    ),
    _rule(
        "SEC-001",
        "Hardcoded credential",
        CRITICAL,
        r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
        r"|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,}"
        r"|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}"
        r"|AIza[0-9A-Za-z_\-]{35}"
        r"|(?:sk|rk)-[A-Za-z0-9_\-]{20,})",
        "A private key, API token, or cloud credential is embedded in the file.",
        "Rotate the credential immediately and load it from a secret manager or environment variable.",
    ),
    _rule(
        "INJ-001",
        "Prompt injection phrasing",
        CRITICAL,
        r"(ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|above|prior|earlier|preceding)\s+instructions?"
        r"|disregard\s+(?:all\s+)?(?:previous|above|prior|earlier)"
        r"|new\s+instructions?\s*:"
        r"|system\s+override"
        r"|you\s+must\s+(?:always|now|instead)"
        r"|override\s+(?:the\s+)?(?:system\s+)?prompt"
        r"|forget\s+(?:everything|all)\s+(?:above|previous|prior))",
        "The text contains classic prompt-injection phrasing aimed at overriding agent instructions.",
        "Delete the instruction. Skill content must describe a task, not re-program the model.",
    ),
    # --------------------------------------------------------------------- high
    _rule(
        "SEC-002",
        "Secret assigned in configuration",
        HIGH,
        r"(?i)(api[_-]?key|secret|token|password|passwd|client[_-]?secret)\s*[:=]\s*[\"'][^\"'\s]{12,}[\"']",
        "A secret-looking value is assigned to a credential-like variable.",
        "Use an environment variable or secret manager; never commit literals.",
    ),
    _rule(
        "CRED-001",
        "Credential store access",
        HIGH,
        r"(~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.aws/config|\.config/gcloud"
        r"|Login\s+Data|cookies\.sqlite|keychain|secret\.pem|credential\.json|\.netrc)",
        "The code reads credential or key material from the user's machine.",
        "Access only explicit, user-approved files; never harvest SSH, cloud, or browser credentials.",
    ),
    _rule(
        "OBF-001",
        "Obfuscated payload",
        HIGH,
        r"([A-Za-z0-9+/]{80,}={0,2}"
        r"|base64\s+(?:-d|--decode|-D)\b|atob\s*\(|FromBase64String\s*\("
        r"|\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){15,})",
        "A long encoded blob or a decode primitive suggests hidden or obfuscated instructions.",
        "Ship readable instructions. If encoding is genuinely required, document why and verify integrity.",
    ),
    _rule(
        "DESTR-001",
        "Destructive filesystem command",
        HIGH,
        r"(rm\s+-[a-z]*r[a-z]*f[a-z]*\s+(?:/|\$HOME|~|C:\\|%USERPROFILE%)"
        r"|rm\s+-rf\s+--no-preserve-root"
        r"|Remove-Item\s+(?:-[A-Za-z]+\s+)*-Recurse\s+(?:-[A-Za-z]+\s+)*-Force"
        r"|rd\s+/s\s+/q\s+[A-Za-z]:\\"
        r"|del\s+/[fsq]\s+/[fsq]\s+[A-Za-z]:\\"
        r"|format\s+[A-Za-z]:\\?)",
        "A recursive force-delete or format command can wipe user data.",
        "Scope deletion to a declared workspace directory and require confirmation.",
    ),
    _rule(
        "PERSIST-001",
        "Persistence mechanism",
        HIGH,
        r"(\.bashrc|\.zshrc|\.profile\b|crontab\s+-|schtasks\s+/create"
        r"|HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        r"|launchctl\s+load|systemd/system/[A-Za-z0-9._-]+\.service)",
        "The code installs a persistence mechanism (shell profile, cron, run key, service).",
        "Do not modify startup paths; ask the user before changing system state.",
    ),
    _rule(
        "SCAN-001",
        "Bulk archive of sensitive data",
        HIGH,
        r"((?:tar|zip|7z|rar)\s+[^\n]{0,120}(?:\.ssh|\.aws|Documents|Desktop|\.config)"
        r"|(?:tar|zip|7z|rar)\s+[^\n]{0,120}(?:\$|~)\s*$)",
        "An archive of sensitive directories is created, likely for exfiltration.",
        "Archive only explicit, user-selected paths; never bundle credentials or documents.",
    ),
    _rule(
        "SKILL-001",
        "Tool poisoning markers",
        HIGH,
        r"(<tool_description|<tool_use|<function\s+=|\"description\"\s*:\s*\"[^\"]{300,}\"|"
        r"Note:\s*(?:the\s+)?(?:user|assistant)\b|IMPORTANT:\s*(?:do\s+not\s+tell|never\s+tell)\b)",
        "Skill text embeds tool-call markup or assistant-directed notes that can hijack tool use.",
        "Keep skill prose free of tool markup; let the harness own the tool schema.",
    ),
    _rule(
        "MCP-006",
        "Secret in MCP environment block",
        HIGH,
        r"(\"env\"\s*:\s*\{[^}]{0,400}(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD)[^}]{0,200}\})",
        "The MCP config embeds a credential in its environment block, often committed by mistake.",
        "Reference an environment variable name (${VAR}) instead of the value, or use a secret manager.",
        scopes=(SCOPE_MCP,),
    ),
    _rule(
        "MCP-001",
        "Unpinned MCP package version",
        HIGH,
        r"(\b(?:npx|pnpx|bunx|uvx|pipx\s+run|yarn\s+dlx)\b[\s\S]{0,120}?@(?:latest|next|\*))",
        "The MCP server is launched from a mutable tag, so upstream can change the code silently.",
        "Pin an exact version (for example pkg@1.4.2) and lock the dependency.",
        scopes=(SCOPE_MCP,),
    ),
    _rule(
        "MCP-003",
        "Permission checks disabled",
        HIGH,
        r"(--dangerously-skip-permissions|dangerouslySkipPermissions|--yolo\b|--allowedTools|--no-confirm|--auto-approve)",
        "The server or harness runs with permission prompts disabled.",
        "Keep approval prompts enabled and scope allowed tools to the minimum set.",
        scopes=(SCOPE_MCP,),
    ),
    _rule(
        "MCP-004",
        "All tools auto-approved",
        HIGH,
        r"(\"autoApprove(?:All)?\"\s*:\s*true"
        r"|\"auto_approve\"\s*:\s*true"
        r"|\"autoApprove\"\s*:\s*\[\s*\"\*\""
        r"|\"allow\"\s*:\s*\[\s*\"\*\"\s*\])",
        "Every tool is approved without review, so a malicious tool call runs unchecked.",
        "Auto-approve only the specific tools the skill actually needs.",
        scopes=(SCOPE_MCP,),
    ),
    # ------------------------------------------------------------------- medium
    _rule(
        "EXEC-003",
        "Dynamic code execution",
        MEDIUM,
        r"(?<![\w.])(eval|exec|compile)\s*\(",
        "Dynamic execution primitives can turn untrusted input into code.",
        "Prefer static dispatch or lookup tables; if unavoidable, sandbox and validate the input.",
    ),
    _rule(
        "MCP-002",
        "Insecure transport",
        MEDIUM,
        r"(\"url\"\s*:\s*\"http://|\"type\"\s*:\s*\"(sse|streamable-http)\"[^\n]{0,120}http://)",
        "The MCP server is reached over plain HTTP, exposing requests and responses.",
        "Use https:// with TLS; prefer stdio for local servers.",
        scopes=(SCOPE_MCP,),
    ),
    _rule(
        "MCP-005",
        "Shell-backed MCP server",
        MEDIUM,
        r"(\"command\"\s*:\s*\"(?:bash|sh|zsh|powershell|pwsh|cmd|cmd\.exe|wsl|python\s+-c))",
        "The MCP server is a shell interpreter; its arguments execute with host privileges.",
        "Prefer a packaged binary server; if a shell is required, constrain the arguments.",
        scopes=(SCOPE_MCP,),
    ),
    _rule(
        "SUP-001",
        "Dependency fetched from VCS or URL",
        MEDIUM,
        r"(git\+https?://[^\s\"']+|https?://[^\s\"']+\.git\b"
        r"|pip\s+install\s+[^\n]*https?://"
        r"|npm\s+(?:i|install)\s+[^\n]*git\+"
        r"|cargo\s+install\s+--git)",
        "A dependency is fetched directly from a repository or URL, bypassing package review.",
        "Install from the registry at an exact version and keep a lockfile.",
    ),
    _rule(
        "SUP-002",
        "Custom package index",
        MEDIUM,
        r"(--index-url\s+https?://[^\s\"']+|--extra-index-url\s+https?://[^\s\"']+|--registry\s+https?://[^\s\"']+)",
        "Package installation is redirected to a custom index, which is a supply-chain risk.",
        "Use the default registry or a vetted private mirror over TLS.",
    ),
    _rule(
        "PERM-001",
        "Overly permissive file rights",
        MEDIUM,
        r"(chmod\s+(?:-R\s+)?777\b|icacls[^\n]{0,80}/grant\s+(?:Everyone\b|F\s*:)|attrib\s+-r\s+/s)",
        "World-writable permissions weaken host integrity.",
        "Use least-privilege permissions (for example 700/600) and targeted ACLs.",
    ),
    # ---------------------------------------------------------------------- low
    _rule(
        "NET-001",
        "Bare IP endpoint",
        LOW,
        r"((?:https?://)?\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?(?:/[^\s\"']*)?)",
        "The file references a raw IP address, which can indicate a throwaway C2 or exfil host.",
        "Use a named, reviewable service endpoint.",
    ),
]

RULES_BY_ID = {rule.id: rule for rule in RULES}
