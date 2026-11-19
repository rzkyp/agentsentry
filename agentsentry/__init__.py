"""AgentSentry — security scanner for MCP servers and AI agent skills."""

__version__ = "0.1.0"

from .scanner import Finding, ScanResult, discover_targets, scan  # noqa: E402,F401

__all__ = ["Finding", "ScanResult", "discover_targets", "scan", "__version__"]
