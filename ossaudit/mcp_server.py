"""OSSAUDIT MCP server — exposes the audit surface as an MCP tool.

``scan`` audits a dependency manifest (path or already-parsed list) under a
distribution policy and returns the structured report dict — the same shape the
CLI emits with ``--format json``. Building the actual server requires the
optional ``cognis_core`` extra; importing this module never does.
"""
from ossaudit.core import audit_dependencies, load_dependencies, TOOL_NAME


def scan(target, policy: str = "proprietary"):
    """Audit a manifest (path or parsed object) and return the report dict."""
    deps = load_dependencies(target)
    return audit_dependencies(deps, policy=policy).to_dict()


def _build():
    from cognis_core.mcp import build_mcp_server  # optional [mcp] extra
    return build_mcp_server(
        tool_name=TOOL_NAME,
        description="OSS license compliance auditor — AGPL contamination + NOTICE generation",
        scan_fn=scan,
    )


def run_mcp_server():
    _build()()


if __name__ == "__main__":
    run_mcp_server()
