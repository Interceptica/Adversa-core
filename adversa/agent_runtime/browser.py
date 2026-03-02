"""Shared Playwright browser tooling for Adversa agents.

A single browser session is created per agent invocation — not one per tool call.
The ``playwright_tools_context`` async context manager wraps the whole agent
invocation, so every browser tool call the agent makes shares the same live session
and page state.

Session isolation is enforced by three layers:

1. ``--isolated``: Playwright MCP launches a clean browser context with no persistent
   profile loaded or saved. Prevents stale cookies or local storage from a previous
   run from being picked up at startup.
2. ``--user-data-dir /tmp/adversa-playwright-<run_id>``: unique temp dir scoped to
   the run, so parallel or sequential runs cannot collide on disk.
3. subprocess kill on context exit: the browser process is killed when the context
   manager exits, discarding all in-memory state.

Per-phase tool allowlists
-------------------------
Each phase defines which tools its agent is permitted to use:

- ``RECON_BROWSER_TOOLS``: read-only observation (navigate, snapshot, inspect).
  No form interaction — recon is passive surface mapping only.
- ``VULN_BROWSER_TOOLS``: extends recon tools with ``browser_fill_form`` for safe
  input-handling verification during vulnerability analysis.

``browser_evaluate`` (arbitrary JS execution) and ``browser_file_upload`` are
excluded from all phases.
"""

from __future__ import annotations

import tempfile
import uuid
from contextlib import asynccontextmanager
from typing import AsyncIterator

from langchain_core.tools import BaseTool

# Read-only tools safe for passive surface mapping (recon phase).
# browser_evaluate excluded: arbitrary JS execution risk.
# browser_file_upload excluded: not relevant for recon.
RECON_BROWSER_TOOLS: frozenset[str] = frozenset(
    {
        "browser_navigate",
        "browser_snapshot",
        "browser_take_screenshot",
        "browser_network_requests",
        "browser_console_messages",
        "browser_click",
        "browser_type",
        "browser_press_key",
        "browser_hover",
        "browser_wait_for",
        "browser_tabs",
        "browser_navigate_back",
    }
)

# Extends recon tools with form interaction for safe input-handling verification.
# Used by the vulnerability phase to test how the app handles user-controlled input.
VULN_BROWSER_TOOLS: frozenset[str] = RECON_BROWSER_TOOLS | {
    "browser_fill_form",
}


@asynccontextmanager
async def playwright_tools_context(
    *,
    allowed_tools: frozenset[str] = RECON_BROWSER_TOOLS,
    headless: bool = True,
    run_id: str | None = None,
) -> AsyncIterator[list[BaseTool]]:
    """Async context manager that yields a single isolated Playwright browser session.

    Wraps the entire agent invocation — not individual tool calls. The browser
    subprocess is spawned once and stays alive for the full duration of the context,
    so the agent can navigate across pages and maintain state within one coherent
    session.

    Args:
        allowed_tools: Whitelist of MCP tool names to expose to the agent.
                       Use ``RECON_BROWSER_TOOLS`` for passive mapping phases and
                       ``VULN_BROWSER_TOOLS`` for safe verification phases.
                       Defaults to ``RECON_BROWSER_TOOLS``.
        headless: Run browser in headless mode. Set False only for debugging.
        run_id: Optional run identifier used to scope the user-data-dir.
                A random UUID is used if not provided.

    Yields:
        List of LangChain BaseTool instances wrapping Playwright MCP tools,
        filtered to the provided ``allowed_tools`` whitelist.
    """
    try:
        from langchain_mcp_adapters.client import MultiServerMCPClient
    except ImportError as exc:
        raise ImportError(
            "langchain-mcp-adapters is required for browser-based agents. "
            "Run: uv add langchain-mcp-adapters"
        ) from exc

    session_id = run_id or str(uuid.uuid4())
    user_data_dir = f"{tempfile.gettempdir()}/adversa-playwright-{session_id}"

    args = [
        "@playwright/mcp@latest",
        "--isolated",
        "--user-data-dir",
        user_data_dir,
    ]
    if headless:
        args.append("--headless")

    server_config: dict[str, object] = {
        "playwright": {
            "transport": "stdio",
            "command": "npx",
            "args": args,
        }
    }

    async with MultiServerMCPClient(server_config) as client:  # type: ignore[attr-defined]
        all_tools: list[BaseTool] = await client.get_tools()
        safe_tools = [t for t in all_tools if t.name in allowed_tools]
        yield safe_tools
