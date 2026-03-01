"""Playwright browser tooling for the recon agent.

Provides an async context manager that spins up a fresh, isolated Playwright MCP
subprocess for each recon run via stdio transport. Session isolation is guaranteed:
the browser process is killed when the context manager exits, so cookies, local
storage, and session state cannot bleed between runs.

Allowed tools are whitelisted to read-only / safe browser interactions.
browser_evaluate (arbitrary JS execution) and browser_file_upload are excluded.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from langchain_core.tools import BaseTool

# Browser tools that are safe for a passive recon agent.
# browser_evaluate is excluded (arbitrary JS execution risk).
# browser_file_upload is excluded (not relevant for recon).
ALLOWED_BROWSER_TOOLS: frozenset[str] = frozenset(
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


@asynccontextmanager
async def playwright_tools_context(
    *,
    headless: bool = True,
) -> AsyncIterator[list[BaseTool]]:
    """Async context manager that yields isolated Playwright browser tools.

    Each call spawns a fresh `@playwright/mcp` subprocess via stdio transport.
    The subprocess (and its browser process) is killed on context exit, ensuring
    zero cookie or session sharing between recon runs.

    Args:
        headless: Run browser in headless mode. Set False only for debugging.

    Yields:
        List of LangChain BaseTool instances wrapping Playwright MCP tools,
        filtered to the ALLOWED_BROWSER_TOOLS whitelist.
    """
    try:
        from langchain_mcp_adapters.client import MultiServerMCPClient
    except ImportError as exc:
        raise ImportError(
            "langchain-mcp-adapters is required for browser-based recon. "
            "Run: uv add langchain-mcp-adapters"
        ) from exc

    args = ["@playwright/mcp@latest"]
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
        safe_tools = [t for t in all_tools if t.name in ALLOWED_BROWSER_TOOLS]
        yield safe_tools
