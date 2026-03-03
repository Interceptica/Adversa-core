"""Scope-enforced bash tool for network discovery commands.

``ScopedBashTool`` wraps subprocess execution with:
- Binary allowlist enforcement (only approved tools can run)
- Target scope validation (only in-scope hosts may be targeted)
- Execution timeout
"""

from __future__ import annotations

import re
import shlex
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from langchain_core.tools import BaseTool, ToolException
from pydantic import Field

from adversa.state.models import ScopeContract


_DEFAULT_ALLOWED_BINARIES: frozenset[str] = frozenset(
    {"subfinder", "nmap", "httpx", "whatweb", "openssl", "nuclei", "curl"}
)


class ScopedBashTool(BaseTool):
    """Execute network discovery bash commands against in-scope hosts only.

    Enforces:

    1. Binary allowlist — only approved network discovery tools may be called.
    2. Scope contract — the target host must be within the authorized scope.
    3. Execution timeout — commands are killed after ``timeout_seconds``.
    """

    name: str = "bash"
    description: str = (
        "Run a network discovery bash command. "
        "Allowed binaries: subfinder, nmap, httpx, whatweb, openssl, nuclei, curl. "
        "Commands must target only in-scope hosts as defined by the scope contract."
    )
    scope: ScopeContract = Field(description="Authorized scope contract for host validation.")
    allowed_binaries: frozenset[str] = Field(default=_DEFAULT_ALLOWED_BINARIES)
    timeout_seconds: int = Field(default=60)

    def _run(self, command: str, **kwargs: Any) -> str:
        """Execute an in-scope network discovery command.

        Args:
            command: Shell command to execute.

        Returns:
            Command stdout output, optionally prefixed with stderr on failure.

        Raises:
            ToolException: If the binary is not allowed, the target is out of scope,
                or the command times out.
        """
        command = command.strip()
        if not command:
            raise ToolException("Empty command.")

        # Parse command to check binary allowlist.
        try:
            parts = shlex.split(command)
        except ValueError as exc:
            raise ToolException(f"Could not parse command: {exc}") from exc

        if not parts:
            raise ToolException("Empty command after parsing.")

        binary_name = Path(parts[0]).name  # e.g. /usr/bin/nmap → "nmap"
        if binary_name not in self.allowed_binaries:
            raise ToolException(
                f"Binary '{binary_name}' is not in the allowlist. "
                f"Allowed: {', '.join(sorted(self.allowed_binaries))}"
            )

        # Validate scope before executing.
        target = self._extract_target(command, parts)
        if target:
            self._validate_target(target)

        # Execute command.
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            output = result.stdout
            if result.returncode != 0 and result.stderr:
                output += f"\nSTDERR: {result.stderr[:500]}"
            return output or "(no output)"
        except subprocess.TimeoutExpired as exc:
            raise ToolException(f"Command timed out after {self.timeout_seconds}s.") from exc

    def _extract_target(self, command: str, parts: list[str]) -> str | None:
        """Extract the target hostname or IP from a network discovery command.

        Checks, in order:

        1. ``-d <domain>`` (subfinder)
        2. ``-u <url|host>`` (httpx, nuclei)
        3. ``-host <host>``
        4. ``-connect <host:port>`` (openssl s_client)
        5. ``http://`` / ``https://`` URLs in any argument position
        6. Last non-flag positional argument (nmap, whatweb, curl)
        """
        # -d flag: subfinder -d example.com
        m = re.search(r"(?:^|\s)-d\s+(\S+)", command)
        if m:
            return m.group(1)

        # -u flag: httpx -u https://example.com  /  nuclei -u https://example.com
        m = re.search(r"(?:^|\s)-u\s+(\S+)", command)
        if m:
            return _host_from_value(m.group(1))

        # -host flag
        m = re.search(r"(?:^|\s)-host\s+(\S+)", command)
        if m:
            return _host_from_value(m.group(1))

        # -connect flag: openssl s_client -connect example.com:443
        m = re.search(r"-connect\s+(\S+)", command)
        if m:
            value = m.group(1)
            return value.rsplit(":", 1)[0]  # strip :port

        # http/https URL in any positional argument
        for part in parts:
            if part.startswith("http://") or part.startswith("https://"):
                parsed = urlparse(part)
                if parsed.hostname:
                    return parsed.hostname

        # Last non-flag positional argument (nmap target, whatweb URL)
        positionals = _extract_positionals(parts[1:])  # skip binary name
        if positionals:
            last = positionals[-1]
            # Skip pure port/range values like "1-1000" or "80,443"
            if not re.match(r"^[\d,\-]+$", last):
                return _host_from_value(last)

        return None

    def _validate_target(self, target: str) -> None:
        """Raise ``ToolException`` if target is outside the authorized scope."""
        hostname = target.split(":")[0]  # strip port suffix if present
        if not self._is_in_scope(hostname):
            raise ToolException(
                f"Target '{hostname}' is outside the authorized scope. "
                "Only in-scope hosts are permitted."
            )

    def _is_in_scope(self, hostname: str) -> bool:
        """Return ``True`` if hostname is within the authorized scope contract."""
        scope = self.scope

        # Check exclusions first.
        for exclusion in scope.exclusions:
            if exclusion in hostname:
                return False

        # Explicit allowed hosts.
        if hostname in scope.allowed_hosts:
            return True

        # Allowed subdomains (*.example.com pattern).
        for allowed_subdomain in scope.allowed_subdomains:
            if hostname.endswith(f".{allowed_subdomain}") or hostname == allowed_subdomain:
                return True

        # Normalized host from intake scope.
        if hostname == scope.normalized_host:
            return True

        return False


def _host_from_value(value: str) -> str:
    """Extract hostname from a URL string, or return the value unchanged."""
    if value.startswith("http://") or value.startswith("https://"):
        parsed = urlparse(value)
        return parsed.hostname or value
    return value


def _extract_positionals(args: list[str]) -> list[str]:
    """Return non-flag positional arguments from a parsed argument list."""
    positionals: list[str] = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg.startswith("-"):
            # Single-char flags (e.g. -p, -s) typically consume the next arg.
            if len(arg) == 2:
                skip_next = True
            continue
        positionals.append(arg)
    return positionals
