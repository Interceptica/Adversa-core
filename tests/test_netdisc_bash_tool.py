"""Unit tests for ScopedBashTool — scope enforcement and binary allowlist."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest
from langchain_core.tools import ToolException

from adversa.netdisc.bash_tool import ScopedBashTool, _extract_positionals, _host_from_value
from adversa.state.models import ScopeContract


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_scope(**kwargs: object) -> ScopeContract:
    defaults: dict[str, object] = dict(
        target_url="https://example.com",
        repo_path="repos/example",
        workspace="test",
        authorized=True,
        safe_mode=True,
        normalized_host="example.com",
        normalized_path="/",
        allowed_hosts=["example.com"],
        allowed_subdomains=["example.com"],
        exclusions=[],
        capability_constraints=[],
        repo_root_validated=True,
        evidence_expectations=[],
        notes=[],
        rules_summary={},
        confidence_gaps=[],
        warnings=[],
    )
    defaults.update(kwargs)
    return ScopeContract(**defaults)  # type: ignore[arg-type]


def _make_tool(**kwargs: object) -> ScopedBashTool:
    scope = kwargs.pop("scope", _make_scope())
    return ScopedBashTool(scope=scope, **kwargs)  # type: ignore[arg-type]


# ── Binary allowlist ──────────────────────────────────────────────────────────


def test_allowed_binary_passes() -> None:
    """Allowlisted binaries are not blocked before execution."""
    tool = _make_tool()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="example.com\n", stderr="")
        result = tool._run("subfinder -d example.com -silent")
    assert "example.com" in result


def test_non_allowlisted_binary_raises() -> None:
    """Non-allowlisted binary raises ToolException before any subprocess call."""
    tool = _make_tool()
    with pytest.raises(ToolException, match="not in the allowlist"):
        tool._run("masscan example.com -p1-65535")


def test_absolute_path_binary_extracted_correctly() -> None:
    """Binary name is extracted from absolute paths like /usr/bin/nmap."""
    tool = _make_tool()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        # Should not raise — nmap is allowed
        tool._run("/usr/bin/nmap -sT -Pn example.com")


def test_empty_command_raises() -> None:
    tool = _make_tool()
    with pytest.raises(ToolException, match="Empty command"):
        tool._run("")


def test_whitespace_only_command_raises() -> None:
    tool = _make_tool()
    with pytest.raises(ToolException, match="Empty command"):
        tool._run("   ")


# ── Scope enforcement ─────────────────────────────────────────────────────────


def test_in_scope_host_passes() -> None:
    """Commands targeting in-scope hosts execute successfully."""
    tool = _make_tool()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="found", stderr="")
        result = tool._run("subfinder -d example.com -silent")
    assert result == "found"


def test_out_of_scope_host_raises() -> None:
    """Commands targeting out-of-scope hosts raise ToolException."""
    tool = _make_tool()
    with pytest.raises(ToolException, match="outside the authorized scope"):
        tool._run("subfinder -d evil.com -silent")


def test_subdomain_in_scope_passes() -> None:
    """Subdomains of allowed domains are permitted."""
    tool = _make_tool()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        result = tool._run("subfinder -d api.example.com -silent")
    assert result == "ok"


def test_excluded_host_raises() -> None:
    """Excluded hosts are blocked even when they match the base domain."""
    tool = _make_tool(scope=_make_scope(exclusions=["admin.example.com"]))
    with pytest.raises(ToolException, match="outside the authorized scope"):
        tool._run("nmap -sT -Pn admin.example.com")


def test_httpx_url_target_in_scope() -> None:
    """httpx -u https://example.com passes scope check."""
    tool = _make_tool()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="{}", stderr="")
        tool._run("httpx -u https://example.com -json")


def test_httpx_url_target_out_of_scope_raises() -> None:
    """httpx -u https://evil.com is blocked by scope check."""
    tool = _make_tool()
    with pytest.raises(ToolException, match="outside the authorized scope"):
        tool._run("httpx -u https://evil.com -json")


def test_openssl_connect_in_scope() -> None:
    """openssl s_client -connect example.com:443 passes scope check."""
    tool = _make_tool()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="CONNECTED", stderr="")
        tool._run("openssl s_client -connect example.com:443")


def test_openssl_connect_out_of_scope_raises() -> None:
    """openssl s_client -connect evil.com:443 is blocked."""
    tool = _make_tool()
    with pytest.raises(ToolException, match="outside the authorized scope"):
        tool._run("openssl s_client -connect evil.com:443")


def test_nmap_positional_target_in_scope() -> None:
    """nmap with positional target passes scope check."""
    tool = _make_tool()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="Host: example.com", stderr="")
        tool._run("nmap -sT -Pn --top-ports 1000 example.com")


def test_nmap_positional_target_out_of_scope_raises() -> None:
    """nmap with out-of-scope positional target is blocked."""
    tool = _make_tool()
    with pytest.raises(ToolException, match="outside the authorized scope"):
        tool._run("nmap -sT -Pn --top-ports 1000 evil.com")


# ── Timeout handling ──────────────────────────────────────────────────────────


def test_timeout_raises_tool_exception() -> None:
    """Timed-out commands raise ToolException."""
    tool = _make_tool(timeout_seconds=1)
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 1)):
        with pytest.raises(ToolException, match="timed out"):
            tool._run("subfinder -d example.com -silent")


# ── Output handling ───────────────────────────────────────────────────────────


def test_stderr_appended_on_nonzero_exit() -> None:
    """Non-zero exit appends STDERR to output."""
    tool = _make_tool()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=1, stdout="partial output\n", stderr="tool not installed"
        )
        result = tool._run("subfinder -d example.com")
    assert "STDERR" in result
    assert "tool not installed" in result


def test_empty_stdout_returns_no_output_sentinel() -> None:
    """Empty stdout returns the sentinel string '(no output)'."""
    tool = _make_tool()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = tool._run("subfinder -d example.com")
    assert result == "(no output)"


# ── Target extraction helpers ─────────────────────────────────────────────────


def test_host_from_value_with_url() -> None:
    assert _host_from_value("https://example.com/path") == "example.com"
    assert _host_from_value("http://api.example.com") == "api.example.com"


def test_host_from_value_plain() -> None:
    assert _host_from_value("example.com") == "example.com"


def test_extract_positionals_skips_single_char_flags() -> None:
    # Single-char flags (-p, -s, etc.) skip their next arg.
    # Long flags (--top-ports) do NOT auto-consume their value;
    # "1000" appears as a positional, but _extract_target filters numeric values.
    args = ["-sT", "-Pn", "--top-ports", "1000", "example.com"]
    result = _extract_positionals(args)
    # "1000" is included (long flags don't consume next arg in this helper)
    assert result == ["1000", "example.com"]


def test_extract_positionals_skips_flag_values() -> None:
    # -p consumes the next arg ("80,443"), leaving "example.com" as positional
    args = ["-p", "80,443", "example.com"]
    result = _extract_positionals(args)
    assert result == ["example.com"]
