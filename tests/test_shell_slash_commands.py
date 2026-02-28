from __future__ import annotations

from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from adversa.cli import app
from adversa.ui.shell import AdversaShell
from adversa.ui.slash_commands import complete_slash_commands, parse_slash_command


def test_parse_slash_command_parses_flags_and_values() -> None:
    command, args = parse_slash_command(
        '/run --repo repos/demo --url https://staging.example.com --workspace ws --i-acknowledge --force'
    )

    assert command.name == "run"
    assert args == {
        "repo": "repos/demo",
        "url": "https://staging.example.com",
        "workspace": "ws",
        "i_acknowledge": True,
        "force": True,
    }


def test_complete_slash_commands_lists_matching_commands() -> None:
    assert complete_slash_commands("/")[:3] == ["/help", "/?", "/run"]
    assert complete_slash_commands("/st") == ["/status"]


def test_shell_prompts_for_missing_required_args_and_dispatches_same_handler() -> None:
    calls: list[tuple[str, dict[str, object]]] = []
    prompts = iter(["repos/target", "https://staging.example.com"])

    shell = AdversaShell(
        handlers={
            "run": lambda **kwargs: calls.append(("run", kwargs)),
            "status": lambda **kwargs: calls.append(("status", kwargs)),
            "resume": lambda **kwargs: calls.append(("resume", kwargs)),
            "cancel": lambda **kwargs: calls.append(("cancel", kwargs)),
            "init": lambda **kwargs: calls.append(("init", kwargs)),
        },
        console=Console(file=StringIO(), force_terminal=False, color_system=None),
        prompt=lambda _: next(prompts),
    )

    shell.handle_line("/run --workspace ws --i-acknowledge")

    assert calls == [
        (
            "run",
            {
                "workspace": "ws",
                "i_acknowledge": True,
                "repo": "repos/target",
                "url": "https://staging.example.com",
            },
        )
    ]


def test_shell_help_and_exit_behaviors_render_and_return() -> None:
    output = StringIO()
    shell = AdversaShell(
        handlers={
            "run": lambda **kwargs: None,
            "status": lambda **kwargs: None,
            "resume": lambda **kwargs: None,
            "cancel": lambda **kwargs: None,
            "init": lambda **kwargs: None,
        },
        console=Console(file=output, force_terminal=False, color_system=None),
        prompt=lambda _: "",
    )

    assert shell.handle_line("/help") is False
    assert "Slash Commands" in output.getvalue()
    assert shell.handle_line("/exit") is True


def test_shell_startup_renders_banner_and_guidance() -> None:
    output = StringIO()
    shell = AdversaShell(
        handlers={
            "run": lambda **kwargs: None,
            "status": lambda **kwargs: None,
            "resume": lambda **kwargs: None,
            "cancel": lambda **kwargs: None,
            "init": lambda **kwargs: None,
        },
        console=Console(file=output, force_terminal=False, color_system=None, width=120),
        prompt=lambda _: "/exit",
    )

    shell.run()

    rendered = output.getvalue()
    assert "Safe-by-default whitebox security CLI" in rendered
    assert "Type /help to explore commands" in rendered
    assert "Exiting Adversa shell." in rendered


def test_shell_unknown_command_fails_cleanly() -> None:
    shell = AdversaShell(
        handlers={},
        console=Console(file=StringIO(), force_terminal=False, color_system=None),
        prompt=lambda _: "",
    )

    with pytest.raises(ValueError, match="Unknown slash command"):
        shell.handle_line("/unknown")


def test_cli_defaults_to_shell_when_no_subcommand(monkeypatch: pytest.MonkeyPatch) -> None:
    state = {"called": False}

    class FakeShell:
        def run(self) -> None:
            state["called"] = True

    monkeypatch.setattr("adversa.cli._build_shell", lambda: FakeShell())

    runner = CliRunner()
    result = runner.invoke(app, [])

    assert result.exit_code == 0
    assert state["called"] is True


def test_shell_uses_prompt_bar_style_message() -> None:
    shell = AdversaShell(
        handlers={"run": lambda **kwargs: None},
        console=Console(file=StringIO(), force_terminal=False, color_system=None),
        prompt=lambda _: "",
    )

    assert shell._prompt_message() == "adversa [/] | "


def test_shell_init_uses_plain_defaults_and_scaffolds_files(tmp_path: Path) -> None:
    shell = AdversaShell(
        handlers={
            "help": lambda **kwargs: None,
            "?": lambda **kwargs: None,
            "run": lambda **kwargs: None,
            "status": lambda **kwargs: None,
            "resume": lambda **kwargs: None,
            "cancel": lambda **kwargs: None,
            "init": __import__("adversa.cli", fromlist=["init_command"]).init_command,
            "config": lambda **kwargs: None,
            "exit": lambda **kwargs: None,
        },
        console=Console(file=StringIO(), force_terminal=False, color_system=None),
        prompt=lambda _: "",
    )

    cwd = Path.cwd()
    try:
        import os

        os.chdir(tmp_path)
        assert shell.handle_line("/init") is False
    finally:
        os.chdir(cwd)

    assert (tmp_path / "adversa.toml").exists()
    assert (tmp_path / "scope.template.json").exists()
