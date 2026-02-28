from __future__ import annotations

from dataclasses import dataclass
import shlex


@dataclass(frozen=True)
class SlashCommand:
    name: str
    description: str
    required_args: tuple[str, ...] = ()
    optional_args: tuple[str, ...] = ()


COMMANDS: dict[str, SlashCommand] = {
    "help": SlashCommand("help", "Show available slash commands."),
    "?": SlashCommand("?", "Alias for /help."),
    "run": SlashCommand(
        "run",
        "Start a safe-mode workflow run.",
        required_args=("repo", "url"),
        optional_args=("workspace", "config", "i_acknowledge", "force"),
    ),
    "status": SlashCommand(
        "status",
        "Inspect workflow status for a workspace/run.",
        required_args=("workspace",),
        optional_args=("run_id",),
    ),
    "resume": SlashCommand(
        "resume",
        "Resume a paused or waiting workflow.",
        required_args=("workspace",),
        optional_args=("run_id", "url", "force_target_mismatch"),
    ),
    "cancel": SlashCommand(
        "cancel",
        "Cancel a workflow.",
        required_args=("workspace",),
        optional_args=("run_id",),
    ),
    "init": SlashCommand(
        "init",
        "Scaffold adversa.toml and scope template.",
        optional_args=("path", "force"),
    ),
    "config": SlashCommand("config", "Show the default config path."),
    "exit": SlashCommand("exit", "Exit interactive shell."),
}


def parse_slash_command(line: str) -> tuple[SlashCommand, dict[str, str | bool]]:
    if not line.startswith("/"):
        raise ValueError("Shell commands must start with '/'.")

    parts = shlex.split(line[1:])
    if not parts:
        return COMMANDS["help"], {}

    command_name = parts[0]
    command = COMMANDS.get(command_name)
    if command is None:
        raise ValueError(f"Unknown slash command '/{command_name}'.")

    args: dict[str, str | bool] = {}
    idx = 1
    while idx < len(parts):
        token = parts[idx]
        if not token.startswith("--"):
            raise ValueError(f"Unexpected positional argument '{token}'.")
        key = token[2:].replace("-", "_")
        if idx + 1 < len(parts) and not parts[idx + 1].startswith("--"):
            args[key] = parts[idx + 1]
            idx += 2
        else:
            args[key] = True
            idx += 1
    return command, args


def complete_slash_commands(prefix: str) -> list[str]:
    if not prefix.startswith("/"):
        return []
    command_prefix = prefix[1:]
    return [f"/{name}" for name in COMMANDS if name.startswith(command_prefix)]


def help_lines() -> list[str]:
    return [f"/{command.name:<7} {command.description}" for command in COMMANDS.values()]
