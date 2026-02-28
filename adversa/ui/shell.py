from __future__ import annotations

from collections.abc import Callable
from contextlib import nullcontext

from rich.console import Console
from rich.table import Table

from adversa.ui.slash_commands import complete_slash_commands, help_lines, parse_slash_command

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import Completer, Completion
except Exception:  # pragma: no cover - fallback only
    PromptSession = None
    Completer = object  # type: ignore[assignment]
    Completion = None  # type: ignore[assignment]


class SlashCommandCompleter(Completer):  # type: ignore[misc]
    def get_completions(self, document, complete_event):  # type: ignore[no-untyped-def]
        if Completion is None:
            return
        for value in complete_slash_commands(document.text_before_cursor):
            yield Completion(value, start_position=-len(document.text_before_cursor))


class AdversaShell:
    def __init__(
        self,
        handlers: dict[str, Callable[..., object]],
        *,
        console: Console | None = None,
        prompt: Callable[[str], str] | None = None,
    ) -> None:
        self.handlers = handlers
        self.console = console or Console()
        self._prompt = prompt or self._build_prompt()

    def run(self) -> None:
        self.console.print("[bold]Adversa shell[/bold]. Type /help for commands.")
        while True:
            raw = self._prompt("adversa> ").strip()
            if not raw:
                continue
            should_exit = self.handle_line(raw)
            if should_exit:
                return

    def handle_line(self, line: str) -> bool:
        command, args = parse_slash_command(line)
        if command.name in {"help", "?"}:
            self.render_help()
            return False
        if command.name == "config":
            self.console.print("Config path: adversa.toml")
            return False
        if command.name == "exit":
            self.console.print("Exiting Adversa shell.")
            return True

        missing = [name for name in command.required_args if name not in args]
        for key in missing:
            response = self._prompt(f"{key}: ").strip()
            if response:
                args[key] = response

        if missing and any(name not in args for name in command.required_args):
            raise ValueError(f"Missing required arguments for /{command.name}.")

        spinner = self.console.status(f"Running /{command.name}...", spinner="dots")
        context = spinner if command.name in {"run", "status", "resume", "cancel", "init"} else nullcontext()
        with context:
            self.handlers[command.name](**args)
        return False

    def render_help(self) -> None:
        table = Table(title="Slash Commands")
        table.add_column("Command", style="cyan")
        table.add_column("Description")
        for line in help_lines():
            command, description = line.split(maxsplit=1)
            table.add_row(command, description)
        self.console.print(table)

    def _build_prompt(self) -> Callable[[str], str]:
        if PromptSession is None:
            return input
        session = PromptSession(completer=SlashCommandCompleter())
        return session.prompt
