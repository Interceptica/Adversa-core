from __future__ import annotations

from collections.abc import Callable
from contextlib import nullcontext
from pathlib import Path
import shutil

from rich.console import Console, Group
from rich.box import ROUNDED
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text
from rich.table import Table

from adversa.ui.slash_commands import complete_slash_commands, help_lines, parse_slash_command

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import Completer, Completion
    from prompt_toolkit.formatted_text import FormattedText
except Exception:  # pragma: no cover - fallback only
    PromptSession = None
    Completer = object  # type: ignore[assignment]
    Completion = None  # type: ignore[assignment]
    FormattedText = None  # type: ignore[assignment]


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
        self.render_startup()
        while True:
            raw = self.ask(self._prompt_message()).strip()
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
        if command.name == "run" and missing and "intake" in self.handlers:
            self.handlers["intake"](**args)
            return False
        for key in missing:
            response = self.ask(f"{key}: ").strip()
            if response:
                args[key] = response

        if missing and any(name not in args for name in command.required_args):
            raise ValueError(f"Missing required arguments for /{command.name}.")

        spinner = self.console.status(f"Running /{command.name}...", spinner="dots")
        context = spinner if command.name in {"run", "status", "resume", "cancel", "init"} else nullcontext()
        with context:
            self.handlers[command.name](**args)
        return False

    def ask(self, message: str | FormattedText) -> str:
        return self._prompt(message)

    def render_startup(self) -> None:
        width = self._terminal_width()
        banner = self._load_banner()
        if banner and width >= 88:
            header = banner
        else:
            header = Text(self._fallback_banner(), style="bold white")

        subheader = Text("Safe-by-default whitebox security CLI", style="bold white")
        guidance = Text("Type /help to explore commands. Explicit safety gates remain active.", style="dim")
        self.console.print(
            Panel(
                Group(header, Rule(style="cyan"), subheader, guidance),
                border_style="bright_black",
                box=ROUNDED,
                style="on #111111",
                padding=(1, 2),
            )
        )

    def render_help(self) -> None:
        table = Table(title="Slash Commands", border_style="bright_black")
        table.add_column("Command", style="bold white")
        table.add_column("Description", style="white")
        for line in help_lines():
            command, description = line.split(maxsplit=1)
            table.add_row(command, description)
        self.console.print(table)

    def _build_prompt(self) -> Callable[[str], str]:
        if PromptSession is None:
            return input
        session = PromptSession(completer=SlashCommandCompleter())
        return lambda _message: session.prompt(
            self._prompt_message(),
            bottom_toolbar=self._bottom_toolbar(),
        )

    def _prompt_message(self) -> str | FormattedText:
        if FormattedText is None:
            return "adversa [/] | "
        width = self._prompt_box_width()
        inner_width = width - 2
        title = " ADVERSA shell "
        context = " slash commands enabled "
        top = f"┌{title:─<{inner_width}}┐\n"
        middle = f"│{context:<{inner_width}}│\n"
        bottom_prefix = "└─"
        bottom_suffix = " "
        bottom_fill = max(0, width - len(bottom_prefix) - len(bottom_suffix) - len("[/]"))
        bottom = f"{bottom_prefix}{'─' * bottom_fill}{bottom_suffix}"
        return FormattedText(
            [
                ("#5f5f5f", top),
                ("#5f5f5f", middle),
                ("#5f5f5f", "│ "),
                ("#9a9a9a", f"{'type /help for commands':<{inner_width - 2}}"),
                ("#5f5f5f", "│\n"),
                ("#5f5f5f", bottom),
                ("#ffffff bold", "[/]"),
            ]
        )

    def _bottom_toolbar(self) -> str | FormattedText | None:
        if FormattedText is None:
            return " /help  safe-mode  repo guardrails active "
        return FormattedText(
            [
                ("bg:#1a1a1a #bbbbbb", " /help "),
                ("bg:#1a1a1a #777777", "  "),
                ("bg:#1a1a1a #bbbbbb", " safe-mode "),
                ("bg:#1a1a1a #777777", "  "),
                ("bg:#1a1a1a #bbbbbb", " repo guardrails active "),
            ]
        )

    def _load_banner(self) -> Text | None:
        assets_dir = Path(__file__).resolve().parents[2] / "assets"
        ansi_path = assets_dir / "adversa_cli_banner.ansi"
        text_path = assets_dir / "adversa_cli_banner.txt"
        if ansi_path.exists():
            return Text.from_ansi(ansi_path.read_text(encoding="utf-8"), style="white")
        if text_path.exists():
            return Text(text_path.read_text(encoding="utf-8"), style="white")
        return None

    def _fallback_banner(self) -> str:
        return "ADVERSA"

    def _terminal_width(self) -> int:
        return shutil.get_terminal_size((100, 24)).columns

    def _prompt_box_width(self) -> int:
        return max(48, self._terminal_width())
