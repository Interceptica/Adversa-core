from __future__ import annotations

from io import StringIO

from rich.console import Console

from adversa.ui.shell import AdversaShell


def test_shell_run_without_required_args_dispatches_intake_handler() -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    shell = AdversaShell(
        handlers={
            "run": lambda **kwargs: calls.append(("run", kwargs)),
            "intake": lambda **kwargs: calls.append(("intake", kwargs)),
        },
        console=Console(file=StringIO(), force_terminal=False, color_system=None),
        prompt=lambda _: "",
    )

    shell.handle_line("/run --workspace ws")

    assert calls == [("intake", {"workspace": "ws"})]
