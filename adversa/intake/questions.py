from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class IntakeQuestion:
    key: str
    prompt: str
    default: str | None = None
    required: bool = False


INTAKE_QUESTIONS: tuple[IntakeQuestion, ...] = (
    IntakeQuestion("repo", "Authorized repo path under repos/", required=True),
    IntakeQuestion("url", "Authorized staging URL", required=True),
    IntakeQuestion("workspace", "Workspace", default="default"),
    IntakeQuestion("i_acknowledge", "Type yes to confirm you are authorized", required=True),
    IntakeQuestion("focus_paths", "Optional focus paths (comma separated)", default=""),
    IntakeQuestion("avoid_paths", "Optional avoid paths (comma separated)", default=""),
    IntakeQuestion("exclusions", "Optional out-of-scope notes (comma separated)", default=""),
    IntakeQuestion("notes", "Optional operator notes", default=""),
)
