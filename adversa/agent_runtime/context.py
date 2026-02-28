from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AdversaAgentContext:
    phase: str
    url: str
    repo_path: str
    workspace: str
    run_id: str
    workspace_root: str = "runs"
    config_path: str = "adversa.toml"

    @property
    def logs_dir(self) -> Path:
        return Path(self.workspace_root) / self.workspace / self.run_id / "logs"

    @property
    def evidence_dir(self) -> Path:
        return Path(self.workspace_root) / self.workspace / self.run_id / self.phase / "evidence"
