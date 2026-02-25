from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


class ProviderConfig(BaseModel):
    provider: Literal["anthropic", "openai_compatible"] = "anthropic"
    model: str = "claude-3-5-sonnet-latest"
    api_key_env: str = "ANTHROPIC_API_KEY"
    base_url: str | None = None


class SafetyConfig(BaseModel):
    acknowledgement: bool = False
    safe_mode: bool = True
    network_discovery_enabled: bool = False


class RunConfig(BaseModel):
    workspace_root: str = "runs"
    repos_root: str = "repos"
    task_queue: str = "adversa-task-queue"


class AdversaConfig(BaseModel):
    provider: ProviderConfig = Field(default_factory=ProviderConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    run: RunConfig = Field(default_factory=RunConfig)


class EffectiveRunInput(BaseModel):
    repo_path: Path
    url: str
    workspace: str
    run_id: str
    safe_mode: bool
    force: bool = False
