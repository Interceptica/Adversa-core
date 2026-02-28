from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, model_validator


class ProviderConfig(BaseModel):
    provider: Literal["anthropic", "openai_compatible", "router"] = "anthropic"
    model: str = "claude-3-5-sonnet-latest"
    api_key_env: str = "ANTHROPIC_API_KEY"
    base_url: str | None = None

    @model_validator(mode="after")
    def validate_provider_settings(self) -> "ProviderConfig":
        if self.provider == "openai_compatible" and not self.base_url:
            raise ValueError("openai_compatible provider requires base_url")
        return self


class SafetyConfig(BaseModel):
    acknowledgement: bool = False
    safe_mode: bool = True
    network_discovery_enabled: bool = False


class RunConfig(BaseModel):
    workspace_root: str = "runs"
    repos_root: str = "repos"
    task_queue: str = "adversa-task-queue"


class RuleConfig(BaseModel):
    action: Literal["focus", "avoid"] = Field(description="Whether the rule prioritizes or blocks matching execution.")
    target_type: Literal["phase", "analyzer", "tag"] = Field(
        description="What kind of runtime object this rule matches."
    )
    target: str = Field(description="Phase name, analyzer name, or tag value to match.")
    phases: list[str] = Field(
        default_factory=list,
        description="Optional list of phases where the rule applies. Empty means all phases.",
    )


class AdversaConfig(BaseModel):
    provider: ProviderConfig = Field(default_factory=ProviderConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    run: RunConfig = Field(default_factory=RunConfig)
    rules: list[RuleConfig] = Field(default_factory=list)


class EffectiveRunInput(BaseModel):
    repo_path: Path
    url: str
    workspace: str
    run_id: str
    safe_mode: bool
    force: bool = False
