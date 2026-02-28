from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

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


class RuleMatcherConfig(BaseModel):
    description: str | None = Field(default=None, description="Optional human-readable explanation for the rule.")
    type: Literal["subdomain", "path", "host", "method", "repo_path", "tag", "phase", "analyzer"] = Field(
        description="User-facing rule surface type."
    )
    value: str = Field(description="Match expression for the selected type.")
    phases: list[str] = Field(
        default_factory=list,
        description="Optional list of phases where the rule applies. Empty means all phases.",
    )

    @model_validator(mode="before")
    @classmethod
    def normalize_aliases(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        normalized = dict(data)
        if "value" not in normalized:
            for alias in ("url_path", "target", "pattern"):
                if alias in normalized:
                    normalized["value"] = normalized[alias]
                    break
        return normalized

    @model_validator(mode="after")
    def validate_value(self) -> "RuleMatcherConfig":
        if not self.value.strip():
            raise ValueError("rule value must not be empty")
        return self


class RulesConfig(BaseModel):
    focus: list[RuleMatcherConfig] = Field(default_factory=list)
    avoid: list[RuleMatcherConfig] = Field(default_factory=list)


class AdversaConfig(BaseModel):
    provider: ProviderConfig = Field(default_factory=ProviderConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    run: RunConfig = Field(default_factory=RunConfig)
    rules: RulesConfig = Field(default_factory=RulesConfig)


class EffectiveRunInput(BaseModel):
    repo_path: Path
    url: str
    workspace: str
    run_id: str
    safe_mode: bool
    force: bool = False
