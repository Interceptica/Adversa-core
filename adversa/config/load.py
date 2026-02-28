from __future__ import annotations

import os
import tomllib
from pathlib import Path

from adversa.config.models import AdversaConfig


DEFAULT_CONFIG_FILE = "adversa.toml"


def load_config(config_path: str | Path | None = None) -> AdversaConfig:
    path = Path(config_path or DEFAULT_CONFIG_FILE)
    if not path.exists():
        return AdversaConfig()

    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    cfg = AdversaConfig.model_validate(raw)

    provider = cfg.provider
    env_model = os.getenv("ADVERSA_MODEL")
    if env_model:
        provider.model = env_model

    env_provider = os.getenv("ADVERSA_PROVIDER")
    if env_provider in {"anthropic", "openai_compatible", "router"}:
        provider.provider = env_provider

    return cfg


def scaffold_default_config(target: Path) -> None:
    target.write_text(
        """[provider]
provider = "anthropic"
model = "claude-3-5-sonnet-latest"
api_key_env = "ANTHROPIC_API_KEY"

[safety]
acknowledgement = false
safe_mode = true
network_discovery_enabled = false

[run]
workspace_root = "runs"
repos_root = "repos"
task_queue = "adversa-task-queue"
""",
        encoding="utf-8",
    )
