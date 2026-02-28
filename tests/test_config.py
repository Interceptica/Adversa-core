from __future__ import annotations

import pytest

from adversa.config.models import AdversaConfig


def test_user_facing_rules_model_parses_focus_and_avoid_groups() -> None:
    cfg = AdversaConfig.model_validate(
        {
            "rules": {
                "focus": [{"description": "Prioritize beta", "type": "subdomain", "value": "beta-admin"}],
                "avoid": [{"type": "repo_path", "value": "repos/private/*", "phases": ["recon"]}],
            }
        }
    )

    assert cfg.rules.focus[0].type == "subdomain"
    assert cfg.rules.focus[0].value == "beta-admin"
    assert cfg.rules.avoid[0].phases == ["recon"]


def test_rules_must_use_grouped_focus_and_avoid_shape() -> None:
    with pytest.raises(ValueError):
        AdversaConfig.model_validate(
            {
                "rules": [
                    {"action": "focus", "target_type": "analyzer", "target": "auth_model_builder"},
                ]
            }
        )


def test_rule_value_must_not_be_empty() -> None:
    with pytest.raises(ValueError, match="rule value must not be empty"):
        AdversaConfig.model_validate({"rules": {"focus": [{"type": "path", "value": "   "}]}})
