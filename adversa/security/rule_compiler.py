from __future__ import annotations

from dataclasses import dataclass

from adversa.config.models import AdversaConfig, RuleMatcherConfig


@dataclass(frozen=True)
class CompiledRule:
    action: str
    target_type: str
    target: str
    phases: tuple[str, ...] = ()
    description: str | None = None


def compile_rules(config: AdversaConfig) -> list[CompiledRule]:
    compiled: list[CompiledRule] = []
    for action, rules in (("focus", config.rules.focus), ("avoid", config.rules.avoid)):
        compiled.extend(_compile_group(action, rules))
    return compiled


def _compile_group(action: str, rules: list[RuleMatcherConfig]) -> list[CompiledRule]:
    return [
        CompiledRule(
            action=action,
            target_type=rule.type,
            target=rule.value,
            phases=tuple(rule.phases),
            description=rule.description,
        )
        for rule in rules
    ]
