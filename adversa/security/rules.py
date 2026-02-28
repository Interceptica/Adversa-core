from __future__ import annotations

from dataclasses import dataclass

from adversa.config.models import RuleConfig


@dataclass(frozen=True)
class AnalyzerSpec:
    name: str
    tags: tuple[str, ...]


@dataclass(frozen=True)
class AppliedRule:
    action: str
    target_type: str
    target: str


@dataclass(frozen=True)
class RuleDecision:
    selected_analyzers: list[str]
    applied_rules: list[AppliedRule]
    blocked_reason: str | None = None


PHASE_ANALYZERS: dict[str, tuple[AnalyzerSpec, ...]] = {
    "intake": (
        AnalyzerSpec("scope_planner", ("planning", "scope")),
        AnalyzerSpec("repo_inventory", ("filesystem", "planning")),
    ),
    "prerecon": (
        AnalyzerSpec("repo_inventory", ("filesystem", "planning")),
        AnalyzerSpec("baseline_metadata", ("metadata", "planning")),
    ),
    "recon": (
        AnalyzerSpec("attack_surface_mapper", ("network", "discovery")),
        AnalyzerSpec("auth_model_builder", ("auth", "modeling")),
        AnalyzerSpec("data_flow_mapper", ("data-flow", "modeling")),
    ),
    "vuln": (
        AnalyzerSpec("static_safe_checks", ("safe", "code")),
        AnalyzerSpec("dependency_review", ("dependencies", "safe")),
        AnalyzerSpec("config_review", ("configuration", "safe")),
    ),
    "report": (
        AnalyzerSpec("finding_summarizer", ("reporting", "summary")),
        AnalyzerSpec("retest_planner", ("reporting", "planning")),
    ),
}


def evaluate_rules(phase: str, rules: list[RuleConfig]) -> RuleDecision:
    analyzers = list(PHASE_ANALYZERS.get(phase, ()))
    applied_rules: list[AppliedRule] = []

    for rule in rules:
        if not _phase_applies(rule, phase):
            continue
        if rule.action == "avoid" and rule.target_type == "phase" and rule.target == phase:
            applied_rules.append(_to_applied_rule(rule))
            return RuleDecision(
                selected_analyzers=[],
                applied_rules=_dedupe_rules(applied_rules),
                blocked_reason=f"Phase '{phase}' blocked by avoid rule '{rule.target}'.",
            )

    remaining = [analyzer for analyzer in analyzers if not _is_avoided(analyzer, phase, rules, applied_rules)]
    focus_scores = {analyzer.name: _focus_score(analyzer, phase, rules, applied_rules) for analyzer in remaining}
    ordered = sorted(remaining, key=lambda analyzer: (-focus_scores[analyzer.name], analyzer.name))
    return RuleDecision(
        selected_analyzers=[analyzer.name for analyzer in ordered],
        applied_rules=_dedupe_rules(applied_rules),
    )


def _phase_applies(rule: RuleConfig, phase: str) -> bool:
    return not rule.phases or phase in rule.phases


def _is_avoided(
    analyzer: AnalyzerSpec,
    phase: str,
    rules: list[RuleConfig],
    applied_rules: list[AppliedRule],
) -> bool:
    for rule in rules:
        if rule.action != "avoid" or not _phase_applies(rule, phase):
            continue
        if rule.target_type == "analyzer" and rule.target == analyzer.name:
            applied_rules.append(_to_applied_rule(rule))
            return True
        if rule.target_type == "tag" and rule.target in analyzer.tags:
            applied_rules.append(_to_applied_rule(rule))
            return True
    return False


def _focus_score(
    analyzer: AnalyzerSpec,
    phase: str,
    rules: list[RuleConfig],
    applied_rules: list[AppliedRule],
) -> int:
    score = 0
    for rule in rules:
        if rule.action != "focus" or not _phase_applies(rule, phase):
            continue
        if rule.target_type == "phase" and rule.target == phase:
            score += 1
            applied_rules.append(_to_applied_rule(rule))
        elif rule.target_type == "analyzer" and rule.target == analyzer.name:
            score += 2
            applied_rules.append(_to_applied_rule(rule))
        elif rule.target_type == "tag" and rule.target in analyzer.tags:
            score += 2
            applied_rules.append(_to_applied_rule(rule))
    return score


def _to_applied_rule(rule: RuleConfig) -> AppliedRule:
    return AppliedRule(action=rule.action, target_type=rule.target_type, target=rule.target)


def _dedupe_rules(rules: list[AppliedRule]) -> list[AppliedRule]:
    seen: set[tuple[str, str, str]] = set()
    deduped: list[AppliedRule] = []
    for rule in rules:
        key = (rule.action, rule.target_type, rule.target)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(rule)
    return deduped
