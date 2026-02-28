from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from urllib.parse import urlparse

from adversa.security.rule_compiler import CompiledRule


@dataclass(frozen=True)
class AnalyzerSpec:
    name: str
    tags: tuple[str, ...]
    surfaces: tuple[str, ...]
    methods: tuple[str, ...] = ()


@dataclass(frozen=True)
class AppliedRule:
    action: str
    target_type: str
    target: str
    description: str | None = None


@dataclass(frozen=True)
class RuleDecision:
    selected_analyzers: list[str]
    applied_rules: list[AppliedRule]
    blocked_reason: str | None = None


@dataclass(frozen=True)
class RuntimeBoundaryDecision:
    applied_rules: list[AppliedRule]
    blocked_reason: str | None = None
    focus_score: int = 0


@dataclass(frozen=True)
class RuntimeTarget:
    phase: str
    host: str
    subdomain: str
    path: str
    repo_path: str
    method: str | None = None

    @classmethod
    def from_inputs(cls, *, phase: str, url: str, repo_path: str, method: str | None = None) -> "RuntimeTarget":
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        return cls(
            phase=phase,
            host=host,
            subdomain=_extract_subdomain(host),
            path=parsed.path or "/",
            repo_path=repo_path,
            method=method.upper() if method else None,
        )


PHASE_ANALYZERS: dict[str, tuple[AnalyzerSpec, ...]] = {
    "intake": (
        AnalyzerSpec("scope_planner", ("planning", "scope"), ("host", "subdomain", "path")),
        AnalyzerSpec("repo_inventory", ("filesystem", "planning"), ("repo_path",)),
    ),
    "prerecon": (
        AnalyzerSpec("repo_inventory", ("filesystem", "planning"), ("repo_path",)),
        AnalyzerSpec("baseline_metadata", ("metadata", "planning"), ("host", "subdomain", "path")),
    ),
    "recon": (
        AnalyzerSpec("attack_surface_mapper", ("network", "discovery"), ("host", "subdomain", "path", "method")),
        AnalyzerSpec("auth_model_builder", ("auth", "modeling"), ("host", "path", "method")),
        AnalyzerSpec("data_flow_mapper", ("data-flow", "modeling"), ("path", "method")),
    ),
    "vuln": (
        AnalyzerSpec("static_safe_checks", ("safe", "code"), ("repo_path", "path", "method")),
        AnalyzerSpec("dependency_review", ("dependencies", "safe"), ("repo_path",)),
        AnalyzerSpec("config_review", ("configuration", "safe"), ("repo_path", "path")),
    ),
    "report": (
        AnalyzerSpec("finding_summarizer", ("reporting", "summary"), ("host", "path", "repo_path")),
        AnalyzerSpec("retest_planner", ("reporting", "planning"), ("host", "path", "repo_path", "method")),
    ),
}

HARD_BLOCK_TARGET_TYPES = {"phase", "host", "subdomain", "repo_path"}


def evaluate_rules(target: RuntimeTarget, rules: list[CompiledRule]) -> RuleDecision:
    analyzers = list(PHASE_ANALYZERS.get(target.phase, ()))
    applied_rules: list[AppliedRule] = []

    for rule in rules:
        if not _phase_applies(rule, target.phase):
            continue
        if (
            rule.action == "avoid"
            and rule.target_type in HARD_BLOCK_TARGET_TYPES
            and _matches_runtime_target(rule, target)
        ):
            applied_rules.append(_to_applied_rule(rule))
            return RuleDecision(
                selected_analyzers=[],
                applied_rules=_dedupe_rules(applied_rules),
                blocked_reason=_blocked_reason(rule, target),
            )

    remaining = [analyzer for analyzer in analyzers if not _is_avoided(analyzer, target, rules, applied_rules)]
    focus_scores = {analyzer.name: _focus_score(analyzer, target, rules, applied_rules) for analyzer in remaining}
    ordered = sorted(remaining, key=lambda analyzer: (-focus_scores[analyzer.name], analyzer.name))
    return RuleDecision(
        selected_analyzers=[analyzer.name for analyzer in ordered],
        applied_rules=_dedupe_rules(applied_rules),
    )


def evaluate_runtime_boundary(target: RuntimeTarget, rules: list[CompiledRule]) -> RuntimeBoundaryDecision:
    applied_rules: list[AppliedRule] = []
    focus_score = 0

    for rule in rules:
        if not _phase_applies(rule, target.phase):
            continue
        if not _matches_runtime_target(rule, target):
            continue
        if rule.action == "avoid":
            applied_rules.append(_to_applied_rule(rule))
            return RuntimeBoundaryDecision(
                applied_rules=_dedupe_rules(applied_rules),
                blocked_reason=_blocked_reason(rule, target),
                focus_score=focus_score,
            )
        if rule.action == "focus":
            focus_score += 1
            applied_rules.append(_to_applied_rule(rule))

    return RuntimeBoundaryDecision(applied_rules=_dedupe_rules(applied_rules), focus_score=focus_score)


def _phase_applies(rule: CompiledRule, phase: str) -> bool:
    return not rule.phases or phase in rule.phases


def _is_avoided(
    analyzer: AnalyzerSpec,
    target: RuntimeTarget,
    rules: list[CompiledRule],
    applied_rules: list[AppliedRule],
) -> bool:
    for rule in rules:
        if rule.action != "avoid" or not _phase_applies(rule, target.phase):
            continue
        if rule.target_type == "analyzer" and rule.target == analyzer.name:
            applied_rules.append(_to_applied_rule(rule))
            return True
        if rule.target_type == "tag" and rule.target in analyzer.tags:
            applied_rules.append(_to_applied_rule(rule))
            return True
        if rule.target_type in analyzer.surfaces and _matches_runtime_target(rule, target):
            applied_rules.append(_to_applied_rule(rule))
            return True
    return False


def _focus_score(
    analyzer: AnalyzerSpec,
    target: RuntimeTarget,
    rules: list[CompiledRule],
    applied_rules: list[AppliedRule],
) -> int:
    score = 0
    for rule in rules:
        if rule.action != "focus" or not _phase_applies(rule, target.phase):
            continue
        if rule.target_type == "analyzer" and rule.target == analyzer.name:
            score += 2
            applied_rules.append(_to_applied_rule(rule))
        elif rule.target_type == "tag" and rule.target in analyzer.tags:
            score += 2
            applied_rules.append(_to_applied_rule(rule))
        elif rule.target_type in analyzer.surfaces and _matches_runtime_target(rule, target):
            score += 1
            applied_rules.append(_to_applied_rule(rule))
    return score


def _matches_runtime_target(rule: CompiledRule, target: RuntimeTarget) -> bool:
    if rule.target_type == "phase":
        return rule.target == target.phase
    if rule.target_type == "host":
        return fnmatch(target.host, rule.target.lower())
    if rule.target_type == "subdomain":
        return fnmatch(target.subdomain, rule.target.lower())
    if rule.target_type == "path":
        return fnmatch(target.path, rule.target)
    if rule.target_type == "repo_path":
        return fnmatch(target.repo_path, rule.target)
    if rule.target_type == "method":
        return target.method is not None and fnmatch(target.method, rule.target.upper())
    return False


def _blocked_reason(rule: CompiledRule, target: RuntimeTarget) -> str:
    boundary = {
        "phase": target.phase,
        "host": target.host,
        "subdomain": target.subdomain,
        "path": target.path,
        "repo_path": target.repo_path,
        "method": target.method or "",
    }.get(rule.target_type, rule.target)
    if rule.description:
        return f"Phase '{target.phase}' blocked by avoid rule '{rule.description}' on {rule.target_type} '{boundary}'."
    return f"Phase '{target.phase}' blocked by avoid rule '{rule.target}' on {rule.target_type}."


def _to_applied_rule(rule: CompiledRule) -> AppliedRule:
    return AppliedRule(action=rule.action, target_type=rule.target_type, target=rule.target, description=rule.description)


def _dedupe_rules(rules: list[AppliedRule]) -> list[AppliedRule]:
    seen: set[tuple[str, str, str, str | None]] = set()
    deduped: list[AppliedRule] = []
    for rule in rules:
        key = (rule.action, rule.target_type, rule.target, rule.description)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(rule)
    return deduped


def _extract_subdomain(host: str) -> str:
    parts = [part for part in host.split(".") if part]
    if len(parts) <= 2:
        return ""
    return ".".join(parts[:-2])
