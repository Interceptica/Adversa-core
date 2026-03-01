from __future__ import annotations

from adversa.config.models import AdversaConfig
from adversa.security.rule_compiler import compile_rules
from adversa.security.rules import RuntimeTarget, evaluate_rules
from adversa.state.models import PHASES, PhaseExpectation, PlanBudget, PlanWarning, RunPlan


PHASE_REQUIRED_ARTIFACTS: dict[str, list[str]] = {
    "intake": ["scope.json", "plan.json", "coverage_intake.json"],
    "prerecon": ["pre_recon.json"],
    "netdisc": ["network_discovery.json"],
    "recon": ["system_map.json", "attack_surface.json"],
    "vuln": ["findings.json", "risk_register.json"],
    "report": ["report.md", "exec_summary.md", "retest_plan.json"],
}

PHASE_GOALS: dict[str, list[str]] = {
    "intake": [
        "Normalize target inputs into an execution contract.",
        "Select analyzers and safe-mode budgets for downstream phases.",
    ],
    "prerecon": [
        "Collect repository and target metadata before active recon.",
    ],
    "netdisc": [
        "Discover network hosts, services, and TLS configurations within authorized scope.",
        "Provide baseline network intelligence for downstream recon.",
    ],
    "recon": [
        "Map the exposed system surface and supporting security models.",
    ],
    "vuln": [
        "Run safe verification analyzers against authorized surfaces only.",
    ],
    "report": [
        "Assemble evidence-backed findings and retest guidance.",
    ],
}


def build_run_plan(
    *,
    url: str,
    repo_path: str,
    config: AdversaConfig,
    safe_mode: bool,
) -> RunPlan:
    compiled_rules = compile_rules(config)
    phase_expectations: list[PhaseExpectation] = []
    warnings: list[PlanWarning] = []

    base_constraints = [
        "Authorization-first execution only.",
        "Safe-mode verification only; destructive testing is not allowed.",
        "Repository access must stay inside the configured repos root.",
        "All findings remain hypotheses until linked to evidence.",
    ]
    if not config.safety.network_discovery_enabled:
        base_constraints.append("Network discovery remains disabled unless explicitly enabled in config.")

    for phase in PHASES:
        decision = evaluate_rules(
            RuntimeTarget.from_inputs(
                phase=phase,
                url=url,
                repo_path=repo_path,
            ),
            compiled_rules,
        )
        if decision.blocked_reason:
            warnings.append(PlanWarning(code=f"{phase}_blocked", message=decision.blocked_reason))
        if not decision.selected_analyzers:
            warnings.append(
                PlanWarning(
                    code=f"{phase}_no_analyzers",
                    message=f"Phase '{phase}' has no selected analyzers after applying focus/avoid rules.",
                )
            )

        phase_constraints = list(base_constraints)
        if phase == "recon" and not config.safety.network_discovery_enabled:
            phase_constraints.append("Recon must rely on approved metadata and repository context only.")
        if phase == "vuln":
            phase_constraints.append("Only safe verification analyzers may execute in vuln.")

        phase_expectations.append(
            PhaseExpectation(
                phase=phase,
                selected_analyzers=decision.selected_analyzers,
                required_artifacts=PHASE_REQUIRED_ARTIFACTS[phase],
                goals=PHASE_GOALS[phase],
                constraints=phase_constraints,
            )
        )

    analyzer_count = sum(len(expectation.selected_analyzers) for expectation in phase_expectations)
    budgets = PlanBudget(
        time_budget_minutes=20 + analyzer_count * 5,
        token_budget=12000 + analyzer_count * 1500,
        cost_budget_usd=round(2.0 + analyzer_count * 0.35, 2),
        tool_call_budget=max(12, analyzer_count * 4),
    )
    max_concurrent_pipelines = 1 if safe_mode else 2
    rationale = (
        "Plan derived deterministically from workflow phases, current focus/avoid rules, "
        "safe-mode defaults, and analyzer surface matching. "
        "Operator rules can reprioritize analyzers or block unsafe boundaries, but the controller "
        "remains the source of truth for budgets, concurrency, and output requirements."
    )

    return RunPlan(
        phases=list(PHASES),
        phase_expectations=phase_expectations,
        budgets=budgets,
        max_concurrent_pipelines=max_concurrent_pipelines,
        constraints=base_constraints,
        warnings=_dedupe_warnings(warnings),
        rationale=rationale,
        safe_mode=safe_mode,
    )


def _dedupe_warnings(warnings: list[PlanWarning]) -> list[PlanWarning]:
    seen: set[tuple[str, str]] = set()
    deduped: list[PlanWarning] = []
    for warning in warnings:
        key = (warning.code, warning.message)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(warning)
    return deduped
