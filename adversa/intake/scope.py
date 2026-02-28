from __future__ import annotations

from urllib.parse import urlparse

from adversa.config.models import AdversaConfig
from adversa.security.rule_compiler import compile_rules
from adversa.state.models import IntakeCoverage, ScopeContract


def build_scope_contract(
    *,
    url: str,
    repo_path: str,
    workspace: str,
    authorized: bool,
    cfg: AdversaConfig,
    focus_paths: list[str],
    avoid_paths: list[str],
    exclusions: list[str],
    notes: list[str],
) -> ScopeContract:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    subdomain = _extract_subdomain(host)
    compiled_rules = compile_rules(cfg)

    confidence_gaps: list[str] = []
    warnings: list[str] = []
    if not notes:
        confidence_gaps.append("Operator notes were not provided during intake.")
    if not focus_paths:
        confidence_gaps.append("No explicit focus paths were provided; later phases should infer priorities cautiously.")
    if exclusions and avoid_paths:
        overlap = sorted(set(exclusions).intersection(avoid_paths))
        if overlap:
            warnings.append(f"Exclusions overlap with avoid rules: {', '.join(overlap)}")

    capability_constraints = [
        "safe_mode_only" if cfg.safety.safe_mode else "operator_override_required",
        "network_discovery_disabled" if not cfg.safety.network_discovery_enabled else "network_discovery_enabled",
        "repo_root_enforced",
    ]
    evidence_expectations = [
        "All findings must link to evidence references.",
        "Audit logs must capture rule-driven scope restrictions.",
        "Unsafe boundaries must be preserved as warnings or hard blocks.",
    ]

    rules_summary = {
        "focus": _rule_entries(compiled_rules, action="focus"),
        "avoid": _rule_entries(compiled_rules, action="avoid"),
    }

    return ScopeContract(
        target_url=url,
        repo_path=repo_path,
        workspace=workspace,
        authorized=authorized,
        safe_mode=cfg.safety.safe_mode,
        source_precedence=["cli", "interactive_intake", "config", "rules", "safe_defaults"],
        normalized_host=host,
        normalized_path=path,
        allowed_hosts=[host] if host else [],
        allowed_subdomains=[subdomain] if subdomain else [],
        allowed_paths=sorted({path, *focus_paths}),
        exclusions=sorted({*avoid_paths, *exclusions}),
        capability_constraints=capability_constraints,
        repo_root_validated=True,
        evidence_expectations=evidence_expectations,
        notes=notes,
        rules_summary=rules_summary,
        confidence_gaps=confidence_gaps,
        warnings=warnings,
    )


def build_intake_coverage(
    *,
    answered_fields: list[str],
    warnings: list[str],
    pending_fields: list[str] | None = None,
) -> IntakeCoverage:
    pending = pending_fields or []
    return IntakeCoverage(
        phase="intake",
        status="incomplete" if pending else "complete",
        answered_fields=answered_fields,
        pending_fields=pending,
        warnings=warnings,
    )


def _rule_entries(compiled_rules, *, action: str):  # type: ignore[no-untyped-def]
    return [
        {
            "type": rule.target_type,
            "value": rule.target,
            "source": "config_or_intake",
        }
        for rule in compiled_rules
        if rule.action == action
    ]


def _extract_subdomain(host: str) -> str:
    parts = [part for part in host.split(".") if part]
    if len(parts) <= 2:
        return ""
    return ".".join(parts[:-2])
