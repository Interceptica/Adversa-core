from __future__ import annotations

from urllib.parse import urlparse

from adversa.config.models import AdversaConfig
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
    host = parsed.hostname or ""
    path = parsed.path or "/"

    confidence_gaps: list[str] = []
    if not notes:
        confidence_gaps.append("Operator notes were not provided during intake.")
    if not focus_paths:
        confidence_gaps.append("No explicit focus paths were provided; later phases should infer priorities cautiously.")

    return ScopeContract(
        target_url=url,
        repo_path=repo_path,
        workspace=workspace,
        authorized=authorized,
        safe_mode=cfg.safety.safe_mode,
        allowed_hosts=[host] if host else [],
        allowed_paths=sorted({path, *focus_paths}),
        exclusions=sorted({*avoid_paths, *exclusions}),
        notes=notes,
        rules_summary={
            "focus": focus_paths,
            "avoid": avoid_paths,
        },
        confidence_gaps=confidence_gaps,
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
