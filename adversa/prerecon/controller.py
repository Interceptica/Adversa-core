from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from langgraph.graph import END, START, StateGraph
from typing_extensions import TypedDict

from adversa.artifacts.store import ArtifactStore
from adversa.config.load import load_config
from adversa.security.scope import ScopeViolationError, ensure_repo_in_repos_root
from adversa.state.models import PreReconReport


class PrereconState(TypedDict, total=False):
    workspace_root: str
    workspace: str
    run_id: str
    repo_path: str
    url: str
    config_path: str
    scope_inputs: dict[str, Any]
    plan_inputs: dict[str, Any]
    repo_top_level_entries: list[str]
    framework_signals: list[str]
    candidate_routes: list[str]
    host: str
    path: str
    repo_root_validated: bool
    warnings: list[str]
    remediation_hints: list[str]


def build_prerecon_report(
    *,
    workspace_root: str,
    workspace: str,
    run_id: str,
    repo_path: str,
    url: str,
    config_path: str,
) -> PreReconReport:
    graph = _build_graph()
    result = graph.invoke(
        {
            "workspace_root": workspace_root,
            "workspace": workspace,
            "run_id": run_id,
            "repo_path": repo_path,
            "url": url,
            "config_path": config_path,
        }
    )
    return PreReconReport(
        target_url=url,
        canonical_url=_canonical_url(url),
        host=result["host"],
        path=result["path"],
        repo_path=repo_path,
        repo_root_validated=result["repo_root_validated"],
        repo_top_level_entries=result["repo_top_level_entries"],
        framework_signals=result["framework_signals"],
        candidate_routes=result["candidate_routes"],
        scope_inputs=result["scope_inputs"],
        plan_inputs=result["plan_inputs"],
        warnings=result["warnings"],
        remediation_hints=result["remediation_hints"],
    )


def _build_graph():
    graph = StateGraph(PrereconState)
    graph.add_node("load_inputs", _load_inputs)
    graph.add_node("inspect_repo", _inspect_repo)
    graph.add_node("finalize", _finalize)
    graph.add_edge(START, "load_inputs")
    graph.add_edge("load_inputs", "inspect_repo")
    graph.add_edge("inspect_repo", "finalize")
    graph.add_edge("finalize", END)
    return graph.compile()


def _load_inputs(state: PrereconState) -> PrereconState:
    store = ArtifactStore(Path(state["workspace_root"]), state["workspace"], state["run_id"])
    scope_path = store.phase_dir("intake") / "scope.json"
    plan_path = store.phase_dir("intake") / "plan.json"

    scope_inputs: dict[str, Any] = {}
    plan_inputs: dict[str, Any] = {}
    warnings: list[str] = []
    remediation_hints: list[str] = []

    if scope_path.exists():
        import json

        scope_payload = json.loads(scope_path.read_text(encoding="utf-8"))
        scope_inputs = {
            "normalized_host": scope_payload.get("normalized_host", ""),
            "normalized_path": scope_payload.get("normalized_path", "/"),
            "allowed_paths": scope_payload.get("allowed_paths", []),
            "exclusions": scope_payload.get("exclusions", []),
            "notes": scope_payload.get("notes", []),
            "rules_summary": scope_payload.get("rules_summary", {}),
        }
        warnings.extend(scope_payload.get("warnings", []))
    else:
        warnings.append("Intake scope.json is missing; prerecon is using workflow inputs only.")
        remediation_hints.append("Run intake successfully before prerecon to improve scoped recon quality.")

    if plan_path.exists():
        import json

        plan_payload = json.loads(plan_path.read_text(encoding="utf-8"))
        prerecon_expectation = next(
            (item for item in plan_payload.get("phase_expectations", []) if item.get("phase") == "prerecon"),
            {},
        )
        plan_inputs = {
            "selected_analyzers": prerecon_expectation.get("selected_analyzers", []),
            "required_artifacts": prerecon_expectation.get("required_artifacts", []),
            "constraints": prerecon_expectation.get("constraints", []),
            "goals": prerecon_expectation.get("goals", []),
        }
    else:
        warnings.append("Intake plan.json is missing; prerecon is using default analyzer assumptions.")
        remediation_hints.append("Regenerate plan.json so prerecon and recon share the same execution contract.")

    parsed = urlparse(state["url"])
    return {
        "scope_inputs": scope_inputs,
        "plan_inputs": plan_inputs,
        "host": (parsed.hostname or "").lower(),
        "path": parsed.path or "/",
        "warnings": warnings,
        "remediation_hints": remediation_hints,
    }


def _inspect_repo(state: PrereconState) -> PrereconState:
    cfg = load_config(state["config_path"])
    config_parent = Path(state["config_path"]).resolve().parent
    repos_root = Path(cfg.run.repos_root)
    if not repos_root.is_absolute():
        repos_root = (config_parent / repos_root).resolve()

    try:
        repo_resolved = ensure_repo_in_repos_root(Path(state["repo_path"]), repos_root)
        repo_root_validated = True
    except ScopeViolationError as exc:
        raise ValueError(
            f"Prerecon cannot inspect repo '{state['repo_path']}'. Ensure it is inside '{repos_root}'."
        ) from exc

    warnings = list(state.get("warnings", []))
    remediation_hints = list(state.get("remediation_hints", []))
    if not repo_resolved.exists():
        warnings.append(f"Authorized repo path '{repo_resolved}' does not exist on disk for prerecon inspection.")
        remediation_hints.append("Clone or place the target repository under the configured repos root before recon.")
        return {
            "repo_root_validated": repo_root_validated,
            "repo_top_level_entries": [],
            "framework_signals": [],
            "candidate_routes": sorted({state["path"], *state.get("scope_inputs", {}).get("allowed_paths", [])})[:30],
            "warnings": warnings,
            "remediation_hints": remediation_hints,
        }

    top_level_entries = sorted(path.name for path in repo_resolved.iterdir())[:25]
    framework_signals = _detect_framework_signals(repo_resolved)
    candidate_routes = sorted(
        {
            state["path"],
            *state.get("scope_inputs", {}).get("allowed_paths", []),
            *_discover_candidate_routes(repo_resolved),
        }
    )[:30]

    if not framework_signals:
        warnings.append("Prerecon did not detect strong framework signals from repository files.")
        remediation_hints.append("Provide operator notes or add clearer app manifests to improve framework inference.")
    if len(candidate_routes) <= 1:
        warnings.append("Prerecon inferred very few candidate routes from current inputs.")
        remediation_hints.append("Add focus paths during intake or expose route files in the authorized repo.")

    return {
        "repo_root_validated": repo_root_validated,
        "repo_top_level_entries": top_level_entries,
        "framework_signals": framework_signals,
        "candidate_routes": candidate_routes,
        "warnings": warnings,
        "remediation_hints": remediation_hints,
    }


def _finalize(state: PrereconState) -> PrereconState:
    return state


def _canonical_url(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    return parsed._replace(path=path, params="", query="", fragment="").geturl()


def _detect_framework_signals(repo_root: Path) -> list[str]:
    signals: list[str] = []
    markers = {
        "package.json": "nodejs_app",
        "pnpm-lock.yaml": "pnpm_workspace",
        "yarn.lock": "yarn_workspace",
        "package-lock.json": "npm_lockfile",
        "pyproject.toml": "python_project",
        "requirements.txt": "python_requirements",
        "Dockerfile": "dockerized_app",
        "docker-compose.yml": "docker_compose",
        "next.config.js": "nextjs_app",
        "next.config.ts": "nextjs_app",
        "vite.config.ts": "vite_app",
        "vite.config.js": "vite_app",
        "manage.py": "django_app",
        "pom.xml": "java_maven_project",
        "go.mod": "go_module",
    }
    for marker, signal in markers.items():
        if (repo_root / marker).exists():
            signals.append(signal)
    return sorted(set(signals))


def _discover_candidate_routes(repo_root: Path) -> list[str]:
    candidates: set[str] = set()
    search_roots = [repo_root / "src", repo_root / "app", repo_root / "pages"]
    for base in search_roots:
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in {".py", ".ts", ".tsx", ".js", ".jsx"}:
                continue
            route = _path_to_route(base, path)
            if route:
                candidates.add(route)
            if len(candidates) >= 30:
                break
    return sorted(candidates)


def _path_to_route(base: Path, path: Path) -> str | None:
    relative = path.relative_to(base)
    if relative.name.startswith("_"):
        return None
    parts = list(relative.parts)
    if parts[-1].startswith("index."):
        parts = parts[:-1]
    else:
        parts[-1] = parts[-1].rsplit(".", 1)[0]
    cleaned = [part for part in parts if part and not part.startswith("(")]
    if not cleaned:
        return "/"
    normalized = []
    for part in cleaned:
        if part.startswith("[") and part.endswith("]"):
            normalized.append(f":{part[1:-1]}")
        else:
            normalized.append(part)
    return "/" + "/".join(normalized)
