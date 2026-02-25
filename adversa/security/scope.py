from __future__ import annotations

from pathlib import Path


class ScopeViolationError(ValueError):
    pass


def ensure_repo_in_repos_root(repo_path: Path, repos_root: Path) -> Path:
    repo_resolved = repo_path.expanduser().resolve()
    root_resolved = repos_root.expanduser().resolve()

    try:
        repo_resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise ScopeViolationError(
            f"Repository must be inside {root_resolved}. Got: {repo_resolved}"
        ) from exc

    return repo_resolved
