from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse


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


def ensure_safe_target_url(url: str, *, network_discovery_enabled: bool = False) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ScopeViolationError(f"Invalid target URL: {url}")

    lowered = url.lower()
    if not network_discovery_enabled and any(token in lowered for token in ["prod", "production"]):
        raise ScopeViolationError("Production targets are out of scope by default.")

    return url
