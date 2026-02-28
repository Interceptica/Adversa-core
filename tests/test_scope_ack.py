from __future__ import annotations

from pathlib import Path

import pytest
from typer import BadParameter

from adversa.cli import run
from adversa.config.models import AdversaConfig, RunConfig, SafetyConfig
from adversa.security.scope import ScopeViolationError, ensure_repo_in_repos_root, ensure_safe_target_url


def test_repo_must_be_under_repos_root(tmp_path: Path) -> None:
    repos_root = tmp_path / "repos"
    repos_root.mkdir()
    outside_repo = tmp_path / "elsewhere" / "target"
    outside_repo.mkdir(parents=True)

    with pytest.raises(ScopeViolationError, match="Repository must be inside"):
        ensure_repo_in_repos_root(outside_repo, repos_root)


def test_production_targets_blocked_by_default() -> None:
    with pytest.raises(ScopeViolationError, match="Production targets are out of scope by default"):
        ensure_safe_target_url("https://production.example.com")


def test_network_discovery_opt_in_allows_production_named_url() -> None:
    assert (
        ensure_safe_target_url(
            "https://production.example.com",
            network_discovery_enabled=True,
        )
        == "https://production.example.com"
    )


def test_missing_acknowledgement_blocks_run_start(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "repos"
    repo_dir = repo_root / "target"
    repo_dir.mkdir(parents=True)

    monkeypatch.setattr(
        "adversa.cli.load_config",
        lambda config="adversa.toml": AdversaConfig(
            safety=SafetyConfig(acknowledgement=False, safe_mode=True, network_discovery_enabled=False),
            run=RunConfig(workspace_root=str(tmp_path / "runs"), repos_root=str(repo_root)),
        ),
    )

    with pytest.raises(BadParameter, match="Acknowledgement required"):
        run(
            repo=str(repo_dir),
            url="https://staging.example.com",
            workspace="default",
            config="adversa.toml",
            i_acknowledge=False,
            force=False,
        )


def test_out_of_scope_url_blocks_before_workflow_start(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "repos"
    repo_dir = repo_root / "target"
    repo_dir.mkdir(parents=True)
    started = {"called": False}

    monkeypatch.setattr(
        "adversa.cli.load_config",
        lambda config="adversa.toml": AdversaConfig(
            safety=SafetyConfig(acknowledgement=True, safe_mode=True, network_discovery_enabled=False),
            run=RunConfig(workspace_root=str(tmp_path / "runs"), repos_root=str(repo_root)),
        ),
    )

    async def fake_start_run(*args, **kwargs):  # type: ignore[no-untyped-def]
        started["called"] = True
        return "wf-123"

    async def fake_get_client():  # type: ignore[no-untyped-def]
        return object()

    monkeypatch.setattr("adversa.cli.start_run", fake_start_run)
    monkeypatch.setattr("adversa.cli.get_client", fake_get_client)

    with pytest.raises(BadParameter, match="Production targets are out of scope by default"):
        run(
            repo=str(repo_dir),
            url="https://production.example.com",
            workspace="default",
            config="adversa.toml",
            i_acknowledge=True,
            force=False,
        )

    assert started["called"] is False
