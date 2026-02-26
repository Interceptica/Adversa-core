from typer.testing import CliRunner

from adversa.cli import app


def test_status_help_mentions_workspace_guidance() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["status", "--help"])
    assert result.exit_code == 0
    assert "Workspace name" in result.stdout
    assert "latest run in the workspace" in result.stdout
