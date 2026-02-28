from __future__ import annotations

from typer.testing import CliRunner

from adversa.cli import app


def test_cli_intake_command_runs_interactive_flow_and_starts_workflow(monkeypatch, tmp_path):  # type: ignore[no-untyped-def]
    started: dict[str, object] = {}

    async def fake_get_client():  # type: ignore[no-untyped-def]
        return object()

    async def fake_start_run(_client, workflow_id, payload):  # type: ignore[no-untyped-def]
        started["workflow_id"] = workflow_id
        started["payload"] = payload

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("adversa.cli.get_client", fake_get_client)
    monkeypatch.setattr("adversa.cli.start_run", fake_start_run)

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["intake"],
        input="\n".join(
            [
                "yes",
                "repos/target",
                "https://staging.example.com/api/users",
                "ws",
                "yes",
                "",
                "/logout",
                "",
                "",
            ]
        )
        + "\n",
    )

    assert result.exit_code == 0
    assert "Started workflow adversa-ws-" in result.output
    assert str(started["workflow_id"]).startswith("adversa-ws-")
    payload = started["payload"]
    assert payload["workspace"] == "ws"
    assert payload["url"] == "https://staging.example.com/api/users"

