from pathlib import Path

from adversa.artifacts.store import latest_run_id


def test_latest_run_id_selects_most_recent(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    (ws / "run-old").mkdir(parents=True)
    (ws / "run-new").mkdir(parents=True)
    assert latest_run_id(tmp_path, "ws") == "run-new"
