from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from adversa.logging.redaction import redact_obj


class AuditLogger:
    def __init__(self, logs_dir: Path):
        logs_dir.mkdir(parents=True, exist_ok=True)
        self.tool_calls = logs_dir / "tool_calls.jsonl"
        self.agent_events = logs_dir / "agent_events.jsonl"

    def log_tool_call(self, event: dict[str, Any]) -> None:
        self._append(self.tool_calls, event)

    def log_agent_event(self, event: dict[str, Any]) -> None:
        self._append(self.agent_events, event)

    def _append(self, path: Path, event: dict[str, Any]) -> None:
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            **redact_obj(event),
        }
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, sort_keys=True) + "\n")
