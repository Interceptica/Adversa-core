from __future__ import annotations

import re
from typing import Any

SECRET_KEY_PATTERN = re.compile(r"(?i)(api[_-]?key|token|secret|password)")
SECRET_VALUE_PATTERNS = [
    re.compile(r"(?i)(bearer\s+)([A-Za-z0-9\-\._~\+\/=]+)"),
    re.compile(r"(?i)((api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?)([\w\-\.]+)(['\"]?)"),
]


def redact_text(value: str) -> str:
    redacted = value
    for pattern in SECRET_VALUE_PATTERNS:
        redacted = pattern.sub(_replace_secret_match, redacted)
    return redacted


def redact_obj(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if SECRET_KEY_PATTERN.search(str(key)) else redact_obj(inner)
            for key, inner in value.items()
        }
    if isinstance(value, list):
        return [redact_obj(inner) for inner in value]
    return value


def _replace_secret_match(match: re.Match[str]) -> str:
    if match.lastindex == 2:
        return f"{match.group(1)}[REDACTED]"
    if match.lastindex and match.lastindex >= 4:
        return f"{match.group(1)}[REDACTED]{match.group(4)}"
    return "[REDACTED]"
