from __future__ import annotations

import re
from typing import Any

SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?([\w\-\.]+)['\"]?"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9\-\._~\+\/=]+"),
]


def redact_text(value: str) -> str:
    out = value
    for pattern in SECRET_PATTERNS:
        out = pattern.sub(lambda m: m.group(0).split(m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(0))[0] + "[REDACTED]", out)
    return out


def redact_obj(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: redact_obj(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_obj(v) for v in value]
    return value
