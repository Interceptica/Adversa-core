from __future__ import annotations

from enum import Enum


class LLMErrorKind(str, Enum):
    TRANSIENT = "transient"
    CONFIG_REQUIRED = "config_required"
    FATAL = "fatal"


class LLMProviderError(RuntimeError):
    def __init__(self, message: str, kind: LLMErrorKind):
        super().__init__(message)
        self.kind = kind
