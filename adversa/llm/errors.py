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

    def __repr__(self) -> str:
        return f"LLMProviderError(kind={self.kind.value!r}, message={str(self)!r})"
