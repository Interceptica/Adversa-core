from __future__ import annotations

from enum import Enum


class ControlSignal(str, Enum):
    PAUSE = "PAUSE"
    RESUME = "RESUME"
    UPDATE_CONFIG = "UPDATE_CONFIG"
    CANCEL = "CANCEL"
