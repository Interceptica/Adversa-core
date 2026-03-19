"""Shared utilities for reading agent-written files and extracting content from messages."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


def read_agent_written_file(path: Path | None) -> str:
    """Read a file the agent wrote via write_file tool."""
    if path and path.exists():
        try:
            return path.read_text(encoding="utf-8").strip()
        except OSError:
            pass
    return ""


def read_agent_written_json(path: Path, model_cls: type[T]) -> T | None:
    """Read and validate a JSON file written by the agent. Returns None on any error."""
    content = read_agent_written_file(path)
    if not content:
        return None
    try:
        return model_cls.model_validate_json(content)
    except Exception:
        pass
    try:
        data = json.loads(content)
        return model_cls.model_validate(data)
    except Exception:
        return None


def extract_markdown_from_messages(messages: list, min_length: int = 500) -> str:
    """Fallback: extract markdown from last substantial agent message.

    Handles both standard models (content field) and thinking/reasoning models
    that put analysis in additional_kwargs['reasoning_content'].
    Also handles multimodal messages where content is a list of content blocks.
    """
    for msg in reversed(messages):
        raw = getattr(msg, "content", "") or ""
        if isinstance(raw, list):
            parts = []
            for block in raw:
                if isinstance(block, str):
                    parts.append(block)
                elif isinstance(block, dict):
                    parts.append(block.get("text", "") or "")
            raw = "\n".join(parts)
        if not raw:
            raw = (getattr(msg, "additional_kwargs", {}) or {}).get("reasoning_content", "") or ""
        content = raw.strip()
        if content and len(content) >= min_length:
            return content
    return ""


def extract_json_from_messages(messages: list, model_cls: type[T]) -> T | None:
    """Fallback: try to parse schema JSON from the last AI message content."""
    for msg in reversed(messages):
        raw = getattr(msg, "content", "") or ""
        if isinstance(raw, list):
            parts = []
            for block in raw:
                if isinstance(block, str):
                    parts.append(block)
                elif isinstance(block, dict):
                    parts.append(block.get("text", "") or "")
            raw = "\n".join(parts)
        content: str = raw or ""
        if not content:
            content = (getattr(msg, "additional_kwargs", {}) or {}).get("reasoning_content", "") or ""
        if not content:
            continue
        try:
            data = json.loads(content.strip())
            return model_cls.model_validate(data)
        except Exception:
            pass
        for match in re.finditer(r"\{[\s\S]*\}", content):
            try:
                data = json.loads(match.group())
                return model_cls.model_validate(data)
            except Exception:
                continue
    return None
