"""Markdown parsing utilities for extracting data from phase reports.

This module provides helpers for downstream phases to parse markdown artifacts
and extract structured data without requiring JSON schemas.
"""

from __future__ import annotations

import re
from pathlib import Path


def parse_markdown_section(markdown: str, section_header: str) -> str:
    """Extract content from a markdown section by header.

    Args:
        markdown: Full markdown document
        section_header: Section title to extract (e.g., "## 3. Authentication")

    Returns:
        Section content as string, empty if not found
    """
    # Normalize header format
    if not section_header.startswith("#"):
        section_header = f"## {section_header}"

    # Count header level
    header_level = section_header.count("#")

    # Match section from header to next header of same or higher level
    # Use negative lookahead to stop at headers with equal or fewer # symbols
    pattern = rf"^{re.escape(section_header)}$\n(.*?)(?=^#{{{1,{header_level}}}}\s|\Z)"
    match = re.search(pattern, markdown, re.MULTILINE | re.DOTALL)

    if match:
        return match.group(1).strip()
    return ""


def extract_tables_from_section(section_content: str) -> list[dict[str, list[str]]]:
    """Extract all markdown tables from a section.

    Args:
        section_content: Markdown section content

    Returns:
        List of tables, each as dict with 'headers' and 'rows' keys
    """
    tables = []

    # Pattern to match markdown tables
    table_pattern = r"\|(.+)\|\n\|[-:\s|]+\|\n((?:\|.+\|\n?)+)"
    matches = re.finditer(table_pattern, section_content)

    for match in matches:
        header_line = match.group(1)
        rows_block = match.group(2)

        # Parse headers - remove leading/trailing pipes
        header_cells = header_line.strip("|").split("|")
        headers = [h.strip() for h in header_cells]

        # Parse rows - preserve empty cells
        rows = []
        for line in rows_block.strip().split("\n"):
            if line.startswith("|"):
                # Remove leading/trailing pipes and split
                row_cells = line.strip("|").split("|")
                cells = [c.strip() for c in row_cells]
                if cells:  # Skip completely empty rows
                    rows.append(cells)

        tables.append({"headers": headers, "rows": rows})

    return tables


def extract_code_blocks(markdown: str, language: str | None = None) -> list[str]:
    """Extract code blocks from markdown.

    Args:
        markdown: Markdown content
        language: Optional language filter (e.g., 'python', 'bash')

    Returns:
        List of code block contents
    """
    if language:
        pattern = rf"```{re.escape(language)}\n(.*?)```"
    else:
        pattern = r"```(?:\w+)?\n(.*?)```"

    matches = re.findall(pattern, markdown, re.DOTALL)
    return [m.strip() for m in matches]


def load_upstream_markdown(phase_dir: Path, filename: str) -> str:
    """Load markdown artifact from upstream phase.

    Args:
        phase_dir: Path to phase artifacts directory
        filename: Markdown filename (e.g., 'pre_recon_analysis.md')

    Returns:
        Markdown content as string

    Raises:
        FileNotFoundError: If markdown file doesn't exist
    """
    markdown_path = phase_dir / filename
    if not markdown_path.exists():
        raise FileNotFoundError(f"Markdown artifact not found: {markdown_path}")

    return markdown_path.read_text(encoding="utf-8")


def extract_file_paths_from_section(section_content: str) -> list[str]:
    """Extract file paths from markdown section.

    Looks for code-formatted paths like `path/to/file.py` or `file.py:123`.

    Args:
        section_content: Markdown section content

    Returns:
        List of file paths
    """
    # Match code-formatted paths
    pattern = r"`([^`]+\.(py|js|ts|tsx|jsx|go|rs|java|rb|php|c|cpp|h|hpp|cs)(?::\d+)?)`"
    matches = re.findall(pattern, section_content)

    # Remove line numbers from file:line format
    paths = [match[0].split(":")[0] for match in matches]

    return list(set(paths))  # Deduplicate
