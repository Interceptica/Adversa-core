"""Tests for markdown parsing utilities."""

from __future__ import annotations

from adversa.utils.markdown import (
    extract_code_blocks,
    extract_file_paths_from_section,
    extract_tables_from_section,
    parse_markdown_section,
)


def test_parse_markdown_section() -> None:
    """Test extracting markdown section by header."""
    markdown = """# Main Title

## Section 1

This is section 1 content.

### Subsection 1.1

Subsection content.

## Section 2

This is section 2 content.
"""

    section1 = parse_markdown_section(markdown, "## Section 1")
    assert "This is section 1 content" in section1
    assert "Subsection content" in section1  # Should include subsections

    section2 = parse_markdown_section(markdown, "Section 2")  # Test without ##
    assert "This is section 2 content" in section2


def test_parse_markdown_section_not_found() -> None:
    """Test parsing non-existent section returns empty string."""
    markdown = """# Title

## Section 1

Content here.
"""

    result = parse_markdown_section(markdown, "## Section 99")
    assert result == ""


def test_extract_tables_from_section() -> None:
    """Test extracting markdown tables."""
    section = """
### Auth Signals

| Signal Type | File:Line | Evidence | Confidence |
|-------------|-----------|----------|------------|
| JWT Auth | auth.js:20 | jwt.verify() | HIGH |
| Session Cookie | session.js:15 | express-session | MEDIUM |

Some text between tables.

| Another | Table |
|---------|-------|
| Row 1 | Data 1 |
| Row 2 | Data 2 |
"""

    tables = extract_tables_from_section(section)
    assert len(tables) == 2

    # First table
    assert tables[0]["headers"] == ["Signal Type", "File:Line", "Evidence", "Confidence"]
    assert len(tables[0]["rows"]) == 2
    assert tables[0]["rows"][0] == ["JWT Auth", "auth.js:20", "jwt.verify()", "HIGH"]

    # Second table
    assert tables[1]["headers"] == ["Another", "Table"]
    assert len(tables[1]["rows"]) == 2


def test_extract_code_blocks() -> None:
    """Test extracting code blocks from markdown."""
    markdown = """
Some text here.

```python
def hello():
    print("world")
```

More text.

```javascript
console.log("test");
```

```
Plain code block
```
"""

    # Extract all code blocks
    all_blocks = extract_code_blocks(markdown)
    assert len(all_blocks) == 3
    assert 'def hello():' in all_blocks[0]
    assert 'console.log' in all_blocks[1]

    # Extract only Python blocks
    python_blocks = extract_code_blocks(markdown, language="python")
    assert len(python_blocks) == 1
    assert 'def hello():' in python_blocks[0]

    # Extract only JavaScript blocks
    js_blocks = extract_code_blocks(markdown, language="javascript")
    assert len(js_blocks) == 1
    assert 'console.log' in js_blocks[0]


def test_extract_file_paths_from_section() -> None:
    """Test extracting file paths from markdown section."""
    section = """
Found vulnerabilities in:
- `routes/auth.js:42`
- `controllers/user.py:120`
- `middleware/cors.ts`

Also check `config/database.js` for credentials.
"""

    paths = extract_file_paths_from_section(section)

    assert "routes/auth.js" in paths
    assert "controllers/user.py" in paths
    assert "middleware/cors.ts" in paths
    assert "config/database.js" in paths

    # Should not include line numbers
    assert "routes/auth.js:42" not in paths


def test_extract_file_paths_deduplication() -> None:
    """Test file path extraction deduplicates paths."""
    section = """
- `test.py:1`
- `test.py:2`
- `other.js`
"""

    paths = extract_file_paths_from_section(section)

    assert len(paths) == 2  # test.py and other.js
    assert "test.py" in paths
    assert "other.js" in paths


def test_extract_tables_with_empty_cells() -> None:
    """Test table extraction handles empty cells."""
    section = """
| Name | Value | Notes |
|------|-------|-------|
| Foo | 123 | |
| Bar | | Some note |
"""

    tables = extract_tables_from_section(section)
    assert len(tables) == 1
    assert tables[0]["rows"][0] == ["Foo", "123", ""]
    assert tables[0]["rows"][1] == ["Bar", "", "Some note"]
