import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "changelog_section", REPO / "scripts" / "changelog-section.py"
)
cs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cs)


CHANGELOG = """\
# Changelog

## [0.7.2] - 2026-06-26

Headline summary line.

### Added

- **A feature.** Details.

## [0.7.1] - 2026-06-17

### Fixed

- Older stuff.
"""


def test_extract_returns_only_the_requested_section(tmp_path):
    f = tmp_path / "CHANGELOG.md"
    f.write_text(CHANGELOG)
    body = cs.extract(str(f), "0.7.2")
    assert body.startswith("Headline summary line.")
    assert "### Added" in body
    assert "**A feature.**" in body
    # Must stop at the next version heading.
    assert "0.7.1" not in body
    assert "Older stuff" not in body


def test_extract_trims_surrounding_blank_lines(tmp_path):
    f = tmp_path / "CHANGELOG.md"
    f.write_text(CHANGELOG)
    body = cs.extract(str(f), "0.7.2")
    assert body == body.strip()


def test_extract_missing_version_is_empty(tmp_path):
    f = tmp_path / "CHANGELOG.md"
    f.write_text(CHANGELOG)
    assert cs.extract(str(f), "9.9.9") == ""
