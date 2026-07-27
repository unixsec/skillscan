"""Tests for the shared SKILL.md frontmatter parser.

SECURITY: the alias-refusing loader is the reason this is shared rather than
reimplemented - yaml.safe_load blocks code execution but still expands
anchors/aliases, so a sub-kilobyte nested-alias payload can expand
exponentially and OOM the process. A length cap does not help; the payload is
small by design.
"""

from __future__ import annotations

from common.frontmatter import parse_frontmatter


class TestParseFrontmatter:
    def test_extracts_a_simple_mapping(self) -> None:
        data = b"---\nname: my-skill\nallowed-tools: [Bash, Read]\n---\n# Body\n"
        assert parse_frontmatter(data) == {"name": "my-skill", "allowed-tools": ["Bash", "Read"]}

    def test_no_frontmatter_returns_none(self) -> None:
        assert parse_frontmatter(b"# Just a heading\n") is None

    def test_unterminated_frontmatter_returns_none(self) -> None:
        assert parse_frontmatter(b"---\nname: x\n") is None

    def test_non_mapping_frontmatter_returns_none(self) -> None:
        assert parse_frontmatter(b"---\n- just\n- a list\n---\n") is None


class TestNeverRaises:
    """Both callers (submit_scan, and a detector inside required_engines) treat
    a parse failure as 'no frontmatter'. Neither can afford an exception."""

    def test_malformed_yaml_returns_none(self) -> None:
        assert parse_frontmatter(b"---\nname: [unclosed\n---\n") is None

    def test_alias_expansion_is_refused(self) -> None:
        # A billion-laughs payload: each level references the one below it.
        payload = (
            b"---\n"
            b"a: &a ['x','x','x','x','x','x','x','x','x']\n"
            b"b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n"
            b"c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n"
            b"d: [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n"
            b"---\n"
        )
        assert parse_frontmatter(payload) is None

    def test_invalid_utf8_returns_none(self) -> None:
        assert parse_frontmatter(b"---\n\xff\xfe\x00\n---\n") is None

    def test_empty_input_returns_none(self) -> None:
        assert parse_frontmatter(b"") is None

    def test_unprintable_control_character_returns_none(self) -> None:
        """2026-07-27 review finding (Critical): PyYAML's Reader checks for
        disallowed control characters at LOADER-CONSTRUCTION time
        (`Reader.__init__` -> `check_printable()`), before `get_single_data()`
        is ever called - raising `yaml.reader.ReaderError` (a `yaml.YAMLError`
        subclass) from a code path that was, at the time this test was
        written, OUTSIDE the `try:` block that catches it. The existing
        `test_invalid_utf8_returns_none` payload (b"\\xff\\xfe\\x00") does NOT
        exercise this: those bytes fail utf-8 decoding first and never reach
        loader construction. This payload is valid UTF-8 (\\x01 decodes fine)
        so it reaches the loader - the payload must start with b"---" for the
        same reason, or `parse_frontmatter` early-returns before ever
        constructing a loader."""
        assert parse_frontmatter(b"---\nname: x\n\x01\n---\n") is None
