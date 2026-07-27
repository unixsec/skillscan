"""Shared SKILL.md YAML-frontmatter parsing.

Extracted from `monolith.modules.orchestration.service` (2026-07-27) so the
floor detectors can reuse it: a detector lives in `services/engine_runner/`
and must not import monolith modules.

SECURITY: `NoAliasSafeLoader` refuses YAML aliases. `yaml.safe_load` blocks
code execution but still expands anchors/aliases, so a sub-kilobyte
nested-alias "billion laughs" payload can expand exponentially and OOM the
process. A length cap does NOT stop this - the payload is small by design - so
aliases are rejected outright at compose time, before any expansion. A
name-bearing SKILL.md frontmatter never legitimately needs them.
"""

from __future__ import annotations

from typing import Any

import yaml

_MAX_FRONTMATTER_BYTES = 64 * 1024


class NoAliasSafeLoader(yaml.SafeLoader):  # type: ignore[misc]
    """`type: ignore[misc]`: PyYAML ships no type information and is declared
    `ignore_missing_imports` in pyproject.toml, so `yaml.SafeLoader` resolves
    to `Any` and mypy --strict rejects subclassing it. The ignore is about the
    missing upstream stub, not about this class."""

    def compose_node(self, parent: object, index: object) -> object:
        event = self.peek_event()
        if isinstance(event, yaml.events.AliasEvent):
            raise yaml.YAMLError("YAML aliases are not permitted in SKILL.md frontmatter")
        return super().compose_node(parent, index)


def parse_frontmatter(data: bytes) -> dict[str, Any] | None:
    """Return the frontmatter mapping of a SKILL.md, or None.

    NEVER raises. Both callers - `submit_scan` (which only wants `name`) and
    the permissions detector (which is inside `required_engines`, where an
    exception would fail every scan closed) - treat None as "no usable
    frontmatter".
    """
    if not data.startswith(b"---"):
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    # Split off the block between the opening `---` and the next `---` line.
    parts = text.split("\n---", 1)
    if len(parts) != 2:
        return None
    block = parts[0][3:]
    if len(block.encode("utf-8")) > _MAX_FRONTMATTER_BYTES:
        return None
    # SECURITY (2026-07-27 review, Critical): loader CONSTRUCTION must be
    # inside the try, not just get_single_data(). PyYAML's Reader.__init__
    # (run via the loader's MRO) calls check_printable() at construction time
    # and raises yaml.reader.ReaderError - a yaml.YAMLError subclass - for any
    # disallowed control character, before get_single_data() is ever reached.
    # `loader` is pre-bound to None so `finally` can check "was construction
    # reached" without risking a NameError if the constructor itself raised.
    loader: NoAliasSafeLoader | None = None
    try:
        loader = NoAliasSafeLoader(block)
        parsed = loader.get_single_data()
    except (yaml.YAMLError, RecursionError, ValueError):
        return None
    finally:
        if loader is not None:
            loader.dispose()
    return parsed if isinstance(parsed, dict) else None
