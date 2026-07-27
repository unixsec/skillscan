"""Where a Skill package's authoritative SKILL.md lives.

WHY THIS EXISTS (2026-07-27, milestone D final review, F-5): three call sites
located the package-root SKILL.md independently, all three with the same
spelling `path == "SKILL.md"`:

  - `engine_runner.detectors.skill_permissions.scan` (the PERM-* findings)
  - `monolith.modules.gateway.router.create_scan` (skill_version.declared_perms)
  - `monolith.modules.orchestration.service._parse_skill_name` (the display name)

That spelling is wrong for the single most common packaging shape there is.
`tar czf skill.tgz my-skill/` produces members under a `my-skill/` wrapper,
and `engine_runner.normalizer._canonicalize_member_path` only strips `.`
segments - it never strips a leading directory. So for
`{my-skill/SKILL.md, my-skill/scripts/run.sh}` all three sites concluded
"there is no SKILL.md", which produced a false `perm.undeclared_permissions`
LOW finding AND silently recorded `declared_perms=None` for a package that
declares its permissions perfectly well. The flat/root equivalent of the same
package produced no finding at all.

THE FIX IS NOT BASENAME MATCHING. A `SKILL.md` nested somewhere inside a
package (`examples/SKILL.md`) must still NEVER count: the Agent reads exactly
one manifest, and letting a bundled example satisfy the check is a false
negative (a genuinely undeclared package reads as declared), which is strictly
worse than the false positive above. What is fixed here is narrower and
precise: recognise the single shared top-level directory that a conventionally
packed tarball adds, and treat what is inside it as the package root. When the
members do NOT all share one top-level directory, the root is the archive root
and nothing nested can pass.

SECURITY: static, pure string work over the already-canonicalised member paths
- no filesystem access, no I/O - so a floor detector (static-analysis only,
FR-DET-130/SEC-INP-020) can call it.

DO NOT unify this with `mcp_config._is_mcp_config`, which deliberately matches
`.mcp.json` by basename ANYWHERE in the package. That asymmetry is intentional
and documented there: an over-flagged non-root MCP config is a harmless false
positive a human can waive and never suppresses the root file's own finding,
whereas a non-root SKILL.md accepted as the manifest suppresses a real
finding.
"""

from __future__ import annotations

from collections.abc import Iterable

SKILL_MD_NAME = "SKILL.md"

# Directory names the Skill package format itself gives a structural role, so
# they can never BE the package - they are always something inside it.
#
# WHY THIS EXISTS (2026-07-28): "all members share one top-level directory" is
# not on its own enough to identify a wrapper, because a degenerate package
# with a single member is indistinguishable from a wrapped one by path shape
# alone:
#
#     {my-skill/SKILL.md, my-skill/scripts/run.sh}  <- wrapper, must strip
#     {examples/SKILL.md}                           <- NOT a wrapper
#
# Both have exactly one top-level directory. Stripping the second accepts a
# bundled example as the package manifest, which SUPPRESSES a real
# `perm.undeclared_permissions` finding - a false negative, and therefore
# strictly worse than the false positive this module was written to fix. The
# disambiguating signal has to come from outside the path structure: a real
# wrapper is named after the SKILL, never after one of the format's own
# structural roles.
#
# Sourced from the repo, not from intuition:
#   - `scripts`, `references`, `assets` and `hooks` are the package components
#     the SRS itself enumerates (glossary "Skill (Agent Skill)" and
#     FR-PAR-010: "系统应解析 `SKILL.md`、`scripts/`、`references/`、
#     `assets/`、随包 `.mcp.json`、hooks").
#   - `examples` and `docs` are this codebase's own established convention:
#     `examples/SKILL.md` is the canonical "bundled example is not the
#     manifest" case named in skill_permissions.py, gateway/router.py and
#     orchestration/service.py, and both appear in package fixtures
#     (`docs/img/a.png`, `assets/font.woff2`).
#
# Over-inclusion here is the SAFE direction: an unrecognised wrapper is simply
# not stripped, so the manifest is not found, so a finding is reported. Adding
# a name can only ever cost a false positive; omitting one costs a false
# negative. Matched case-insensitively for the same reason.
_STRUCTURAL_DIRECTORIES = frozenset(
    {"scripts", "references", "assets", "hooks", "examples", "docs"}
)

# Packaging metadata that conventionally sits loose at the ARCHIVE root even
# when the skill itself is wrapped: `tar czf skill.tgz LICENSE my-skill/` is an
# ordinary shape. Without this, a single stray `LICENSE` collapsed the prefix
# back to `""` and reinstated the very false positive F-5 fixed.
#
# Matched on the stem (name minus extension) so `README`, `README.md` and
# `LICENSE.txt` all qualify, plus any dotfile - a dotfile is configuration, it
# is never the skill's own content. Anything else loose at the archive root
# means the root really is the package root and nothing is stripped, which is
# again the SAFE direction: `{skill.py, mylib/SKILL.md}` must NOT accept
# `mylib/SKILL.md` as the manifest.
_ROOT_METADATA_STEMS = frozenset(
    {
        "LICENSE",
        "LICENCE",
        "COPYING",
        "NOTICE",
        "README",
        "CHANGELOG",
        "CHANGES",
        "HISTORY",
        "AUTHORS",
        "CONTRIBUTORS",
        "CONTRIBUTING",
        "CODEOWNERS",
    }
)


def _is_root_metadata(name: str) -> bool:
    if name.startswith("."):
        return True
    stem = name.split(".", 1)[0]
    return stem.upper() in _ROOT_METADATA_STEMS


def package_root_prefix(paths: Iterable[str]) -> str:
    """The single wrapper directory every member shares, or `""`.

    `{"my-skill/SKILL.md", "my-skill/scripts/run.sh"}` -> `"my-skill/"`.
    `{"SKILL.md", "scripts/run.sh"}`                   -> `""` (already flat).
    `{"examples/SKILL.md", "scripts/run.sh"}`          -> `""` (two top-level
        directories, so neither is a wrapper - the archive root IS the package
        root, and `examples/SKILL.md` is correctly NOT the manifest).
    `{"examples/SKILL.md"}`                            -> `""` (the DEGENERATE
        case the two-top-level-directories rule above misses entirely: one
        member, so one top-level directory, so it looked exactly like a
        wrapper. `examples` is a structural directory name, so it is package
        SUB-STRUCTURE, not the package - see `_STRUCTURAL_DIRECTORIES`).
    `{"my-skill/SKILL.md", "my-skill/scripts/run.sh", "LICENSE"}`
                                                       -> `"my-skill/"` (a
        stray packaging-metadata file loose at the archive root does not stop
        the wrapper being a wrapper - see `_ROOT_METADATA_STEMS`).
    `{"skill.py", "mylib/SKILL.md"}`                   -> `""` (a real member
        loose at the archive root means the root IS the package root, so
        `mylib/SKILL.md` is nested and must not be the manifest).

    EXACTLY ONE level is stripped, deliberately. `tar czf skill.tgz my-skill/`
    adds one wrapper, and that is the whole shape this exists to handle.
    Stripping greedily instead would reopen the false negative this module's
    docstring warns about: `{"my-skill/scripts/SKILL.md",
    "my-skill/scripts/run.sh"}` shares a top-level directory at BOTH levels, so
    a greedy strip would accept a SKILL.md sitting inside `scripts/` as the
    package manifest - which the Agent would never read. A doubly wrapped
    archive therefore reads as "no root manifest", i.e. one extra finding, the
    safe direction.

    Returns `""` for an empty input: a package with no members has no root to
    speak of, and every caller then looks for a `SKILL.md` that is not there.
    """
    tops: set[str] = set()
    for path in paths:
        head, separator, _rest = path.partition("/")
        if not separator:
            if _is_root_metadata(head):
                continue  # LICENSE/README/dotfile packed beside the wrapper
            return ""  # a real member sits at the archive root: no wrapper
        tops.add(head)
        if len(tops) > 1:
            return ""  # more than one top-level directory: neither is a wrapper
    if len(tops) != 1:
        return ""
    wrapper = tops.pop()
    if wrapper.lower() in _STRUCTURAL_DIRECTORIES:
        # The format gives this name a role INSIDE a package, so the package
        # cannot BE it. Without this, the degenerate single-member archive
        # `{examples/SKILL.md}` is shape-identical to a wrapped package and
        # its bundled example would be accepted as the manifest - a false
        # negative, worse than the false positive this module fixes.
        return ""
    return f"{wrapper}/"


def root_skill_md_path(paths: Iterable[str]) -> str:
    """The path the package's one authoritative SKILL.md would occupy.

    Callers compare member paths against this rather than against the bare
    string `"SKILL.md"`. It is returned whether or not that member exists, so
    a caller reporting "no root manifest" has a real path to name.
    """
    materialized = list(paths)
    return f"{package_root_prefix(materialized)}{SKILL_MD_NAME}"
