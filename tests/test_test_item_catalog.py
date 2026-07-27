"""Cross-registry guard: every `test_item_id` any engine can emit must be a
real row of the authoritative detection catalog.

WHY THIS EXISTS (2026-07-27, milestone D final review, F-1): osv-scanner - the
system's only known-CVE detection - emitted `test_item_id="SUP-01"` for its
entire life. There is no `SUP-*` prefix anywhere in
`企业Skill安全评估测试维度清单.xlsx`; the supply-chain dimension D8 is
`SUPPLY-01`…`SUPPLY-06`. Every one of those findings was therefore labelled
with an id no compliance report can resolve, and D8 read as uncovered.

The earlier audit that was supposed to catch exactly this swept for the
**shape** `[A-Z]{3,7}-\\d{2}` instead of **membership** in the real 62 items.
`SUP-01` is shaped exactly like a valid id, so a shape check can never find
this class of error. This module therefore does the only thing that works:
read the authoritative spreadsheet and assert membership.

Two complementary checks, because either alone has a hole:

  1. `TestMappingTablesAreCatalogMembers` imports the REAL, LIVE mapping
     tables/classifier functions each engine uses at runtime and asserts every
     value it can produce is a catalog member. This proves the values actually
     emitted are right, not merely that some literal in the file is right.

  2. `TestEngineSourcesContainNoUnknownCatalogIds` AST-parses every engine
     source file and asserts every catalog-id-shaped string literal in it is a
     catalog member. This is the completeness half: it needs no registration
     step, so a NEW detector, or a new hardcoded id inline in a `Finding(...)`
     call that no mapping table knows about, is covered by construction. The
     module lists are globs, so a newly added detector/adapter file is swept
     the moment it lands.

Plus `TestYaraRuleFilesDeclareCatalogIds`, because `yara.py` is data-driven:
its ids live in `policies/yara/*.yar` meta fields, not in Python at all.

SKIPPING: the catalog spreadsheet is a working document that does not ship to
the VM (its checkout arrives by rsync with `--exclude=*.xlsx`), so every test
here skips cleanly when the file is absent rather than failing there. It runs
for real in the local kernel suite (`uv run pytest tests/ -q`), where the file
is present.

Reading the .xlsx uses stdlib `zipfile` + `xml.etree` (an xlsx IS a zip of
XML) rather than `openpyxl`, so this guard adds no dependency to a repo whose
kernel suite is deliberately dependency-light.

SECURITY (stdlib XML): the parsed input is one repo-local, version-controlled
working document read by a local test - never scanned content, never anything
a submitter controls, so this is not an untrusted-XML parsing surface at all.
`xml.etree.ElementTree` additionally does not resolve external entities and
raises on an undefined entity rather than expanding it, so neither XXE nor
billion-laughs applies here. `defusedxml` is deliberately not pulled in for
this: adding a dependency to read a developer spreadsheet would cost more
than it buys.
"""

from __future__ import annotations

import ast
import json
import re
import unittest
import zipfile
from pathlib import Path
from xml.etree import ElementTree

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CATALOG_XLSX = _REPO_ROOT / "企业Skill安全评估测试维度清单.xlsx"

# The catalog has 62 items. Asserted exactly (not `>= 60`) on purpose: this is
# an authoritative registry, so a legitimate change to it must be a deliberate,
# reviewed edit here rather than something a parser bug can silently absorb.
_CATALOG_ITEM_COUNT = 62

_SHEET_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_ITEM_ID_COLUMN = "C"  # 条目编号
_ITEM_ID_HEADER = "条目编号"

# Used ONLY to decide "is this string literal trying to be a catalog id?" -
# never to decide whether an id is valid (that is membership, below). Kept
# deliberately looser than the real ids so a near-miss typo (`SUPPLY-2`,
# `PERM-002`) is still caught rather than silently ignored as "not an id".
_ID_SHAPED = re.compile(r"^[A-Z]{2,10}-\d{1,3}$")

_SWEPT_SOURCES: tuple[Path, ...] = (
    _REPO_ROOT / "libs" / "skillscan_core" / "engines.py",
    _REPO_ROOT / "apps" / "monolith" / "modules" / "intel" / "matcher.py",
    *sorted((_REPO_ROOT / "services" / "engine_runner" / "detectors").glob("*.py")),
    *sorted((_REPO_ROOT / "services" / "engine_runner" / "adapters").glob("*.py")),
)

_YARA_RULES_DIR = _REPO_ROOT / "policies" / "yara"
_YARA_FINDINGS_JSON = re.compile(r'findings_json\s*=\s*"((?:[^"\\]|\\.)*)"')


def _cell_text(cell: ElementTree.Element, shared_strings: list[str]) -> str:
    value = cell.find(f"{_SHEET_NS}v")
    if cell.get("t") == "inlineStr":
        return "".join(t.text or "" for t in cell.iter(f"{_SHEET_NS}t"))
    if value is None or value.text is None:
        return ""
    if cell.get("t") == "s":
        return shared_strings[int(value.text)]
    return value.text


def _read_catalog_ids() -> frozenset[str]:
    """Every 条目编号 (column C) of the authoritative catalog, verbatim.

    Deliberately NOT filtered by shape - filtering here would reintroduce the
    exact assumption that let `SUP-01` through.
    """
    with zipfile.ZipFile(_CATALOG_XLSX) as archive:
        shared_root = ElementTree.fromstring(archive.read("xl/sharedStrings.xml"))
        shared_strings = [
            "".join(t.text or "" for t in si.iter(f"{_SHEET_NS}t"))
            for si in shared_root.findall(f"{_SHEET_NS}si")
        ]
        sheet_root = ElementTree.fromstring(archive.read("xl/worksheets/sheet1.xml"))

    ids: list[str] = []
    for row in sheet_root.iter(f"{_SHEET_NS}row"):
        for cell in row.findall(f"{_SHEET_NS}c"):
            ref = cell.get("r") or ""
            if re.match(rf"^{_ITEM_ID_COLUMN}\d+$", ref) is None:
                continue
            text = _cell_text(cell, shared_strings).strip()
            if text and text != _ITEM_ID_HEADER:
                ids.append(text)
    return frozenset(ids)


class _CatalogTestCase(unittest.TestCase):
    catalog: frozenset[str]

    @classmethod
    def setUpClass(cls) -> None:
        if not _CATALOG_XLSX.exists():
            raise unittest.SkipTest(
                f"detection catalog {_CATALOG_XLSX.name} is not present in this checkout "
                "(the VM rsync excludes *.xlsx) - membership cannot be verified here"
            )
        cls.catalog = _read_catalog_ids()

    def assert_are_catalog_items(self, ids: object, *, source: str) -> None:
        unknown = sorted(i for i in ids if i not in self.catalog)  # type: ignore[union-attr]
        self.assertEqual(
            unknown,
            [],
            f"{source} emits test_item_id(s) that are not rows of "
            f"{_CATALOG_XLSX.name}: {unknown}. A syntactically plausible id is not "
            "enough - it must be one of the catalog's own 条目编号 values, or no "
            "compliance report keyed on the catalog can resolve the finding.",
        )


class TestCatalogParse(_CatalogTestCase):
    """If the parser silently returned garbage, every membership assertion
    below would pass or fail for the wrong reason."""

    def test_the_catalog_has_its_expected_item_count(self) -> None:
        self.assertEqual(len(self.catalog), _CATALOG_ITEM_COUNT)

    def test_known_anchor_items_are_present(self) -> None:
        # One per dimension actually referenced by the engines, so a parser
        # that read the wrong column/sheet cannot pass this.
        for anchor in ("INTEL-01", "CODE-01", "CRED-04", "NET-06", "PROMPT-01", "SUPPLY-02"):
            self.assertIn(anchor, self.catalog)

    def test_the_defect_this_guard_exists_for_is_not_a_catalog_item(self) -> None:
        # F-1: osv.py shipped "SUP-01" for its entire life. Shape-identical to
        # a real id, absent from the catalog.
        self.assertNotIn("SUP-01", self.catalog)


class TestMappingTablesAreCatalogMembers(_CatalogTestCase):
    """The live values, read from the real registries the engines use."""

    def test_static_keyword_engine(self) -> None:
        from skillscan_core import engines

        self.assert_are_catalog_items(
            set(engines._TEST_ITEM_IDS.values()), source="skillscan_core.engines"
        )

    def test_mcp_config_detector(self) -> None:
        from engine_runner.detectors import mcp_config

        self.assert_are_catalog_items(
            {item_id for item_id, _category in mcp_config._TEST_ITEM_IDS.values()},
            source="detectors.mcp_config",
        )

    def test_skill_permissions_detector(self) -> None:
        from engine_runner.detectors import skill_permissions

        self.assert_are_catalog_items(
            set(skill_permissions._TEST_ITEM_IDS.values()), source="detectors.skill_permissions"
        )

    def test_file_type_detector(self) -> None:
        from engine_runner.detectors import file_type

        self.assert_are_catalog_items(
            set(file_type._TEST_ITEM_IDS.values()), source="detectors.file_type"
        )

    def test_chinese_instruction_detectors(self) -> None:
        from engine_runner.detectors import jailbreak_inducement_zh, prompt_injection_zh

        self.assert_are_catalog_items(
            {prompt_injection_zh._TEST_ITEM_ID}, source="detectors.prompt_injection_zh"
        )
        self.assert_are_catalog_items(
            {jailbreak_inducement_zh._TEST_ITEM_ID}, source="detectors.jailbreak_inducement_zh"
        )

    def test_skillspector_adapter(self) -> None:
        from engine_runner.adapters import skillspector

        self.assert_are_catalog_items(
            set(skillspector._TEST_ITEM_ID_BY_RULE_ID.values()), source="adapters.skillspector"
        )

    def test_intel_matcher(self) -> None:
        from monolith.modules.intel import matcher

        self.assert_are_catalog_items(
            set(matcher._TEST_ITEM_ID_BY_IOC_TYPE.values()), source="intel.matcher"
        )

    def test_bandit_adapter_including_its_fallback(self) -> None:
        """bandit maps through a function, not a dict - drive the function
        over every bandit test_id it knows plus one it does not, so the
        fallback path is covered too."""
        from engine_runner.adapters import bandit

        known: set[str] = set()
        for name, value in vars(bandit).items():
            if name.endswith("_TEST_IDS") and isinstance(value, frozenset | set | tuple):
                known.update(str(v) for v in value)
        self.assertNotEqual(known, set(), "bandit's test-id groups moved - update this guard")
        emitted = {bandit._test_item_id_and_category(t)[0] for t in known}
        emitted.add(bandit._test_item_id_and_category("B000-not-a-real-bandit-id")[0])
        self.assert_are_catalog_items(emitted, source="adapters.bandit")

    def test_aig_adapter_including_its_fallback(self) -> None:
        from engine_runner.adapters import aig

        emitted = {item_id for _keywords, item_id, _category in aig._KEYWORD_RULES}
        emitted.add(aig._classify("nothing", "matches these keywords")[0])
        self.assert_are_catalog_items(emitted, source="adapters.aig")


class TestEngineSourcesContainNoUnknownCatalogIds(_CatalogTestCase):
    """The completeness half - no registration step, so a new detector or a
    fresh inline literal is covered the moment it lands."""

    def test_every_engine_source_file_is_swept(self) -> None:
        for path in _SWEPT_SOURCES:
            self.assertTrue(path.is_file(), f"swept source {path} no longer exists")
        # The detector/adapter entries are globs; assert they actually matched
        # something so a moved package silently reduces this to a no-op test.
        self.assertGreater(len(_SWEPT_SOURCES), 10)

    def test_no_source_file_contains_a_non_catalog_id_literal(self) -> None:
        for path in _SWEPT_SOURCES:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            literals = {
                node.value
                for node in ast.walk(tree)
                if isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and _ID_SHAPED.match(node.value)
            }
            with self.subTest(source=path.name):
                self.assert_are_catalog_items(literals, source=str(path.relative_to(_REPO_ROOT)))


class TestYaraRuleFilesDeclareCatalogIds(_CatalogTestCase):
    """`yara.py` reads test_item_id out of each rule's own `findings_json`
    meta field, so its ids live in `policies/yara/*.yar`, not in Python."""

    def test_every_yara_rule_declares_a_catalog_id(self) -> None:
        rule_files = sorted(_YARA_RULES_DIR.glob("*.yar"))
        self.assertNotEqual(rule_files, [], "no YARA rule files found - guard would be vacuous")
        declared: set[str] = set()
        for path in rule_files:
            text = path.read_text(encoding="utf-8")
            for match in _YARA_FINDINGS_JSON.finditer(text):
                raw = match.group(1).replace('\\"', '"').replace("\\\\", "\\")
                item_id = json.loads(raw).get("test_item_id")
                if item_id is not None:
                    declared.add(str(item_id))
        self.assertNotEqual(
            declared, set(), "no findings_json meta parsed - guard would be vacuous"
        )
        self.assert_are_catalog_items(declared, source="policies/yara/*.yar")

    def test_the_adapters_fallback_id_is_a_catalog_item(self) -> None:
        """A rule whose meta omits test_item_id falls back to this literal."""
        from engine_runner.adapters import yara

        source = ast.parse(Path(yara.__file__).read_text(encoding="utf-8"))
        fallbacks = {
            node.value
            for node in ast.walk(source)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and _ID_SHAPED.match(node.value)
        }
        self.assert_are_catalog_items(fallbacks, source="adapters.yara fallback")
