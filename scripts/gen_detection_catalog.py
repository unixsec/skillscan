#!/usr/bin/env python3
"""Generate `policies/detection_catalog.json` from the authoritative .xlsx.

WHY THIS EXISTS (2026-07-29, milestone C task 6). The authoritative detection
catalog is `企业Skill安全评估测试维度清单.xlsx` - 62 items, D1..D10, with its own
review history. That file is:

  * **binary**, so no diff of it is reviewable and nothing at runtime can read
    it without a spreadsheet parser, and
  * **gitignored** (`.gitignore:35 /*.xlsx`), so it exists on exactly one
    machine. It is in no clone, no CI checkout, and no container image.

`tests/test_test_item_catalog.py` - the guard that exists because `SUP-01`, an
id that was never in the catalog, shipped as osv-scanner's `test_item_id` for
its entire life - read that .xlsx directly and **skipped itself** wherever the
file was absent. That is everywhere except the authoring Mac: the VM, CI, and
every fresh clone. A skip is indistinguishable from a pass in every summary
anyone reads, so the strongest guard in this repository was switched off in
precisely the environments whose artifacts get deployed.

This script extracts the one field code actually needs - the 条目编号 (item id)
column - into a small, sorted, version-controlled JSON manifest that travels
with the repository. The guard reads the manifest and therefore runs
everywhere; the .xlsx stays the authority.

WHAT IS AND IS NOT COPIED OUT. Ids only. No item names, no 检测要点, no
descriptions - the catalog's actual security content stays in the spreadsheet.
The ids themselves are not content: `SUPPLY-02`, `CODE-01` and the rest are
already written throughout the engine sources, the tests and the SAD. So the
manifest carries nothing the source tree does not already carry, which is also
why it is safe for the stripped `main` snapshot while the .xlsx is not.

THE DRIFT OBLIGATION. A generated file checked in beside its source is a second
source of truth unless something fails when the two disagree. `--check`
regenerates the manifest in memory and compares it byte-for-byte with the file
on disk, and it is wired into `deploy_and_test_vm.sh` step 1 (which runs on the
Mac, before anything is shipped) and into `tests/test_test_item_catalog.py`.
The .xlsx can only be edited on the machine that has it, so a check that runs
there covers the whole mutation surface.

`--check` compares the rendered document, not a digest of the source: a
cosmetic edit to the spreadsheet that does not touch any id must not force a
regeneration commit, or the guard becomes noise people learn to bypass.

Usage:
    uv run python scripts/gen_detection_catalog.py           # rewrite manifest
    uv run python scripts/gen_detection_catalog.py --check   # fail on drift

READING THE .xlsx uses stdlib `zipfile` + `xml.etree` (an xlsx IS a zip of XML)
rather than `openpyxl`, so neither this script nor the kernel test suite it
serves gains a dependency.

SECURITY (stdlib XML): the parsed input is one repo-local working document read
by a developer tool - never scanned content, never anything a submitter
controls, so this is not an untrusted-XML parsing surface. `xml.etree` does not
resolve external entities and raises on an undefined one rather than expanding
it, so neither XXE nor billion-laughs applies. Pulling in `defusedxml` to read a
developer spreadsheet would cost more than it buys.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from pathlib import Path
from xml.etree import ElementTree

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG_XLSX = REPO_ROOT / "企业Skill安全评估测试维度清单.xlsx"
MANIFEST_PATH = REPO_ROOT / "policies" / "detection_catalog.json"

# The catalog has 62 items. Asserted exactly (not `>= 60`) on purpose: this is
# an authoritative registry, so a legitimate change to it must be a deliberate,
# reviewed edit rather than something a parser bug can silently absorb.
CATALOG_ITEM_COUNT = 62

_SHEET_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_ITEM_ID_COLUMN = "C"  # 条目编号
_ITEM_ID_HEADER = "条目编号"

_MANIFEST_WARNING = (
    "GENERATED FILE - do not edit by hand. Regenerate with "
    "`uv run python scripts/gen_detection_catalog.py`. Source of truth is "
    "企业Skill安全评估测试维度清单.xlsx, which is gitignored and lives only on the "
    "authoring machine; `--check` fails if this file and that spreadsheet disagree."
)


def _cell_text(cell: ElementTree.Element, shared_strings: list[str]) -> str:
    value = cell.find(f"{_SHEET_NS}v")
    if cell.get("t") == "inlineStr":
        return "".join(t.text or "" for t in cell.iter(f"{_SHEET_NS}t"))
    if value is None or value.text is None:
        return ""
    if cell.get("t") == "s":
        return shared_strings[int(value.text)]
    return value.text


def read_catalog_ids(xlsx_path: Path = CATALOG_XLSX) -> list[str]:
    """Every 条目编号 (column C) of the authoritative catalog, verbatim, sorted.

    Deliberately NOT filtered by shape - filtering here would reintroduce the
    exact assumption that let `SUP-01` through (it is shaped like a valid id).
    """
    with zipfile.ZipFile(xlsx_path) as archive:
        shared_root = ElementTree.fromstring(archive.read("xl/sharedStrings.xml"))
        shared_strings = [
            "".join(t.text or "" for t in si.iter(f"{_SHEET_NS}t"))
            for si in shared_root.findall(f"{_SHEET_NS}si")
        ]
        sheet_root = ElementTree.fromstring(archive.read("xl/worksheets/sheet1.xml"))

    ids: set[str] = set()
    for row in sheet_root.iter(f"{_SHEET_NS}row"):
        for cell in row.findall(f"{_SHEET_NS}c"):
            ref = cell.get("r") or ""
            if re.match(rf"^{_ITEM_ID_COLUMN}\d+$", ref) is None:
                continue
            text = _cell_text(cell, shared_strings).strip()
            if text and text != _ITEM_ID_HEADER:
                ids.add(text)
    return sorted(ids)


def render_manifest(ids: list[str]) -> str:
    """The exact bytes `policies/detection_catalog.json` must contain."""
    document = {
        "_warning": _MANIFEST_WARNING,
        "source": CATALOG_XLSX.name,
        "generator": "scripts/gen_detection_catalog.py",
        "item_count": len(ids),
        "test_item_ids": ids,
    }
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"


def load_manifest_ids(manifest_path: Path = MANIFEST_PATH) -> frozenset[str]:
    """Read the checked-in manifest. Raises if it is absent or malformed.

    This is the accessor the guard uses, so it must never degrade to an empty
    set on a bad read: an empty catalog makes every membership assertion pass.
    """
    if not manifest_path.is_file():
        raise FileNotFoundError(
            f"the detection-catalog manifest {manifest_path} is missing. It is a "
            "version-controlled file - restore it from git, or regenerate it on a "
            "checkout that has 企业Skill安全评估测试维度清单.xlsx with "
            "`uv run python scripts/gen_detection_catalog.py`."
        )
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    ids = document.get("test_item_ids")
    if not isinstance(ids, list) or not ids or not all(isinstance(i, str) for i in ids):
        raise ValueError(
            f"{manifest_path} has no usable `test_item_ids` list. Regenerate it with "
            "`uv run python scripts/gen_detection_catalog.py`; do not hand-edit it."
        )
    declared = document.get("item_count")
    if declared != len(ids):
        raise ValueError(
            f"{manifest_path} declares item_count={declared!r} but lists {len(ids)} ids. "
            "It has been hand-edited; regenerate it."
        )
    return frozenset(ids)


def _require_source() -> list[str]:
    if not CATALOG_XLSX.is_file():
        print(
            f"ERROR: the authoritative catalog {CATALOG_XLSX.name} is not in this "
            f"checkout ({REPO_ROOT}).\n"
            "It is gitignored (.gitignore: /*.xlsx) and lives only on the authoring\n"
            "machine, so this script can only run there. Copy the spreadsheet into the\n"
            "repository root and re-run.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    ids = read_catalog_ids()
    if len(ids) != CATALOG_ITEM_COUNT:
        print(
            f"ERROR: parsed {len(ids)} item ids from {CATALOG_XLSX.name}, expected "
            f"{CATALOG_ITEM_COUNT}.\n"
            "Either the catalog genuinely changed - in which case update "
            "CATALOG_ITEM_COUNT here\n"
            "and in tests/test_test_item_catalog.py as a deliberate, reviewed edit - or "
            "column\n"
            f"{_ITEM_ID_COLUMN} / sheet1 is no longer where the 条目编号 live and this "
            "parser is wrong.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return ids


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; exit non-zero if the manifest differs from the spreadsheet",
    )
    args = parser.parse_args(argv)

    expected = render_manifest(_require_source())

    if args.check:
        actual = MANIFEST_PATH.read_text(encoding="utf-8") if MANIFEST_PATH.is_file() else ""
        if actual != expected:
            print(
                f"ERROR: {MANIFEST_PATH.relative_to(REPO_ROOT)} is out of sync with "
                f"{CATALOG_XLSX.name}.\n"
                "The spreadsheet is the authority and the manifest is what every other\n"
                "machine validates against, so they must not disagree. Regenerate and\n"
                "commit:  uv run python scripts/gen_detection_catalog.py",
                file=sys.stderr,
            )
            return 1
        print(f"detection catalog manifest is in sync ({CATALOG_ITEM_COUNT} items)")
        return 0

    MANIFEST_PATH.write_text(expected, encoding="utf-8")
    print(f"wrote {MANIFEST_PATH.relative_to(REPO_ROOT)} ({CATALOG_ITEM_COUNT} items)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
