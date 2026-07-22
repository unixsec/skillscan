"""yara adapter (coding spec §10: "yara(yara-python,在 sandbox 内)") → NET-03
后门/CODE-07 恶意程序特征.

SECURITY (INV-15 resolution): §10's file listing names this "yara-python",
but INV-15 (coding spec §1/§14, non-negotiable, CI-enforced per the acceptance
checklist "引擎适配器无 import 引擎代码(仅 subprocess)") is an explicit,
numbered, blanket rule with no yara-specific carve-out - and this project's
own `vendor/VENDOR.md` already documents ALL FIVE vendored engines uniformly
as "consumed only via subprocess". Where these two spec passages conflict,
the numbered invariant wins: this adapter shells out to the standalone `yara`
CLI binary (distinct from the `yara-python` bindings), never `import yara`.

Rule format: this project's own YARA rules (policies/yara/*.yar) each declare
a single `findings_json` string meta field containing this finding's full
mapping (rule_id/test_item_id/category/severity/title) as an escaped JSON
string - e.g. (illustrative; real rules have the same shape with real values):
    rule net_c2_beacon_pattern {
        meta:
            findings_json = "{\\"test_item_id\\":\\"NET-03\\", ...}"
        strings:
            $a = "beacon.example" wide ascii
        condition:
            $a
    }
This sidesteps parsing YARA's own multi-key `[k=v,k2=v2]` bracket metadata
syntax (whose exact quoting/escaping rules are harder to get right without a
live binary to verify against in this environment) - `yara -m` still prints
whatever meta fields a rule declares verbatim, so a single JSON-string field
is valid, standard YARA and trivial to parse reliably.

SECURITY: assumed CLI output format (this project has no yara binary
available to verify live in this environment - see docs/USER_GUIDE.md's
honesty notes on environment-blocked verification, same posture as gVisor):
`yara -m -r <rules_dir> <target>` prints one line per match,
`rule_name [meta_k=v,...] file_path`. If a real yara binary's output differs,
`_MATCH_LINE_RE` is the single place to adjust.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

from skillscan_core import (
    DetectionCategory,
    EngineCapability,
    EngineMetadata,
    Finding,
    Severity,
)

from .base import SubprocessEngineAdapter

_MATCH_LINE_RE = re.compile(r"^(?P<rule>\S+)\s+\[(?P<meta>.*)\]\s+(?P<path>.+)$")
_FINDINGS_JSON_RE = re.compile(r'findings_json="((?:[^"\\]|\\.)*)"')

_SEVERITY_MAP = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}
_CATEGORY_MAP = {c.value: c for c in DetectionCategory}


def _metadata(*, ruleset_digest: str, version: str) -> EngineMetadata:
    return EngineMetadata(
        name="yara",
        version=version,
        ruleset_digest=ruleset_digest,
        capabilities=frozenset({EngineCapability.STATIC}),
    )


class _ArgvBuilder:
    """yara additionally needs a fixed RULES directory (policies/yara/)
    alongside the per-scan TARGET directory `SubprocessEngineAdapter`
    provides, so `build_argv` here is a small stateful callable rather than a
    bare function. SECURITY: `rules_path` is a fixed, operator-controlled path
    (config-as-code) - never derived from scanned content.

    CORRECTNESS (confirmed against a real `yara 4.2.3` binary, 2026-07-09 -
    this project had no yara binary to verify against until now): yara's
    actual CLI signature is `yara [OPTION]... [NAMESPACE:]RULES_FILE... FILE
    | DIR | PID` - `-r`/`--recursive` means "recursively search the TARGET
    directory," not "accept a rules directory." Passing a directory as
    RULES_FILE fails immediately with a flex-lexer parse error (the
    directory's raw listing isn't valid rule syntax). YARA DOES accept
    multiple RULES_FILE positional arguments, so a `rules_path` directory is
    resolved here to every `*.yar`/`*.yara` file inside it, each passed as
    its own positional arg - this also confirmed that `_MATCH_LINE_RE`'s
    assumed `rule_name [meta] file_path` output shape and the
    `findings_json` meta convention were both already correct; the directory
    argument was the only real bug."""

    def __init__(self, rules_path: Path) -> None:
        self._rules_path = rules_path

    def __call__(self, target_dir: Path) -> list[str]:
        if self._rules_path.is_dir():
            rule_files = sorted(
                p for p in self._rules_path.iterdir() if p.suffix in (".yar", ".yara")
            )
        else:
            rule_files = [self._rules_path]
        return ["yara", "-m", "-r", *(str(p) for p in rule_files), str(target_dir)]


def parse_output(
    completed: subprocess.CompletedProcess[bytes], _target_dir: Path, _files: dict[str, bytes]
) -> tuple[Finding, ...]:
    text = completed.stdout.decode("utf-8", errors="replace")
    findings: list[Finding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        match = _MATCH_LINE_RE.match(line)
        if match is None:
            raise ValueError(f"unrecognized yara output line: {line!r}")

        meta = match.group("meta")
        file_path = match.group("path")
        json_match = _FINDINGS_JSON_RE.search(meta)
        if json_match is None:
            raise ValueError(
                f"yara rule {match.group('rule')!r} matched but has no findings_json meta field"
            )
        raw_json = json_match.group(1).replace('\\"', '"').replace("\\\\", "\\")
        decoded = json.loads(raw_json)

        severity = _SEVERITY_MAP.get(str(decoded.get("severity")), Severity.HIGH)
        category = _CATEGORY_MAP.get(str(decoded.get("category")), DetectionCategory.NETWORK_INTEL)
        findings.append(
            Finding(
                rule_id=str(decoded.get("rule_id", match.group("rule"))),
                test_item_id=str(decoded.get("test_item_id", "NET-03")),
                category=category,
                title=str(decoded.get("title", match.group("rule"))),
                severity=severity,
                confidence=0.85,  # SECURITY: a YARA signature match is a deterministic pattern hit
                source_engine="yara",
                source_capability=EngineCapability.STATIC,
                file_path=file_path or None,
                snippet_hash=hashlib.sha256(line.encode("utf-8")).hexdigest(),
                evidence_redacted=f"yara rule {match.group('rule')!r} matched",
            )
        )
    return tuple(findings)


def make_adapter(*, rules_path: Path, ruleset_digest: str, version: str) -> SubprocessEngineAdapter:
    return SubprocessEngineAdapter(
        metadata=_metadata(ruleset_digest=ruleset_digest, version=version),
        build_argv=_ArgvBuilder(rules_path),
        parse_output=parse_output,
    )
