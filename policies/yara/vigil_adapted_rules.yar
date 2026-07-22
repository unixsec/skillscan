/*
 * Rules ADAPTED FROM A THIRD-PARTY SOURCE - unlike skillscan_rules.yar and
 * prompt_permission_rules.yar, these are NOT original in-house content.
 *
 * Source:  deadbits/vigil-llm  (author: Adam M. Swanda)
 * License: Apache-2.0 (permissive; compatible with this repo's use - the
 *          rules are consumed as data by the sandboxed yara engine, same
 *          posture as the vendored engines per VENDOR.md / coding spec
 *          §10A.1 / INV-15)
 * Upstream files this content came from:
 *   - data/yara/instruction_bypass.yar   -> instruction_bypass_phrase
 *   - data/yara/system_instructions.yar  -> fake_system_role_tags
 *   - data/yara/mdexfil.yar              -> markdown_image_exfiltration
 * Fetched and confirmed verbatim from raw.githubusercontent.com on
 * 2026-07-09; vendored into this repo on 2026-07-22 with explicit owner
 * authorization (VENDOR.md's owner-confirmation gate for third-party
 * detection content).
 *
 * ADAPTATION: the string/condition bodies are upstream's, unmodified. Only
 * the meta blocks were rewritten to this project's `findings_json`
 * convention (see services/engine_runner/adapters/yara.py), mapping each
 * rule onto the test_item_id it covers.
 *
 * COVERAGE: PROMPT-01 and PROMPT-03 had ZERO rule coverage before this file.
 * NET-03 also had zero actual *rule* coverage - it appeared only as the
 * adapter's fallback default test_item_id and in test fixtures, which is not
 * detection.
 *
 * SECURITY (calibration, same posture as this directory's other rule files
 * and policies/gate/v1.yaml's FP-tuning notes): none of these are added to
 * hard_gate_rules. They score toward severity/REVIEW like every other yara
 * finding, never an unwaivable forced BLOCK.
 *
 * ── MEASURED EFFECTIVENESS (yara 4.5.0 on the dev VM, 2026-07-22) ─────────
 * These rules were empirically tested after adaptation, not assumed to work.
 * Only ONE of the three is genuinely effective. Do not read this file as
 * "PROMPT-01/PROMPT-03/NET-03 are now covered".
 *
 * [OK] fake_system_role_tags (PROMPT-03) - genuinely effective. It matches
 *      fixed literal chat-template tokens (`<|im_start|>system`, `<</SYS>>`
 *      etc.), which are case-stable by nature, so ascii/case-sensitive
 *      matching is correct here rather than a limitation.
 *
 * [!!] instruction_bypass_phrase (PROMPT-01) - SEVERELY LIMITED. Upstream's
 *      regex has no `nocase` and requires the verb, the qualifier and the
 *      noun to be strictly adjacent. Verified misses:
 *        "ignore previous instructions"      (lowercase)      -> NO MATCH
 *        "IGNORE PREVIOUS INSTRUCTIONS"      (uppercase)      -> NO MATCH
 *        "Ignore all previous instructions"  (inserted "all") -> NO MATCH
 *        "Ignore the above instructions"     (inserted "the") -> NO MATCH
 *      Only the stilted "Ignore previous instructions" capitalization with
 *      no intervening word matches. Real-world injections overwhelmingly
 *      fall in the miss set, so PROMPT-01 should be treated as still
 *      effectively uncovered.
 *
 * [!!] markdown_image_exfiltration (NET-03) - NEARLY INERT. The regex needs
 *      a literal `?q=` immediately followed by `)`, plus a single-word alt
 *      text and single-segment path, i.e. only `![x](https://h/p?q=)`. Real
 *      rendered-image exfiltration carries stolen data in the query VALUE
 *      (`?data=<secret>`) or a template placeholder - none of which match.
 *      Treat NET-03 as still effectively uncovered.
 *
 * All three are kept verbatim for provenance and re-diffability against
 * upstream. Hardening them (adding `nocase`, tolerating inserted qualifiers,
 * generalizing the exfil query pattern) means diverging from upstream and is
 * a separate, owner-authorized decision - if taken, prefer ADDING in-house
 * rules alongside these rather than editing upstream's bodies in place.
 */

rule instruction_bypass_phrase {
    meta:
        findings_json = "{\"test_item_id\":\"PROMPT-01\",\"category\":\"instruction\",\"severity\":\"HIGH\",\"title\":\"instruction-bypass injection phrase (ignore/disregard prior instructions)\"}"
    strings:
        $a = /(Ignore|Disregard|Skip|Forget|Neglect|Overlook|Omit|Bypass|Pay no attention to|Do not follow|Do not obey)\s*(prior|previous|preceding|above|foregoing|earlier|initial)?\s*(content|text|instructions|instruction|directives|directive|commands|command|context|conversation|input|inputs|data|message|messages|communication|response|responses|request|requests)\s*(and start over|and start anew|and begin afresh|and start from scratch)?/
    condition:
        $a
}

rule fake_system_role_tags {
    meta:
        findings_json = "{\"test_item_id\":\"PROMPT-03\",\"category\":\"instruction\",\"severity\":\"HIGH\",\"title\":\"embedded fake system/role-turn tags (chat-template injection)\"}"
    strings:
        $a = "System Instruction: " ascii
        $b = "[system](#assistant)" ascii
        $c = "[system](#context)" ascii
        $d = "<s>[INST] <<SYS>>" ascii
        $e = "<</SYS>>" ascii
        $f = "<|im_start|>assistant" ascii
        $g = "<|im_start|>system" ascii
        $h = "{{#system~}}" ascii
        $i = "{{/system~}}" ascii
    condition:
        any of them
}

rule markdown_image_exfiltration {
    meta:
        findings_json = "{\"test_item_id\":\"NET-03\",\"category\":\"network_intel\",\"severity\":\"HIGH\",\"title\":\"markdown image with query-string used as a rendered-image exfiltration side-channel\"}"
    strings:
        $a = /\!\[\w+]\((https?:\/\/[\w\.-]+)\/(\w+)\?q=\)/
    condition:
        $a
}
