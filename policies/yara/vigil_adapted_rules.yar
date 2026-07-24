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
        findings_json = "{\"test_item_id\":\"PROMPT-01\",\"category\":\"instruction\",\"severity\":\"HIGH\",\"title\":\"指令绕过型提示词注入话术（忽略/无视此前指令）\",\"risk\":\"该内容试图诱导宿主 AI 助手忽略/无视此前的系统指令或规则约束，属于直接提示词注入攻击的典型话术。若被宿主 AI 助手当作合法指令解析，可能导致其绕过安全策略、泄露系统提示词或执行未经授权的操作。\"}"
    strings:
        $a = /(Ignore|Disregard|Skip|Forget|Neglect|Overlook|Omit|Bypass|Pay no attention to|Do not follow|Do not obey)\s*(prior|previous|preceding|above|foregoing|earlier|initial)?\s*(content|text|instructions|instruction|directives|directive|commands|command|context|conversation|input|inputs|data|message|messages|communication|response|responses|request|requests)\s*(and start over|and start anew|and begin afresh|and start from scratch)?/
    condition:
        $a
}

rule fake_system_role_tags {
    meta:
        findings_json = "{\"test_item_id\":\"PROMPT-03\",\"category\":\"instruction\",\"severity\":\"HIGH\",\"title\":\"嵌入伪造的 system/角色轮次标签（对话模板注入）\",\"risk\":\"该内容嵌入了伪造的对话模板控制标签（如 <|im_start|>system、<<SYS>> 等），试图让模型把后续文本误认为是真正的系统级指令而非普通用户输入，从而绕过角色边界注入伪造的高权限指令。\"}"
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
        findings_json = "{\"test_item_id\":\"NET-03\",\"category\":\"network_intel\",\"severity\":\"HIGH\",\"title\":\"带查询字符串的 markdown 图片，被用作渲染图片的外泄旁路\",\"risk\":\"markdown 图片会被渲染器自动请求，如果图片 URL 带有查询字符串，攻击者可以把敏感数据编码进查询参数，在用户毫无察觉、无需任何点击的情况下随图片请求一起外泄到攻击者控制的服务器（零点击外泄）。\"}"
    strings:
        $a = /\!\[\w+]\((https?:\/\/[\w\.-]+)\/(\w+)\?q=\)/
    condition:
        $a
}
