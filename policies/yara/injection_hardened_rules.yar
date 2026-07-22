/*
 * ORIGINAL in-house rules - NOT adapted from any third-party source.
 *
 * These exist because the upstream-derived rules in vigil_adapted_rules.yar
 * were empirically measured (2026-07-22, yara 4.5.0) and found to miss the
 * forms real injections actually take:
 *   - instruction_bypass_phrase (PROMPT-01) has no `nocase` and requires the
 *     verb/qualifier/noun to be strictly adjacent, so lowercase, uppercase,
 *     and "Ignore ALL previous instructions" all escaped it.
 *   - markdown_image_exfiltration (NET-03) only matched a literal `?q=)`.
 * Those rules are kept verbatim there for provenance and re-diffability
 * against upstream; the working detection for PROMPT-01/NET-03 lives HERE.
 * Do not "fix" the upstream file - that is the deliberate split.
 *
 * SECURITY (calibration, same posture as this directory's other rule files
 * and policies/gate/v1.yaml's FP-tuning notes): neither rule is added to
 * hard_gate_rules. Both require a multi-part structural match rather than a
 * single suspicious word, but natural-language matching is inherently
 * FP-prone - a skill's own documentation explaining prompt injection can
 * legitimately contain these phrases. They therefore score toward
 * severity/REVIEW for human adjudication, never an unwaivable forced BLOCK.
 *
 * FP-TUNING (2026-07-22 code review): two branches were narrowed after a
 * review flagged real false positives -
 *   - image exfil: the param-name branch matched generic CDN query params
 *     (token/data/content/...), flagging legitimate signed image URLs. It now
 *     lists only explicit exfil indicators; the reliable NET-03 signal is the
 *     template-interpolation ({{ }}/${ }) shapes, which have near-zero FPs.
 *     NET-03 coverage is therefore "templated / obviously-named exfil", NOT
 *     any `?data=<value>` image URL - static param names can't prove intent.
 *   - instruction bypass: the "$b and $c" persona+reveal branch made $c's
 *     qualifier (system/initial/...) REQUIRED so it targets prompt-exfil
 *     intent instead of firing on ordinary "print the instructions" prose.
 */

rule instruction_bypass_phrase_hardened {
    meta:
        findings_json = "{\"test_item_id\":\"PROMPT-01\",\"category\":\"instruction\",\"severity\":\"HIGH\",\"title\":\"instruction-bypass injection phrase (case-insensitive, tolerates inserted qualifiers)\"}"
    strings:
        /*
         * Structure required: <override verb> [optional qualifiers] <temporal
         * or authority reference> <instruction noun>. All three parts must be
         * present, which is what keeps this from firing on ordinary prose
         * containing the word "ignore".
         */
        $a = /(ignore|disregard|forget|discard|override|bypass|skip|neglect|overlook|omit)\s+((all|any|the|these|those|your|my|其他)\s+){0,3}(previous|prior|preceding|above|earlier|initial|original|foregoing|former|last|system)\s+((of\s+the\s+|of\s+)?)(instruction|instructions|directive|directives|prompt|prompts|rule|rules|command|commands|guideline|guidelines|constraint|constraints|context|message|messages)/ nocase

        /* "you are no longer X" / "from now on you are X" persona-override */
        $b = /(you\s+are\s+(now\s+|no\s+longer\s+)|from\s+now\s+on[,\s]+you\s+(are|will|must)\s+)/ nocase

        /* explicit demand to reveal the *system/hidden* prompt. The
         * qualifier (system|initial|...) is REQUIRED, not optional: without
         * it, "$b and $c" fired on ordinary tutorial prose like "You are now
         * ready. Print the instructions below." ("print the instructions" is
         * extremely common in CLI/shell docs). Requiring a leak-specific
         * qualifier keeps this on prompt-exfiltration intent - "reveal your
         * system prompt" / "show the initial instructions" still match,
         * "print the instructions" no longer does. */
        $c = /(reveal|print|repeat|output|show|display|disclose|dump)\s+((all|the|your|any)\s+){0,3}(system|initial|original|internal|hidden|underlying|secret)\s+(prompt|prompts|instruction|instructions|directive|directives)/ nocase
    condition:
        $a or ($b and $c)
}

rule markdown_image_exfiltration_hardened {
    meta:
        findings_json = "{\"test_item_id\":\"NET-03\",\"category\":\"network_intel\",\"severity\":\"HIGH\",\"title\":\"image reference whose URL query carries interpolated data (rendered-image exfiltration side-channel)\"}"
    strings:
        /*
         * Markdown image whose URL query interpolates a template variable -
         * the classic zero-click exfil: the renderer fetches the URL and the
         * secret leaves in the query string.
         */
        $md_tpl1 = /!\[[^\]\n]{0,64}\]\(https?:\/\/[^\s)\n]{1,160}\?[^\s)\n]{0,80}=[^\s)\n]{0,20}\{\{/ nocase
        $md_tpl2 = /!\[[^\]\n]{0,64}\]\(https?:\/\/[^\s)\n]{1,160}\?[^\s)\n]{0,80}=[^\s)\n]{0,20}\$\{/ nocase

        /* Markdown image whose query parameter is named like an EXFIL carrier.
         * The name list is deliberately restricted to explicit exfiltration
         * indicators (exfil/payload/secret/leak/dump/prompt). Generic names a
         * real image CDN / presigned URL uses (token/data/content/info/msg/
         * body) were removed - they matched legitimate signed image URLs like
         * `?token=<sig>`, forcing a HIGH->BLOCK on public tier. Static
         * param-name matching cannot tell a benign `?data=` from an exfil one,
         * so the reliable NET-03 signal is the template-interpolation shapes
         * above; this branch only adds obviously-malicious parameter names. */
        $md_par = /!\[[^\]\n]{0,64}\]\(https?:\/\/[^\s)\n]{1,160}\?([^\s)\n&]{0,60}&)?(exfil|payload|secret|leak|dump|prompt)=[^\s)&\n]+/ nocase

        /* Same two shapes for raw HTML <img>, which markdown renderers pass through. */
        $html_tpl = /<img[^>]{0,120}src\s*=\s*["']?https?:\/\/[^\s"'>]{1,160}\?[^\s"'>]{0,80}=[^\s"'>]{0,20}(\{\{|\$\{)/ nocase
        $html_par = /<img[^>]{0,120}src\s*=\s*["']?https?:\/\/[^\s"'>]{1,160}\?([^\s"'>&]{0,60}&)?(exfil|payload|secret|leak|dump|prompt)=[^\s"'>&]+/ nocase
    condition:
        any of them
}
