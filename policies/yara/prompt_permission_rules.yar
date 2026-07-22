/*
 * Original rules covering PROMPT-07/PERM-06/PERM-07 (企业Skill安全评估测试维度
 * 清单.xlsx) - a 2026-07-09 code re-audit confirmed these three had ZERO
 * detection coverage anywhere in skillscan or the vendored skillspector
 * analyzers (unlike most of D5/D6, which skillspector's static analyzers
 * already substantially cover). No existing OSS tool covers these narrow,
 * skillscan/Claude-Code-ecosystem-specific concerns either (searched:
 * llm-guard, garak, rebuff, bawbel/scanner, cisco-ai-defense/mcp-scanner) -
 * these are original, in-house rules, not adapted from any third-party
 * source.
 *
 * SECURITY (calibration, same posture as skillscan_rules.yar's existing
 * rules and policies/gate/v1.yaml's own pii.credit_card/provenance
 * FP-tuning notes): none of these are added to hard_gate_rules. Plain string
 * co-occurrence in a single file is a real signal but not proof of intent -
 * these score toward severity/REVIEW like every other yara finding, never an
 * unwaivable forced BLOCK.
 */

rule model_endpoint_redirection {
    meta:
        findings_json = "{\"test_item_id\":\"PROMPT-07\",\"category\":\"instruction\",\"severity\":\"HIGH\",\"title\":\"skill code overrides the AI inference endpoint (model-substitution / interception risk)\"}"
    strings:
        $env1 = "ANTHROPIC_BASE_URL" ascii
        $env2 = "OPENAI_BASE_URL" ascii
        $env3 = "OPENAI_API_BASE" ascii
        $env4 = "ANTHROPIC_API_URL" ascii
        $set1 = "os.environ[" ascii
        $set2 = "os.environ.setdefault" ascii
        $set3 = "os.putenv(" ascii
        $set4 = "process.env." ascii
    condition:
        (any of ($env*)) and (any of ($set*))
}

rule agent_memory_file_write {
    meta:
        findings_json = "{\"test_item_id\":\"PERM-06\",\"category\":\"permission\",\"severity\":\"HIGH\",\"title\":\"code writes to an agent memory/identity file (CLAUDE.md/MEMORY.md/AGENTS.md/SOUL.md/.claude settings-class memory-poisoning entry point)\"}"
    strings:
        $target1 = "CLAUDE.md" ascii
        $target2 = "MEMORY.md" ascii
        $target3 = "AGENTS.md" ascii
        $target4 = "SOUL.md" ascii
        $target5 = ".claude/settings" ascii
        $write1 = "open(" ascii
        $write2 = "fs.writeFile" ascii
        $write3 = "fs.appendFile" ascii
        $write4 = "writeFileSync" ascii
        $write5 = ".write(" ascii
        $write6 = ".writelines(" ascii
    condition:
        (any of ($target*)) and (any of ($write*))
}

rule hook_configuration_abuse {
    meta:
        findings_json = "{\"test_item_id\":\"PERM-07\",\"category\":\"permission\",\"severity\":\"HIGH\",\"title\":\"skill defines/modifies agent tool-execution hooks (PreToolUse/PostToolUse-class monitoring, exfiltration, or memory-dump interception)\"}"
    strings:
        $hook1 = "PreToolUse" ascii
        $hook2 = "PostToolUse" ascii
        $hook3 = "SessionEnd" ascii
        $hook4 = "\"Stop\"" ascii
        $settings_key = "\"hooks\"" ascii
        $settings_path = ".claude/settings" ascii
    condition:
        (any of ($hook*)) and ($settings_key or $settings_path)
}
