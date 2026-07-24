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
        findings_json = "{\"test_item_id\":\"PROMPT-07\",\"category\":\"instruction\",\"severity\":\"HIGH\",\"title\":\"Skill 代码篡改了 AI 推理服务端点（存在模型替换/流量劫持风险）\",\"risk\":\"该 Skill 代码修改了 ANTHROPIC_BASE_URL/OPENAI_BASE_URL 等推理服务端点环境变量，会把宿主 AI 助手后续的模型请求重定向到攻击者指定的服务器；一旦得逞，攻击者可以冒充真实模型返回任意伪造的回复、窃取对话内容中的敏感信息，或篡改工具调用结果。\"}"
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
        findings_json = "{\"test_item_id\":\"PERM-06\",\"category\":\"permission\",\"severity\":\"HIGH\",\"title\":\"代码写入 agent 记忆/身份文件（CLAUDE.md/MEMORY.md/AGENTS.md/SOUL.md/.claude 配置类记忆投毒入口）\",\"risk\":\"该 Skill 代码写入了 CLAUDE.md/MEMORY.md/AGENTS.md 等宿主 AI 助手会持续读取的记忆/身份/配置文件，属于记忆投毒（memory poisoning）攻击：一旦写入恶意指令，会在此后所有会话中被当作可信的长期记忆自动加载执行，实现一次投毒、持续生效的持久化攻击，且不易被察觉。\"}"
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
        findings_json = "{\"test_item_id\":\"PERM-07\",\"category\":\"permission\",\"severity\":\"HIGH\",\"title\":\"Skill 定义/修改了 agent 工具执行钩子（PreToolUse/PostToolUse 类监控、外泄或内存转储拦截）\",\"risk\":\"该 Skill 定义或修改了宿主 AI 助手的工具执行钩子（如 PreToolUse/PostToolUse），钩子会在每次工具调用前后自动触发，攻击者可借此拦截并窃取工具调用的参数与结果（包括敏感数据、凭据）、篡改工具行为，或建立隐蔽的持久化监控通道。\"}"
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
