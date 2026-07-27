# 企业 Skill 安全检测系统 — 内核威胁模型

本文档随 M1 交付（编码规格 §11.1 验收要求），是编码规格 §15 五条威胁的完整展开——不是
逐字复述规格的一句话概述，而是每条都给出真实攻击场景、当前代码里具体的缓解机制
（file:line）、以及验证该机制的具体测试用例名。范围限定在 `libs/skillscan_core`（内核）
本身；沙箱隔离、供应链、Web UI 等威胁面见 SAD v2.0 的 STRIDE 建模，不在此文档重复。

---

## 威胁①：聚合/裁决出错，导致本应拦截的内容被错误放行

**场景：** 内核是全系统唯一的裁决权威——如果 `aggregate()`/`decide()` 在聚合评分或分类判
定时算错，后果不是"某个字段显示错误"，而是一个真正危险的 Skill 包拿到 `PASS`，绕过后续
所有人工复核环节直接进入市场发布流程。

**缓解机制：**
- **MAX 聚合，不做平均/加权**（`scoring.py:34` `evaluate_findings()`）——多条 finding 里
  最严重的一条决定整体严重度，稀释攻击（大量低危 finding 掩盖一条高危 finding)无法生效。
- **fail-closed（INV-1）**（`gate.py:47-58` `decide()`）——`required_engines` 里任何一个
  未完成或失败，直接返回 `policy.fail_closed_verdict`（构造时已强制不能是 `PASS`，见
  `models.py` 的 `GatePolicy.__post_init__`），不进入后续任何裁决逻辑。
- **硬门禁（INV-3）**（`gate.py:60-75`）——命中 `hard_gate_rules` 的规则,在加白检查**之
  前**就直接 `BLOCK`,核心内没有任何路径能让硬门禁被绕过。
- **flood 不可 PASS（INV-5）**（`scoring.py:99-100`，`gate.py:141-144`）——findings 超过
  `max_findings` 上限时置位 `findings_capped=True`；`decide()` 末尾强制：即使正常分类给出
  `PASS`，只要 `findings_capped` 为真就改判 `REVIEW`。且 `scoring.py:88-97` 明确在**截断
  之前**（pre-cap）就计算好硬门禁命中和三要素信号，flood 无法把它们"挤出"可见范围。
- **致命三要素强制升级（INV-4）**（`scoring.py:40-44`）——见威胁③单独展开。

**验证：** `tests/test_invariants.py::test_inv1_fail_closed_on_missing_or_failed_required_engine`、
`test_inv1_fail_closed_verdict_must_not_be_pass`、`test_inv3_hard_gate_unwaivable`、
`test_inv5_flood_capped_cannot_pass`、`test_inv5_cap_keeps_worst_and_preserves_hard_gate`；
`tests/test_scoring.py::test_findings_capped_and_pre_cap_hard_gate_preserved`、
`test_findings_capped_and_pre_cap_trifecta_preserved`、`test_worst_first_truncation_keeps_most_severe`。

---

## 威胁②：LLM 语义分析被用作"判定洗白"通道

**场景：** LLM 引擎的输出本质上是概率性的、可被提示注入影响的。如果一条高置信度的确定性
（静态/规则）finding 可以被一条低危的 LLM finding"稀释"或"覆盖"，攻击者只需要让 Skill 包
的内容对 LLM 分析器"看起来人畜无害"，就能把一个本该 `BLOCK` 的结果洗白成 `PASS`——LLM 分
析器于是从"增强检测"变成了攻击者可操纵的绕过入口。

**缓解机制：**
- **单调性 floor（INV-2）**（`gate.py:92-125`）——`decide()` 对"全部有效 finding"和"仅确
  定性 finding 子集"分别独立跑一遍分类，取更严的判定（`verdict = max(verdict_all,
  verdict_non_llm)`）。LLM finding 因此在结构上只能让判定更严，绝不可能让一个确定性引擎已
  经判定 `BLOCK` 的结果被 LLM 的介入拉回 `PASS`。
- **无"安全"信号通道**（`models.py` 的 `Finding.__post_init__`）——finding 的 `severity`
  字段禁止为 `NONE`（构造时校验，不允许"NONE severity"的合法 finding 存在），杜绝了"LLM 主
  动生成一条极低权重的 finding 去挤占 dedup 位、顶替掉更严重的确定性发现"这种攻击面。
- **按来源分区去重**（`scoring.py:49-59` `_dedup()`）——去重键是 `(dedup_key,
  is_llm_sourced)`，LLM finding 与确定性 finding 永远不会共享同一个去重槽位,不存在"LLM
  finding 顶替确定性 finding"的可能。

**验证：** `tests/test_invariants.py::test_inv2_llm_monotonicity_randomized_fixed_seed`
（固定 seed 随机化属性测试，规格明确要求）、
`test_inv2_llm_only_cannot_pass_when_static_alone_blocks`；
`tests/test_scoring.py::test_llm_and_non_llm_at_same_key_both_survive`。

---

## 威胁③：加白（allowlist）机制被滥用为绕过通道

**场景：** 加白本身是合法、必要的功能（处理已知误报），但如果加白检查存在逻辑漏洞——比如
允许自己审批自己的申请、允许豁免高危规则、或允许过期条目继续生效——它就从"误报处理工具"变
成了"内部人员绕过审计"的现成后门。

**缓解机制：**
- **硬门禁不可加白（INV-3/INV-8）**（`gate.py:79-90` `_is_waived()` 第一行判断）——即使存
  在一条完全匹配、生效中的加白条目，只要 finding 命中 `hard_gate_rules`，`_is_waived()`
  直接返回 `False`。这是纵深防御：`combined_hard_gate` 检查已经在加白逻辑运行**之前**就
  拦截返回,这里的判断理论上不可达,但仍显式保留。
- **四眼原则在构造时强制**（`models.py` 的 `AllowlistEntry.__post_init__`）——
  `approved_by == requested_by` 直接 `raise`,不是运行时才检查,不存在"忘记校验"的路径；
  数据库层还有一道 `CHECK (approved_by <> requested_by)` 约束兜底（`db/migrations/` 的
  `allowlist` 表定义）。
- **严格过期 + scope 匹配**（`models.py` 的 `AllowlistEntry.is_active()`）——`now >=
  expires_at` 即判定失效（不是宽松的 `>`）；`scope_type` 不识别的一律返回 `False`
  （fail-closed，未知 scope 类型不会被"默认放行"）。
- **严重度上限**（`gate.py:85`）——finding 的 `severity` 超过 `policy.
  allowlistable_max_severity` 直接不可豁免,防止把加白当成绕过高危发现的工具。

**验证：** `tests/test_invariants.py::test_inv3_hard_gate_unwaivable`、
`test_inv8_allowlist_four_eyes_enforced_at_construction`、
`test_inv8_allowlist_expiry_enforced`、`test_inv8_scope_mismatch_not_waived`、
`test_inv8_severity_above_ceiling_not_waivable`。

---

## 威胁④：内容寻址哈希发生碰撞，或在归一化过程中丢失安全相关字节

**场景：** `content_hash` 是全系统判定、缓存、审计的锚点——如果两个内容不同（尤其是安全
语义不同,比如一个有可执行位、一个没有）的 Skill 包被算出相同的 `content_hash`，攻击者就能
让一个恶意版本"冒用"一个已经拿到 `PASS` 判定的良性版本的哈希，绕过重新扫描。

**缓解机制：**
- **对原始字节求哈希,不解码/不转码**（`canonical.py:67-69` `content_hash()`）——直接对传
  入的 `bytes` 调用 `hasher.update()`，不做任何编码转换，不会因为字符集转换而丢失安全相关
  字节。
- **文件 mode 位纳入哈希**（`canonical.py:57,66`）——`mode & 0o7777` 与内容一起参与哈希，
  两个字节完全相同但一个带可执行位、一个不带的文件会产生不同的 `content_hash`。
- **域分隔 + 长度前缀编码**（`canonical.py:15-22` `_encode_chunk()`）——每个字段前缀 8
  字节大端长度,不同字段拼接不会产生歧义（比如 `"ab"+"c"` 和 `"a"+"bc"` 不会被哈希成一样的
  字节流）。
- **顺序无关**（`canonical.py:60`）——按归一化路径排序后再哈希，文件提交顺序不影响结果。
- **拒绝路径穿越/重复路径/空文件集**（`canonical.py:25-38`）——NUL 字节、绝对路径、
  drive-letter、`.`/`..`/空段、NFC 归一化后的重复路径，均在 `_validate_and_normalize_path()`
  里被拒绝；空文件集本身也被 `content_hash()` 拒绝（拒绝"认证空内容"）。

**验证：** `tests/test_invariants.py::test_inv6_content_hash_order_independent_and_mode_sensitive`。

---

## 威胁⑤：Stale-PASS——引擎/策略升级后，旧的缓存判定继续被信任

**场景：** 如果今天某条检测规则有漏洞（比如漏检了一种攻击手法），团队修复后升级了规则集，
但一个**在漏洞被修复前**就已经拿到 `PASS` 判定并被缓存的旧 Skill 版本,理应被视为"用旧规
则判定过、需要重新评估",而不是继续被信任。如果缓存键不感知这种升级，攻击者的思路会变成
"赶在规则修复前提交一次,拿到 PASS 之后就永远安全"。

**缓解机制：**
- **`toolchain_digest` 绑定引擎版本+策略版本+prompt 版本**（`canonical.py:73-88`）——对
  `sorted(f"{engine.name}@{engine.version}#{engine.ruleset_digest}")` 加上
  `policy_version`、`prompt_version` 一起求哈希，任一项变化,digest 就变。
- **`cache_key` 绑定 `content_hash` 与 `toolchain_digest` 两者**（`canonical.py:91-95`）——
  `toolchain_digest` 变化会级联使 `cache_key` 变化,旧的缓存 PASS 判定因为查不到匹配的新
  `cache_key` 而自然失效，不需要额外的失效逻辑。

**验证：** `tests/test_invariants.py::test_inv7_toolchain_digest_change_invalidates_cache_key`。

---

## 残余风险与本次核查的新发现（2026-07-06）

以上都是"设计上应该生效"的缓解机制——但 2026-07-06 针对编码规格 v2.0 的一次全量合规审计
（6 路独立核查，直接对照当前源码与测试，不采信任何自述结论）发现,其中两条**在实际代码里
并未像设计描述的那样完全生效**，本次已一并修复:

**威胁①/致命三要素抬升（INV-4）在 `decide()` 层被 `_dedup()` 的去重冲突静默绕过。**
`scoring.aggregate()` 本身在去重/截断**之前**（pre-cap）正确算出了真实的
`ScanResult.severity`/`trifecta_present`（`scoring.py:88-97,109-111`），这两个字段从未出
错。但修复前的 `gate.decide()` 从不读取这两个字段——它总是基于**已经去重后**的
`scan_result.findings` 重新计算一遍。当携带致命三要素信号（比如 `EXTERNAL_EGRESS`）的一条
finding，恰好与另一条**不携带该信号、但 `(severity, confidence)` 更高**的 finding 共享同
一个 `dedup_key`（`scoring.py:53-58`：去重只保留每个键下 `(severity, confidence)` 最大的
一条），该信号就会在 `scan_result.findings` 里彻底消失——且这个过程**完全不涉及 flood 截
断**，INV-5"截断结果不可 PASS"的兜底根本不会触发。现场用一个真实构造的 `ScanResult`
复现：`scan_result.severity=CRITICAL`、`trifecta_present=True`，但（修复前的）
`decide()` 计算出 `effective_severity=MEDIUM`、`trifecta_present=False`，最终判定
`PASS`——一个真正的 CRITICAL+致命三要素场景被静默放行。

修复（`gate.py:102-125`）：`decide()` 现在额外对**未加白**的 `scan_result.findings` 重新
跑一遍 `evaluate_findings`（`sev_unwaived`/`trif_unwaived`），如果这个"未加白"版本已经
弱于 `ScanResult` 自身的权威字段，说明差距纯粹来自去重冲突（不是任何加白决策造成的，因为
加白检查这时候还没发生），必须无条件恢复；如果"未加白"版本与 `ScanResult` 一致（去重没有
丢信息），那么后续经过合法四眼加白造成的降级——按规格 §5.4 第 6 步"pre-cap trifecta 未被
(经四眼加白)移除"的原文——依然允许生效。两条新回归测试区分了这两种情况：
`tests/test_invariants.py::test_inv4_dedup_collision_does_not_silently_lose_trifecta`（去
重冲突场景，必须强制 BLOCK）与
`test_inv4_legitimate_waiver_can_still_defeat_trifecta_without_dedup_collision`（无去重冲
突、纯四眼加白场景，允许合法降级，证明修复没有把"加白" 变成"完全不可能")。

**威胁④/路径穿越校验目前只识别正斜杠。** `canonical.py:35`
（`for segment in normalized.split("/")`) 只按 `/` 切分路径段做 `.`/`..`/空段校验，一个用
反斜杠拼接的路径穿越字符串（如 `..\\..\\etc\\passwd`）不会被识别为非法路径。`services/
engine_runner/normalizer.py` 里镜像了同样的校验逻辑,同样的缺口。实际利用面因为部署目标是
POSIX/Linux（反斜杠不是真实路径分隔符）而降低，但校验函数自身"拒绝路径穿越"的字面承诺并
不完整——**这是一条尚未修复的已知缺口**（本文档撰写时 `canonical.py` 仍是上述状态；如果你
正在阅读的是这之后的版本，请直接检查 `_validate_and_normalize_path()` 是否已经同时识别
`/` 和 `\` 两种分隔符,并相应更新本节）。

## 残余、可接受的风险（编码规格 §15 收尾）

以下是内核设计上就**假定成立、自身无法验证**的边界,不是缺陷,而是明确的信任边界:

- **内核信任引擎适配器如实设置 `capability`/`severity`，并且真的在隔离环境里运行。** 一个
  被攻陷或写错的适配器如果谎报 `EngineCapability`（比如把 LLM 来源伪装成确定性来源），能绕
  过 INV-2 的单调性 floor——这条防线在 §10（适配器契约）和部署层（gVisor 隔离），不在内核。
- **floor 引擎（`StaticKeywordEngine`）只做字节级匹配。** 面对足够复杂的混淆/编码,字节级
  匹配会漏检——深度检测能力依赖沙箱内的真实 OSS 引擎/LLM 分析，floor 引擎只是"即使沙箱被压
  制也不至于完全失明"的下限,不是完整检测能力本身。
- **策略正确性是 config-as-code + PR 评审假设，内核不做语义校验。** `GatePolicy` 的构造函
  数只校验结构性不变式（阈值合法、`fail_closed_verdict != PASS` 等），不校验"这份策略在业
  务意义上是否合理"——一份结构合法但阈值设得过于宽松的策略,内核会诚实地按它执行,这个责任
  边界在人工评审流程,不在代码。

---

## 相关文档

- [`docs/stories/BACKLOG.md`](stories/BACKLOG.md) — 里程碑实现状态、本项目历次真实发现的
  缺陷（含 2026-07-06 全量审计的完整清单）
- [`docs/USER_GUIDE.md`](USER_GUIDE.md) §8.1 — M1 已知问题的用户可见故障排查视角
- `企业Skill安全检测系统-系统设计文档-编码规格v2.0.md` §1（不变式表）、§14（不变式测试清
  单）、§15（本文档所依据的原始威胁列表）
