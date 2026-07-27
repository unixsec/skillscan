# 运维指南（Maintenance Guide）— skillscan

日常维护、故障排查、已知问题（含 2026-07-06 完整规格合规审计的 18 项修复清单与修复后
仍诚实标注的剩余差距）。构建/部署/日常使用见另外三份指南。

## 1. 日常维护

- **改动 `libs/skillscan_core` 后必须重跑不变式测试套件：** `python3 -m unittest discover
  -s tests -v`（96 项），尤其是修改 `gate.py`/`scoring.py` 后。
- **跑全量 pytest 前先停掉本地实时后端**（`lsof -ti :8000 | xargs kill`）：实时后端的
  后台 worker 与测试套件共享同一 Redis stream / MySQL，会互抢消息导致伪失败（2026-07-06
  晚实测：worker 运行时 2 个测试互抢失败，停掉后 721/721 全绿）。测试完再重启
  `uv run python3 scripts/dev/run_local.py`。
- **改代码后跑质量三件套：** `uv run mypy`（171 文件）、`uv run ruff check .`、
  `uv run ruff format .`。
- **审计链维护：** `apps/monolith/modules/audit/service.py` 的 `verify_chain(session,
  *, since_seq=0)` 重新计算每条记录哈希核对链一致性；默认 `since_seq=0` 会重算整条链
  （开发/测试期可以，生产环境应传入上次已验证过的 `seq` 做增量校验）。
- **Break-glass 运维：** 激活默认限时 900 秒、单次可用；TOTP 校验容忍 ±30 秒时钟漂移
  （`valid_window=1`）；每次激活/登录均写审计+触发 SecOps 告警。
- **后台 worker（2026-07-06 晚补齐，关键）：** `apps/monolith/worker.py` 的常驻循环由
  `SKILLSCAN_WORKER_ENABLED=true` 启用（`scripts/dev/run_local.py` 与 docker-compose 默认开，
  自动化测试套件默认关——测试自己显式驱动各 tick，绝不能与后台消费者抢同一批 Redis 消息）。
  每个 tick 依次执行：策略热重载（最新 `applied` 提案）→ 队列滞留 scan_job 补投递（覆盖
  reeval 触发的纯 DB 插入重扫）→ 引擎执行 → 打分/裁决（每 tick 实时读活跃白名单）→
  verdict 驱动生命周期状态机 → 审计链 drain → outbox drain（市场/SIEM）→ 报表 cron 调度。
- **SIEM 运维（2026-07-06 新增）：** `SyslogSiemAdapter`（CEF-over-syslog）是 fire-and-
  forget——SIEM 不可达只记一条 ERROR 日志，绝不影响 `gate_outbox` 的正常 dispatch/重试逻辑。
  worker 的 outbox drain 已经是它的常驻调用方。
- **报表运维：** `POST /v1/reports/schedule` 的 cron 由 worker 每分钟评估执行（Redis SET NX
  按"计划×分钟"去重，多副本安全）；投递目标为 SIEM 事件（未配置 SIEM 时记日志，邮件投递
  需要本代码库从未具备的 SMTP 基础设施——诚实跳过并记日志，不假装送达）。
- **策略生效语义（2026-07-06 晚新增）：** 管理员批准提案 → `promote_approved_policy` 当场
  应用并把该行标为 `applied`（ENUM 新值，迁移 `e4b8c31a90d2`）；worker 每 tick 重读最新
  `applied` 行使之跨重启/跨副本收敛。**历史上只停留在 `approved` 的行永远不会自动生效**
  （激活是逐提案的显式动作——共享开发库里积累的测试提案因此保持惰性，不会突然改写门禁）。
  两个 fail-closed 防护：YAML 解析失败拒绝应用；required_engines 引用本部署不存在的引擎
  拒绝应用（否则扫描将永远等不齐结果）。

## 2. 2026-07-06 完整规格合规审计 — 18 项修复清单

以下按审计报告的严重度顺序列出，均已修复、有回归测试、已现场验证零回归（706 pytest +
96 unittest 全绿，`mypy --strict`/ruff/format 全干净）。

**严重（2 项）：**
1. **`gate.decide()` 去重冲突可致三要素判定静默丢失（INV-1/INV-4）**——`libs/skillscan_core/
   gate.py` 现在会用 `scan_result` 自身预计算的 `severity`/`trifecta_present` 字段做兜底：
   若去重导致的重新计算结果比预计算字段弱，说明是去重信息丢失（不是合法的加白豁免），
   强制恢复。合法的四眼加白豁免逻辑不受影响（见 `tests/test_invariants.py` 的两条对照测试）。
2. **`POST /v1/reeval/{skill_id}` 缺少 CSRF 保护**——已补 `require_csrf` 依赖。

**高（6 项）：** `docs/THREAT_MODEL.md` 已创建；skillspector 的 OSV 端点已可通过
`osv_proxy_url` 重定向（见编译指南 §4）；`SKILLSCAN_VAULT_ADDR` 现通过统一 `Settings`
类做内网地址校验（此前 break-glass 路径遗漏了这一步，signer 路径本就正确）；SIEM 集成
已实现（见 §1）；intel-sync 内网同步已可通过 `POST /v1/admin/intel/sync` 触发。

**中（6 项，多为架构层面的完善，不影响功能）：** `libs/ports/` 已建立并收纳 7 个端口协议；
新增 `apps/monolith/config.py` 统一 `Settings` 类（编码规格 §13）；单扫描 SARIF 端点已补上；
真实 OIDC/SAML 登录路由已实现（见部署指南 §4，此前唯一能登录的路径是 break-glass）；
`ruleset_digest` 现在覆盖规则的 severity/category/trifecta 变更；路径穿越校验现在同时
识别正斜杠和反斜杠。

**低（4 项）：** osv-scanner 的 `--offline` 保持硬编码不变（有意为之，见编译指南 §4 的
安全说明，不是遗漏）；新增经典 XSW（签名包装攻击）回归测试；intel matcher 测试覆盖确认
早已存在（此前审计漏查了文件名）；`dynamic_sandbox_enabled` 配置项已加入 schema（功能
本身仍未构建，设置为 true 会在启动时收到明确警告而非静默无效）。

## 3. 剩余已知差距（诚实标注，非隐藏）

**2026-07-06 晚已关闭的原差距 1/2：** 扫描裁决 worker 循环（原差距 1，最重要的一条）与
`ScanRuntime.allowlist` 启动快照（原差距 2）已由 `apps/monolith/worker.py` 关闭——见 §1
"后台 worker"。同批工作还打通了：库存写入侧（`POST /v1/scans` 可选 `skill_id`/`trust_tier`
表单字段登记 skill/skill_version 并进入生命周期状态机，verdict 由 worker 驱动
scanning→published/review_pending）、策略批准即生效（见 §1）、报表 cron 调度执行（见 §1）、
reeval 触发的重扫真正执行（worker 的队列补投递把 DB-only scan_job 送进 airlock）。

仍然开放的差距：

1. **大多数列表端点无分页**——`/v1/allowlist`、`/v1/reviews`、`/v1/reeval`、
   `/v1/inventory` 均无 limit/offset（`/v1/audit` 已有）。
2. **`IntelMatcher` 测试充分但无实际扫描流程调用它**——`orchestration/floor.py` 的注释
   解释了原因（需要异步 DB 读取构造，不符合 floor 引擎"零参数可构建"的要求）。
3. **`SamlRequestTracker` 是进程内存状态，非多副本安全**——单体多副本部署时，SP-initiated
   请求的防重放追踪不会跨副本共享；不影响单副本部署。
4. **`test_audit_service.py` 偶发在全量测试套件下失败，单独运行必然通过**——真实 MySQL
   并发测试对测试执行顺序/累积数据量敏感，是已知的基础设施层面噪音（不是逻辑回归）。
5. **BLOCK 判定没有对应的生命周期状态**——§16.2 状态机没有 `blocked` 态，被 BLOCK 的
   skill 停留在 `scanning`（其签名 BLOCK verdict 在扫描页可见，市场发布永远不会发生）；
   如需显式状态需要扩状态机+迁移，属规格层决策，不在代码层擅自发明。
6. **~~worker 的引擎执行仍是进程内 floor 引擎~~（2026-07-28 已关闭）**——sandbox 层引擎
   （bandit / yara / skillspector / osv-scanner）现在真正参与裁决：裁决前会等待它们的结果，
   最长 300 秒，另加 30 秒 sweep 宽限（让引擎自己的 TIMEOUT 结果有机会先落盘——"我超时了"
   比"它没来"对运维更有信息量）。超时后以已到结果裁决，并在 `reasons` 里记录哪些引擎
   没赶上。等待是 advisory 的——sandbox 引擎缺席只降级为"未赶上"，不触发 fail-closed
   BLOCK，避免单个引擎故障造成批量误判。
   **等待时长从"开始等待"起算，而非从提交起算**（`scan_job.sandbox_wait_started_at`，
   迁移 `b7c41f9d2e08`）：否则 worker 停机后积压的扫描会在 floor 结果刚落盘的同一个
   tick 里因"提交时间已很旧"被强制裁决，整个 sandbox 层被跳过——方向是把本应 REVIEW
   的包判成 PASS，比误报危险得多。
   真实提交验证：同一份判定里同时含 floor 层与 bandit/skillspector 的 finding。
   **注意由此产生的体验落差**：扫描从毫秒级变为分钟级，而扫描详情页目前无自动轮询
   也无刷新按钮，提交后需手动刷新才能看到最终判定。

## 4. 故障排查

### 4.1 已知问题速查表

| 现象 | 原因 | 解决 |
|---|---|---|
| `ModuleNotFoundError: No module named 'skillscan_core'` | `uv sync` 先于源码文件创建执行 | `uv sync --reinstall-package skillscan` |
| `address already in use`（`scripts/one_click_dev.sh` 启动失败） | 端口 8000 被前一次未清理的进程占用 | `lsof -i :8000` 找到 PID 后 `kill` |
| 前端 CSRF 相关 403 | 状态变更请求未携带 `x-csrf-token` 头 | 检查 `require_csrf` 覆盖的 3 种会话 cookie（普通/break-glass/SAML）是否都已识别，见 §5 |
| break-glass 登录反复 401 | TOTP 码在到达服务端前已过期（30 秒窗口） | 已修复为 `valid_window=1`（±30秒容忍）；仍失败则确认时钟同步 |

### 4.2 CSRF cookie 枚举陷阱（重要的通用教训）

**教训：** 当"这是不是 cookie 认证请求"的判断靠枚举具体 cookie 名称实现时，每新增一种
会话类型都有可能被遗漏，导致该类型的写请求静默豁免 CSRF。这在本项目发生过两次：
break-glass（更早修复）、以及本次为 SAML 新增会话类型时**主动**同步更新了
`require_csrf`（`apps/monolith/modules/gateway/auth/dependencies.py`），避免第三次重犯
同一类问题。**任何未来新增的会话/cookie 类型，必须同步检查 `require_csrf` 是否已识别。**

### 4.3 MySQL 并发已知注意事项（M3 已修复，供未来修改审计链代码时参考）

审计哈希链在真实并发下暴露过三个真实 MySQL/InnoDB 行为（挑选待处理记录无锁导致双写、
链尾追加在 REPEATABLE READ 下死锁、READ COMMITTED 下仍可能拿到陈旧链尾导致静默分叉）——
均已修复（`SELECT...FOR UPDATE SKIP LOCKED` + READ COMMITTED + 显式陈旧性检测），修改
`append_one_intent`/`drain_pending_outbox` 或任何"读链尾→算哈希→追加"逻辑前务必了解。

### 4.4 环境受限项（非缺陷，本机验证深度的诚实边界）

gVisor 沙箱隔离本身（Linux-only）、真实 K8s 集群 apply/隔离测试/DR 演练、持续运行的真实
Vault、真实企业 IdP、真实 Skill 市场——均无法在本开发环境验证，相关代码/配置本身已通过
静态校验（`helm lint`/`kubeconform`/mypy/ruff），详见编译指南 §5-6。

---

## 相关文档

- [`BUILD_GUIDE.md`](BUILD_GUIDE.md) — 编译指南
- [`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md) — 部署指南
- [`USAGE_GUIDE.md`](USAGE_GUIDE.md) — 操作指南
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — 内核威胁模型
