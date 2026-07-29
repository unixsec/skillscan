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
- **审计链维护：** `apps/monolith/modules/audit/service.py` 的 `verify_chain(session)`
  从创世条目起重算每条记录哈希、核对整条链，**不接受任何游标参数**（里程碑 F Task 17）。
  它曾经有 `since_seq`：传入时锚定在游标那条记录上（信任它自己存的哈希），游标之前的记录
  一条都不读，返回的布尔值却与整链校验的返回值毫无区别——`GET /v1/audit?since_seq=N`
  就这样把"第 N 页内部自洽"当成"审计日志完整"报给了控制台。实测（本机纯 CPU）重算 3000 条
  记录的哈希约 8 ms，而整链扫描本来就是该端点默认调用一直在付的代价，所以取消游标没有引入
  新开销。将来账本真的大到扛不住时，正确解法是**带签名、定期重验的检查点**，而不是让调用方
  自带一个不可信的游标。
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
- **市场对接部署后必须重跑 `db/setup_grants.py`（里程碑 B'，关键）：** `marketplace_api`
  的取用审计写入用的是独立数据库账号 `svc_marketplace`（`policies/grants/manifest.yaml`），
  这个账号不会随镜像/代码部署自动创建。**危险之处在于故障是完全无声的**：进程照常启动
  （数据库引擎惰性连接，启动阶段不会探测这个账号是否存在），`POST/GET /v1/market/scans`
  照常返回正确结果（审计写入失败不允许阻塞轮询响应，见 §7 设计），唯一的外部表现是
  `marketplace_fetch_log` 表永远空着——看起来像"系统健康、只是还没人轮询过"。部署本里程碑
  后，第一次真实轮询发生后应主动 grep 应用日志中的 `marketplace_fetch_audit_write_failed`；
  出现即说明 `svc_marketplace` 授权缺失或过期，重跑 `db/setup_grants.py` 补上。
- **改过 `企业Skill安全评估测试维度清单.xlsx` 后必须重跑目录生成器（2026-07-29，里程碑 C
  Task 6）：** `uv run python scripts/gen_detection_catalog.py`，并把
  `policies/detection_catalog.json` 一起提交。那份 .xlsx 是 62 个 `test_item_id` 的唯一权威源，
  但它被 `.gitignore` 排除（`/*.xlsx`）、只存在于作者本机——**任何 clone、CI checkout 与容器镜像里
  都没有它**。因此 `tests/test_test_item_catalog.py`（`SUP-01` 事故后建立的三重守卫）改为读那份
  生成的 JSON 清单：清单随仓库走，守卫因此在所有环境里都真跑；清单缺失是**硬失败**，不再是 skip。
  同步性由两处保证：`deploy_and_test_vm.sh` 第 1 步在 Mac 上跑 `--check`（.xlsx 缺失也算失败），
  以及 `TestManifestMatchesTheAuthoritativeXlsx`。**只导出条目编号，不导出条目名称/检测要点**——
  编号本来就散布在引擎源码、测试与 SAD 里，不属于需要留在表格内的内容。
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
6. **~~worker 的引擎执行仍是进程内 floor 引擎~~（2026-07-28 已关闭，里程碑 D）**——sandbox
   层引擎（bandit / yara / skillspector / osv-scanner）现在真正参与裁决：裁决前会等待
   它们的结果，最长 300 秒（另加 30 秒 sweep 宽限），超时后以已到结果裁决并在 `reasons`
   里记录哪些引擎没赶上。等待是 advisory 的——sandbox 引擎缺席只降级为"未赶上"，不触发
   fail-closed BLOCK，避免单个引擎故障造成批量误判。等待时长从"开始等待"起算而非从提交
   起算（`scan_job.sandbox_wait_started_at`，迁移 `b7c41f9d2e08`），否则 worker 停机后
   积压的扫描会在 floor 结果刚落盘的同一个 tick 里被强制裁决、跳过整个 sandbox 层。
   真实提交验证：同一份判定里同时含 floor 层与 bandit/skillspector 的 finding。
   **注意由此产生的体验落差**：扫描从毫秒级变为分钟级，而扫描详情页目前无自动轮询也无
   刷新按钮，提交后需手动刷新才能看到最终判定（属里程碑 F 的前端闭环范围）。
7. **市场对接（里程碑 B'）刻意只做拉取，主动推送与 ORPHAN 对账均未实现**——两者都不是
   遗漏，而是这次范围的明确边界：
   - **主动推送（push）**：现有 `gate_outbox` + `HttpMarketplaceAdapter.write_verdict`
     代码保留但默认关闭（`reconciliation_push_enabled=False`）。它调用的 URL 形状是适配器
     自己假设的，对方接口从未被确认过，修好了也没有办法验证是否真的对得上——用户
     2026-07-28 已明确本轮只做 pull。
   - **ORPHAN 对账**：ORPHAN 的定义是"市场已上架但我方从未出过判定"，检测它必须能读取
     对方已上架的清单（`list_published()`）。pull-only 模型下我方没有可调的对方接口，
     这个检测**结构上不可实现**——接上去只会得到一个永远返回空、看起来在工作但什么也
     检测不到的调度器。§6.8（取用审计表 `marketplace_fetch_log`）是这个空缺在 pull 模型
     下唯一可实现的对偶：能查"已出判定但从未被取走"，是最接近 ORPHAN 的信号，且完全来自
     我方数据，不依赖对方接口。
8. **控制台 `POST /v1/scans` 仍接受调用方表单提交的 `trust_tier`**——本里程碑（B'）只把
   `/v1/market/scans` 改成了服务端按身份决定 tier（见 `USAGE_GUIDE.md` §6.3），控制台路径
   未改动。这被认为风险模型不同（控制台面向已认证的内部人员，市场路径面向不受控的外部
   提交内容），因此不在本里程碑范围内，但仍是一个真实差距：一个内部提交者理论上仍可以
   声明 `trust_tier=internal` 把本该 BLOCK 的 HIGH 级 finding 降级为 REVIEW。

## 4. 故障排查

### 4.1 已知问题速查表

| 现象 | 原因 | 解决 |
|---|---|---|
| `ModuleNotFoundError: No module named 'skillscan_core'` | `uv sync` 先于源码文件创建执行 | `uv sync --reinstall-package skillscan` |
| `address already in use`（`scripts/one_click_dev.sh` 启动失败） | 端口 8000 被前一次未清理的进程占用 | `lsof -i :8000` 找到 PID 后 `kill` |
| 前端 CSRF 相关 403 | 状态变更请求未携带 `x-csrf-token` 头 | 检查 `require_csrf` 覆盖的 4 种会话 cookie（普通/break-glass/SAML/local）是否都已识别，见 §4.2 |
| 页面能正常浏览，但所有保存/提交操作都返回 403 | 会话 cookie 仍在，但共享的 `csrf_token` cookie 已过期（读请求不校验 CSRF，写请求校验） | 已修复：`CSRF_COOKIE_MAX_AGE_S` 使 CSRF cookie 长于任何会话 TTL，见 §4.2 |
| break-glass 登录反复 401 | TOTP 码在到达服务端前已过期（30 秒窗口） | 已修复为 `valid_window=1`（±30秒容忍）；仍失败则确认时钟同步 |
| 市场轮询正常返回结果，但 `marketplace_fetch_log` 表始终为空 | `svc_marketplace` 数据库账号未建立/授权过期，审计写入按设计静默失败且不影响响应（见 §1） | grep 日志中的 `marketplace_fetch_audit_write_failed` 确认；重跑 `db/setup_grants.py` |

### 4.2 CSRF cookie 陷阱（重要的通用教训）

本项目**现有 4 种**会话 cookie，全部在 `middleware.py` 的 `SESSION_COOKIE_NAMES` 注册表中：
`skillscan_session`（OIDC）、`skillscan_breakglass_session`、`skillscan_saml_session`、
`skillscan_local_session`（2026-07-13 新增）。而 CSRF cookie 只有 `csrf_token` **一个名字**，
被所有 4 条登录路径共用。这一"1 对 4"的不对称，已经用两种不同的方式咬过这个项目：

**（一）名字枚举导致的静默豁免（fail-OPEN）。** 当"这是不是 cookie 认证请求"的判断靠枚举
具体 cookie 名称实现时，每新增一种会话类型都可能被遗漏，导致该类型的写请求完全豁免 CSRF。
break-glass 就这样漏过一次（只有真实浏览器测试才发现）。现已结构性修复：`require_csrf`
（`apps/monolith/modules/gateway/auth/dependencies.py`）改为查 `SESSION_COOKIE_NAMES` 单一
注册表，不再手抄名单；`test_dependencies.py::TestCsrfCoversEverySessionCookie` 会自动发现
模块里声明的所有会话 cookie 常量，与注册表比对，漏掉一个就红。

**（二）共享 cookie 名 + 各自的 TTL 导致的静默锁写（2026-07-29 修复）。** 每条登录路径原本
用**自己会话的 TTL** 去写这个共享的 `csrf_token`：一次 900 秒的 break-glass 登录，会把一个
8 小时 local/SAML/OIDC 会话的 CSRF cookie 覆盖成 15 分钟。15 分钟后，那个仍然有效的 8 小时
会话**读请求一切正常**（CSRF 只校验状态变更方法）、**所有写请求 403**——用户看到的是"页面
能看但什么都保存不了"，且没有任何提示指向真实原因。修法：CSRF cookie 的生命周期与"是哪条
登录写的它"彻底解耦——`CSRF_COOKIE_MAX_AGE_S`（7 天，远长于最长的会话 TTL），且
`set_csrf_cookie()` **不再接受 max_age 参数**，因此"某条登录路径漏改"是 mypy 能查出来的事实，
而不是需要有人记得的事情。双重提交令牌不是凭据（它必须能被同源 JS 读到），延长它不降低任何
安全性；`test_middleware.py::TestCsrfCookieOutlivesEverySessionType` 会自动发现所有会话 TTL
常量并断言它们都短于 CSRF cookie。

**通用教训：单一硬编码的 cookie 名，默认了"所有会话类型是同一种东西"。** 任何未来新增的
会话/cookie 类型，必须同步检查：(1) 是否已进入 `SESSION_COOKIE_NAMES`；(2) 它的 TTL 是否仍
短于 `CSRF_COOKIE_MAX_AGE_S`（若通过环境变量把会话 TTL 调到 7 天以上，(二) 会复现）。

### 4.3 结果收集器的真实驱动方式（读源码会得出错误结论的一处）

`apps/monolith/main.py` 曾经在 `_build_scan_runtime` 里留过一条 KNOWN GAP 注释，称
`run_result_collector_tick`"从未被本代码库中任何存活进程调用"。这个结论本身就是**只读源码**
得出的，而且是错的——它在里程碑 F 的残留清理（`7136e0e`）里已经改正：`worker.worker_tick`
每个 tick 自行做实时白名单读取，并把结果传给 `run_result_collector_tick`，收集器**是**有
存活驱动方的。那条旧注释曾经为真的部分，其实是 **chart 层面**的缺口——里程碑 E 发现整个
Helm chart 里根本不存在 `SKILLSCAN_WORKER_ENABLED`，默认 false，于是扫描永远卡在 `queued`：
代码有调用方，是部署没启用它。chart 已在 `deploy/helm/skillscan/values.yaml`
（`config.workerEnabled: true`）补上。

**2026-07-29 在 VM 上现场核实（不是读源码推断）的结论：**

- **驱动方是单个 monolith 进程内的后台协程，不是独立的 worker 进程/Deployment。**
  `kubectl get pods -n skillscan` 只有一个 `monolith-*` pod 和一个 `engine-runner-*` pod，
  没有第三个"worker"工作负载；`monolith` 容器的 entrypoint（`/entrypoint/run.py`）就是
  `create_app()` + `uvicorn.run()` 单进程，lifespan 里按 `SKILLSCAN_WORKER_ENABLED` 起一个
  `asyncio.create_task(run_worker_loop(...))`。`kubectl exec deploy/monolith -- env` 现场
  确认部署里 `SKILLSCAN_WORKER_ENABLED=true`。
- **tick 间隔是可配置的，当前用的是代码默认值。** `SKILLSCAN_WORKER_INTERVAL_S`
  在部署的 configmap/env 里**没有被设置**（`kubectl exec deploy/monolith -- env | grep
  SKILLSCAN` 未出现该变量），所以取 `config.py` 的默认值 1.0 秒；chart 目前没有任何地方
  覆盖它，想调需要新增一个 chart 值。
- **engine-runner 结构上不可能自己落库**（INV-10：`services/engine_runner/worker.py` 只碰
  Redis + blob store，代码里没有任何 SQLAlchemy/DB session），它只把结果写进 Redis Stream
  `skillscan:results`。`XINFO GROUPS skillscan:results` 显示唯一的消费组 `orchestrators`
  下唯一的消费者名叫 `monolith-worker`——正是 `worker.py` 里 `run_worker_loop`/`worker_tick`
  的默认 `consumer` 参数值——`pending=0`、`lag=0`、`entries-read` 与流总长度相等，说明这个
  消费者在持续、无积压地把 engine-runner 写的每一条结果读走。
- **端到端落库已用真实数据核实**：MySQL `verdict` 表里 `scan_id=5df592e4-8d3b-49dc-95b2-
  6336cb9bf107` 的一行正是 `REVIEW / 47`，与设计文档 §8 引用的那次"提交真实包后走到
  Decided / REVIEW / 47"完全对应；`scan_job.created_at`（22:52:03.634）到
  `verdict.issued_at`（22:52:09.423）相隔约 5.8 秒，另几条最近记录（4fbd9c73...、
  347a959c...）也都是 5-6 秒量级的 queued→decided 延迟——与"约 1 秒一个 tick、裁决要跨
  好几个 tick 才能走完排队/引擎执行/打分/裁决多个阶段"完全吻合，不是一次性瞬间写入。
- **陷阱：`kubectl logs` 看不出 worker 在跑，但这不代表它没在跑。**
  `libs/common/log.py` 的 `get_logger()` 从未调用 `logger.setLevel(...)`，这些 logger 因此
  沿用 Python 的默认根 level（`WARNING`），`worker.py` 里 `_logger.info("background worker
  started", ...)` 之类的 INFO 日志会被静默丢弃——`kubectl logs deploy/monolith | grep
  worker` 在这套部署上什么都搜不到。日志里能看到的 INFO 行只是 uvicorn 自己的访问日志（它
  自己配置了 log level）。**下一个人如果靠 `grep worker kubectl logs` 来判断 worker 是否
  存活，会被这个空结果误导成"没在跑"**——要看 Redis 消费组状态（`XINFO GROUPS`/
  `XINFO CONSUMERS`）或 DB 里的实际时间戳，不要只看日志。

**结论：与改正后的注释不矛盾**，`run_result_collector_tick` 确实由 `apps/monolith/
worker.py` 的 `worker_tick` 驱动，跑在唯一的 monolith 进程里；§3 的遥测存储设计可以继续
假设"落库发生在 monolith 侧"这个前提成立。

### 4.4 MySQL 并发已知注意事项（M3 已修复，供未来修改审计链代码时参考）

审计哈希链在真实并发下暴露过三个真实 MySQL/InnoDB 行为（挑选待处理记录无锁导致双写、
链尾追加在 REPEATABLE READ 下死锁、READ COMMITTED 下仍可能拿到陈旧链尾导致静默分叉）——
均已修复（`SELECT...FOR UPDATE SKIP LOCKED` + READ COMMITTED + 显式陈旧性检测），修改
`append_one_intent`/`drain_pending_outbox` 或任何"读链尾→算哈希→追加"逻辑前务必了解。

### 4.5 环境受限项（非缺陷，本机验证深度的诚实边界）

gVisor 沙箱隔离本身（Linux-only）、真实 K8s 集群 apply/隔离测试/DR 演练、持续运行的真实
Vault、真实企业 IdP、真实 Skill 市场——均无法在本开发环境验证，相关代码/配置本身已通过
静态校验（`helm lint`/`kubeconform`/mypy/ruff），详见编译指南 §5-6。

---

## 相关文档

- [`BUILD_GUIDE.md`](BUILD_GUIDE.md) — 编译指南
- [`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md) — 部署指南
- [`USAGE_GUIDE.md`](USAGE_GUIDE.md) — 操作指南
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — 内核威胁模型
