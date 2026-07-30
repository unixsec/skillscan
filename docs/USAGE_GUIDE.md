# 操作指南（Usage Guide）— skillscan

本指南面向系统的实际使用者（提交者/审批人/管理员/审计员）与集成方，覆盖 API 用法、
Web 控制台操作、按角色的典型流程。构建/部署见另外两份指南。

## 1. 作为 Python 库使用内核（无需部署）

```python
from skillscan_core import GatePolicy, StaticKeywordEngine, aggregate, decide
```

`skillscan_core` 是纯函数 + 值对象集合，没有网络接口——"使用"就是 Python `import`，
参见编译指南与 `libs/skillscan_core/__init__.py` 的完整导出列表。

## 2. 完整 `/v1` API（全部已实现并测试；`✳` 标记为 2026-07-06 审计修复新增/变更）

| Method | Path | 角色 | 说明 |
|---|---|---|---|
| POST | `/v1/scans` | submitter+ | multipart 上传（字段名 `package`，tar 包） |
| GET | `/v1/scans` | submitter(仅自己)/approver+(全部) | 列表；`limit`（上限 200）+ `offset`，**不返回总数**，见下方 ✳ |
| GET | `/v1/scans/{scan_id}` | 提交者本人/approver+ | 详情：`state`/`verdict`/`findings[]`/`provenance`/`hard_gate_hits`/`reasons`/`required_ok`/`sarif_ref`（现指向下一行的真实端点）；归属与层级见下方 ✳ |
| GET | `/v1/scans/{scan_id}/sarif` ✳ | 同上 | **新增：** 单扫描 SARIF 2.1.0 导出，此前恒为 404/null |
| GET | `/v1/me` | submitter+ | 当前会话 `subject`/`roles`/`tier`，仅供前端 UX 判断菜单显示 |
| GET/POST | `/v1/auth/oidc/*`、`/v1/auth/saml/*` ✳ | 无（登录前） | **新增：** 真实 OIDC/SAML 登录握手，见部署指南 §4 |
| GET/POST | `/v1/reviews`、`/v1/reviews/{scan_id}` | approver+ | 待复核队列/批准或拒绝（SoD：审批人≠提交者） |
| GET/POST/DELETE | `/v1/allowlist`、`/v1/allowlist/{id}` | approver+（硬门禁豁免需 admin） | 标准加白（四眼+有效期） |
| GET/POST | `/v1/inventory*` | approver+（隔离/退役/恢复/基线需 admin） | 清单生命周期：`submitted→scanning→(review_pending)→published→[quarantined⇄published]→retired` |
| GET/POST | `/v1/inventory/ownership/unowned`、`/v1/inventory/ownership/assign`、`/v1/inventory/{skill_id}/owner` ✳ | admin | **新增：** 归属指派与转移。`skill.owner` 决定谁能为该 skill 提交新版本，`owner IS NULL` 失败关闭（仅 admin）；这三个端点是把存量无主 skill 交还给真实归属方、以及在人员离职时转移归属的唯一途径。列表附带创世提交者**仅作参考证据**，系统不会自动采用。每次指派都写审计链（记录原归属人与新归属人） |
| GET/POST | `/v1/reeval`、`/v1/reeval/{skill_id}` ✳ | approver+/admin | 工具链过期检测+手动触发重扫；**手动触发端点现已要求 CSRF token**（此前的真实缺口，已修复） |
| GET | `/v1/reconciliation` | admin/auditor | 市场对账状态 |
| GET | `/v1/reports`、`/v1/reports/sarif`、`/v1/reports/schedule` | approver+ | 5 个报表模板，导出 json/csv/pdf，`/v1/reports/sarif?scan_ids=` 支持多扫描 |
| GET | `/v1/audit` | admin/auditor | 哈希链状态+分页条目（`?limit=`，服务端上限 500，默认按最近优先） |
| GET/PATCH | `/v1/admin/engines*` | admin | 引擎启停（floor 引擎受 INV-1 保护） |
| GET/POST | `/v1/admin/policy*` | admin | 门禁策略两人四眼审批工作流 |
| GET | `/v1/admin/users` | admin | 只读 IdP 组映射视图 |
| GET/POST | `/v1/admin/intel`、`/v1/admin/intel/import`、`/v1/admin/intel/sync` ✳ | admin | 离线签名导入 + **新增：**手动触发内网情报同步（此前实现但无路由可调用） |
| GET/POST | `/v1/admin/breakglass*` | admin(前二者)/无(login) | 应急登录通道，见运维指南 §4 |
| GET | `/healthz`、`/readyz`、`/.well-known/jwks.json` | 无需认证 | 探针+验签公钥 |

**✳ `GET /v1/scans` 不返回总数，这是刻意的（2026-07-29，里程碑 F Task 16）。**
响应体只有 `items`，没有 `total`、没有 `page_count`。**不要自己推算总页数**——推算不出来，
猜出来的数字调用方也无从发现是错的。

原因不是"没顾上"，是评估后的取舍：总数意味着每次请求都要 `SELECT COUNT(*) FROM scan_job`，
而 approver/admin/auditor 看的是全量、没有 `submitter` 谓词可以收窄，InnoDB 又不缓存行数，
所以那是一次全索引扫描。`scan_job` 是本系统行数最多的表（每次扫描一行，永久保留），
而**这个端点是被轮询的**：控制台 Scans 页在页面上还有未终态扫描时按 3s → 5s → 10s → 20s
退避重复拉取，标签页重新获得焦点时重置回 3s。按这个频率、每个打开的标签页各来一次全表计数，
代价与收益不成比例。（只看自己扫描的 submitter 那条路径其实很便宜，`scan_submitter.idx_submitter`
能服务——问题在于贵的那条恰好是最常用的那条。）

**推荐的翻页方式**（控制台自己就是这么做的）：请求 `limit = 每页条数 + 1`，只渲染前
每页条数 条，多出来的那一行仅用于判断"还有没有下一页"。于是界面如实显示"第 N 页"，
不会编造一个它无从知道的总页数。**诚实的降级优于昂贵的完整。**

**✳ `GET /v1/scans/{scan_id}` 的归属与信任层级字段（2026-07-29，里程碑 F）。**
内容完全相同的提交会被单飞去重（`cache_key` 唯一），**一次扫描合法地拥有 N 个提交者**，
因此这些字段一律是列表形状，不会因数据条数变成标量：

- `submitters: string[]`——全部有权读取本次扫描的提交者；`submitter`（标量）仍是**首个**提交者。
- `source: string[]` / `submitter_sources: [{submitter, source, requested_trust_tier}]`
  ——扫描到达的渠道集合，以及每个名字各自的渠道与请求层级。`null` 表示该行没有记录该事实
  （列存在之前写入的行），**如实返回 null，绝不猜测**。
- `trust_tier`——**本次调用方自己请求的层级**；`judged_at_tier`——判定实际依据的层级。
  二者相同是常态。去重跨层级时会不同：判定不会为后来者重做，所以后来者拿到的是在
  **别人的层级**上作出的结论。调用方自己没有请求记录时（复核人员读他人扫描、或迁移前的老行），
  两者都回落为判定层级并因此相等，不会伪造出一个差异。
- `tier_direction`——`"looser"` / `"stricter"` / `"equivalent"` / `null`，由服务端依据
  **门禁策略的真实拦截阈值**（`GatePolicy.block_threshold`）计算，不是按层级名字的顺序推的。
  `"looser"` 是需要警觉的一侧：判定所依据的规则集比调用方请求的更宽松
  （`policies/gate/v1.yaml` 里 `public` 在 HIGH 拦截，其余层级只在 CRITICAL 拦截，
  即 **`public` 最严格、`internal` 最宽松**），在请求层级上本应拦截的发现项可能显示为通过。

**`submitters` / `submitter_sources` / `source` 三个字段在
`GET /v1/scans/{scan_id}`、`GET /v1/scans` 的每个 item、`GET /v1/reviews` 的每个 scan 上
形状完全一致**（同一个函数产出，里程碑 F Task 16）。同一个概念在不同端点上有不同形状，
是消费方 bug 的稳定来源，所以请按同一套代码解析这三处。没有任何关联记录的扫描返回**空列表**，
不会把标量 `submitter` 提升成单元素列表——那等于声称首个提交者是唯一有权读取的人。

**对象级授权（IDOR 防护）在 `/v1/scans` 与 `/v1/scans/{scan_id}/sarif` 上真实生效**：
提交者读取不属于自己的 `scan_id` 得到 `404`（不是 `403`，防止状态码探测）。**所有状态变更
请求（POST/PATCH/DELETE）均要求 CSRF token**——`require_csrf` 依赖已覆盖每一个已知的会话
cookie 类型（普通会话/break-glass/SAML，三者均已核对，见运维指南 §5 的具体教训）。

**⚠ 上表整个控制台面（`/v1/scans*`、`/v1/me`）对机器身份（M2M client-credentials /
mTLS）返回 `403`**（2026-07-28，里程碑 B'）。理由：这些响应给的是**内部**扫描形制
（含 `snippet_hash`、`provenance`、`required_ok`、`hard_gate_hits`），而 §6 的市场投影
正是为了不外露这四项而存在——机器身份若能用同一个 token 读控制台端点，投影就只是装饰。
机器身份并未因此少拿到任何东西：`POST /v1/market/scans` 提交、`GET /v1/market/skills/{skill_id}`
轮询，是为它建的那一面，读的是同一批扫描。判别依据是身份的**种类**（`is_machine`）而不是
某个 scope——scope 清单只要新增一项就可能无声地重新放行。这里返回 `403` 而非对象级授权
惯用的 `404`：端点存在、身份有效，被拒的是身份类别，`404` 只会让集成方去找一个并没有消失
的扫描。

## 3. Web BFF 集成模式

Web 前端不直接持有任何 token——浏览器只拿到 HttpOnly/Secure/SameSite 会话 cookie。
前端所有请求走同源 `/v1/*`；生产环境由反向代理（nginx，见部署指南）同时服务静态资源和
`/v1/*` API，实现同源。

## 4. 按角色使用（角色/权限矩阵，SRS 附录 C）

| 权限 | Submitter(默认) | Approver | Administrator | Auditor | Service(M2M) |
|---|---|---|---|---|---|
| 提交扫描 | ✓ | ✓ | ✓ | ✗ | ✓（仅 `/v1/market/scans`） |
| 查看自身结果 | ✓ | ✓ | ✓ | ✓ | ✓（仅 `/v1/market/skills/{id}` 投影） |
| 查看全部结果/清单 | ✗ | ✓ | ✓ | ✓ | ✗ |
| 处理 REVIEW | ✗ | ✓ | ✓ | ✗ | ✗ |
| 创建标准加白 | ✗ | ✓ | ✓ | ✗ | ✗ |
| 创建高危/硬门禁豁免 | ✗ | ✗ | ✓ | ✗ | ✗ |
| 管理策略/引擎/情报源/RBAC | ✗ | ✗ | ✓ | ✗ | ✗ |
| 查看审计日志 | ✗ | ✗ | ✓ | ✓ | ✗ |

> 职责分离（SoD）强制且独立于角色：某 `REVIEW` 的审批人必须 ≠ 提交者；高危豁免的审批人
> 必须 ≠ 请求者——两者都在数据库约束/构造函数层面强制，不只是 UI 隐藏。

**Submitter 典型流程：** ① `POST /v1/scans` 或 Web 控制台 Scans 页面提交；② 轮询
`GET /v1/scans/{scan_id}`（webhook 回调尚未实现）；③ 查看按引擎/按检测类别分组的态势
展示（Web 控制台扫描详情页，见 §6）。

**Approver 典型流程：** ① Reviews 页面查看待处理 REVIEW；② 批准/拒绝并填写理由；
③ 为已知误报建标准加白（Allowlist 页面）。

**Administrator 典型流程：** ① Admin·Policy 提议门禁策略变更（两人四眼）；② Admin·Engines
启停检测引擎；③ 管理 RBAC/情报源/break-glass（Admin·Users/Intel/BreakGlass）。

**Auditor 典型流程：** Audit 页面/`GET /v1/audit` 只读查询防篡改哈希链审计记录；Reports
页面生成 5 类报表（含专为审计场景设计的 exception audit 模板）。

## 5. Web 控制台

`web/`，React 19 + Vite + TypeScript SPA，13 个页面 + 登录页：Dashboard/Scans(+详情)/
Reviews/Allowlist/Inventory(+详情)/Reeval/Reconciliation/Reports/Audit/
Admin·{Engines,Policy,Users,Intel,BreakGlass}。

**中英文双语：** 右上角语言选择器，默认中文，选择存于浏览器 `localStorage`
（`skillscan.locale`）。手写、零依赖的翻译层（`web/src/i18n/`，259 个键，中英文一一对应）。

**扫描详情页的分模块态势展示：** 在扁平 findings 明细表之上，两个对同一批 findings 的
重新分组视图——**按引擎（模块）**（对照 `provenance` 分组：引擎/版本/finding 数/最高
严重级别/态势）和**按检测类别**（固定展示 8 类"8类61项"，0 个 finding 即为通过）。
这是对同一份数据的诚实展示层重新分组，不是新的策略判定——顶部仍只展示 gate 的唯一权威
判定（PASS/REVIEW/BLOCK）。

**引擎覆盖度（2026-07-30 新增，`GET /v1/scans/{scan_id}` 的 `engine_coverage` 字段）：**
判定页原本只有 `required_ok`，它只覆盖 floor（必需）引擎，而那些引擎是 **fail-closed** 的。
**其余引擎全部 fail-open**：不交付就丢弃其发现，判定按"这些引擎什么都没找到"算出。290 次
真实扫描实测：证据完整的扫描 60% 进入复审，证据不完整的只有 29%——负载升高时扫描器实际上
变得更宽松。详情页因此在 findings 之上给出"本次判定基于 N/M 个引擎的证据"，并列出**具体
哪些引擎**没有交付、各自的状态（复用 `engineHealth.ts` 的六态词表与配色，`error` 与
`not_reported` 永不同色）与耗时。

覆盖度分两类，渲染方式不同：

- **缺失（missing）** ——本应交付却没有，且没有可查证的原因。计入分母，标红。
- **本部署不运行（not_applicable）** ——`aig-mcp-scan` 这类 LLM 门控引擎在没有内部 LLM
  端点的部署上每次扫描都"未上报"（语料中 290/290）。**列出但不计为故障**：每次扫描都亮红
  只会训练读者跳过整段。附「当前配置」原因说明，并注明该判断读的是**当前**配置而非扫描
  当时的配置。

另有一处旧的自相矛盾一并修好：`unavailable_engine_result` 会为未交付的引擎伪造一条
provenance 三元组（好让 gate fail-closed），于是"按引擎"表把一个超时引擎按 0 个 finding
判成绿色"通过"，与上方的覆盖度告警直接冲突。该单元格现在有第三态**"无证据"**，由覆盖度
读取驱动，而不是由分不清二者的 finding 计数驱动。

无逐引擎记录的扫描（判定前即死信、超出健康数据保留窗口、或扫描早于该记录表）显示"没有
保留逐引擎记录"，**不显示为完整**——沉默与"全部引擎都已上报"无法区分。

**敌对内容展示安全：** findings/路径/规则标题可能含攻击者可控串，一律经 React 默认转义
（禁 `dangerouslySetInnerHTML`，已 grep 确认零使用）；证据字段本身已是脱敏/哈希后内容
（后端 INV-9），前端只是原样渲染。

## 6. 市场对接（拉取模型，里程碑 B'）

skill 市场通过独立前缀 `/v1/market` 与本系统对接，与控制台 `/v1/scans` 完全分离——市场
定时轮询，本系统不推送（现有 `gate_outbox`/`HttpMarketplaceAdapter` 推送通道保留但默认
关闭，见运维指南 §3 开放差距）。

### 6.1 端点

| Method | Path | scope | 说明 |
|---|---|---|---|
| POST | `/v1/market/scans` | `scan:submit` | 提交扫描包（multipart：`package` = tar 或 zip，`skill_id` **必填**）。响应仅 `{"scan_id": ...}` |
| GET | `/v1/market/skills/{skill_id}` | `scan:read` | 轮询该 skill **最新版本**安全与否 |

提交端点存在的理由：市场必须用**同一身份**提交和轮询，否则"这个 skill 是不是它自己的"这一
对象级授权判断无从比对（见 §6.2）。

> **⚠ 2026-07-30 契约替换。** 旧端点 `GET /v1/market/scans/{scan_id}` **已删除**，不保留
> 双跑。市场以 `skill_id` 轮询，得到「安全 / 不安全」**二值**判定；不安全时附机器可读的
> `unsafe_reason` 与完整发现明细（见 §6.5、§6.7）。
>
> **`skill_id` 由"刻意不接受"改为"必填"。** 原先不接受它是为了不触发清单生命周期副作用，
> 而按 `skill_id` 轮询要求 `skill_id` 存在于市场的世界里，且提交时以市场服务账号登记为
> `skill.owner` 是 §6.2 鉴权能对任何人答"是"的唯一来源——这条反转是契约替换的**必要前提**。
> 必填而非可选：没有 `skill_id` 的提交永远无法轮询，对结果读不到的请求回 `202` 比报错更糟。
> 缺失返回 `422`（FastAPI 校验），空白返回 `400`。
>
> 路径参数声明为 `{skill_id:path}`：本生态的 skill id 常态是 `@handle/slug`，裸路径参数
> 会在斜杠上 404，让一整类 skill 静默不可轮询。
>
> 提交会登记 skill + 该版本并进入生命周期状态机（`submitted → scanning`），与控制台
> `POST /v1/scans` 同一套检查、同一套状态码：不属于你的 `skill_id` → `403`；这份字节已登记
> 在别的 skill 名下 → `409`；该 skill 当前生命周期状态没有 `→ submitted` 边
> （`scanning`/`retired`/`quarantined`）→ `409`。

### 6.2 认证与授权

- M2M client-credentials 或 mTLS，走与交互式会话相同的校验路径，没有"可信服务"绕过对象级
  授权的例外。
- scope 按服务账号授予（`M2MGrant`），不是全仓共享的常量——未显式配置的服务账号保持迁移前
  默认值 `{"scan:submit"}`，不会因这次改造凭空获得读权限。
- 市场身份即使持有 `scan:read`，也只能读**自己拥有的** skill；读取他人的 `skill_id` 返回
  `404`（不是 `403`，避免探测 skill_id 是否存在——与控制台 `GET /v1/scans/{scan_id}` 同一
  形制，且"未知的 skill"与"不是你的 skill"连响应体都一样）。请求越权但对象存在性不是
  问题时（例如没有 `scan:read` scope）返回 `403`——这里暴露"你没有这个权限"不泄漏任何
  他人数据。
- **"自己拥有的"按 `skill.owner` 判定（2026-07-30 修订）**，不再按关联表 `scan_submitter`。
  按 `skill_id` 查会问到自己从未提交过的 skill：可能是自己的 skill 但其最新版本的扫描是
  别人提交时建的（单飞去重），也可能压根没提交过。**归属**才是这个问题真正关于的属性。
  判定函数是 `inventory.ownership.authorize_skill_read`，**没有 admin 覆盖**（本面向机器
  身份封闭，不存在 reviewer/admin 逃生口）。
- **`skill.owner` 为 NULL 的 skill 对任何人都是 `404`**（读侧 fail-closed，与写侧一致）。
  部署库里有数百个在该列存在之前批量导入的 skill owner 为 NULL；要让它们可轮询，必须先经
  `/admin/ownership` 由管理员显式指派（`POST /v1/inventory/{skill_id}/owner`）。
- `scan_submitter` 关联表**保留且仍然必要**：控制台的 `GET /v1/scans/{id}`、`.../sarif`、
  `GET /v1/scans` 三处对象级授权仍然判它。提交是单飞去重的（键为
  `content_hash + toolchain_digest`），字节相同的包重复提交返回**同一个** `scan_id`，
  因此一次扫描合法地有多个提交者；若按 `scan_job.submitter` 单列判定，后提交者永远读不到
  自己刚拿到的 `scan_id`——而"控制台和市场扫同一批 skill"是常态。

### 6.3 `trust_tier` 由服务端决定，不接受调用方传入

`trust_tier` 直接决定 BLOCK 阈值：`internal`/`partner` 在 `CRITICAL`，`public` 在 `HIGH`
（最严）。`POST /v1/market/scans` 的表单字段或查询串中一旦出现 `trust_tier`，返回 `400`
而非静默忽略——静默忽略会让调用方误以为自己的设置生效了。实际生效的 tier 来自该服务账号的
`M2MGrant.tier` 配置（未配置时为最严格的 `PUBLIC`），提交时随扫描持久化，供后台 worker
异步裁决时使用（此时原始会话早已不存在）。

> **控制台路径 `POST /v1/scans` 仍接受调用方表单提交的 `trust_tier`**——本里程碑只修了
> 市场路径，这是已知且记录在案的差距（运维指南 §3）。

### 6.4 状态语义（内部 5 态 → 对外 3 态）

| 内部状态 | 对外 `status` | 市场动作 |
|---|---|---|
| `queued` | `PENDING` | 继续轮询 |
| `running`、`scored` | `RUNNING` | 继续轮询（`scored` 是内部中间步，对外无意义） |
| `decided` | `COMPLETED` | 停止轮询，读 `verdict` |
| `failed` | `COMPLETED` | 停止轮询，读判定（恒为 `is_safe: false` + `unsafe_reason: "scan_incomplete"`） |
| （该 skill 最新版本尚无扫描） | `PENDING` | 继续轮询——`is_safe: false` + `unsafe_reason: "not_yet_scanned"` |

**`failed` 映射为 `COMPLETED` 而不是独立的 `FAILED`，这是本节最容易被误解、也最值得记住
的一点：** 系统在 fail-closed 时做出并签署了一个真实的 BLOCK 判定——扫描管线本身出了问题，
因此按最保守方式处理。如果对外报"FAILED"，市场侧自然的反应是重试或忽略；而重试一个
fail-closed BLOCK 恰恰是错的，会绕开系统刚刚做出的保守判定。因此对外只有一个终态
`COMPLETED`，判定本身承载全部含义，而 `unsafe_reason: "scan_incomplete"` 说明这次"不安全"
的来源是"管线失败后的兜底"而非常规裁决。此时 `findings` 恒为空数组（管线没能产出结果）——
这正是为什么必须有这个原因码：否则市场拿到的是"不安全 + 无任何发现 + 无解释"。
2026-07-29 一次 226 包真实语料跑出 18 个 BLOCK，其中 **17 个**是这种。

> **2026-07-30：** 响应里已不再有 `verdict` 与 `fail_closed` 字段（契约改为二值），
> 但本节的映射与理由完全不变。

### 6.5 判定值：二值 `is_safe` + 机器可读的 `unsafe_reason`

```
is_safe = (verdict == PASS 且 status == COMPLETED)
```

**未通过即不安全，一律如此**：`REVIEW`、待复核、`PENDING`/`RUNNING`、fail-closed 的
`BLOCK`，全部 `is_safe: false`。市场侧只有两种结局，`PASS` 是唯一可上架的答案。

> **为什么这不是"把 REVIEW 放行"。** 设计 spec §5.2 曾把「二值判定折叠」列为明确反目标，
> 理由是折叠会让 findings 超限截断触发的**强制** REVIEW 变成绕过通道：攻击者把发现数刷到
> 5000 条上限之上，就为自己换来一个可上架的判定。**那条论证针对的是 `REVIEW → 安全`。**
> 这里的方向是 `REVIEW → 不安全`，恰好相反——那条绕过通道被**关闭**而不是打开，比它替换掉
> 的三值契约**严格更紧**。原论证仍然成立，只是不适用于这个方向；spec §5.2 里逐字保留了它。

**`verdict` 三值不再外露，但信息没丢**：`is_safe` 给结论，`unsafe_reason` 给类别，
`verdict_jws` 仍然携带签名判定原文供独立验签。原 `requires_review` 字段已删除
（现为 `unsafe_reason == "pending_review"`）——一份契约里同一个事实有两种拼法就有两个真相来源。

| `unsafe_reason` | 含义 | 建议反应 |
|---|---|---|
| `scan_incomplete` | **fail-closed**：必需引擎缺失或失败，扫描没能完成 | 不是内容问题。重试或联系我方，**不要**当成"这个包有毒" |
| `hard_gate` | 命中**不可豁免**的硬门规则（INV-3），`hard_gate_hits` 列出规则 id | 任何加白都改不了它 |
| `pending_review` | 需人工复核 | 等我方复核结论 |
| `content_findings` | 普通内容判定不通过，`findings[]` 给明细 | 按明细修包 |
| `not_yet_scanned` | 还没有判定（非终态，或该 skill 最新版本尚未扫描） | 按 `poll_after_ms` 继续轮询 |

`is_safe` 与 `unsafe_reason` **恰有一个携带信息**：安全时后者为 `null`，不安全时必为上表
之一。没有第三态，没有 unknown。

### 6.6 轮询节奏与限速

`poll_after_ms`（响应字段之一）按 `status` 给出建议轮询间隔：

| status | `poll_after_ms` |
|---|---|
| `PENDING` | `5000` |
| `RUNNING` | `15000` |
| `COMPLETED` | `0`（可停止轮询） |

依据：里程碑 D 之后扫描从毫秒级变为分钟级（需等待沙箱引擎，最长 300 秒+30 秒 sweep
宽限），不给提示对方按秒轮询纯属浪费。

限速是**不遵守 `poll_after_ms` 的调用方的兜底**，不是引导本身：每服务账号每分钟 `120`
次请求（`SKILLSCAN_MARKETPLACE_RATE_LIMIT_PER_MIN`），超限返回 `429` + `Retry-After`
（秒）。计数按服务账号隔离，一个市场超限不影响另一个；覆盖提交和轮询两个端点，且在 scope
校验**之前**计数——探测自己没有的 scope 同样计入限速预算。简言之：限速是惩罚，
`poll_after_ms` 是引导，两者互补。

### 6.7 响应字段

**顶层：**

| 字段 | 类型 | 说明 |
|---|---|---|
| `skill_id` | string | 请求的 skill |
| `content_hash` | string \| null | **这个判定是关于哪份内容的**——"最新版本语义"的落实。无版本记录时 `null`。少了它，"skill X 安全"是一句无法被证伪的话 |
| `status` | enum | `PENDING`/`RUNNING`/`COMPLETED` |
| `is_safe` | bool | **仅** `verdict == PASS` 且 `status == COMPLETED` 时 `true`，见 §6.5 |
| `unsafe_reason` | enum \| null | 见 §6.5；`is_safe` 为 `true` 时 `null` |
| `hard_gate_hits` | array[string] | 命中的硬门**规则 id** 列表（不是证据文本）。见下方说明 |
| `score` | int \| null | 0–100 |
| `policy_version` | string \| null | |
| `decided_at` | ISO8601 \| null | |
| `verdict_jws` | string \| null | 签名令牌，市场可独立验签，不必信任传输层 |
| `poll_after_ms` | int | 见 §6.6 |
| `judged_at_tier` | enum \| null | 本次判定**实际所依据的** trust tier。因单飞去重，它未必等于本次提交方自己的 tier：字节相同的包若已被别人扫过，返回的是**那次**判定，判定不会为后来者重算，因此也不能改述成按后来者的 tier 判的。tier 决定 BLOCK 阈值，差异是实打实的。`null` 表示该扫描未记录 tier（判定时回退到部署默认值） |
| `requested_tier` | enum \| null | **本调用方自己请求的** trust tier（即该服务账号被授予的 tier，记在它自己的 `scan_submitter` 行上）。与 `judged_at_tier` 成对读：只报后者，等于让调用方默认二者相同，而在这条接口上通常**并不**相同。`null` 表示该行没有记录请求（该列出现之前写入的历史行）——**不会**回退成 `judged_at_tier`，否则就是在替调用方断言一个没人记录过的"一致" |
| `tier_direction` | enum \| null | `looser` / `stricter` / `equivalent`，说明二者不一致时**往哪个方向**偏。`looser` 是要紧的那个：判定所依据的规则集比你请求的**更宽松**，本该为你 BLOCK 的 finding 可能读作 PASS。**这是本接口上最常见的方向**：未配置的服务账号默认 `public`（**最严**，HIGH 即 BLOCK），而控制台通常按 `internal` 提交（仅 CRITICAL 才 BLOCK）。由 `GatePolicy.block_threshold` 推出，**不是**按 tier 名字的顺序——严格程度写在策略文件的 `tier_block_overrides` 里，改策略即可改变顺序。任一侧为 `null`、二者相同、或存储值不是合法 tier 时均为 `null` |
| `engines_expected` | int | 本次判定**本应**纳入证据的引擎数。**已排除**本部署根本不运行的引擎（那些计入 `engines_not_applicable`），所以不同部署之间这个数会不同 |
| `engines_reported` | int | 其中真正交付了可用结果的引擎数（`ok` 或 `partial`）。自行报告 `timeout`/`error` 的引擎**不算**交付：它写出了一份合法但零发现的结果，其发现同样不在判定里 |
| `engines_not_applicable` | int | 因本部署根本不运行而从 `engines_expected` 中排除的引擎数。公布而非悄悄减掉——分母无故变小的覆盖率是无法被证伪的 |
| `evidence_complete` | bool \| null | `engines_reported == engines_expected`。`null` 表示该扫描**没有任何逐引擎记录**（判定前即被死信处理、超出引擎健康数据保留窗口、或扫描发生在该记录表启用之前）；这种情况下**绝不返回 `true`** |
| `engine_coverage_basis` | enum \| null | 有覆盖度答案时恒为 `current_config`，否则 `null`。见下方说明 |
| `summary` | object | `total`/`critical`/`high`/`medium`/`low`/`truncated`；`total` 是真实总数，即便 `findings` 因超限被截断（5000 条上限）也不变 |
| `findings` | array | 见下；`fail_closed` 时为空数组 |

#### 引擎覆盖度（2026-07-30 新增五字段）

**要解决的问题。** `required_engines`（floor 引擎）是 **fail-closed** 的：不交付就强制
BLOCK。290 次真实扫描里 18 个 BLOCK 有 17 个正是这条路径，机制有效。**其余引擎全部
fail-open**：不交付就丢弃它的发现，判定按"这些引擎什么都没找到"照常算出。实测后果：

| | 扫描数 | 平均交付引擎 | PASS / REVIEW / BLOCK |
|---|---|---|---|
| 证据完整 | 162 | 14.0 | 61 / 97 / 4 |
| 证据不完整 | 128 | 9.3 | 73 / 37 / 18 |

即：**负载升高 → 有效规则集收缩 → `is_safe: true` 更容易拿到**。判定语义没有改变（忽略这
五个字段，你拿到的答案与之前完全一致），改变的是"证据不完整"不再隐形。

**怎么用。** `evidence_complete === false` 时，`is_safe` 仍然是系统的正式答案，但它是在比
平常更少的引擎证据上得出的——真实严重级别可能更高。集成方可以据此选择稍后重新提交同一份
内容以获得一次完整扫描（该语料中超时的根因是 2 核机器上的排队，而非引擎本身慢：每次扫描
引擎耗时之和的中位数约 1.5 秒，扫描期限是 300 秒）。**注意**：`unsafe_reason ==
"scan_incomplete"` 是另一件事——那是 floor 引擎缺失导致的**已签名的** fail-closed BLOCK，
按 §6.4 不应当重试。

**为什么切在"交付"而不是"是否收到上报"。** 该语料里每一次引擎超时都写出了合法的
findings blob（airlock 掐断 `analyze()` 后仍会写，只是零发现）。所以"是否收到上报"这个
定义在有超时和无超时的扫描上都读出 14.0 个引擎，什么也说明不了；按交付切分才读出
14.0 vs 9.3。

**`aig-mcp-scan` 这类引擎为什么不算缺口。** 它是 LLM 门控引擎，在任何没有内部 LLM 端点的
部署上每次扫描都是"未上报"（语料中 290/290，无一例外）——这是诚实的默认状态，不是故障。
把它算作缺口就等于永远返回 `evidence_complete: false`；一个永远亮着的告警不是信号，它只会
训练集成方彻底忽略这个字段，那比不提供更糟。所以它被排除出 `engines_expected` 并单独计入
`engines_not_applicable`。

**`engine_coverage_basis` 为什么必须随行。** 上面那次排除读的是**当前**配置（Redis 停用集合
＋本进程的 LLM 端点状态），而没有任何记录保存了扫描当时的配置——今早停用的引擎会让上周的
扫描读作"完整"。这与 `tier_direction_basis` 是同一种告知义务。

**这里不给引擎名**（只给数字）：具体是哪些引擎缺失、以及各自的状态与原因，属于控制台
`GET /v1/scans/{scan_id}` 的 `engine_coverage` 字段，见 §5 控制台部分。

**`findings[]`（12 个字段，2026-07-30 契约替换时**未**改动）：** `rule_id` ·
`test_item_id` · `category` · `title` · `severity` · `confidence` · `source_engine` ·
`source_capability` · `trifecta_signals` · `file_path` · `start_line` · `evidence_redacted`

二值契约要求"不安全时给出具体原因"，而这 12 个字段**已经覆盖控制台「发现明细」表渲染的
每一个字段**，因此无须加宽。`confidence` 保持**原始 0..1 不取整**：取整会在恰好决定
REVIEW 的那个阈值上抹掉 0.69 与 0.70 的差别。

**2026-07-30 已从契约中删除的字段（不是遗漏）：**

| 删除 | 去处 |
|---|---|
| `scan_id` | 契约的键被替换。保留它会让集成方在新契约之上把旧契约重建起来 |
| `verdict` | 三值。`is_safe` + `unsafe_reason` 就是全部答案；签名原文仍在 `verdict_jws` |
| `fail_closed` | → `unsafe_reason == "scan_incomplete"` |
| `requires_review` | → `unsafe_reason == "pending_review"` |

**刻意不外露的内部字段：**

| 字段 | 不外露的理由 |
|---|---|
| `snippet_hash` | 哈希虽非原文，但低熵密钥可被离线爆破验证，给市场没有实际用途，只增加暴露面 |
| `provenance` / `required_ok` | 内部裁决过程细节，一旦外露即成为对外契约的一部分，日后再难改动 |
| 原文证据片段 | 违反 INV-9——一条 PII/凭据类 finding 的原文本身就是那个凭据 |

> **`hard_gate_hits` 的排除已于 2026-07-30 反转。** 它原先与 `provenance`/`required_ok`
> 同列——在**三值**契约下那是对的，因为调用方同时拿到 `verdict` 能看见 BLOCK。二值契约下
> 不再成立：只说"不安全"却说不出**为什么**的答案不可行动，而"命中了不可豁免的规则"
> （任何加白都改不了）与"发现累积到了阈值"（改代码即可）是两类完全不同的问题。它是
> **规则 id 列表，不是证据文本**，不触及 INV-9。`snippet_hash` 与 `provenance` 在同一次
> 评估中被重新审视并**保持排除**——这些排除项从来不是一个整体包。
>
> 注意它是**记录**的那一份集合。`gate` 还会按当前策略重算硬门并按并集 BLOCK，所以一条
> "扫描当时不是硬门、后来才成为硬门"的规则不在此列；那种情形必然带着产生它的 findings，
> 因此会被标为 `content_findings`。

字段集合是白名单（`marketplace_api/views.py` 的 `EXTERNAL_TOP_LEVEL_FIELDS`/
`EXTERNAL_FINDING_FIELDS`）而非黑名单过滤：内部新增字段默认对外不可见，须显式加入投影
才会出现——遗漏是"功能缺失"，容易被发现；黑名单式过滤的遗漏则是"数据泄漏"，不会被发现。
有跨注册表守卫测试断言投影输出恰好等于这两个集合。

### 6.8 取用审计

每次成功轮询会在 `marketplace_fetch_log` 留一行，用于不可否认性（能证明何时告知了对方什么
判定）与反向缺口检测（已出判定但从未被取走，是 pull 模型下最接近"市场未读结论即上架"的
信号）。写入失败只记日志，绝不影响轮询响应本身——详见运维指南关于 `svc_marketplace`
数据库授权的说明。

列（2026-07-30 随契约替换扩列）：`skill_id`（**调用方实际查询的键**）·
`scan_id`（作答所依据的扫描，**可为 null**：最新版本尚未扫描时没有 scan 可指名）·
`content_hash_shown`（该答案关于哪个版本）· `service_account` · `fetched_at` ·
`status_shown` · `is_safe_shown` · `unsafe_reason_shown` ·
`verdict_shown`（**该答案所派生自的内部 verdict**——响应已不再返回 `verdict`，所以这一列
不再是返回值的副本；列名与历史数据都不动，只把含义写清楚，因为一张审计表的列含义在历史行
底下悄悄漂移比列名过时严重得多）。

新增列全部 nullable 且**不回填**：旧契约的行确实没有 skill_id、没有 is_safe，NULL 就是
"这个字段早于这个问题"的诚实答案。表级 `INSERT+SELECT` 授权自动覆盖新列，append-only
姿态（无 UPDATE/DELETE）**未放宽**。

---

## 相关文档

- [`BUILD_GUIDE.md`](BUILD_GUIDE.md) — 编译指南
- [`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md) — 部署指南
- [`MAINTENANCE_GUIDE.md`](MAINTENANCE_GUIDE.md) — 运维指南
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — 内核威胁模型（2026-07-06 审计修复新增）
