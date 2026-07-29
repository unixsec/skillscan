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
机器身份并未因此少拿到任何东西：`/v1/market/scans` 提交、`/v1/market/scans/{scan_id}`
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
| 查看自身结果 | ✓ | ✓ | ✓ | ✓ | ✓（仅 `/v1/market/scans/{id}` 投影） |
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
严重级别/通过或不通过）和**按检测类别**（固定展示 8 类"8类61项"，0 个 finding 即为通过）。
这是对同一份数据的诚实展示层重新分组，不是新的策略判定——顶部仍只展示 gate 的唯一权威
判定（PASS/REVIEW/BLOCK）。

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
| POST | `/v1/market/scans` | `scan:submit` | 提交扫描包（multipart，字段名 `package`）。响应仅 `{"scan_id": ...}` |
| GET | `/v1/market/scans/{scan_id}` | `scan:read` | 轮询扫描状态与结果 |

提交端点存在的理由：市场必须用**同一身份**提交和轮询，否则"这是不是它自己提交的扫描"这一
对象级授权判断无从比对（见 §6.2）。提交比控制台 `POST /v1/scans` 窄：不接受 `skill_id`，
不触发清单生命周期状态机——对外契约是"扫描进、判定出"，登记清单与生命周期流转是内部人工
审核流程，不对市场开放。

### 6.2 认证与授权

- M2M client-credentials 或 mTLS，走与交互式会话相同的校验路径，没有"可信服务"绕过对象级
  授权的例外。
- scope 按服务账号授予（`M2MGrant`），不是全仓共享的常量——未显式配置的服务账号保持迁移前
  默认值 `{"scan:submit"}`，不会因这次改造凭空获得读权限。
- 市场身份即使持有 `scan:read`，也只能读**自己提交的** scan；读取他人的 `scan_id` 返回
  `404`（不是 `403`，避免探测 scan_id 是否存在——与控制台 `GET /v1/scans/{scan_id}` 同一
  形制）。请求越权但 scan_id 本身存在性不是问题时（例如没有 `scan:read` scope）返回
  `403`——这里暴露"你没有这个权限"不泄漏任何他人数据。
- **"自己提交的"按关联表 `scan_submitter` 判定，不是按 `scan_job.submitter` 单列**
  （2026-07-28 修订）。提交是单飞去重的（键为 `content_hash + toolchain_digest`）：字节
  相同的包重复提交会返回**同一个** `scan_id`，因此一次扫描合法地有多个提交者。若按单列判定，
  控制台先扫过的包被市场再提交时，市场拿到 `scan_id` 却永远读不到它（且该 404 与"不存在"
  不可区分，无法诊断）——而"控制台和市场扫同一批 skill"是常态。

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
| `failed` | `COMPLETED` | 停止轮询，读 `verdict`（恒为 `BLOCK`，且 `fail_closed: true`） |

**`failed` 映射为 `COMPLETED` 而不是独立的 `FAILED`，这是本节最容易被误解、也最值得记住
的一点：** 系统在 fail-closed 时做出并签署了一个真实的 BLOCK 判定——扫描管线本身出了问题，
因此按最保守方式处理。如果对外报"FAILED"，市场侧自然的反应是重试或忽略；而重试一个
fail-closed BLOCK 恰恰是错的，会绕开系统刚刚做出的保守判定。因此对外只有一个终态
`COMPLETED`，判定本身（`verdict`）承载全部含义，`fail_closed: true` 说明这个 BLOCK 的
来源是"管线失败后的兜底"而非常规裁决。`fail_closed` 时 `findings` 恒为空数组（管线没能
产出结果）。

### 6.5 判定值

`verdict` 如实给三值 `PASS` / `REVIEW` / `BLOCK`，不折叠为二值——系统内部有三条独立路径
会产出 `REVIEW`（严重度达 HIGH 但未达该 tier 的 BLOCK 阈值、低置信度证据、findings 超限
截断触发的强制 REVIEW），折叠成二值会让其中任何一条变成事实上的绕过通道。`REVIEW` 具体
如何处理由市场自行决定（本系统不替市场做主）；`requires_review: bool` 字段把这个语义
显式化，调用方不必先理解三值判定语义就能正确分支。

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
| `scan_id` | string | |
| `status` | enum | `PENDING`/`RUNNING`/`COMPLETED` |
| `verdict` | enum \| null | `PASS`/`REVIEW`/`BLOCK`；非 `COMPLETED` 时为 `null` |
| `score` | int \| null | 0–100 |
| `policy_version` | string \| null | |
| `decided_at` | ISO8601 \| null | |
| `verdict_jws` | string \| null | 签名令牌，市场可独立验签，不必信任传输层 |
| `fail_closed` | bool | 仅 fail-closed 产生的 BLOCK 为 `true` |
| `requires_review` | bool | `verdict == REVIEW` 时为 `true` |
| `poll_after_ms` | int | 见 §6.6 |
| `judged_at_tier` | enum \| null | 本次判定**实际所依据的** trust tier。因单飞去重，它未必等于本次提交方自己的 tier：字节相同的包若已被别人扫过，返回的是**那次**判定，判定不会为后来者重算，因此也不能改述成按后来者的 tier 判的。tier 决定 BLOCK 阈值，差异是实打实的。`null` 表示该扫描未记录 tier（判定时回退到部署默认值） |
| `requested_tier` | enum \| null | **本调用方自己请求的** trust tier（即该服务账号被授予的 tier，记在它自己的 `scan_submitter` 行上）。与 `judged_at_tier` 成对读：只报后者，等于让调用方默认二者相同，而在这条接口上通常**并不**相同。`null` 表示该行没有记录请求（该列出现之前写入的历史行）——**不会**回退成 `judged_at_tier`，否则就是在替调用方断言一个没人记录过的"一致" |
| `tier_direction` | enum \| null | `looser` / `stricter` / `equivalent`，说明二者不一致时**往哪个方向**偏。`looser` 是要紧的那个：判定所依据的规则集比你请求的**更宽松**，本该为你 BLOCK 的 finding 可能读作 PASS。**这是本接口上最常见的方向**：未配置的服务账号默认 `public`（**最严**，HIGH 即 BLOCK），而控制台通常按 `internal` 提交（仅 CRITICAL 才 BLOCK）。由 `GatePolicy.block_threshold` 推出，**不是**按 tier 名字的顺序——严格程度写在策略文件的 `tier_block_overrides` 里，改策略即可改变顺序。任一侧为 `null`、二者相同、或存储值不是合法 tier 时均为 `null` |
| `summary` | object | `total`/`critical`/`high`/`medium`/`low`/`truncated`；`total` 是真实总数，即便 `findings` 因超限被截断（5000 条上限）也不变 |
| `findings` | array | 见下；`fail_closed` 时为空数组 |

**`findings[]`：** `rule_id` · `test_item_id` · `category` · `title` · `severity` ·
`confidence` · `source_engine` · `source_capability` · `trifecta_signals` ·
`file_path` · `start_line` · `evidence_redacted`

**刻意不外露的内部字段：**

| 字段 | 不外露的理由 |
|---|---|
| `snippet_hash` | 哈希虽非原文，但低熵密钥可被离线爆破验证，给市场没有实际用途，只增加暴露面 |
| `provenance` / `required_ok` / `hard_gate_hits` | 内部裁决过程细节，一旦外露即成为对外契约的一部分，日后再难改动 |
| 原文证据片段 | 违反 INV-9——一条 PII/凭据类 finding 的原文本身就是那个凭据 |

字段集合是白名单（`marketplace_api/views.py` 的 `EXTERNAL_TOP_LEVEL_FIELDS`/
`EXTERNAL_FINDING_FIELDS`）而非黑名单过滤：内部新增字段默认对外不可见，须显式加入投影
才会出现——遗漏是"功能缺失"，容易被发现；黑名单式过滤的遗漏则是"数据泄漏"，不会被发现。
有跨注册表守卫测试断言投影输出恰好等于这两个集合。

### 6.8 取用审计

每次成功轮询会在 `marketplace_fetch_log` 留一行（`scan_id`/`service_account`/
`fetched_at`/`status_shown`/`verdict_shown`），用于不可否认性（能证明何时告知了对方什么
判定）与反向缺口检测（已出判定但从未被取走，是 pull 模型下最接近"市场未读结论即上架"的
信号）。写入失败只记日志，绝不影响轮询响应本身——详见运维指南关于 `svc_marketplace`
数据库授权的说明。

---

## 相关文档

- [`BUILD_GUIDE.md`](BUILD_GUIDE.md) — 编译指南
- [`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md) — 部署指南
- [`MAINTENANCE_GUIDE.md`](MAINTENANCE_GUIDE.md) — 运维指南
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — 内核威胁模型（2026-07-06 审计修复新增）
