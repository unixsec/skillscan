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
| GET | `/v1/scans` | submitter(仅自己)/approver+(全部) | 列表 |
| GET | `/v1/scans/{scan_id}` | 提交者本人/approver+ | 详情：`state`/`verdict`/`findings[]`/`provenance`/`hard_gate_hits`/`reasons`/`required_ok`/`sarif_ref`（现指向下一行的真实端点） |
| GET | `/v1/scans/{scan_id}/sarif` ✳ | 同上 | **新增：** 单扫描 SARIF 2.1.0 导出，此前恒为 404/null |
| GET | `/v1/me` | submitter+ | 当前会话 `subject`/`roles`/`tier`，仅供前端 UX 判断菜单显示 |
| GET/POST | `/v1/auth/oidc/*`、`/v1/auth/saml/*` ✳ | 无（登录前） | **新增：** 真实 OIDC/SAML 登录握手，见部署指南 §4 |
| GET/POST | `/v1/reviews`、`/v1/reviews/{scan_id}` | approver+ | 待复核队列/批准或拒绝（SoD：审批人≠提交者） |
| GET/POST/DELETE | `/v1/allowlist`、`/v1/allowlist/{id}` | approver+（硬门禁豁免需 admin） | 标准加白（四眼+有效期） |
| GET/POST | `/v1/inventory*` | approver+ | 清单生命周期：`submitted→scanning→(review_pending)→published→[quarantined⇄published]→retired` |
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

**对象级授权（IDOR 防护）在 `/v1/scans` 与 `/v1/scans/{scan_id}/sarif` 上真实生效**：
提交者读取不属于自己的 `scan_id` 得到 `404`（不是 `403`，防止状态码探测）。**所有状态变更
请求（POST/PATCH/DELETE）均要求 CSRF token**——`require_csrf` 依赖已覆盖每一个已知的会话
cookie 类型（普通会话/break-glass/SAML，三者均已核对，见运维指南 §5 的具体教训）。

## 3. Web BFF 集成模式

Web 前端不直接持有任何 token——浏览器只拿到 HttpOnly/Secure/SameSite 会话 cookie。
前端所有请求走同源 `/v1/*`；生产环境由反向代理（nginx，见部署指南）同时服务静态资源和
`/v1/*` API，实现同源。

## 4. 按角色使用（角色/权限矩阵，SRS 附录 C）

| 权限 | Submitter(默认) | Approver | Administrator | Auditor | Service(M2M) |
|---|---|---|---|---|---|
| 提交扫描 | ✓ | ✓ | ✓ | ✗ | ✓ |
| 查看自身结果 | ✓ | ✓ | ✓ | ✓ | ✓ |
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

---

## 相关文档

- [`BUILD_GUIDE.md`](BUILD_GUIDE.md) — 编译指南
- [`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md) — 部署指南
- [`MAINTENANCE_GUIDE.md`](MAINTENANCE_GUIDE.md) — 运维指南
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — 内核威胁模型（2026-07-06 审计修复新增）
