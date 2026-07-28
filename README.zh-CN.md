# skillscan

[English](README.md)

企业级 Skill 安全检测系统——在 Agent Skill 包（`SKILL.md` + `scripts/` +
内置的 `.mcp.json`/hooks）进入市场准入前对其进行扫描，产出 `PASS` / `REVIEW` /
`BLOCK` 判定结果。内部工具，本地部署，零外部网络连接。

项目基于分层的规格体系构建（需求规格 → 架构设计 → 编码规格），配有按里程碑
划分、每个故事都带独立状态说明的需求积压清单——这两者在本仓库对外发布的这份
快照之外单独维护。运维指南与内核威胁模型随本仓库发布，位于 `docs/` 下。

## 现状

**M1-M8 全部实现**。针对编码规格做过一轮完整的逐项审计（2026-07-06）发现 18 个
真实缺口，全部已修复，包括一个关键内核缺陷：`gate.decide()` 里的去重碰撞可能
悄悄丢弃一个刚好凑齐三要素的检测结果、`POST /v1/reeval/{skill_id}` 缺失 CSRF
校验，以及真正可用的 OIDC/SAML 登录回调（`/v1/auth/oidc/*`、`/v1/auth/saml/*`），
break-glass 不再是唯一可用的会话登录方式。那轮审计暴露的最大结构性缺口——扫描
判定的 worker 循环未被任何实际进程调用——已由 `apps/monolith/worker.py` 于同日
晚间关闭。

此后新增：

- **本地账号 + RBAC**——部署方无需 IdP 也能引导出第一个管理员，与既有的 SSO
  路径并存。
- **中文提示词注入 floor 检测器**（PROMPT-01/04）——采用同行共现判定而非单
  关键词匹配。上游的提示词注入正则全是英文，此前中文内容可以干净通过。
- **逐规则的安全风险说明**，覆盖全部 14 个引擎——每条 finding 都解释**为什么
  这是风险**，而不是复述规则名。
- **0-100 安全评分**，与 PASS/REVIEW/BLOCK 判定并存。评分是**已决出判定的纯
  下游派生量**：判定先选定档位（BLOCK `[0,39]` / REVIEW `[40,74]` /
  PASS `[75,100]`），findings 再在档内调制。评分永远不作为 `decide()` 的输入
  ——正是这个数据流方向让「BLOCK 却拿高分」在结构上不可能发生，而不只是靠测试
  去堵。
- **sandbox 层引擎真正参与裁决**。bandit / yara / skillspector / osv-scanner
  此前只有恰好赶在裁决之前跑完才会被计入；现在裁决会等待它们，最长 300 秒。
  等待是 advisory 的——某个 sandbox 引擎缺席只会记进 `reasons`，裁决照常进行，
  单个引擎劣化不会 fail-close 掉整批扫描。代价是时延：扫描从毫秒级变为分钟级，
  而扫描详情页尚无自动刷新。
- **两个新增 floor 检测器**，`required_engines` 由 7 增至 9：随包 `.mcp.json`
  （server 定义中的命令注入、非本机端点、疑似凭据的环境变量透传）与 `SKILL.md`
  frontmatter 权限声明（过度授权组合、未声明权限）。两者都是纯静态分析——
  `.mcp.json` 检测器从不连接它读到的那些端点。声明的权限现已按 skill 版本持久化。
- **逐规则置信度**取代此前"每引擎一个常数"，按证据强度分档：结构化验证的匹配
  约 0.9，特征明确的 API 调用形态 0.7-0.8，裸子串 0.4-0.5。这让一条此前不可达的
  门禁策略分支重新生效——因为过去 floor 层从未产出低于其阈值的置信度。对 836 条
  真实历史判定实测，该改动使 2.3% 的扫描由 PASS 变为 REVIEW。
- **检测目录编号的正确性**。每条 finding 都带一个来自检测目录的 `test_item_id`；
  此前有若干引擎写出的是自己的内部规则名、或是目录里根本不存在的编号，导致按目录
  统计的合规报表把真实运行着的能力误判为未覆盖。现已加测试断言：凡引擎可能发出的
  编号必须是目录中的真实条目——**形状检查抓不住一个形状完全合法的错误编号**。

- **市场现在可以轮询扫描结果。** `POST /v1/market/scans` 与
  `GET /v1/market/scans/{scan_id}`，接口面与控制台刻意分离。跨越这道边界的是**投影**而非
  内部模型：十三个字段的显式白名单，因此新增内部字段在对外是无操作，而不是泄漏。只给脱敏
  证据——`snippet_hash` 与裁决过程内部量（`provenance`/`required_ok`/`hard_gate_hits`）
  一律不外露。判定如实给出三个值；`REVIEW` 对市场意味着什么由市场自己决定。
- **机器身份的 scope 与 trust tier 改为按服务账号授予。** 此前 scope 是所有 M2M 调用方共享的
  一个模块级集合，而 trust tier 硬编码为最宽松的一档——提交第三方内容的调用方因此按内部内容的
  阈值被判定。两者现已按身份区分，且 tier 随扫描持久化，不再于裁决时读取进程级常量。
- **控制台接口面对机器身份关闭。** 否则投影只是市场**被期望走**的那扇门，而不是它**唯一能走**的门。

**1202 个后端测试**针对真实 MySQL/Redis 全部通过（不 mock 被测系统），另有
**184 个内核测试**（`tests/`，纯 `skillscan_core`，仅依赖标准库）。
`ruff check` / `ruff format --check` / `mypy --strict` 全部干净，
`scripts/check_import_boundaries.py` 守住跨模块 ORM 边界——每个模块拥有自己的
表和自己的最小权限数据库账号，这个检查防止代码侧的边界被侵蚀。前端（`web/`，
React 19 + Vite 单页应用，15 个页面 + 登录页，中英双语）`tsc`/`vite build`/
`oxlint` 全部干净。

一键部署同时支持本地开发（`scripts/one_click_dev.sh`，已端到端验证，含真实的
break-glass 登录）和生产形态的 Docker Compose（`docker-compose.yml` +
`scripts/one_click_deploy_docker.sh`）。注意 Compose 这条路径**有意不包含**
`services/engine-runner`，因此只跑 floor 引擎；完整拓扑见
`docs/DEPLOYMENT_GUIDE.md`。

## 开发

需要 Python >= 3.12、[uv](https://docs.astral.sh/uv/)，以及（如果要跑前端）
Node/npm。

```bash
uv sync                    # 安装全部依赖（后端 + 开发工具）到 .venv
uv run pytest -q           # 针对本地 MySQL/Redis 跑后端测试套件（1202 个测试）
uv run pytest tests/ -q    # 内核测试套件，无外部依赖（184 个测试）
uv run mypy                # 严格类型检查
uv run ruff check .        # lint
uv run ruff format --check .
python3 scripts/check_import_boundaries.py   # 跨模块 ORM 边界检查

cd web && npm install && npm run build && npm run lint   # 前端
```

或者直接跑 `./scripts/one_click_dev.sh`——一条命令拉起 MySQL/Redis、跑
migration、构建前端，并以一个可用的（仅供开发用）break-glass 登录启动后端；
生产形态也可以通过 `docker-compose.yml` + `scripts/one_click_deploy_docker.sh`
这套 Docker Compose 路径使用。

其余内容都在 `docs/` 下的运维指南里：`BUILD_GUIDE.md`（工具链、容器镜像、
OSS 引擎 vendoring）、`DEPLOYMENT_GUIDE.md`（本地/Compose/Kubernetes 部署、
真实 OIDC/SAML 配置）、`USAGE_GUIDE.md`（完整 API 列表、各角色操作流程）、
`MAINTENANCE_GUIDE.md`（日常维护、**剩余已知差距的诚实清单**、故障排查）、
`THREAT_MODEL.md`（内核威胁模型）。

`libs/skillscan_core` 本身依然**零运行时依赖**（编码规格 §2 的设计要求）——
它必须只靠标准库就能被测试，独立于 M2 之后基于它构建的一切上层代码。
