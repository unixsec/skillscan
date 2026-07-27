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

**951 个后端测试**针对真实 MySQL/Redis 全部通过（不 mock 被测系统），另有
**117 个内核测试**（`tests/`，纯 `skillscan_core`，仅依赖标准库）。
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
uv run pytest -q           # 针对本地 MySQL/Redis 跑后端测试套件（951 个测试）
uv run pytest tests/ -q    # 内核测试套件，无外部依赖（117 个测试）
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
