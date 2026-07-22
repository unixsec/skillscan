# skillscan

[English](README.md)

企业级 Skill 安全检测系统——在 Agent Skill 包（`SKILL.md` + `scripts/` +
内置的 `.mcp.json`/hooks）进入市场准入前对其进行扫描，产出 `PASS` / `REVIEW` /
`BLOCK` 判定结果。内部工具，本地部署，零外部网络连接。

项目基于分层的规格体系构建（需求规格 → 架构设计 → 编码规格），配有按里程碑
划分、每个故事都带独立状态说明的需求积压清单，一套按关注点拆分的运维指南
（构建/部署/使用/维护），以及一份专门的内核威胁模型——这些文档在本仓库对外
发布的这份快照之外单独维护。

## 现状

**M1-M8 全部实现**，并针对编码规格做过一轮完整的逐项审计（2026-07-06，6 轮
独立验证，对照真实代码/测试）发现 18 个真实缺口——**18 个全部已修复**，包括
一个关键内核缺陷：`gate.decide()` 里的去重碰撞可能悄悄丢弃一个刚好凑齐三要素
的检测结果（已修复并补充专门的回归测试）、`POST /v1/reeval/{skill_id}` 缺失
CSRF 校验，以及影响最大的结构性缺口——现在已有真正可用的 OIDC/SAML 登录回调
（`/v1/auth/oidc/*`、`/v1/auth/saml/*`）；break-glass 不再是唯一可用的会话
登录方式。仍然遗留的最大已知缺口：扫描判定的 worker 循环目前还没有被任何
实际运行的进程调用。

706 个后端测试针对真实本地 MySQL/Redis 全部通过（不 mock 被测系统），
`mypy --strict`/ruff/ruff-format 在 171 个文件上全部干净；前端（`web/`，
React 19 + Vite 单页应用，13 个页面 + 登录页，中英双语）`tsc`/`vite build`/
`oxlint` 全部干净。一键部署现在同时支持本地开发（`scripts/one_click_dev.sh`，
已端到端验证，含真实的 break-glass 登录）和生产形态的 Docker Compose
（`docker-compose.yml` + `scripts/one_click_deploy_docker.sh`，此环境未做
构建验证——本环境没有 Docker daemon，跟仓库里其它 Dockerfile 的验证状态
一致）。

## 开发

需要 Python >= 3.12、[uv](https://docs.astral.sh/uv/)，以及（如果要跑前端）
Node/npm。

```bash
uv sync                    # 安装全部依赖（后端 + 开发工具）到 .venv
uv run pytest -q           # 针对本地 MySQL/Redis 跑完整后端测试套件（706 个测试）
uv run mypy                # 严格类型检查
uv run ruff check .        # lint

cd web && npm install && npm run build && npm run lint   # 前端
```

或者直接跑 `./scripts/one_click_dev.sh`——一条命令拉起 MySQL/Redis、跑
migration、构建前端，并以一个可用的（仅供开发用）break-glass 登录启动后端；
生产形态也可以通过 `docker-compose.yml` + `scripts/one_click_deploy_docker.sh`
这套 Docker Compose 路径使用。本地 MySQL/Redis 环境搭建细节、各角色的使用
说明、以及已知的常见坑，都写在项目内部的运维文档里。

`libs/skillscan_core` 本身依然**零运行时依赖**（编码规格 §2 的设计要求）——
它必须只靠标准库就能被测试，独立于 M2 之后基于它构建的一切上层代码。
