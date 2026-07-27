# 编译指南（Build Guide）— skillscan

本指南只讲"如何从源码构建出可运行的产物"——后端 Python 环境、前端 SPA、容器镜像、OSS
引擎 vendoring。部署/运维/日常使用见同目录下的另外三份指南（文末索引）。

M1–M8 全部里程碑均已实现，**2026-07-06 完整规格合规审计发现的 18 项差距也已全部修复**
（详见 `docs/stories/BACKLOG.md` 与本文档各处的"审计修复"标注）——本指南描述的是当前
真实、可运行的构建流程，不是设计目标。

---

## 1. 前置条件

| 工具 | 版本 | 用途 |
|---|---|---|
| Python | ≥ 3.12 | 后端 |
| [uv](https://docs.astral.sh/uv/) | 最新 | Python 依赖/虚拟环境管理 |
| Node.js / npm | Node ≥ 20 | 前端构建 |
| MySQL | 8.0.x（非 9.x） | 本地开发/测试数据库 |
| Redis | 最新 | 本地开发/测试队列+会话存储 |
| Docker（可选） | 最新 | 仅在需要构建容器镜像时需要——本机开发环境**没有 Docker
  daemon**，本指南列出的所有 Dockerfile 均未在此环境实际构建验证过，语法/结构层面已核对 |

## 2. 后端构建

```bash
cd ~/dev/projects/skillscan
uv sync                                    # 安装全部依赖（含 mypy/ruff/pytest）到 .venv
```

`libs/skillscan_core` 本身**零运行时依赖**（编码规格 §2 的明确设计约束）——只需要 Python
标准库；`mypy`/`ruff`/`pytest` 只是开发期工具。

**已知坑：** 如果先执行了 `uv sync` 再补充源码文件到 `libs/skillscan_core/`，`uv` 不会自动
感知包内容变化，需要显式重装：`uv sync --reinstall-package skillscan`。

**验证构建产物：**

```bash
uv run python3 -c "import skillscan_core; print(skillscan_core.__file__)"
uv run mypy                                # 严格类型检查，当前 171 个源文件全绿
uv run ruff check . && uv run ruff format --check .
uv run pytest -q                           # 706 项通过（真实本地 MySQL/Redis，不 mock 被测系统）
python3 -m unittest discover -s tests -v   # M1 内核不变式套件，96 项通过（stdlib only）
```

若看到 `706 passed`/`Ran 96 tests ... OK`，后端构建环境即已就绪。

**新增子系统（本次审计修复涉及的构建产物，均随 `uv sync` 一起装好，无需额外步骤）：**

| 子系统 | 位置 | 说明 |
|---|---|---|
| 统一配置 | `apps/monolith/config.py` | 编码规格 §13 的 `Settings` 类，见部署指南 §2 的环境变量表 |
| 端口协议 | `libs/ports/` | 7 个 Protocol 定义（`SignerPort`/`MarketplacePort`/`DetectionEnginePort`/`RepositoryPort`/`LLMPort`/`IntelPort`/`NotificationPort`），六边形架构的核心/适配器边界 |
| SIEM 集成 | `apps/monolith/modules/integration_relay/siem.py` | CEF-over-syslog 真实实现，见运维指南 §3 |
| 登录回调 | `apps/monolith/modules/gateway/auth/login_router.py` | 真实 OIDC/SAML 登录路由，见部署指南 §4 |

## 3. 前端构建

```bash
cd web
npm install
npm run build   # tsc -b && vite build
npm run lint    # oxlint（SessionContext.tsx/I18nContext.tsx 的 2-3 条 warning 是预期的，
                 # 同一文件导出 Provider 组件 + 对应 hook 的既有模式，非需要修复的问题）
```

零新增 UI 框架依赖——中英文 i18n 是手写的、零依赖的 `web/src/i18n/` 翻译层。

## 4. OSS 引擎 vendoring（编码规格 §10A）

```bash
git submodule update --init --recursive     # 拉取已 vendor 的引擎子模块源码
uv run python3 scripts/vendor_engines.py verify-pins    # 核对 vendor/engines.lock.yaml 的 pin
uv run python3 scripts/vendor_engines.py license-scan   # 许可证扫描（仅 Apache/BSD/MIT 放行）
uv run python3 scripts/vendor_engines.py status
```

5 个引擎已 vendor（skillspector/aig/bandit/osv_scanner/yara）。4 个适配器（bandit/osv/yara/
skillspector）已实现，AIG 因真实接口是网络服务扫描器而**有意不做适配器**（详见
`docs/stories/BACKLOG.md` S5）。Cisco skill-scanner 从未 vendor（官方仓库地址从未确认），其
候选能力缺口（多语言/非英文提示词注入检测）已由自研中文 floor 检测器填补，见
`docs/superpowers/specs/2026-07-22-chinese-prompt-injection-detectors-design.md`。

`scripts/vendor_engines.py` **有意不**自动化 `git submodule add` 本身——拉入新的第三方源码
是一次性、需要人工确认的网络操作，不应被脚本静默执行。

**审计修复（2026-07-06）：** skillspector 引擎适配器新增 `osv_proxy_url` 可选参数
(`services/engine_runner/adapters/skillspector.py`)——vendored 的 `osv_client.py` 内部用
`httpx.Client`（默认 `trust_env=True`），可以通过 `HTTPS_PROXY`/`https_proxy` 环境变量把其
`api.osv.dev` 调用重定向到内网镜像，无需修改 vendor 源码本身（`# LICENSE:` 禁止）。

## 5. 容器镜像构建（未在本机验证，无 Docker daemon）

| 镜像 | Dockerfile | 说明 |
|---|---|---|
| 单体后端 | `apps/monolith/Dockerfile` | 多阶段构建，`uv sync --frozen --no-dev` |
| Web 控制台 | `web/Dockerfile` | Node 构建 + nginx 提供静态资源 + 反向代理 `/v1`（同源 BFF，见部署指南） |
| bandit/osv-scanner/yara/skillspector | `deploy/engines/<name>/Dockerfile` | 从 `vendor/<engine>/` 本地源码构建，禁止构建期访问公网 |

```bash
# 语法/结构校验（不需要 Docker daemon）：
uv run python3 -c "import yaml; yaml.safe_load(open('docker-compose.yml'))"  # 已验证通过

# 真实构建（需要 Docker，未在本环境验证）：
docker compose build
```

## 6. IaC 静态校验（K8s 部署清单，编码规格 §11.7）

```bash
helm lint deploy/helm/skillscan                              # 已验证通过
helm template deploy/helm/skillscan | kubeconform -strict     # 已验证通过，4/4 valid
shellcheck dr/backup.sh scripts/one_click_dev.sh scripts/one_click_deploy_docker.sh  # 已验证通过
```

真实 K8s 集群 apply/隔离测试/DR 演练需要真实集群，本机无法验证——见运维指南的环境受限说明。

---

## 相关文档

- [`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md) — 部署指南（一键本地开发部署 + 一键容器化部署 + K8s）
- [`USAGE_GUIDE.md`](USAGE_GUIDE.md) — 操作指南（按角色的日常使用）
- [`MAINTENANCE_GUIDE.md`](MAINTENANCE_GUIDE.md) — 运维指南（日常维护 + 故障排查）
- [`stories/BACKLOG.md`](stories/BACKLOG.md) — 里程碑实现状态与验收细节
