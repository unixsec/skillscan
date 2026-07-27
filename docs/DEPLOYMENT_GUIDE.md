# 部署指南（Deployment Guide）— skillscan

三条部署路径，按适用场景选择：

| 路径 | 适用场景 | 一键脚本 | 登录方式 |
|---|---|---|---|
| **本地开发/演示** | 开发调试、功能演示 | `scripts/one_click_dev.sh` | break-glass（脚本自带 dev 专用固定凭据） |
| **容器化生产部署** | 单机/少量 VM，无 K8s | `scripts/one_click_deploy_docker.sh` | 真实 OIDC/SAML（需在 `.env` 配置）或 break-glass |
| **Kubernetes** | 集群规模生产部署 | `deploy/helm/skillscan`（Helm chart，未在本环境 apply 验证） | 同上 |

---

## 1. 本地开发/演示部署 ✅已验证

```bash
./scripts/one_click_dev.sh
```

这一条命令做了什么（均已在本机实际运行验证）：

1. 检查前置工具（uv/npm/mysql/redis-cli）
2. 启动本地 MySQL 8 + Redis（Homebrew services）
3. `uv sync` 安装后端依赖
4. 建库 + `alembic upgrade head` 应用迁移
5. 应用 `policies/grants/manifest.yaml` 的 per-module GRANT
6. 构建前端（`npm install && npm run build`）
7. 启动后端（`scripts/dev/run_local.py`）——真实 `create_app()`，唯一的差异是强制
   `breakglass_enabled=True` 并用一个**明确标注 dev-only** 的固定凭据/TOTP secret
   （`scripts/dev/breakglass_dev_port.py`，与 `LocalDevSigner`/
   `_LOCAL_DEV_DEFAULT_PASSWORD` 是完全同一类"清晰标注、绝不用于生产"的既有模式）

脚本结束时会打印登录说明（TOTP secret、如何激活 break-glass、登录凭据）。**幂等**——
`CREATE DATABASE IF NOT EXISTS`/`alembic upgrade head`/`setup_grants.py` 的
`CREATE USER IF NOT EXISTS` 在已配置好的环境上重复执行都是空操作，可以放心重跑。

前端开发服务器需要单独在另一个终端启动（会代理 `/v1` 到上面的后端）：

```bash
cd web && npm run dev   # http://localhost:5173
```

**这不是生产入口**——生产环境永远直接跑 `uvicorn monolith.main:create_app --factory`
（见 `apps/monolith/main.py` 自己的文档字符串），`SKILLSCAN_BREAKGLASS_ENABLED` 默认为
`false`，除非真的需要且已接好真实 Vault 才手动开启。

## 2. 容器化生产部署（docker-compose）⚠未在本环境验证构建

**前置条件：** Docker + docker compose 插件（本机开发环境没有 Docker daemon，以下命令
未在此实际运行过——`docker-compose.yml` 本身已通过 YAML 语法校验）。

```bash
cp .env.example .env
# 编辑 .env，填入真实的 Vault/OIDC/SAML/数据库密码等（见下方环境变量表）
./scripts/one_click_deploy_docker.sh
```

这会构建并启动：MySQL 8 + Redis + 一次性 `migrate`（迁移+GRANT）+ 单体后端（`monolith`，
端口 8000）+ Web 控制台（`web`，nginx 反向代理到单体，端口 80，同源 BFF——见 §5 安全说明）。

**没有 Docker 的最小可替代路径：** 直接在一台已装好 Python/Node/MySQL/Redis 的宿主机上，
参照编译指南 §2/§3 构建，再用 §4 的环境变量表配置后运行
`uvicorn monolith.main:create_app --factory --host 0.0.0.0 --port 8000`（对应 SAD §3.4
"拓扑 B2：docker-compose + systemd" 中不使用容器的等价形态）。

### `.env` 环境变量表（`.env.example` 是权威模板，逐项都已在此列出）

| 分组 | 变量 | 必需 | 说明 |
|---|---|---|---|
| MySQL | `SKILLSCAN_MYSQL_ROOT_PASSWORD` | 是 | 仅一次性 `migrate` 服务使用，运行中的单体从不用 root |
| MySQL | `SKILLSCAN_DB_PASSWORD_{ORCHESTRATION,GATE,REEVAL,REPORTING,INVENTORY,AUDIT,INTEL}` | 是 | 对应 `policies/grants/manifest.yaml` 的 per-module 最小权限账户 |
| Vault | `SKILLSCAN_VAULT_ADDR` / `_TOKEN` / `_TRANSIT_KEY_NAME` | 判定签名+break-glass需要 | 未配置则退回 `LocalDevSigner`（仅限测试） |
| Break-glass | `SKILLSCAN_BREAKGLASS_ENABLED` | 否，默认 `false` | INV-17：默认禁用，启用需已配置 Vault |
| OIDC | `SKILLSCAN_OIDC_ISSUER` / `_CLIENT_ID` / `_CLIENT_SECRET` / `_REDIRECT_URI_ALLOWLIST` / `_AUTHORIZATION_ENDPOINT` / `_TOKEN_ENDPOINT` / `_JWKS_URI` | 否 | **审计修复(2026-07-06)新增：** 留空则 `GET /v1/auth/oidc/*` 返回 404（未配置），不报错 |
| SAML | `SKILLSCAN_SAML_SP_ENTITY_ID` / `_SP_ACS_URL` / `_IDP_ENTITY_ID` / `_IDP_SSO_URL` / `_IDP_SLO_URL` / `_IDP_X509_CERT` | 否 | 同上，留空则 `GET /v1/auth/saml/*` 返回 404 |
| 会话 | `SKILLSCAN_SESSION_INTROSPECTION_ENDPOINT` 等 | OIDC 登录需要 | RFC 7662 introspection 端点 |
| 市场 | `SKILLSCAN_MARKETPLACE_API_BASE_URL` / `_POLL_TOKEN` / `_WRITE_TOKEN` | 否 | 留空则判定回写/对账禁用 |
| SIEM | `SKILLSCAN_SIEM_ENDPOINT` | 否 | **审计修复(2026-07-06)新增：** 留空则 SIEM 转发禁用（市场回写仍正常） |
| M2M | `SKILLSCAN_M2M_ALLOWED_SERVICE_ACCOUNTS` | 否 | 逗号分隔 client_id 白名单 |
| 情报 | `SKILLSCAN_INTEL_TRUSTED_KEYS_DIR` | 否 | 留空则离线导入 fail-closed 拒绝一切 |
| 构建期 | `SKILLSCAN_PIP_INDEX_URL` / `SKILLSCAN_NPM_REGISTRY` | 内网构建需要 | INV-14 零外部出站在构建期的延伸 |

**未配置 Vault + OIDC/SAML 时：** 单体正常启动、健康检查通过，但没有任何登录路径可用
（除非显式设置 `SKILLSCAN_BREAKGLASS_ENABLED=true` 且 Vault 可达）——这是刻意的
fail-closed 设计（INV-17），不是 bug。

## 3. Kubernetes 部署 ⚠未在本环境 apply 验证

```bash
helm install skillscan deploy/helm/skillscan -f my-values.yaml
```

`deploy/helm/skillscan` 的模板已通过 `helm lint` + `helm template | kubeconform -strict`
校验（见编译指南 §6），但从未在真实集群上 apply 过——本机无 K8s 集群可用。`deploy/
networkpolicy/`（default-deny + 白名单）、`deploy/kyverno/`（签名镜像/禁特权/gVisor
RuntimeClass 准入）同样只做过语法/结构校验。完整拓扑（含 gVisor 沙箱化的
`engine-runner` 独立命名空间）见架构设计说明书 SAD §3.4 拓扑 A。

## 4. 真实 OIDC/SAML 登录路径（审计修复，2026-07-06 新增）

**此前的状态：** M2 建好了完整的 OIDC/SAML 校验逻辑并测试充分，但没有任何路由真正完成
一次登录握手并创建会话——`set_session_cookie` 全代码库唯一的调用点是 break-glass 登录。
这意味着此前任何部署形态下，**唯一能实际登录的路径是 break-glass**。

**现在：** `apps/monolith/modules/gateway/auth/login_router.py`（挂载于 `/v1/auth`）提供：

| Method | Path | 说明 |
|---|---|---|
| GET | `/v1/auth/oidc/login` | 构造 PKCE+state+nonce 授权跳转 |
| GET | `/v1/auth/oidc/callback` | 完成 code 交换，校验后签发会话（cookie 携带 IdP 自己的 access_token，之后每次请求走 introspection 重新校验，未额外落库） |
| GET | `/v1/auth/saml/login` | 构造 SP-initiated AuthnRequest 跳转 |
| POST | `/v1/auth/saml/acs` | Assertion Consumer Service——校验断言后签发会话 |

**架构说明：** OIDC 天然适配 M2 已有的"opaque token + introspection"模型；SAML 没有
可反复 introspect 的 bearer token，因此 SAML 会话改为 Redis 落库（与 break-glass 完全相同
的模式，`SAML_SESSION_COOKIE_NAME`），而非强行套用 OIDC 的模型——这是经过权衡的架构决定，
不是权宜之计。两条登录端点均不挂 `require_csrf`（登录端点定义上就是会话建立之前，没有
可供该检查识别的会话 cookie）。

**配置：** 见 §2 环境变量表的 OIDC/SAML 分组；`SKILLSCAN_OIDC_ISSUER`/
`SKILLSCAN_SAML_SP_ENTITY_ID` 任一留空即视为该登录方式未启用（对应端点 404，不报错）。

## 5. 安全部署要点（INV-16/17，已验证）

- **BFF 同源反向代理：** Web 控制台与 `/v1` API 必须同源——`web/nginx.conf` 里的
  `location /v1/` 反代到 `monolith:8000`，与 `web/vite.config.ts` 开发模式下的 proxy
  是同一个理由：会话/CSRF cookie 是 `SameSite=Strict`，跨域永远不会被发送。
- **无默认管理员口令**（INV-17，已 grep 确认）：主 admin 唯一常规路径是 IdP 组映射
  （`policies/rbac/group_role_map.yaml`），未匹配的组一律降级为 `submitter`（deny-by-default）。
- **Break-glass 默认禁用**，启用需要 Vault 封存凭据 + TOTP + 二人 + 全审计 + SecOps 告警——
  见运维指南 §4。
- **CSP/安全头** 由 `SecurityHeadersMiddleware` 统一下发，`docker-compose.yml`/Helm chart
  均不额外配置反向代理层的安全头（避免两处配置互相覆盖导致意外弱化）。

---

## 相关文档

- [`BUILD_GUIDE.md`](BUILD_GUIDE.md) — 编译指南
- [`USAGE_GUIDE.md`](USAGE_GUIDE.md) — 操作指南
- [`MAINTENANCE_GUIDE.md`](MAINTENANCE_GUIDE.md) — 运维指南
- `.env.example` — 完整环境变量模板
- `docker-compose.yml` / `scripts/one_click_dev.sh` / `scripts/one_click_deploy_docker.sh` —
  实际部署脚本本身
