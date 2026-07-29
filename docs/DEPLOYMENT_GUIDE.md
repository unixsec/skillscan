# 部署指南（Deployment Guide）— skillscan

三条部署路径，按适用场景选择：

| 路径 | 适用场景 | 一键脚本 | 登录方式 |
|---|---|---|---|
| **本地开发/演示** | 开发调试、功能演示 | `scripts/one_click_dev.sh` | break-glass（脚本自带 dev 专用固定凭据） |
| **容器化生产部署** | 单机/少量 VM，无 K8s | `scripts/one_click_deploy_docker.sh` | 真实 OIDC/SAML（需在 `.env` 配置）或 break-glass |
| **Kubernetes** | 集群规模生产部署 | `deploy/helm/skillscan`（Helm chart） | 同上 |
| **Kubernetes（隔离网）** | 无外网、无 registry 的隔离集群 | `scripts/build_offline_bundle.sh` + `helm install`——**完整步骤见 §6** | 本地账号 / OIDC / SAML，需手工配置（§6.9） |

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
校验（见编译指南 §6）。`deploy/networkpolicy/`（default-deny + 白名单）、
`deploy/helm/skillscan-kyverno-policies/`（签名镜像/禁特权/gVisor RuntimeClass 准入，
namespace 从 `.Release.Namespace` 渲染，见 §6.1⑥）只做过语法/结构校验，从未在真实集群上
apply 过。完整拓扑（含 gVisor 沙箱化的 `engine-runner` 独立命名空间）见架构设计说明书
SAD §3.4 拓扑 A。

**隔离网（无外网、无 registry）的完整安装步骤见 §6**——那一节是可以照着从头做到尾的
操作手册，本节只是入口。

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

## 6. 隔离网（air-gapped）Kubernetes 部署

**读者假设：** 会用 `kubectl`、在目标集群上有 cluster-admin、**对本项目没有任何背景知识**。
本节只回答"怎么做"；为什么这么设计见 SAD，以及 `deploy/helm/skillscan/values.yaml`
（chart 自带 MySQL/Redis 而非依赖外部实例的取舍）与 `scripts/build_offline_bundle.sh`
（镜像走离线包而非 registry 的取舍）各自的注释。

全流程分两侧：**有网侧**做一个离线镜像包，**隔离侧**导入镜像 + 一条 `helm install`。
隔离侧不需要任何 registry，也不会有任何对外连接。

### 6.1 装之前的检查清单

下面每一条如果跳过，都会在安装之后变成一个难查的故障，其中两条（RWX、gVisor）在装完
之后基本无法就地补救。

**① 工具与权限**

| 位置 | 需要 |
|---|---|
| 有网侧 | `docker`（daemon 可达）、本仓库完整 checkout、`sha256sum` 或 `shasum` |
| 隔离侧 | `kubectl`（cluster-admin）、`helm` ≥ 3、**每个节点的 root**（导镜像要写 containerd） |

chart 用到的 API 版本（`apps/v1`、`batch/v1`、`networking.k8s.io/v1` Ingress、
RuntimeClass）要求 Kubernetes ≥ 1.21。已实跑过的组合：k3s v1.36.2 + helm 3.21.3 +
containerd。

**② RWX（ReadWriteMany）StorageClass——必须先确认存在**

`monolith` 与 `engine-runner` 共用同一个卷传递扫描包和检测结果。`kubectl get sc` 不显示
访问模式，唯一可靠的确认方式是真建一个 RWX PVC 看它绑不绑。**要探测的是你打算用的那个
StorageClass，不是集群默认那个**——RWX 的 class 通常恰恰不是默认（默认往往是本地盘）：

```bash
NS=<你要装进去的 namespace>      # 不要用一个可能已有系统在跑的 namespace
SC=<你打算给 blobstore 用的 StorageClass>
kubectl create namespace "$NS"
kubectl -n "$NS" apply -f - <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: rwx-probe
spec:
  accessModes: [ReadWriteMany]
  storageClassName: $SC
  resources:
    requests:
      storage: 1Gi
EOF
kubectl -n "$NS" get pvc rwx-probe -w      # 必须变成 Bound
kubectl -n "$NS" describe pvc rwx-probe    # Pending 时看这里的 Events，别只看状态
kubectl -n "$NS" delete pvc rwx-probe
```

⚠ **`Pending` 本身不等于"没有 RWX"，要看 Events 里的原因**（实测于 k3s v1.36.2）：

- `waiting for first consumer to be created before binding` —— 这是
  `volumeBindingMode: WaitForFirstConsumer` 的正常表现，还没有结论。这类 class 必须再
  起一个挂载它的 pod 才会真正去分配。**只看"一直 Pending"会把一个好的 class 判成坏的。**
- `failed to provision volume with StorageClass "local-path": NodePath only supports
  ReadWriteOnce and ReadWriteOncePod` —— 这才是"没有 RWX"的确认。

k3s 默认的 `local-path`、hostPath、以及绝大多数块存储都只有 RWO。需要 NFS / CephFS /
Longhorn(RWX) 之类的 provisioner。RWX 的 class 不是集群默认时，安装时加
`--set persistence.blobstore.storageClass=<名字>`。

⚠ **NFS 后端还要确认一件事：导出必须尊重客户端传来的附加组（supplementary groups）。**
两个 Deployment 以不同 uid（10001 / 10002）跑，靠共享的 `fsGroup: 10000` 同时写这个卷。
Debian/Ubuntu 的 `/etc/nfs.conf` 默认带 `[mountd] manage-gids=y`，那会让服务端用**自己
的** `/etc/passwd` 反查用户所属组、丢弃客户端传来的组列表——实测结果是 pod 对一个
`drwxrwsr-x root:10000` 的目录 `Permission denied`，而 `ls -l` 看上去完全正常。企业的 NFS
若开着 manage-gids，需要另行安排（关掉它，或让导出以 `all_squash` 映射到一个固定 uid）。

⚠ 关键：**两个 pod 不共用同一个卷时，系统不会报任何错**——所有 pod 都 Running、健康检查
全绿、日志干净，扫描永远停在 `running`。这就是 §6.8 第一条要处理的现象。

**③ gVisor RuntimeClass**

```bash
kubectl get runtimeclass
```

`engine-runner` 默认带 `runtimeClassName: gvisor`（不可信 Skill 内容在这里被解析）。
集群里没有这个 RuntimeClass 时，engine-runner 的 pod **一个都不会被创建**——
`kubectl get pods` 里干脆看不到它们，错误只出现在 ReplicaSet 的事件里。

没有 gVisor 又必须先跑起来：`--set runtimeClass.engineRunner=""`。
这会让不可信内容退回普通容器隔离运行，是一次明确的安全降级，请当成决定来做，不是配置细节。

⚠ **这条规则不止对这个 chart 成立。** `deploy/vm/60-engine-runner.yaml`——内部 dev VM
（10.211.55.10）用的原始清单，不走这个 chart，是它的 dev/test 对照版本，`deploy/vm/` 目录
下其余文件同理——同样不设 `runtimeClassName`，原因相同：那台节点上没有 `gvisor`
RuntimeClass（`kubectl get runtimeclass` 实测确认过，见该文件自己的注释）。如果要在那个
namespace 上装 `deploy/helm/skillscan-kyverno-policies`，必须用
`--set gvisorSandboxRuntimeClass.enabled=false` 渲染——默认值（`true`）在那里不会强制任何
真实的安全边界（没有 gVisor 可以要求），只会挡住这个 Deployment 之后的每一次
`kubectl apply`/`rollout restart`。

**④ 镜像是 side-load 到每个节点的，不是从 registry 拉的**

**每一个可能调度 skillscan pod 的节点都要各导入一次。** 少导一个节点，被调度到那里的
pod 就是 `ImagePullBackOff`，而且没有 registry 可以兜底。

**⑤ 集群要有多少空余 CPU**

默认副本数（monolith 1 + engine-runner 3 + web 2 + mysql + redis）的 **requests 合计约
2.2 core**，还不含迁移 Job 的 0.1。节点余量不够时的表现是 pod 卡在 `Pending`，事件里写
`0/N nodes are available: N Insufficient cpu`——这条不在 §6.8 的现象表里，因为它不是本
系统的故障，但第一次装最容易撞上。余量不够就调
`--set replicaCount.engineRunner=1 --set replicaCount.web=1`（都是无状态的，见 §6.5）。

**⑥ namespace 选哪个**

chart 装进任何 namespace 都可以（模板与默认值里已无 namespace 硬编码），
`deploy/networkpolicy/*.yaml` 也不再写死 namespace（用 `kubectl apply -n <你的 namespace>`
应用）。**`deploy/kyverno/pod-security-baseline.yaml`、`require-signed-images.yaml` 与
`require-gvisor-sandbox-runtimeclass.yaml` 这三条同样的问题已分两批（Task 10、Task 11）
修掉**：`deploy/kyverno/` 目录已不存在，三条都不再是可以直接 `kubectl apply -f` 的静态
YAML，全部搬进了 `deploy/helm/skillscan-kyverno-policies/`，match 的 namespace 从
`.Release.Namespace` 渲染而来，用配套脚本生成再 apply：

```bash
deploy/helm/skillscan-kyverno-policies/render.sh -n <你的 namespace> \
    | kubectl apply -f -
```

`-n` 必须和 `helm install` 装 skillscan 本体时用的 namespace 完全一致，否则准入保护的是
另一个 namespace。忘记传 `-n` 时脚本直接报错退出，不会用错误的默认值悄悄渲染。

`pod-security-baseline` 与 `require-gvisor-sandbox-runtimeclass` 默认开启，随上面这条命令
一起渲染。`require-signed-images` 是可选项，要签名校验才加 `-k <你自己的 cosign 公钥文件>`
——脚本会先用 `openssl pkey -pubin -noout` 校验这个文件是不是真的能解析成公钥，解析不出来
直接拒绝渲染，不会像旧版那样让一个占位符公钥被 Kyverno 接受、然后在准入时拒光每一个镜像。
省略 `-k` 就只渲染前两条。

渲染完 apply 之后，`kubectl get clusterpolicy` 应能看到 READY True，再用一个故意违规的 pod
确认它真的会被拒（见 §6.8 ⑦）。

**⑦ 要传进隔离网的东西（三份，缺一不可）**

1. 离线镜像包目录（§6.2 产出，几百 MB）
2. 本仓库源码——chart 在 `deploy/helm/skillscan`，离线包里**不含** chart
3. `deploy/networkpolicy/`、`deploy/helm/skillscan-kyverno-policies/`
   （如果要用，随源码一起——都已在 1 份源码里，不是额外的传输动作）

### 6.2 有网侧：做离线包

```bash
bash scripts/build_offline_bundle.sh
```

脚本会构建 `monolith` / `engine-runner` / `web` 三个镜像，再收集 chart 引用的
`mysql:8.0` 与 `redis:7-alpine`（这两个在隔离网里同样拉不到，少带就会让数据库起不来），
一共 **5 个**镜像打成一个目录：

```
dist/skillscan-offline-0.1.0-<arch>/
  images.tar                 5 个镜像，一次 docker save
  manifest.txt               镜像引用 + 出处（chart 版本 / 平台 / 构建时间 / 源 commit）
  SHA256SUMS                 覆盖上面两个 + 下面这个脚本
  import_offline_bundle.sh   隔离侧执行的就是它
```

要点：

- 镜像名不是硬编码的，是从 `deploy/helm/skillscan/values.yaml` 读出来的，所以包里的名字
  不可能和 chart 要的名字对不上。
- 内网 pip/go/npm 镜像源通过环境变量传入（非空才会传给 `docker build`）：
  `PIP_INDEX_URL`、`GOPROXY`、`NPM_CONFIG_REGISTRY`。
- 构建机的架构决定包的架构。arm64 的包导到 amd64 节点上，容器会以
  `exec format error` 起不来——导入脚本会在导之前就拒绝，不会让你走到那一步。
- `--tag X` 可以改 tag，但那样安装时**必须**加 `--set image.tag=X`，脚本结束时会把这句话
  打出来。默认（tag `0.1.0`、registry 空）不需要任何 `--set`。

### 6.3 隔离侧：导入镜像

把**整个目录**传过去（四个文件都要，`SHA256SUMS` 是让这次传输可验证的东西），然后在
**每一个**节点上以 root 执行：

```bash
bash skillscan-offline-0.1.0-<arch>/import_offline_bundle.sh
```

它按顺序做：核对包与本节点的架构 → 校验 sha256（不匹配直接拒绝导入，不是警告）→ 找到
containerd CLI（`k3s ctr` / `ctr` / rke2 自带的）→ 导入 → **核对 containerd 里注册的
镜像名就是 chart 会向 kubelet 要的那些**。任何一步失败都会中止并说明原因。

- 不是 root：需要一个同时覆盖 `ctr images import` 与 `ctr images ls` 的 sudo 规则，
  否则脚本会在导入**之前**停下（不能核对就不导，这是有意的）。
- containerd 的 socket 位置不标准时：`--ctr 'ctr --address /run/containerd/containerd.sock'`。

### 6.4 values.yaml：必须先决定的项

以下每一项都是一个决定，默认值**不能**假定适用于你的集群。用 `-f my-values.yaml` 或
`--set` 覆盖。

1. **`persistence.blobstore.storageClass`** —— 留空用集群默认。默认 StorageClass 不是
   RWX 的话必须显式指定（见 §6.1②）。指定错了的表现是 PVC 一直 `Pending`。
2. **`runtimeClass.engineRunner`**（默认 `gvisor`）—— 集群没有这个 RuntimeClass 就必须
   置空，否则 engine-runner 的 pod 不会被创建（见 §6.1③）。
3. **`localAccounts.seed`**（默认空）—— 第一个管理员账号。`config.localAuthEnabled`
   为 `true`（默认）而这里是空的话，**渲染阶段就会失败并告诉你该做什么**，不会装出一个
   谁都登不进去的系统。怎么生成口令哈希见 §6.9。用外部 IdP 时才改成
   `--set config.localAuthEnabled=false`。
4. **`config.vaultAddr`**（默认空）—— chart 不安装 Vault，判定结论的签名由它提供。
   **空值表示退回 `LocalDevSigner`，签出来的结论不可信**——生产部署必须指向真实的内网
   Vault。（这一项以前的默认值是一个占位符 FQDN，那会让 monolith 在启动时直接崩溃，
   见下面的 ⚠。）
5. **`config.vllmBaseUrl` / `config.osvSource` / `config.marketplaceApiBaseUrl`**
   （默认 空 / `offline` / 空）—— 分别是内网 LLM 端点、OSV 镜像源、skill 市场。
   默认值的含义是"这个集成关着"：`vllmBaseUrl` 为空时 skillspector 以 `use_llm=False`
   运行（另外三个引擎不受影响），`osvSource=offline` 是 osv-scanner 自己的隔离网模式。
   要用就填**内网**地址。`config.reconciliationPollEnabled` 默认 `true`，没有对接市场时
   关掉（`--set config.reconciliationPollEnabled=false`）。
6. **`ingress.*`**（默认 `enabled: false`）—— 需要从集群外访问控制台才打开，且必须给
   `ingress.host`。开 TLS 时 `ingress.tls.secretName` 必须指向**已经存在于该 namespace 的**
   TLS Secret；chart 不生成、不自签、不给默认证书，缺了会直接让渲染失败。
   不开 Ingress 时用 `kubectl port-forward` 访问（见 §6.6）。
   ⚠ **会话 cookie 带 `Secure` 标志**，所以纯 HTTP 访问是登不进去的：登录接口会返回
   `200 {"status":"ok"}`，但客户端会丢掉 cookie，之后每个请求都是未登录。浏览器对
   `http://localhost` 有例外，所以 `kubectl port-forward` + 浏览器可以用；`curl` 没有这个
   例外（见 §6.7 第三步）。正式访问请走 TLS。

⚠ 上面第 4、5 条的默认值在 2026-07-29 之前是**占位符 FQDN**（`vllm.skillscan.svc...` 等）。
`require_internal_endpoint` 对解析失败是 fail-closed 的，解析不出来和公网地址是同一个结论，
所以那些占位符不是"等着被替换的惰性值"，而是必定的启动崩溃：monolith 与每个 engine-runner
都在 `CrashLoopBackOff`，日志是
`'vllm.skillscan.svc.cluster.local' does not resolve to an internal/private address`。
现在默认值是"关闭"，填错了仍然 fail-closed。

### 6.5 values.yaml：保持默认即可的项

这些不是"暂时不用管"，是**照默认装就是对的**——离线包就是按这些默认值打的。

| 项 | 默认 | 说明 |
|---|---|---|
| `image.registry` | `""` | 空值就是隔离网的正确配置：裸镜像名，直接命中节点上 side-load 的镜像。企业确有内部 registry 时才填 |
| `image.tag` | `0.1.0` | 与离线包一致。除非打包时用了 `--tag` |
| `image.pullPolicy` | `IfNotPresent` | 保证不会向不存在的网络发起拉取 |
| `mysql.enabled` / `redis.enabled` | `true` | chart 自带 MySQL 8 + Redis 7，是"一条命令装出可用系统"的前提。改成 `false` 走外部实例的路径本里程碑**未验证** |
| `replicaCount.monolith` | `1` | 不要调大：SAML 重放保护是进程内状态，多副本会静默失效（MAINTENANCE_GUIDE §3.3） |
| `replicaCount.engineRunner` / `.web` | `3` / `2` | 按负载调，无隐含约束 |
| `resources.*` | 见文件 | 每个容器都必须有 limits（Kyverno `pod-security-baseline` 会在准入处拒绝没有的） |
| `persistence.*.size` | 20Gi / 50Gi | 按容量调 |
| `persistence.blobstore.mountPath` | `/var/lib/skillscan/blobstore` | **单一真相源**，同时被 ConfigMap 和两个 Deployment 引用。改它是安全的，改成两处不一致才是灾难 |
| `config.mysqlHost` / `config.redisUrl` / `config.mysqlDatabase` | `mysql` / `redis://redis:6379/0` / `skillscan` | 指向 chart 自己装的实例，用**裸服务名**跟着 release 走到任何 namespace。不要改成 FQDN |
| `secrets.create` | `true` | chart 自动生成随机口令并在 `helm upgrade` 时保留（`lookup` + `resource-policy: keep`）。企业用 Vault 注入时才改 `false` 并自行创建 `secretRefs.name` 那个 Secret |
| `secretRefs.keys` | 见文件 | chart 为其中每个 key 生成一个随机口令，与代码里实际消费的 env 一一对应，增删都会造成静默失效。`SKILLSCAN_LOCAL_ACCOUNTS_JSON` **不在**这个表里（它是 JSON 不是口令，见 `localAccounts.seed`） |
| `web.*` | 8080 / 80 / 64m | 容器端口刻意不是 80（非 root 用户）；Service 对外仍是 80 |
| `engineRunner.readyPort` | `8080` | 与容器端口、readinessProbe 三处同源，不要单独改 |
| `config.minioEndpoint` | `""` | **死配置**，代码里没有任何消费方，设了没有效果 |
| `networkPolicy.enabled` | `true` | **死配置**，chart 里没有任何模板读它。NetworkPolicy 要手工 `kubectl apply -n <你的 namespace> -f deploy/networkpolicy/`（先读 §6.8 ⑫） |
| `localAccounts.seed` | `[]` | **不是默认值，是必填项**——见 §6.4 第 3 条与 §6.9 |
| `engineRunner.tmpSizeLimit` | `1Gi` | engine-runner 的可写 `/tmp`（emptyDir）上限，引擎在这里解包。要大于你允许上传的最大包 |

### 6.6 安装

```bash
helm install skillscan deploy/helm/skillscan \
  -n skillscan --create-namespace \
  -f my-values.yaml \
  --timeout 15m
```

`--timeout 15m`：安装会等一个 post-install 的迁移 Job 跑完，而 MySQL 第一次启动很慢，
前一两个 Job pod 因 `Connection refused` 失败是正常的（`backoffLimit: 6` 就是为此存在），
默认 5 分钟可能不够。

#### 6.6.1 `my-values.yaml` 最少长什么样

至少要有第一个管理员账号（§6.4 第 3 条），没有它 helm 在渲染阶段就会停下：

```yaml
localAccounts:
  seed:
    - username: admin
      password_hash: "scrypt$<salt-hex>$<digest-hex>"   # 生成方法见 6.9
      role: admin

# 下面这些按 6.1/6.4 的实际情况填
persistence:
  blobstore:
    storageClass: <你的 RWX class>
# runtimeClass:
#   engineRunner: ""        # 集群没有 gVisor 时（安全降级，见 6.1③）
# config:
#   vaultAddr: http://vault.<内网>:8200
#   reconciliationPollEnabled: false
```

（2026-07-29 之前这一节写的是安装后要补两条 `kubectl set env`——那两个缺口
`SKILLSCAN_GATE_POLICY_PATH` 与 `SKILLSCAN_WORKER_ENABLED` 已经在 chart 里修好，
现在**不需要**任何安装后的手工 `kubectl`。）

### 6.7 装完的三步验证

**第一步：pod 全部就绪**

```bash
kubectl -n skillscan get pods
```

期望：`skillscan-mysql` / `skillscan-redis` / `skillscan-monolith` /
`skillscan-engine-runner`（3 个）/ `skillscan-web`（2 个）全部 `Running` 且 READY 满格。
任何一个不满足，直接跳到 §6.8 按现象查。

**第二步：迁移 Job 的自验证**

迁移 Job 不只是跑 `alembic upgrade head` 和建账号，跑完还会**回头核对**：数据库记录的
schema 版本是否等于代码里的 head、`policies/grants/manifest.yaml` 里每一个 `svc_*` 账号
是否真的存在。对不上就让 Job 失败，Job 失败就让 `helm install` 失败。

```bash
# ⚠ 不要用 `kubectl logs job/skillscan-migrate-1`：Job 通常有多个 pod（前几个在等 MySQL
# 起来），那条命令挑到的往往是失败的那个，你会看到一大段 "Can't connect to MySQL server"
# 的 traceback 并以为迁移失败了。要显式挑成功的那个 pod：
POD=$(kubectl -n skillscan get pod -l job-name=skillscan-migrate-1 \
      --field-selector=status.phase=Succeeded -o name | head -1)
kubectl -n skillscan logs "$POD"
```

（`1` 是 helm 的 revision，第二次 `helm upgrade` 就是 `skillscan-migrate-2`。）

期望**最后一行**正好是：

```
migration verified: schema at head, all module users present
```

失败长这样，两条都是自验证发现的、不是执行本身报的错：

```
!!! schema at <实际版本>, repo head is <期望版本>
!!! module users missing: svc_xxx svc_yyy
```

前面几个 Job pod 因 MySQL 还没起来而 `Connection refused` 属正常，看最后成功的那个。

**第三步：提交一个包，看它跑到底**

先起一条通道（没开 Ingress 时）。`port-forward` 是前台命令，让它占着一个终端，
下面的操作另开一个终端做：

```bash
kubectl -n skillscan port-forward svc/skillscan-web 8080:80
```

浏览器打开 `http://localhost:8080` 就是控制台，用 §6.4 第 3 条里那个账号登录。

⚠ **用 `curl` 走同样的流程需要一个额外动作。** 会话 cookie 与 CSRF cookie 都带 `Secure`，
`curl` 在 `http://` 下会**直接丢弃**它们：登录返回 `200 {"status":"ok"}`，而
`-c /tmp/ss.jar` 存下来的 cookie 罐是空的，后面每个请求都是未登录（浏览器对
`http://localhost` 有例外，`curl` 没有）。要么走 TLS，要么像下面这样从响应头里把值取出来
自己带上：

```bash
BASE=http://localhost:8080

# 1. 登录，从响应头（不是 cookie 罐）里取会话与 CSRF
H=$(curl -sS -D - -o /dev/null -X POST "$BASE/v1/admin/local/login" \
      -H 'Content-Type: application/json' \
      -d '{"username":"admin","password":"<你设的口令>"}')
SESS=$(printf '%s' "$H" | sed -n 's/.*skillscan_local_session=\([^;]*\).*/\1/p')
CSRF=$(printf '%s' "$H" | sed -n 's/.*csrf_token=\([^;]*\).*/\1/p')
COOKIE="skillscan_local_session=$SESS; csrf_token=$CSRF"

# 2. 提交一个 tar 包（字段名固定是 package）
curl -sS -b "$COOKIE" -H "X-CSRF-Token: $CSRF" \
  -F package=@my-skill.tar "$BASE/v1/scans"
# -> {"scan_id":"..."}

# 3. 轮询
curl -sS -b "$COOKIE" "$BASE/v1/scans/<scan_id>"
```

⚠ 同一个包内容重复提交会拿回**同一个 scan_id**（按内容哈希去重），看起来像"秒出结果"。
要真正验证一次完整流程，改一个字节再打包。

`state` 的实际取值是 `queued` → `running` → `scored` → `decided`（失败是 `failed`），
**不是** `PENDING/RUNNING/COMPLETED`。看到 `decided` 且有 `verdict` 就是走通了。
停在 `queued` 或 `running` 不动，见 §6.8 第一条和第二条。

### 6.8 故障速查（按现象查，不按组件查）

#### ① 所有 pod 都 Running，扫描一直停在 `running` 不动 —— blobstore 没有共享

这是本系统最危险的故障：`monolith` 写扫描包、`engine-runner` 读它并写回检测结果、
`monolith` 再读结果。两边看的不是同一个卷时**什么都不会报错**——pod 全 Running、
`/healthz` 200、日志干净，扫描就是永远不结束。

**确认（只认这一条 ERROR 日志）：**

```bash
kubectl -n skillscan logs deploy/skillscan-monolith | grep 'blobstore not shared'
kubectl -n skillscan logs deploy/skillscan-engine-runner | grep 'blobstore not shared'
```

⚠ **不要去找"共享正常"的确认行——它不会出现。** 本仓库没有任何地方配置日志级别，
root logger 默认 WARNING，所有 INFO 都被丢弃，包括那条 `blobstore sharing confirmed`。
判据是**那条 ERROR 在不在**，不是有没有看到成功提示。

**第二个确认点**（自检结果也进了 `/readyz`）：

```bash
kubectl -n skillscan port-forward deploy/skillscan-monolith 8000:8000
curl -s localhost:8000/readyz
# 坏的时候：503 {"status":"not_ready","checks":{"redis":true,"orchestration_db":true,
#                "blobstore_shared":false}}
```

`redis` 和 `orchestration_db` 仍是 `true`，所以这个输出直接指出了是哪一项坏了。
（monolith 镜像里**没有 curl**，所以这里用 `port-forward` 而不是 `kubectl exec ... curl`。
`engine-runner` 的 `/readyz` 只返回 `{"status": ...}`，没有 `checks` 明细，看 monolith 那个。）

注：pod 刚起来的 60 秒是宽限期，这期间不算故障（两个 pod 不会同时就绪）。

**排查顺序：**

```bash
# 1. PVC 真的是 RWX 且 Bound 吗
kubectl -n skillscan get pvc skillscan-blobstore -o \
  jsonpath='{.status.phase} {.spec.accessModes}{"\n"}'

# 2. 两个 pod 挂的是不是同一个 claim、同一个路径
kubectl -n skillscan get deploy skillscan-monolith skillscan-engine-runner -o \
  jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.template.spec.volumes[*].persistentVolumeClaim.claimName}{" "}{.spec.template.spec.containers[0].volumeMounts[*].mountPath}{"\n"}{end}'

# 3. 直接验一次：一边写，另一边读
kubectl -n skillscan exec deploy/skillscan-monolith -- \
  sh -c 'echo ok > /var/lib/skillscan/blobstore/manual-check'
kubectl -n skillscan exec deploy/skillscan-engine-runner -- \
  cat /var/lib/skillscan/blobstore/manual-check      # 看不到就是没共享
```

最常见的真实原因：provisioner 接受了 `ReadWriteMany` 但底层并不真共享，于是两个 pod 被
调度到不同节点就分裂了。修法是换一个真正支持 RWX 的 StorageClass 重建 PVC——
`persistence.blobstore.mountPath` 是单一真相源，路径不一致这种错在 chart 里已经不可能了。

#### ② 扫描提交后一直停在 `queued`，从来不进 `running`

后台 worker 没开（chart 默认是开的，被 values 覆盖掉才会这样）。确认：

```bash
kubectl -n skillscan get cm skillscan-config -o jsonpath='{.data.SKILLSCAN_WORKER_ENABLED}{"\n"}'
# 期望 "true"；是 "false" 就是 config.workerEnabled 被关掉了
```

#### ②b 所有 pod Running、扫描停在 `running`，但**不是** blobstore 的问题

先按 ① 确认过 `blobstore not shared` 那条 ERROR **没有**出现，再看 engine-runner 的日志
本身。实测见过的一种：

```
FileNotFoundError: [Errno 2] No usable temporary directory found in
['/tmp', '/var/tmp', '/usr/tmp', '/app']
```

engine-runner 的根文件系统是只读的，每个引擎都要一个可写的 `/tmp` 解包。chart 挂了一个
emptyDir 在 `/tmp`（`engineRunner.tmpSizeLimit`）；被删掉或被改小到装不下一个包时，
每一次 tick 都抛这个异常，而 worker 会**故意不 ack、等待重投**——所以 pod 一直 Running、
Ready，日志刷同一段 traceback，扫描永远不结束。

```bash
kubectl -n skillscan logs deploy/skillscan-engine-runner --tail=50 | grep -c "sandbox engine tick failed"
```

#### ③ PVC 一直 `Pending`

```bash
kubectl -n skillscan describe pvc skillscan-blobstore
```

事件里通常是 `no persistent volumes available` 或 provisioner 报不支持的 accessMode。
原因就是集群没有 RWX StorageClass（§6.1②）。这是**刻意让它在这里失败**的——PVC 绑不上是
一个看得懂的错误，而带着一个假的共享卷装上去则完全不可诊断。

`skillscan-mysql-data` 是 RWO，一般不会卡在这里；它卡住就是普通的存储容量/provisioner 问题。

#### ④ pod `ImagePullBackOff` / `ErrImageNeverPull`

三种可能，按顺序排：

```bash
kubectl -n skillscan describe pod <pod> | grep -A3 Events   # 看它到底在要哪个镜像名
```

1. **这个节点没导过镜像。** side-load 是节点本地的。确认 pod 落在哪个节点
   （`kubectl get pod -o wide`），在那个节点上再跑一次导入脚本。
2. **tag 不匹配。** 打包时用了 `--tag X`，安装时没加 `--set image.tag=X`。
   包里的 `manifest.txt` 有 `image_tag` 一行，与 `values.yaml` 的 `image.tag` 比对。
3. **`image.registry` 被填了但节点上是裸名镜像**（或反过来）。离线包的正确配置是留空。

#### ⑤ `helm install` 失败：`post-install hooks failed` / `timed out waiting for the condition`

迁移 Job 失败了。helm 会把整个 install 判为失败，这是设计如此。

```bash
kubectl -n skillscan get jobs
kubectl -n skillscan logs job/skillscan-migrate-1 --tail=50
```

- 全是 `Connection refused` 且重试用尽 → MySQL 起得太慢或根本没起来，先看
  `kubectl -n skillscan logs deploy/skillscan-mysql`；确认没问题后加大 `--timeout` 重来。
- `!!! schema at ... / !!! module users missing: ...` → 是自验证抓到了真实的不一致，
  **不要绕过它**，这两条检查各自对应过一次真实事故（迁移"跑过了"但部署库其实缺列/缺账号，
  症状是应用正常启动、只有写入静默失败）。

#### ⑥ engine-runner 一个 pod 都没有被创建

`kubectl get pods` 里完全看不到 engine-runner，Deployment 显示 `0/3`：

```bash
kubectl -n skillscan describe deploy skillscan-engine-runner | tail -20
kubectl -n skillscan get events --sort-by=.lastTimestamp | tail
```

看到 `RuntimeClass "gvisor" not found` 就是 §6.1③。装 gVisor，或
`--set runtimeClass.engineRunner=""`（安全降级，见该节）。

#### ⑦ pod 被准入策略拒绝

本项目自带三条 ClusterPolicy，**都是 `Enforce`**。装之前先决定要不要 apply：

- `pod-security-baseline`（`deploy/helm/skillscan-kyverno-policies/`）要求非特权 / 非 root /
  每个容器都有 cpu+memory limits。chart 的默认值满足这三条。自己调 `resources` 时不要把
  limits 删掉。用 `render.sh -n <你的 namespace> | kubectl apply -f -` 装（namespace 已
  参数化，不再只 match `skillscan`——见 §6.1⑥）。
- **`require-signed-images`（同一个 chart，`-k` 才会渲染）会拒绝离线包里的每一个镜像。**
  它对 `imageReferences: "*"` 要求 cosign 签名，而离线包 side-load 的是未签名的裸名镜像。
  **不加 `-k` 就不会渲染这一条**；加了 `-k` 但给的不是真的能被企业自己 cosign 密钥验证的
  镜像，一样会拒光每一个镜像——这是设计如此（签名是真实的安全要求），不是配置错误。
  `render.sh` 会在渲染前用 `openssl pkey -pubin -noout` 校验你给的公钥文件本身能否解析，
  但不校验、也不可能校验"镜像是否真被这把私钥签过"——那是 admission 时才能验证的事。
- `require-gvisor-sandbox-runtimeclass`（同一个 chart，默认开启，随
  `render.sh -n <你的 namespace>` 一起渲染，namespace 同样已参数化——不再只
  match `skillscan`）要求 engine-runner 必须是 `gvisor`——与 §6.1③ 的
  `--set runtimeClass.engineRunner=""` 直接冲突，两者只能取一。
- 用 `deploy/vm/` 的原始清单（不是这个 chart）时同样适用：`60-engine-runner.yaml` 不设
  `runtimeClassName`，若对那个 namespace 装 `require-gvisor-sandbox-runtimeclass` 时保持
  默认（`gvisorSandboxRuntimeClass.enabled=true`），会拒绝它——渲染时同样要加
  `--set gvisorSandboxRuntimeClass.enabled=false`，见 §6.1③ 的补充说明。

拒绝时报错会指名具体是哪条规则：

```bash
kubectl -n skillscan get events --sort-by=.lastTimestamp | grep -i policy
```

#### ⑧ web pod `CrashLoopBackOff`，日志 `host not found in upstream "skillscan-monolith"`

已知且会自愈。nginx 对字面量 upstream 主机名只在配置加载时解析一次，解析不到就拒绝启动；
web pod 抢在 Service 的 DNS 记录传播之前起来就会撞上。**下一次重启即恢复**，不需要处理。
反复不恢复才去查 CoreDNS。

#### ⑨ 控制台页面能打开，但每一个 API 调用都 502

控制台与 `/v1` 必须同源（会话/CSRF cookie 是 `SameSite=Strict`）。chart 用一个 ConfigMap
（`skillscan-web-nginx`）覆盖镜像里那份写给 docker-compose 的 nginx.conf。确认覆盖生效：

```bash
kubectl -n skillscan exec deploy/skillscan-web -- grep proxy_pass /etc/nginx/nginx.conf
# 期望：proxy_pass http://skillscan-monolith:80;
```

看到 `monolith:8000` 说明挂载没生效（那是 compose 的服务名，在 K8s 里不存在）。
另：改了这个 ConfigMap 之后要手工 `kubectl -n skillscan rollout restart deploy/skillscan-web`，
chart 没有给它加 checksum annotation。

**第二种可能原因（实测于验证阶段）：`engine-runner` 被缩到了 0 副本。** 上面这条 nginx
ConfigMap 检查完全正常时，问题可能根本不在 web 这一层——`monolith` 的 `/readyz` 用与
§6.8①相同的共享探针机制确认 engine-runner 这个对等端还活着，探针时间戳超过
`SHARE_PROBE_TTL_S`（300 秒）没有刷新就判定"看不到对方"，于是 `monolith` 自己
fail-closed 返回 503。这是设计如此——宁可控制台整体不可用，也不要一个假装能扫描的系统，
和 §6.8①的 `blobstore_shared` 检查是同一个机制——但**从"缩容一个后台 Deployment"到
"整个控制台打不开"之间没有任何提示**：503 的 `/readyz` 让 monolith 的 pod 失去
Service 的 ready endpoint，`skillscan-web` 代理到一个没有健康后端的 Service，于是每一个
API 调用都 502，即使 nginx 配置本身毫无问题。确认与恢复：

```bash
kubectl -n skillscan get deploy skillscan-engine-runner       # READY 是不是 0/N
kubectl -n skillscan port-forward deploy/skillscan-monolith 8000:8000
curl -s localhost:8000/readyz | grep blobstore_shared          # false 就是这一种
kubectl -n skillscan scale deploy/skillscan-engine-runner --replicas=1
```

调回至少 1 副本后 `monolith` 会在下一次探针周期自愈，不需要重启（实测确认）。

#### ⑩ monolith `CrashLoopBackOff`，日志 `cannot read <某个策略文件>`

fail-closed 行为，不是 bug——策略文件读不到时绝不退回空策略。chart 用三个环境变量把
路径显式指到镜像里的真实位置（代码里的默认值是按源码树算的，在容器里会落到
`/app/.venv/lib/python3.12/...`，那里什么都没有）：

```bash
kubectl -n skillscan get cm skillscan-config -o jsonpath='{.data.SKILLSCAN_GATE_POLICY_PATH}{"\n"}{.data.SKILLSCAN_RBAC_GROUP_ROLE_MAP_PATH}{"\n"}{.data.SKILLSCAN_ENGINES_LOCK_PATH}{"\n"}'
# 期望：/app/policies/gate/v1.yaml
#       /app/policies/rbac/group_role_map.yaml
#       /app/vendor/engines.lock.yaml
```

第三个是 fail-soft 的（读不到不会崩，只是控制台首页的引擎面板永远显示
`dashboard.noEngineData`，`GET /v1/reports?template=engine_coverage` 返回
`total_engines: 0, rows: []`）。

#### ⑪ 登录不了：`local auth is not configured`（404）或界面上没有任何登录方式

见 §6.9。另一种表现是**登录返回 200 但一直是未登录状态**——那不是账号问题，是
`Secure` cookie 在纯 HTTP 下被客户端丢弃，见 §6.7 第三步。

#### ⑫ apply 了 `deploy/networkpolicy/` 之后控制台打不开 / 系统各种超时

先确认你 apply 时带了 `-n <你的 namespace>`：这些文件**不再**写死 namespace，不带 `-n`
会装进当前 context 的 namespace。

`default-deny.yaml` 对 namespace 内所有 pod 默认拒绝 Ingress 和 Egress，其余文件是加在
它上面的白名单，**必须整目录一起 apply**：单独 apply default-deny（或漏掉
`mysql-ingress.yaml` / `monolith-ingress.yaml` / `web-allowlist.yaml` /
`migration-egress-allowlist.yaml` 中的任何一个）会得到这些实测症状——

- `GET /` 200 但每个 API 都 502：缺 `monolith-ingress` 或 `web-allowlist`
- monolith 重启后 `CrashLoopBackOff`，`Can't connect to MySQL server on 'mysql'`：
  缺 `mysql-ingress`。**注意它不会立刻发作**：已经在跑的 monolith 靠现有连接池活着，
  下一次重启（或下一次 `helm upgrade`）才死
- `helm upgrade` 卡住后失败、迁移 Job 反复 `Connection refused`：缺
  `migration-egress-allowlist`

回退：`kubectl -n <你的 namespace> delete -f deploy/networkpolicy/`。

kubelet 的探针流量在 k3s v1.36.2 上实测不受影响；换一个 CNI 不要假定同样成立。

（`deploy/networkpolicy/dev/` 是开发专用的出站例外，生产集群不要 apply——注意
`kubectl apply -f deploy/networkpolicy/` 不递归，默认不会带上它。）

### 6.9 第一个管理员账号

**本系统没有内置管理员账号，也没有任何默认口令**（INV-17），chart 不会替你创建一个。
这是刻意的，不是遗漏。装完之后有三条可选的登录路径，都需要你显式配置：

| 路径 | 适用 | 状态 |
|---|---|---|
| OIDC / SAML（企业 IdP） | 有 IdP 的正式部署 | 角色由 `policies/rbac/group_role_map.yaml` 的组映射决定，未匹配的组一律降级为 `submitter` |
| 本地账号（用户名口令） | 隔离网、没有 IdP | 默认关闭，见下 |
| Break-glass | IdP 挂了的应急 | 默认关闭，需要 Vault + TOTP + 二人 + 全审计，见运维指南 §4 |

隔离网部署最实际的是本地账号，chart 直接支持：`config.localAuthEnabled`（默认 `true`）
加上 `localAccounts.seed`。**不需要任何手工 `kubectl`**——种子会被写进 chart 自己管理的
Secret（`secretRefs.name`，默认 `skillscan-secrets`）。

**（1）在有 Python 的机器上生成口令哈希**（口令至少 12 位，明文永远不进配置）：

```bash
python3 - <<'EOF'
import hashlib, secrets
password = "换成你的口令"
salt = secrets.token_bytes(16)
digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
print(f"scrypt${salt.hex()}${digest.hex()}")
EOF
```

**（2）把账号写进 `my-values.yaml`**（`role` 取 `admin` / `approver` / `auditor` /
`submitter` 之一），安装时 `-f` 带上它：

```yaml
localAccounts:
  seed:
    - username: admin
      password_hash: "scrypt$<salt-hex>$<digest-hex>"
      role: admin
```

`--set-json 'localAccounts.seed=[{"username":"admin","password_hash":"scrypt$...","role":"admin"}]'`
也可以，但哈希里有 `$`，写进文件更省事。

⚠ **`config.localAuthEnabled=true` 而 `localAccounts.seed` 为空时，helm 在渲染阶段就会
报错并把上面这段告诉你**，不会装出一个没人能登录的系统。用外部 IdP 时把
`config.localAuthEnabled` 设成 `false`。

这个种子 **只在第一次启动、`local_account` 表还是空的时候**被写进数据库（"bootstrap
seed"）。之后账号以数据库为准，改 values 不再有任何效果——改密请用下面的
`reset-password` 接口。`helm uninstall` 会保留这个 Secret（`resource-policy: keep`）但
删掉数据库 PVC，所以重装后表是空的、种子会**再灌一次**。

**登录：** 控制台页面直接登录，或 `POST /v1/admin/local/login`（见 §6.7 第三步）。
连续 5 次失败会按用户名锁定 15 分钟。

**改口令 / 加账号**（都需要管理员会话 + `X-CSRF-Token` 头）：

```bash
# 改某个账号的口令（口令 ≥ 12 位）
curl -sS -b "$COOKIE" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
  -X POST "$BASE/v1/admin/accounts/<account_id>/reset-password" \
  -d '{"new_password":"新口令"}'

# 建新账号
curl -sS -b "$COOKIE" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
  -X POST "$BASE/v1/admin/accounts" \
  -d '{"username":"alice","role":"approver","initial_password":"至少十二位的口令"}'

# 列出账号（拿 account_id）
curl -sS -b "$COOKIE" "$BASE/v1/admin/accounts"
```

口令用 scrypt 加盐哈希存储，任何环节都不出现明文；没有自助改密端点，改密由管理员执行。

### 6.10 卸载与重装

```bash
helm uninstall skillscan -n skillscan
```

**会被删掉：** 两个 PVC（`skillscan-mysql-data`、`skillscan-blobstore`）——
数据库和历史扫描产物一起没。要留就先自己备份。

**会被保留：** `skillscan-secrets`（带 `helm.sh/resource-policy: keep`）。所以重装时
MySQL 会用回同一套口令去初始化一个全新的空库，是自洽的；但如果你手工删掉了这个 Secret
而 PVC 还在，新生成的 root 口令与卷里旧数据不匹配，MySQL 会起不来。要么两个都留，要么
两个都删。

**也会留下（helm 不管它们）：** 迁移 Job 与它的 pod。实测 `helm uninstall` 之后
`kubectl -n <ns> get all` 里还有一个 `job.batch/skillscan-migrate-1` 和 3 个 pod
（2 个 `Error`、1 个 `Completed`）。它们不影响重装——下一次安装的 hook 同名，
`hook-delete-policy: before-hook-creation` 会先把旧的删掉——只是看起来像残留。

**重装实测**（同一个 namespace，不删 namespace）：`helm install` 直接成功，两个 PVC 是
全新的（新的 PV，旧数据确实没了），全部 pod `Running`，重新提交一个包能跑到 `decided`。
重装就是再跑一次 §6.6，不需要任何额外步骤。

---

## 相关文档

- [`BUILD_GUIDE.md`](BUILD_GUIDE.md) — 编译指南
- [`USAGE_GUIDE.md`](USAGE_GUIDE.md) — 操作指南
- [`MAINTENANCE_GUIDE.md`](MAINTENANCE_GUIDE.md) — 运维指南
- `.env.example` — 完整环境变量模板
- `docker-compose.yml` / `scripts/one_click_dev.sh` / `scripts/one_click_deploy_docker.sh` —
  实际部署脚本本身
