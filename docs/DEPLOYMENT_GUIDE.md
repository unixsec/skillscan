# 部署指南（Deployment Guide）— skillscan

三条部署路径，按适用场景选择：

| 路径 | 适用场景 | 一键脚本 | 登录方式 |
|---|---|---|---|
| **本地开发/演示** | 开发调试、功能演示 | `scripts/one_click_dev.sh` | break-glass（脚本自带 dev 专用固定凭据） |
| **容器化生产部署** | 单机/少量 VM，无 K8s | `scripts/one_click_deploy_docker.sh` | 真实 OIDC/SAML（需在 `.env` 配置）或 break-glass |
| **Kubernetes** | 集群规模生产部署 | `deploy/helm/skillscan`（Helm chart） | 同上 |
| **Kubernetes（隔离网）** | 无外网、无 registry 的隔离集群 | `scripts/build_offline_bundle.sh` + `helm install`——**完整步骤见 §6** | 本地账号 / OIDC / SAML，需手工配置（§6.9） |

## 0. 构建期依赖与主机要求

本节是**从源码构建**（§2 的 docker-compose 一键部署、以及自建内网镜像）唯一需要读的一节：
它逐项列出构建机必须能取到的东西（基础镜像 digest、apt 包、PyPI/npm/Go 依赖源）和宿主机
必须满足的条件（版本、磁盘、CPU/内存、端口）。**照着 §0.2–§0.4 就能把内网镜像源准备齐，
不需要再去读任何一个 Dockerfile。**

**隔离网的目标机器一项都不需要**——那正是离线镜像包（§6）的意义，见 §0.1 的两列对照。

> ### 隔离网部署的唯一推荐路径：离线镜像包（§6）
>
> 面向企业隔离网交付时，**请走 §6 的离线镜像包**：有网侧
> `scripts/build_offline_bundle.sh` 打出 `dist/skillscan-offline-<tag>-<arch>/`
> （`images.tar` + `manifest.txt` + `SHA256SUMS` + `import_offline_bundle.sh`），
> 隔离侧导入镜像 + 一条 `helm install`，全程零对外连接、不需要任何 registry。
>
> **需要说清楚的一点：把仓库 clone 过去是不够的。** 2026-07-29 起五个引擎的源码已直接
> 提交进本仓库（不再是 git submodule），所以 `git clone` 确实不再需要访问 github.com 去
> 取**引擎源码**了——但这只解决了"源码从哪来"，没有解决"怎么构建"：
>
> | 构建期仍然需要联网取的东西 | 出现在哪 |
> |---|---|
> | 基础镜像（`FROM ...`） | 三个 Dockerfile 全部 |
> | `go mod download`（osv-scanner 的 **Go 依赖图**） | `services/engine_runner/Dockerfile` |
> | `apt-get`：yara 的**编译工具链**（autoconf/automake/libtool/bison/flex/gcc + libjansson-dev/libmagic-dev/libssl-dev）与运行期共享库（libjansson4/libmagic1） | `services/engine_runner/Dockerfile`、`deploy/engines/yara/Dockerfile` |
> | PyPI：`uv sync` 的项目依赖，以及 **bandit / skillspector / aig-mcp-scan 各自的依赖图**（bandit 需要 pbr、PyYAML、stevedore、rich） | `apps/monolith/Dockerfile`、`services/engine_runner/Dockerfile` |
> | npm（`npm ci`） | `web/Dockerfile` |
>
> **2026-07-29 起五个引擎全部从 `vendor/` 构建**（此前 bandit 走 PyPI、yara 走 Debian
> 源）。请注意这消除的是哪一类联网需求：**引擎自身的源码**不再需要外网，但**引擎的依赖图
> 不等于引擎的源码**——vendor 了 osv-scanner 的源码不等于 vendor 了它的 Go module，
> vendor 了 bandit 的源码不等于 vendor 了 pbr/PyYAML/stevedore/rich。上表第 2、4 行
> 正是这个区别，不要误读成"已经不需要索引源了"。
>
> 另外 bandit 的打包用 `pbr`，版本号从 **git tag** 推导，而 vendor 子树只有源码没有
> git 历史——所以构建时由 `PBR_VERSION` 从 `vendor/engines.lock.yaml` 注入。
>
> 这些都**不在**仓库里。如果隔离侧有完整的内网镜像源，可以用 `PIP_INDEX_URL`、
> `GOPROXY`、`NPM_CONFIG_REGISTRY`（三个 Dockerfile 都已参数化）在内网自建；否则
> 就走离线镜像包——**它送过去的是构建完成的镜像，不是一次构建**，隔离侧因此一个都不需要。
>
> **同一张表也适用于 §2 的 docker-compose 一键部署**：它构建的就是这三个 Dockerfile
> （2026-07-29 起包含 `engine-runner`），所以它需要的联网项与上表逐行相同。compose 侧
> 把这三个参数暴露为 `SKILLSCAN_PIP_INDEX_URL` / `SKILLSCAN_GOPROXY` /
> `SKILLSCAN_NPM_REGISTRY`。**compose 路径不是离线包，也不具备离线包的性质**——它在目标
> 机器上真做一次完整构建。
>
> committed vendor 源码要解决的是另一件事：可审计（对得上
> `vendor/engines.lock.yaml` 的 commit/tree pin）与可自建，不是替代离线包。
>
> **版本一致性是构建期强制的，不是靠注释。** 每个产出引擎二进制的 Dockerfile 都有一步
> 断言：镜像里 `yara --version` / `bandit --version` / `osv-scanner --version` 必须等于
> `vendor/engines.lock.yaml` 钉的版本，不等就构建失败（`scripts/vendor_pinned_version.sh`）。
> 这是 INV-7 的直接要求——`toolchain_digest`（以及其下的 `cache_key`）由该 lock 文件推导，
> 若镜像里的引擎与它不一致，摘要指纹的就是一套从未真正运行过的工具链。旧镜像正是如此：
> lock 记 v4.5.7、实际跑 4.2.3，而这个缺口当时只被写在一句诚实的注释里。

### 0.1 两列对照：构建机需要什么，运行机需要什么

下面每一行的两列**互不重叠**。左列是"这台机器要能构建镜像"，右列是"这台机器只要能跑起
已经构建好的镜像"。离线包（§6）交付的正是右列——所以隔离侧左列一项都不需要。

| 需要的东西 | 🔨 构建机（§2 compose / 自建内网镜像） | 📦 运行机（§6 离线包目标 / 已有镜像的集群） |
|---|:---:|:---:|
| 基础镜像 `python` / `debian` / `golang` / `node` / `uv`（§0.2） | **需要** | 不需要（已烘进镜像层） |
| 运行期镜像 `mysql:8.0` / `redis:7-alpine` / `nginx`（§0.2） | 需要（构建 web 用 nginx） | **需要**（离线包已含，无需外网） |
| apt 归档：yara 的编译工具链 11 个包（§0.3） | **需要** | 不需要 |
| apt 归档：运行期共享库 `libjansson4` / `libmagic1` 等（§0.3） | 需要 | 不需要（已装进镜像） |
| PyPI 索引：uv.lock 74 包 + 三个引擎各自的依赖图（§0.4） | **需要** | 不需要 |
| npm registry：`package-lock.json` 171 包（§0.4） | **需要** | 不需要 |
| Go module proxy：osv-scanner 292 个模块（§0.4） | **需要** | 不需要 |
| `vendor/` 源码树（五个引擎） | **需要**（`git clone` 自带，源码包/`git archive` 可能不带） | 不需要 |
| 磁盘 ≥15 GB、内存 ≥4 GB、Docker ≥20.10 + compose ≥2.0（§0.5） | **需要** | 只需运行期部分（§0.5 表末） |
| 宿主机端口 80 / 8000（§0.5） | 构建阶段不占，`up` 之后占 | **需要** |

**"vendor 了源码"不等于"vendor 了依赖图"**，这是最容易读错的一点：vendor 了
osv-scanner 的源码不等于 vendor 了它的 292 个 Go module，vendor 了 bandit 的源码不等于
vendor 了 pbr/PyYAML/stevedore/rich。上表 PyPI/npm/Go 三行就是这个区别。

### 0.2 基础镜像清单（含 digest）

内网 registry 运维照这张表 `docker pull` + `docker tag` + `docker push` 即可，不必读
Dockerfile。digest 为 **2026-07-29 在 dev VM 上实测**的 manifest index digest（多架构索引，
amd64/arm64 通用），体积为该架构**压缩后的下载字节**（`docker manifest inspect` 累加层大小）。

| 基础镜像 | 出现在 | 阶段 | Dockerfile 里的钉法 | 实测 digest | 下载体积 amd64 / arm64 |
|---|---|---|---|---|---|
| `python:3.12-slim-bookworm` | `apps/monolith/Dockerfile`、`services/engine_runner/Dockerfile` | 构建 + 运行（两个 Dockerfile 的 builder 与 final 阶段都用它） | **digest** | `sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b` | 43.3 / 43.0 MB |
| `debian:bookworm-slim` | `services/engine_runner/Dockerfile`、`deploy/engines/yara/Dockerfile` | 仅构建（`yara-builder`） | **digest** | `sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818` | 26.9 / 26.8 MB |
| `golang:1.26.4-alpine3.23` | `services/engine_runner/Dockerfile`、`deploy/engines/osv_scanner/Dockerfile` | 仅构建（`osv-builder`） | **digest** | `sha256:18b460dd17542c2ba43299a633cf6ebfc1115101509531471d7cfce1019af083` | 68.1 / 65.4 MB |
| `ghcr.io/astral-sh/uv:0.5` | `apps/monolith/Dockerfile`、`services/engine_runner/Dockerfile` | 构建 + 运行（engine-runner 的 final 阶段也 COPY 了 `uv`/`uvx`） | **digest** | `sha256:7bff3c3776ec467fc1437960f2c469d8beb30f536a6465a3350c647ccd260ec2` | 15.4 / 14.7 MB |
| `node:22-slim` | `web/Dockerfile` | 仅构建 | **digest** | `sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3` | 76.2 / 76.2 MB |
| `nginx:1.27-alpine` | `web/Dockerfile` | 构建（final 阶段）+ 运行 | **digest** | `sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10` | 20.0 / 20.8 MB |
| `mysql:8.0` | `docker-compose.yml` | 仅运行（不参与构建） | **digest** | `sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b` | 222.8 / 218.5 MB |
| `redis:7-alpine` | `docker-compose.yml` | 仅运行（不参与构建） | **digest** | `sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2` | 15.5 / 16.0 MB |

合计：**构建期 6 个镜像约 250 MB**（python + debian + golang + uv + node + nginx），
**运行期额外 2 个约 238 MB**（mysql + redis），全量约 **488 MB**（amd64 压缩）。

**✅ 2026-07-30 起八个全部 digest 钉死**，上表 digest 列就是仓库里真正写着的值——这张表
现在可以直接当内网镜像同步清单用，不需要再回去核对 Dockerfile。

在此之前只有 `golang` 一行是 digest，**而且那个 digest 已经过期**：`golang:1.26.4-alpine3.23`
这个 tag 现在解析到 `sha256:18b460dd…`，而 Dockerfile 里钉的是 `sha256:f23e8b22…`。所以
"我们钉了 digest" 这句话当时**既不完整（8 选 1）也不属实（那 1 个是旧的）**。旧 digest 仍
然能拉到（这正是 digest 钉法的价值），但它意味着构建出来的是一套没人再看的旧基础层。现已
全部重钉到当天实测值，并由 `apps/monolith/tests/test_engine_build_pins.py::
TestEveryDockerfileIsSupplyChainPinned` 守住——该测试 **glob 全部 Dockerfile**，新增第七个
Dockerfile 而忘了钉 digest 会当场失败，不依赖谁记得这张表。

**重钉之后要做什么：** tag 被上游重建时，digest 不会自己更新，构建仍然稳定地拉旧镜像（这是
想要的行为）。**主动升级基础镜像是一个显式动作**：
```bash
docker buildx imagetools inspect python:3.12-slim-bookworm --format '{{.Manifest.Digest}}'
# 把新值填回 Dockerfile，然后重新构建 + 跑一次真实扫描验证
```

### 0.3 apt 包清单（构建期 / 运行期分列）

来源 Debian **bookworm**（`deb.debian.org`）主仓库，需按目标架构（amd64/arm64）准备。
两列**没有交集**：左列是编译 yara 用的工具链，构建完就被丢弃（多阶段构建，约 250 MB 不进
最终镜像）；右列是最终镜像里真正 `ldd` 得到的共享库。

| 🔨 仅构建期（`yara-builder` 阶段，`debian:bookworm-slim`） | 📦 仅运行期（各 final 阶段） |
|---|---|
| `autoconf` `automake` `libtool` `pkg-config` `bison` `flex` `make` `gcc` | engine-runner：`ca-certificates` `libjansson4` `libmagic1` |
| `libjansson-dev` `libmagic-dev` `libssl-dev` | monolith：`ca-certificates` `default-mysql-client` |
| 另：两个 python builder 阶段各装一个 `ca-certificates` | web：**无**（`node:22-slim` / `nginx:1.27-alpine` 都不跑 apt） |

几个不能省的理由，都是实测踩出来的而不是抄的：

- `bison` / `flex` **必须有**：`./bootstrap.sh`（`autoreconf --force`）会重新生成
  `libyara/lexer.c`，缺了会以 `flex: command not found` 失败。
- `libjansson-dev` / `libmagic-dev` 对应 `--enable-cuckoo --enable-magic`，是为了与旧的
  Debian 版 yara 4.2.3 模块集持平；缺了不会报错，只会让某条 `import "magic"` 的规则永远
  不命中。
- `libssl-dev` 让 yara 的 `hash` 模块（openssl）保持开启。
- 运行期只需要 `libjansson4` / `libmagic1`：yara 的 CLI 已把 libyara 静态链进去了
  （`--disable-shared`），所以**不需要** `libyara9`。
- `default-mysql-client` 只有 monolith 镜像需要——同一个镜像兼作 `migrate` 一次性容器，
  迁移后的自校验查询要用它。

#### apt 为什么**没有**参数化（明确决定，2026-07-30）

PyPI / npm / Go 三个源都有重定向变量（§0.4），apt **没有**，所以隔离网自建目前仍需改
Dockerfile 或换基础镜像。**评估结论是不加这个变量**，理由如下——这不是遗漏，是取舍：

- **加了会重建刚刚修掉的那类缺陷。** 参数化的做法是 `ARG APT_MIRROR` + 一句 `sed` 改写
  `/etc/apt/sources.list.d/debian.sources`。上游一改文件布局（bookworm 已经从
  `sources.list` 换成 deb822 格式的 `.sources` 一次了），那句 sed 就**静默无操作**，构建
  照常成功、照常走 `deb.debian.org`——正好是 §0.4 那个"变量看起来配好了其实没生效"的失败
  模式，而这次连报错都不会有。alpine 还得再来一套（`/etc/apk/repositories`）。
- **这里没有会骗人的旋钮。** `PIP_INDEX_URL` 的问题在于它**存在**、看起来管用、留空却悄悄
  走公网；apt 根本没有这个变量，是一个诚实的"没有"。补一个不可验证的旋钮，比没有更糟。
- **验不了。** 本环境没有内网 Debian/Alpine 镜像源，`APT_MIRROR` 这条路径无法真跑一次，
  只能靠读代码判断"应该能行"——这个项目已经吃过多次这种亏。

**那真隔离网怎么办**（两条都是实际可行的，不是把问题推走）：

1. **走离线镜像包（§6，推荐）。** 送过去的是构建完成的镜像，隔离侧一次 apt 都不跑。
2. **换基础镜像。** 企业一般有自己的 golden base image，其 `sources.list` 本来就指向内网。
   把 §0.2 表里 `python:3.12-slim-bookworm` / `debian:bookworm-slim` / `node:22-slim` /
   `nginx:1.27-alpine` 换成对应的内部镜像（连 digest 一起换）即可，**不需要改任何一句 apt
   命令**——这也是现实中企业真正的做法，而不是去 sed 别人 Dockerfile 里的源。

§0.3 这张表就是为第 2 条准备的：内网镜像里只要有这些包，构建就能过。

### 0.4 PyPI / npm / Go 依赖源，以及三个重定向变量

**这三个变量是企业内网构建实际使用的机制**，`.env` 里设一次，compose 会把它们作为 build arg
传进三个 Dockerfile，再由 Dockerfile 翻译成各工具自己的原生环境变量：

| `.env` 变量 | → build arg | → 工具原生变量 | 覆盖哪些构建步骤 | 规模（实测） |
|---|---|---|---|---|
| `SKILLSCAN_PIP_INDEX_URL` | `PIP_INDEX_URL` | `UV_INDEX_URL` | ① `uv sync --frozen`（monolith + engine-runner）② `uv pip install /tmp/bandit-src`③ `uv pip install /tmp/skillspector-src`④ `uv pip install -r vendor-aig-mcp-scan/requirements.txt`（独立 venv） | `uv.lock` **74** 个包；bandit 另需 `pbr`(构建后端) + `PyYAML` `stevedore` `rich`；aig mcp-scan `requirements.txt` **5** 行（含 `pydantic==2.12.4`，故必须装进独立 venv） |
| `SKILLSCAN_NPM_REGISTRY` | `NPM_CONFIG_REGISTRY` | `NPM_CONFIG_REGISTRY` | ① `npm install -g npm@10.8.2`（**也走 registry**，容易漏）② `npm ci` | `web/package-lock.json` **171** 个包 |
| `SKILLSCAN_GOPROXY` | `GOPROXY` | `GOPROXY` | `go mod download`（`vendor/osv-scanner`） | `vendor/osv-scanner/go.sum` **292** 个模块 |

```bash
# .env 里的内网写法（示例）
SKILLSCAN_PIP_INDEX_URL=https://nexus.corp.example/repository/pypi/simple
SKILLSCAN_NPM_REGISTRY=https://nexus.corp.example/repository/npm/
SKILLSCAN_GOPROXY=https://nexus.corp.example/repository/go/
```

**⚠ 留空从来不是 fail-closed，而是走公网——2026-07-30 起这条路被堵死了。**

先说事实（实测，不是推断）：三个工具都把**空值当作未设置**，然后用自己的公网默认源。

| 设置 | 实测结果 |
|---|---|
| `UV_INDEX_URL=""` | `uv sync --frozen` 从 pypi.org 解析全部 74 个包，一声不吭 |
| `NPM_CONFIG_REGISTRY=""` | `npm config get registry` → `https://registry.npmjs.org/` |
| `GOPROXY=""` | `go env GOPROXY` → `https://proxy.golang.org,direct` |

这是**和 `SESSION_INTROSPECTION` 完全同一类缺陷**："空字符串"与"键不存在"被当成两回事，而
`cp .env.example .env` 恰好生产的就是空字符串。后果比登录崩溃严重：一个以为自己在做隔离网
构建的操作者，实际上连了三个公网服务，而且没有任何提示。

**现在的行为：构建直接拒绝启动**，除非二选一显式表态（`scripts/require_build_index.sh`，
是每个联网构建阶段的第一个 `RUN`，秒级失败而不是八分钟后失败）：

```bash
# 1) 内网镜像源 —— 隔离网路径，INV-14 保持
SKILLSCAN_PIP_INDEX_URL=https://nexus.corp.example/repository/pypi/simple

# 2) 就是要走公网 —— 开发机 / 评估 / CI / 在联网侧打离线包
SKILLSCAN_ALLOW_PUBLIC_INDEXES=true
```

**为什么保留第 2 条而不是一律硬失败：** 强制要求先有镜像源才能构建，会挡住开发机、本仓库
自己的 CI、以及 `scripts/build_offline_bundle.sh`（它的工作本来就是**在联网侧**构建）。一道
没人能满足的闸门的下场是被删掉，或者更糟——被人直接改 Dockerfile 绕过去。所以公网仍然可达，
只是**必须指名道姓地要**，而这个选择会出现在构建命令、compose 文件和镜像的 `docker history`
里，不再是从三行空白里被**推断**出来的。空值与未设置现在行为完全一致，且都不等于"公网"。

守护它的是 `test_engine_build_pins.py::TestEveryDockerfileIsSupplyChainPinned`，**glob 全部
Dockerfile**：新加一个声明了 `ARG PIP_INDEX_URL` 却没接闸门的 Dockerfile 会当场测试失败。

其余两条构建期外网需求，这三个变量**管不到**：

- **基础镜像**（§0.2）：由 registry mirror / `docker tag` 解决，现已全部 digest 钉死。
- **apt**（§0.3）：**刻意没有参数化**，理由与替代做法见 §0.3 的"apt 为什么没有参数化"。
  一句话版本：加一个 `sed` 改源的旋钮会重建上面刚堵掉的那类静默失效，而且本环境验证不了；
  真隔离网请走离线包，或换成内网 golden base image。

另外 bandit 的打包用 `pbr`，版本号从 **git tag** 推导，而 vendor 子树只有源码没有 git 历史
——所以构建时由 `PBR_VERSION` 从 `vendor/engines.lock.yaml` 注入，无需外网。

### 0.5 宿主机要求

`scripts/one_click_deploy_docker.sh` 的 preflight 会在**构建开始前**逐项检查下表中标了
"脚本检查"的项，检查不过直接退出——不会让你在 yara 编译到第 8 分钟时才发现 80 端口被占。

| 项 | 最低要求 | 实测环境（dev VM，通过） | 脚本检查 | 不满足时的真实症状 |
|---|---|---|---|---|
| Docker Engine | ≥ 20.10 | 29.1.3 | ✅ | 旧 daemon 会**忽略**而不是拒绝 `depends_on: condition`，表现为启动顺序错乱 |
| docker compose | **≥ 2.0（v1 不行）** | v5.3.1 | ✅ | v1 读不了本仓库的 compose 文件（无 `version:` 键），报的错跟"compose 版本"毫无关系 |
| docker buildx | 建议安装 | v0.35.0 | — | 缺失时 compose 告警并回落到 classic builder；能构建，但更慢且无并行（实测） |
| CPU | 2 核可用 | 2 核 aarch64 | — | 核数直接决定构建时长（§0.6）：yara 走 `make -j$(nproc)`，Go/npm 同样吃核 |
| 内存（**daemon 视角**） | ≥ 4 GB | 7.7 GB | ✅ | `npm run build` 被 OOM kill，表现为裸的 `Killed` / exit 137，不提内存二字。Docker Desktop 的默认分配常低于宿主机真实内存 |
| 磁盘（docker data-root） | ≥ 15 GB 空闲 | 163 GB 空闲 | ✅ | BuildKit 中途 ENOSPC，报的是当时在写的那个工具的错（链接错误 / apt 错误 / npm 缓存截断），**从不说"磁盘满了"** |
| 宿主机端口 | **80**（web）、**8000**（monolith） | 空闲 | ✅ | `address already in use`——但只在构建结束后才发生。MySQL/Redis **不**发布到宿主机，仅在 compose 网络内可达 |
| `.env` | 存在且 `chmod 600` | — | ✅ | 见 §2；`cp .env.example .env` 在默认 umask 下是 0644，里面是全部 DB 口令 + Vault token + IdP client secret |
| `.env` 中的 `$` | 必须写成 `$$` | — | ✅ | **口令被静默截断**，见 §2 的 `$` 陷阱说明 |
| `vendor/` 源码树 | 五个引擎齐全 | 齐全 | ✅ | `git clone` 自带；源码包 / `git archive` 可能不带，缺了会在 engine-runner 构建数分钟后以一句裸的 "file not found" 失败 |
| 出网（或内网镜像源） | §0.2 / §0.3 / §0.4 | 公网 | — | 见 §0.4 |

**运行机（离线包目标）只需要上表的最后几行的运行期部分**：Docker + compose 或 K8s、
端口 80/8000、磁盘放得下镜像与数据卷；构建相关的内存/CPU/索引源一项都不需要。

### 0.6 构建耗时与磁盘占用（实测，不是估算）

**实测环境：** dev VM 10.211.55.10，**2 vCPU aarch64 / 7.7 GB**，Ubuntu 24.04，
Docker 29.1.3 + compose v5.3.1 + buildx v0.35.0，2026-07-29。"冷"＝`docker builder prune -af`
之后（层缓存为空，基础镜像已在本地）；"热"＝紧接着再跑一次。

| 阶段 | 冷（层缓存为空） | 热（全缓存） | 备注 |
|---|---:|---:|---|
| preflight | 0–1 s | 0–1 s | §0.5 全部检查项 |
| build 1/5 `monolith` | **43 s** | 0–8 s | `uv sync` 74 个包 |
| build 2/5 `migrate` | 1 s | 0 s | 与 monolith 同一个 Dockerfile，整层命中 |
| build 3/5 `blobstore-init` | 0 s | 0–1 s | 同上 |
| build 4/5 `engine-runner` | **411 s（6m51s）** | 0–3 s | 见下 |
| build 5/5 `web` | **22 s** | 0–1 s | `npm ci` 171 个包 + `npm run build` |
| 构建小计 | **477 s ≈ 8 分钟** | **≈ 2 s** | |
| MySQL + Redis 起来并健康 | 0 s | 0 s | 已有卷时更快 |
| `migrate`（迁移 + GRANT） | 6 s | 2–12 s | 空库首次建表最慢 |
| `blobstore-init` | 1 s | 0–1 s | |
| 起 monolith + engine-runner + web | 13 s | 13 s | 含 monolith healthcheck 变绿 |
| blobstore 共享校验 | 0 s | 0 s | 上一步已把 engine-runner 等成 healthy |
| **脚本总耗时** | **≈ 8 分 11 秒** | **17–36 s** | |

**`engine-runner` 是全部时间的 86%，而它里面 `go mod download` 一步就占 319.5 秒**——那是
292 个 Go module 的下载，**受网络带宽支配而不是 CPU**。所以：

- 内网 `SKILLSCAN_GOPROXY`（§0.4）能把这一段砍掉大半，**冷构建 8 分钟里最容易优化的就是它**。
- 反过来，公网慢的环境下这一步可能远超 5 分钟。**这段过程几乎不打印任何输出**，第一次跑的人
  很容易判定为卡死——一键脚本因此按镜像逐个报时，并在开始前打印预期耗时。
- 核数更多时 yara 的 `make -j$(nproc)` 和 Go 编译会明显变快，但 `go mod download` 不会。

**产出镜像大小（实测 `docker images`，arm64）：**

| 镜像 | 大小 | 说明 |
|---|---:|---|
| `skillscan-engine-runner` | **1.04 GB** | 五个引擎 + 两个 venv（主 venv 与 aig 专用 venv） |
| `skillscan-monolith` | **578 MB** | `migrate` / `blobstore-init` 是同一个镜像的另外两个 tag，**不额外占盘** |
| `skillscan-web` | **77.2 MB** | 多阶段：`node:22-slim` 只在构建期，最终镜像是 nginx + 静态文件 |

**磁盘占用（实测 `df` 增量，docker data-root）：**

| 项目 | 实测 | 说明 |
|---|---:|---|
| 冷构建（基础镜像已在本地） | **+6.04 GiB** | 产出镜像 + BuildKit 层缓存 |
| 首次拉基础镜像 | +约 0.49 GB | 压缩下载量，见 §0.2 |
| 运行中的栈（空数据库） | **+约 0.5 GiB** | MySQL/Redis/blobstore 三个具名卷 |
| **首次部署合计** | **≈ 7 GiB** | 一键脚本的 preflight 门槛设为 **15 GB**，留出再构建一次的余量 |

`docker compose down -v` 会把三个数据卷一起删掉（**含数据库**）；只 `down` 则保留。层缓存要用
`docker builder prune` 单独回收——上表的 6 GiB 里大部分是它。

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

## 2. 容器化生产部署（docker-compose）✅已在 dev VM 跑通（含真实扫描）

**验证到什么程度，说准确（2026-07-30 重跑，接缝已闭合）：** 这一节写的命令序列**原样**跑过一遍，
起点就是 `cp .env.example .env`：

1. `docker compose down -v` 清空，`cp .env.example .env`（`diff` 确认与模板逐字节相同）；
2. **只**填本节环境变量表里标"必需/必填"的那几项——8 个 DB 口令 +
   `SKILLSCAN_ALLOW_PUBLIC_INDEXES=true`。**没有增删任何一个键**（键集合与 `.env.example`
   `diff` 为空）；这一点是刻意验的，见下方那段教训；
3. `./scripts/one_click_deploy_docker.sh` → 退出码 0，**总耗时 289 秒**（含全部镜像构建），
   preflight 8 项全过，共享 blobstore 探针被脚本实际断言通过；
4. 提交一个真实 skill 包 → `decided` / `REVIEW` / score 43 / 9 条 findings；
5. 从 compose 自己的 mysql 容器读回 `scan_engine_health`（下表）。

**在此之前这条路是断的，而且断点很有代表性。** 7-29 那次端到端验证用的是**手写的 `.env`**，
它恰好**整段漏掉**了 `SESSION_INTROSPECTION` 三个键——于是取到代码默认值，跑通了；而
`cp .env.example .env` 得到的是 `KEY=` 空串，`os.environ.get` 不会回落默认值，monolith 启动
即崩溃循环。**"少写一个键"和"写了个空值"是两种不同的东西**，而验证用的配置恰好落在能跑的
那一侧。同一类问题在构建期还有一份（三个索引变量留空＝静默走公网，§0.4），一并修掉了。
所以本次重跑刻意保持键集合与模板完全一致，只填值——否则验证的仍然不是用户会走的那条路。

**前置条件：** 见 §0.5 那张表——Docker ≥20.10、compose ≥2.0、≥4 GB 内存、≥15 GB 磁盘、
80/8000 端口空闲。这些**脚本会在构建开始前自己检查**，不必事先手工核对。

```bash
cp .env.example .env
chmod 600 .env      # 里面是全部 DB 口令 + Vault token + IdP client secret；
                    # 默认 umask 下 cp 出来是 0644，脚本会因此拒绝启动
# 编辑 .env，填入真实的 Vault/OIDC/SAML/数据库密码等（见下方环境变量表）
# ⚠ 口令里每个 $ 都要写成 $$，否则会被 compose 静默吃掉——见下方"`$` 陷阱"
./scripts/one_click_deploy_docker.sh
```

**脚本在开始那次数十分钟的构建之前先跑一遍 preflight**（构建到第 8 分钟才发现 80 端口被
占，是很差的交易）。检查项与失败时的真实症状见 §0.5 的表；每一项都被**故意弄失败验证过**，
不是只会打勾的装饰。三条值得单独说：

- **`$` 陷阱（安全项，不是格式项）。** compose 在任何容器看到 `.env` 之前就会做变量插值，
  所以 `PW=ab$cd` 进到容器里是 `ab`，而 `PW=ab$HOME` 会**一声不响**地变成 `ab/home/xxx`
  （若 `$` 后面的名字在部署者 shell 里恰好有值，连告警都没有）。危险之处在于这个替换是
  **一致的**：`migrate` 用被改短的口令建账号，单体也用同一个被改短的口令连接，整套系统绿
  得很正常——直到有人用自己真正设的那个口令去登录，或者审计问这口令到底几位。因此脚本对
  未转义的 `$` **直接拒绝部署**而不是告警。写法：字面量 `$` 一律写成 `$$`。
- **重复执行是安全的。** 构建走缓存；`alembic upgrade head` 在 head 上是空操作；
  `db/setup_grants.py` 是 `CREATE USER IF NOT EXISTS` **加** `ALTER USER ... IDENTIFIED BY`，
  所以两次运行之间在 `.env` 里轮换过的口令确实会被应用，而不是静默停留在旧值；
  `blobstore-init` 重复执行也是空操作。**唯一不会重置的是数据**：MySQL/Redis/blobstore 三个
  具名卷会保留，迁移只前滚。要从零开始，先 `docker compose down -v`（这会销毁数据库）。
- **失败之后剩下什么。** 五个镜像**全部构建完才会启动任何容器**，所以构建期失败（engine-runner
  那一段是最长也最可能失败的）之后没有任何新容器在跑，只剩构建缓存；脚本会明说这一点。若是
  启动之后才失败，脚本打印 `docker compose ps -a` 的真实状态和两条恢复命令
  （`down` 保数据 / `down -v` 连数据一起删），并且**不替你 down**——失败容器里的日志正是要
  查的东西，`down` 会连证据一起删掉。

这会构建并启动：MySQL 8 + Redis + 一次性 `migrate`（迁移+GRANT）+ 一次性
`blobstore-init`（准备共享卷权限）+ 单体后端（`monolith`，端口 8000）+
**`engine-runner`（五个真实 OSS 检测引擎）** + Web 控制台（`web`，nginx 反向代理到单体，
端口 80，同源 BFF——见 §5 安全说明）。

**2026-07-29 之前这个文件里没有 `engine-runner`。** 照着本节部署出来的系统只跑单体进程内
的 floor 引擎，整个 sandbox 引擎层静默缺席——不报任何错，扫描照常出结论，只是引擎比操作者
有任何理由预期的要少。现在补上了。

**本节 2026-07-29 在 dev VM 上实测到什么程度，说准确：** 空层缓存冷构建 → 一键脚本跑通 →
`/healthz` 200、`/`（web）200、`/readyz` 的 `redis` / `orchestration_db` /
`blobstore_shared` 三项全为 `true` → 又原样重跑两次验证幂等 → `down -v` 拆掉。镜像里的引擎
二进制实测为 `yara 4.5.7` / `bandit 1.9.4` / `osv-scanner 2.4.0`，与
`vendor/engines.lock.yaml` 一致。**没有**在这条 compose 路径上提交过真实 skill 包——下面那张
`scan_engine_health` 表来自同一套镜像的 k3s 部署，不是 compose 栈的实测。

**这条路径是从源码构建的，联网需求与"把仓库 clone 过去"完全相同**——**逐项清单见 §0**
（§0.2 基础镜像含 digest、§0.3 apt 包、§0.4 三个索引源与重定向变量），因为构建的正是那三个
Dockerfile。`engine-runner` 会用 autotools 编译 `vendor/yara`、用 Go 构建
`vendor/osv-scanner`，冷缓存下是这五个镜像里最久的一个（实测数字见 §0.6，第一次跑的人务必
先看一眼——那段会长时间没有输出，很像卡死），并且**版本与 `vendor/engines.lock.yaml` 不一致
时构建直接失败**。内网可以用 `SKILLSCAN_PIP_INDEX_URL` / `SKILLSCAN_GOPROXY` /
`SKILLSCAN_NPM_REGISTRY` 指向自建镜像源（§0.4）。**三个都留空时构建会直接拒绝启动**——
要走公网必须显式写 `SKILLSCAN_ALLOW_PUBLIC_INDEXES=true`，因为留空从来不是 fail-closed。
**它不是离线包，也不具备离线包的性质**——离线包（§6）送过去的是构建完成的镜像，隔离侧
一次构建都不做；本节则是在目标机器上真做一次完整构建。真隔离网请走 §6。

**拓扑说明（诚实版）：** 这里的 `engine-runner` 是与单体同一台 Docker 宿主机上的普通容器，
**不是** Helm chart（拓扑 A）里那个 gVisor RuntimeClass + 独立命名空间 + NetworkPolicy
围起来的部署。引擎完全一样，围着引擎的隔离更弱。以"不可信 skill 包"为威胁模型时应选拓扑 A。

**共享 blobstore 是这里最容易静默出错的地方。** 单体写 `artifacts/<hash>/pkg.tar`，
engine-runner 读它、写回 `findings/<scan_id>/<engine>.json`，单体再读回来。两边不是同一个
存储时**什么错都不会报**：容器全是 Running、`/healthz` 全是 200、日志干干净净，扫描永远停在
`running`。compose 里用一个具名卷同时挂给两个服务，路径与两个 `SKILLSCAN_BLOBSTORE_ROOT`
共用同一个 YAML 锚点；两个进程 uid 不同（10001/10002），靠 `group_add: 10000` 这个共享附加组
+ 一次性 `blobstore-init` 把卷根设成 `root:10000 2770` 才能互相写。一键脚本最后会**实际等待
并断言** engine-runner 的 `/readyz` 变健康（对端探针文件可见），不是假设挂载成功了——注意
它的 `start_period` 是 90 秒，因为 60 秒宽限期内 `/readyz` 无论如何都返回 200，比这更早的
检查测的是宽限期而不是共享。

**验证引擎真的跑了（不要看日志，读表）：** `GET /v1/admin/engines/health` 背后的
`scan_engine_health` 按 scan × engine 记录 `report_state` / `engine_status` /
`analyze_duration_ms`。"从未上报"和"上报了但 ERROR"是两种不同状态，这张表能区分。
下表是 2026-07-30 那次接缝重跑（scan `f1629fe6`）在 dev VM 的 **compose 栈**上读回的结果
（省略 11 个 inhouse/floor 引擎），查询在 compose 的 mysql 容器里对 compose 的 `skillscan`
库执行（`docker compose exec mysql mysql ... SELECT ... FROM scan_engine_health WHERE
scan_id=...`），不是 k3s。全部基础镜像改钉 digest（§0.2）之后复测，结果与之前一致：

| engine | report_state | engine_status | 耗时 | findings |
|---|---|---|---|---|
| bandit | reported | ok | 106ms | 4 |
| yara | reported | ok | 6ms | 1 |
| skillspector | reported | ok | 6528ms | 4 |
| osv-scanner | reported | **error** | 19ms | 0 |
| aig-mcp-scan | **not_reported** | — | — | — |

**后两行是预期状态，不是故障，而且是两种不同的情况：**

- `osv-scanner` 真的跑了并 fail-closed 了，错误是 `no offline version of the OSV database
  is available`。镜像**故意不去下载** Google 的 OSV 离线库（那是一次真实的外部数据拉取），
  所以它宁可诚实报错也不去连 `api.osv.dev`（INV-14）。要让它出结果，需自行提供离线库并设
  `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`。Helm 路径用的是同一个镜像，行为完全一样。
- `aig-mcp-scan` 根本没被构造（没配 `SKILLSCAN_VLLM_BASE_URL`），所以它连"跑过"都算不上。

**没有 Docker 的最小可替代路径：** 直接在一台已装好 Python/Node/MySQL/Redis 的宿主机上，
参照编译指南 §2/§3 构建，再用 §4 的环境变量表配置后运行
`uvicorn monolith.main:create_app --factory --host 0.0.0.0 --port 8000`（对应 SAD §3.4
"拓扑 B2：docker-compose + systemd" 中不使用容器的等价形态）。注意这条路径同样要**另外**
起一个 `python -m engine_runner.main`，并让它与单体看到同一个 `SKILLSCAN_BLOBSTORE_ROOT`，
否则就退化成"只有 floor 引擎"的那种静默缺席。

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
| 沙箱引擎 | `SKILLSCAN_VLLM_BASE_URL` | 否 | **单体与 engine-runner 共用同一个值**（compose 里是一个 YAML 锚点）。只设一边＝静默脑裂：引擎跑了但单体不等它，结果被丢弃。留空则 skillspector 退到静态模式、aig-mcp-scan 根本不构造。INV-14：必须内网可解析 |
| 沙箱引擎 | `SKILLSCAN_LLM_API_KEY` / `SKILLSCAN_LLM_MODEL` | 否 | 仅在上面设了内网端点、且该端点自带鉴权/指定模型时需要。只给 engine-runner（INV-10：单体不需要） |
| 沙箱引擎 | `SKILLSCAN_OSV_SOURCE` | 否，默认 `offline` | 非 `offline` 时按内网端点校验；osv-scanner adapter 自身固定 `--offline`，不消费此值 |
| 时间预算 | `SKILLSCAN_SCAN_DEADLINE_S` | 否，默认 `300` | 一次扫描的总墙钟。单体**执行**它，engine-runner 只读来在启动时告警"每引擎超时之和装不下"。设了 `SKILLSCAN_VLLM_BASE_URL` 后总和是 480s > 300s，需一并抬到 ≥480（同时抬 `SKILLSCAN_SANDBOX_WAIT_TIMEOUT_S`，两者刻意保持相等） |
| 时间预算 | `SKILLSCAN_ENGINE_TIMEOUT_S` / `SKILLSCAN_ENGINE_TIMEOUTS_JSON` | 否 | 每引擎子进程超时；留空＝内置表（60s，aig-mcp-scan 240s）。JSON 里出现不认识的引擎名会让 engine-runner 启动即失败，而不是被静默忽略 |
| 构建期 | `SKILLSCAN_PIP_INDEX_URL` / `SKILLSCAN_NPM_REGISTRY` / `SKILLSCAN_GOPROXY` | 二选一必填 | INV-14 零外部出站在构建期的延伸；机制、覆盖的构建步骤、依赖图规模见 **§0.4** |
| 构建期 | `SKILLSCAN_ALLOW_PUBLIC_INDEXES` | 二选一必填 | 设为 `true` 表示“就是要走公网”。三个镜像源变量全空且此项不为 `true` 时**构建拒绝启动**——留空从来不是 fail-closed，见 §0.4 |

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
2. 本仓库源码——chart 在 `deploy/helm/skillscan`，离线包里**不含** chart。
   注意体积：2026-07-29 起 `vendor/` 里是五个引擎的完整源码（约 134 MB / 6273 个文件，
   不再是空的 submodule 目录），所以源码这一份比以前大得多；好处是它自带引擎源码，
   拷过去不需要再做任何 `git submodule` 步骤
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
