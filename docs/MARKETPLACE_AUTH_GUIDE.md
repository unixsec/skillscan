# 市场接入认证配置指南（Marketplace Authentication）— skillscan

面向对象：把 skill 市场接入 skillscan 的部署方与集成方。

本文只讲**认证怎么配、怎么调通**。市场接口的字段契约以
`apps/monolith/modules/marketplace_api/views.py` 中的响应投影白名单为准
（该白名单是权威定义：未列入的内部字段一律不对外暴露）。

---

## 0. 先选认证方式

市场访问的是 `/v1/market` 这一组机器接口（与控制台的 `/v1/scans` 完全分离）。
可用的认证方式有三种，**可以共存**，同一个服务账号的权限配置（scopes/tier）是共用的：

| 方式 | HTTP 头 | 依赖 | 适用场景 |
|---|---|---|---|
| **OAuth2 client-credentials** | `Authorization: Bearer <token>` | 需要企业 IdP 提供 RFC 7662 introspection 端点 | **有 IdP 时的首选** |
| **账号名 + 密码** | `Authorization: Basic base64(账号:密码)` | 无外部依赖 | **没有 IdP、或需要快速接入时** |
| mTLS | `X-Forwarded-Client-Cert`（SPIFFE） | 需要服务网格 sidecar | 已有 mesh 的集群 |

> **账号密码方式的取舍，先看清楚再用**：它是**长期有效凭据**——不会过期、无法集中吊销
> （只能改配置并重启才算撤销），而且校验由 skillscan 自己完成，而不是交给 IdP。
> 这是有意接受的弱化，代码里 `apps/monolith/modules/gateway/auth/m2m.py` 的模块
> 注释也如实写明了这一点。**具备 IdP 条件时请用 client-credentials。**
>
> 它并没有放弃的部分（都是强制生效，不是承诺）：机器身份隔离（控制台端点仍拒绝它）、
> 同一份服务账号白名单、同一套 per-account 授权、scrypt 口令哈希、未知账号等时校验
> 防枚举、失败锁定。

本文第 1–5 节讲账号密码方式；client-credentials 的配置见第 6 节。

---

## 1. 账号密码方式：三个环境变量

三者职责分离，**缺一不可**：

| 环境变量 | 回答的问题 | 漏配的后果 |
|---|---|---|
| `SKILLSCAN_M2M_BASIC_ACCOUNTS_JSON` | 你是谁（账号 → 口令哈希） | 401 |
| `SKILLSCAN_M2M_ALLOWED_SERVICE_ACCOUNTS` | 是否放行这个账号 | 401 |
| `SKILLSCAN_M2M_GRANTS_JSON` | 允许做什么（scopes / tier） | **提交成功、轮询 403** |

格式：

```bash
# 账号 -> scrypt 口令哈希。禁止明文（见 §2）。留空 = 该认证方式不可用（fail-closed）
SKILLSCAN_M2M_BASIC_ACCOUNTS_JSON={"marketplace-svc":"scrypt$<salt_hex>$<digest_hex>"}

# 逗号分隔。留空 = 谁都不放行，而不是"不限制"
SKILLSCAN_M2M_ALLOWED_SERVICE_ACCOUNTS=marketplace-svc

# scopes 必须同时包含 scan:submit 与 scan:read
SKILLSCAN_M2M_GRANTS_JSON={"marketplace-svc":{"scopes":["scan:submit","scan:read"],"tier":"public"}}
```

### 两个最常踩的坑

**坑 1：`scopes` 只写了 `scan:submit`。**
未在 `GRANTS_JSON` 中配置的账号会落到默认授权
（`m2m.DEFAULT_M2M_GRANT`）——**只有 `scan:submit`，没有 `scan:read`**。
表现为提交扫描成功（202），轮询结果一律 403。两个 scope 都要写。

**坑 2：`tier` 填成了 `internal`。**
取值只能是 `internal` / `partner` / `public`。**市场场景请填 `public`**：
它是最严格的一档（HIGH 即 BLOCK，其余 tier 需 CRITICAL 才 BLOCK）。
市场分发的是第三方内容，本就该按最严判定。

> `trust_tier` 由服务端根据服务账号配置决定，**调用方不能传**。
> 请求里带了这个字段会直接返回 400，而不是被静默忽略——避免调用方
> 误以为自己的设置生效了。

---

## 2. 第 1 步：生成口令哈希

**配置中禁止出现明文口令**（INV-17）。写了明文，进程会**启动失败**并报错，
而不是启动后每次登录都拒绝——这是刻意设计，避免"看起来配好了其实用不了"。

```bash
# 方式一：在有源码的机器上
uv run python -c "from common.password import hash_password; print(hash_password('你要设置的口令'))"

# 方式二：在运行中的 pod 里
kubectl exec -n skillscan deploy/monolith -- \
  python3 -c "from common.password import hash_password; print(hash_password('你要设置的口令'))"
```

输出形如（scrypt，N=2^14/r=8/p=1，每个口令独立随机盐）：

```
scrypt$6a9499bfed013e44c1362466618ff064$3f2a...
```

口令本身请用高强度随机串，并保存在你们的密钥管理系统里——skillscan 只存哈希，无法找回。

---

## 3. 第 2 步：按部署形态写入配置

### 3.1 Kubernetes（推荐：口令哈希走 Secret）

与现有 `skillscan-local-accounts` 的做法保持一致：

```bash
kubectl create secret generic skillscan-m2m-basic -n skillscan \
  --from-literal=accounts.json='{"marketplace-svc":"scrypt$6a94...完整哈希"}'
```

在 monolith 的容器上追加三个环境变量：

```yaml
        env:
          - name: SKILLSCAN_M2M_BASIC_ACCOUNTS_JSON
            valueFrom:
              secretKeyRef:
                name: skillscan-m2m-basic
                key: accounts.json
          - name: SKILLSCAN_M2M_ALLOWED_SERVICE_ACCOUNTS
            value: "marketplace-svc"
          - name: SKILLSCAN_M2M_GRANTS_JSON
            value: '{"marketplace-svc":{"scopes":["scan:submit","scan:read"],"tier":"public"}}'
```

用 `kubectl patch` 直接追加：

```bash
kubectl patch deploy monolith -n skillscan --type=json -p='[
  {"op":"add","path":"/spec/template/spec/containers/0/env/-","value":{
    "name":"SKILLSCAN_M2M_BASIC_ACCOUNTS_JSON",
    "valueFrom":{"secretKeyRef":{"name":"skillscan-m2m-basic","key":"accounts.json"}}}},
  {"op":"add","path":"/spec/template/spec/containers/0/env/-","value":{
    "name":"SKILLSCAN_M2M_ALLOWED_SERVICE_ACCOUNTS","value":"marketplace-svc"}},
  {"op":"add","path":"/spec/template/spec/containers/0/env/-","value":{
    "name":"SKILLSCAN_M2M_GRANTS_JSON",
    "value":"{\"marketplace-svc\":{\"scopes\":[\"scan:submit\",\"scan:read\"],\"tier\":\"public\"}}"}}
]'
```

### 3.2 docker-compose / .env

```bash
SKILLSCAN_M2M_BASIC_ACCOUNTS_JSON={"marketplace-svc":"scrypt$6a94...完整哈希"}
SKILLSCAN_M2M_ALLOWED_SERVICE_ACCOUNTS=marketplace-svc
SKILLSCAN_M2M_GRANTS_JSON={"marketplace-svc":{"scopes":["scan:submit","scan:read"],"tier":"public"}}
```

`.env` 不得进入 Git 仓库。

---

## 4. 第 3 步：重启并**核实**生效

```bash
kubectl rollout restart deploy/monolith -n skillscan
kubectl rollout status  deploy/monolith -n skillscan
```

**不要只看 rollout 成功就认为配置生效。** 本项目出现过 ConfigMap 挂载遮蔽镜像内容、
导致"镜像重建了但文件没变"的情况。进容器里实际确认：

```bash
kubectl exec -n skillscan deploy/monolith -- \
  sh -c 'echo "$SKILLSCAN_M2M_ALLOWED_SERVICE_ACCOUNTS"'
```

若配置里写了明文口令或 JSON 格式有误，pod 会 **CrashLoopBackOff**，
`kubectl logs` 中有明确报错。

---

## 5. 第 4 步：市场侧调用

`curl -u` 会自动完成 Basic 编码。

### 5.1 提交扫描

```bash
curl -u marketplace-svc:你的口令 \
  -X POST https://<host>/v1/market/scans \
  -F "package=@skill.zip" \
  -F "skill_id=@alice/hello-world"
```

- `package`：skill 软件包，**tar 或 zip 均可**（按魔数分发）
- `skill_id`：**必填**，轮询就是按它来的
- 返回 `202 {"scan_id":"..."}`

### 5.2 轮询结果

```bash
curl -u marketplace-svc:你的口令 \
  https://<host>/v1/market/skills/@alice/hello-world
```

`skill_id` 可以直接含斜杠（路由按 `path` 匹配，专为 `@handle/slug` 这种规范形式设计）。

**不需要 CSRF token**——Bearer/Basic 这类 API 调用自动豁免。

按响应里的 `poll_after_ms` 控制轮询节奏：`PENDING` 5000ms / `RUNNING` 15000ms / `COMPLETED` 0。

### 5.3 响应示例

```json
{
  "skill_id": "@alice/hello-world",
  "content_hash": "9f2c...",
  "status": "COMPLETED",
  "poll_after_ms": 0,
  "is_safe": false,
  "unsafe_reason": "content_findings",
  "score": 72,
  "hard_gate_hits": [],
  "summary": {"total": 5, "critical": 0, "high": 1, "medium": 2, "low": 2, "truncated": false},
  "findings": [
    {
      "rule_id": "...", "test_item_id": "...", "category": "code",
      "title": "...", "severity": 3, "confidence": 0.9,
      "source_engine": "...", "file_path": "...", "start_line": 42,
      "evidence_redacted": "..."
    }
  ],
  "engines_expected": 15, "engines_reported": 15, "evidence_complete": true,
  "policy_version": "...", "decided_at": "...", "verdict_jws": "..."
}
```

**`is_safe` 是二值的**，只有 `status == COMPLETED` **且**判定为 PASS 时才为 `true`；
其余一律 `false`，并给出机器可判读的 `unsafe_reason`：

| `unsafe_reason` | 含义 | 建议动作 |
|---|---|---|
| `not_yet_scanned` | 尚未产出判定 | 继续轮询 |
| `scan_incomplete` | 扫描未能完成（引擎超时等），已按失败关闭处理 | **不要重试绕过**，转人工 |
| `hard_gate` | 命中不可豁免的硬门禁规则 | 拒绝上架 |
| `pending_review` | 需要人工复核 | 等待复核结论 |
| `content_findings` | 内容问题导致不通过 | 按 `findings` 修复后重新提交 |

**`evidence_complete` 值得单独关注**：为 `false` 时说明部分引擎未能交付结果，
判定是在不完整证据上做出的（顾问型引擎失败时不阻断流程）。为 `null` 表示无逐引擎记录可查。

---

## 6. 附：client-credentials（有 IdP 时的首选）

skillscan **不签发 token**，只做校验。市场向企业 IdP 走标准 client-credentials
拿 token，skillscan 拿到后向 IdP 的 introspection 端点核验。

```bash
SKILLSCAN_SESSION_INTROSPECTION_ENDPOINT=https://idp.internal/oauth2/introspect
SKILLSCAN_SESSION_INTROSPECTION_CLIENT_ID=skillscan
SKILLSCAN_SESSION_INTROSPECTION_CLIENT_SECRET=<secret>
# 下面两个与账号密码方式完全共用
SKILLSCAN_M2M_ALLOWED_SERVICE_ACCOUNTS=marketplace-svc
SKILLSCAN_M2M_GRANTS_JSON={"marketplace-svc":{"scopes":["scan:submit","scan:read"],"tier":"public"}}
```

IdP 的 introspection 响应必须满足：

| 字段 | 要求 |
|---|---|
| `active` | 必须为 `true` |
| `sub` 或 `client_id` | 服务账号名，**必须与 `ALLOWED_SERVICE_ACCOUNTS` 完全一致** |
| `exp` | 数值且在未来 |

调用方式只是把 `-u 账号:口令` 换成 `-H "Authorization: Bearer <token>"`，
接口路径与响应契约完全相同。introspection 结果缓存 30 秒（上限固定，不可调高）。

---

## 7. 排错对照表

| 现象 | 原因 | 处理 |
|---|---|---|
| 401 | 口令错 / 账号不在白名单 / `BASIC_ACCOUNTS_JSON` 未配 | 逐项核对 §1 三个变量 |
| 401 且此后持续 401 | 触发**失败锁定**（5 次 / 15 分钟） | 等 15 分钟，或删 Redis key `skillscan:m2m:basic:failcount:<账号>` |
| 401 且日志有 `introspection endpoint failure` | 走的是 Bearer 路径但 IdP 不可达 | 改用账号密码方式，或修复 IdP 连通性 |
| **403 `not granted the 'scan:read' scope`** | **`GRANTS_JSON` 漏了 `scan:read`** | 见 §1 坑 1 |
| 403 访问 `/v1/scans/*` | 正常且刻意：机器身份被控制台端点拒绝 | 只用 `/v1/market` 两个接口 |
| 404 轮询 | skill 不存在**或**属于其他服务账号（刻意不区分，防枚举） | **提交方与轮询方必须是同一个服务账号** |
| 409 | 该 skill 正处于 `scanning` 状态 | 等本次扫描结束再提交 |
| 429 | 超过限流（默认 120 次/分钟/账号） | 按 `Retry-After` 退避；并遵守 `poll_after_ms` |
| 400 `trust_tier is determined server-side` | 请求里带了 `trust_tier` | 去掉该字段 |
| pod CrashLoopBackOff | 配置中有明文口令或 JSON 格式错误 | 看 `kubectl logs`，按 §2 重新生成哈希 |

排查时可直接过滤这两个 logger：

```bash
kubectl logs -n skillscan deploy/monolith | grep -E "marketplace_api.router|gateway.auth"
```

---

## 8. 口令轮换与吊销

账号密码是长期凭据，**没有自动过期**。轮换流程：

1. 按 §2 生成新哈希
2. 更新 Secret：`kubectl create secret generic skillscan-m2m-basic -n skillscan --from-literal=accounts.json='...' --dry-run=client -o yaml | kubectl apply -f -`
3. `kubectl rollout restart deploy/monolith -n skillscan`
4. 通知市场侧更换口令

**紧急吊销**：把该账号从 `SKILLSCAN_M2M_ALLOWED_SERVICE_ACCOUNTS` 中移除并重启即可——
白名单是口令之外的第二道闸门，即使哈希还留在配置里，账号也已失效。

---

## 9. 相关文件

| 内容 | 位置 |
|---|---|
| 认证实现与安全取舍说明 | `apps/monolith/modules/gateway/auth/m2m.py` |
| 口令哈希原语 | `libs/common/password.py` |
| 市场接口路由 | `apps/monolith/modules/marketplace_api/router.py` |
| 响应字段白名单（字段契约的权威定义） | `apps/monolith/modules/marketplace_api/views.py` |
| 部署方式 | `docs/DEPLOYMENT_GUIDE.md` |
