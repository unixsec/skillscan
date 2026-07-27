# 用户指南 — 已拆分为 4 份独立文档（2026-07-06）

本文档此前是一份覆盖构建/部署/使用/运维的综合指南。为便于查阅，现已拆分为 4 份独立、
完整的文档，内容不再在此重复维护：

- [`BUILD_GUIDE.md`](BUILD_GUIDE.md) — **编译指南**：环境准备、后端/前端/容器镜像构建、
  OSS 引擎 vendoring、IaC 静态校验。
- [`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md) — **部署指南**：本地一键开发部署、
  容器化一键生产部署、Kubernetes 部署、真实 OIDC/SAML 登录配置、安全部署要点。
- [`USAGE_GUIDE.md`](USAGE_GUIDE.md) — **操作指南**：完整 API 列表、Web 控制台使用、
  按角色的典型操作流程。
- [`MAINTENANCE_GUIDE.md`](MAINTENANCE_GUIDE.md) — **运维指南**：日常维护、
  2026-07-06 完整规格合规审计的 18 项修复清单、剩余已知差距、故障排查。

以及：

- [`THREAT_MODEL.md`](THREAT_MODEL.md) — 内核威胁模型（M1 交付物，2026-07-06 补齐）。
