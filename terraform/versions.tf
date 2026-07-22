# SECURITY: MySQL/Redis/MinIO/IdP are reused enterprise-existing internal
# services (SAD's own convention: "int" = 企业既有内网服务,复用,不自建" -
# reused, not self-built) - this module does NOT provision them. It manages
# only the two things THIS project's own deployment specifically needs:
# the Kubernetes namespace/RBAC for the skillscan workload, and the Vault
# Transit engine/key/policy this project's gate.signer.VaultTransitSigner
# depends on (within the enterprise's own already-running Vault).
terraform {
  required_version = ">= 1.7"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.31"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.4"
    }
  }
}
