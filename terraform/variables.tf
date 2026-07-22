variable "namespace" {
  description = "Kubernetes namespace for the skillscan workload."
  type        = string
  default     = "skillscan"
}

variable "vault_transit_key_name" {
  description = "Vault Transit key name for gate verdict signing (gate.signer.VaultTransitSigner)."
  type        = string
  default     = "skillscan-gate-signing"
}

variable "resource_quota" {
  description = "Namespace-level ResourceQuota - defense in depth against a runaway workload."
  type = object({
    cpu_limit    = string
    memory_limit = string
  })
  default = {
    cpu_limit    = "16"
    memory_limit = "32Gi"
  }
}
