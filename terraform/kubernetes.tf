# SECURITY: no ServiceAccount token auto-mounted anywhere by default
# (automountServiceAccountToken: false, matching the Helm chart's own
# Deployment templates) - this project's pods authenticate to Vault/MySQL
# via injected credentials (coding spec §13), not the Kubernetes API.
resource "kubernetes_namespace" "skillscan" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/name" = "skillscan"
    }
  }
}

resource "kubernetes_resource_quota" "skillscan" {
  metadata {
    name      = "skillscan-quota"
    namespace = kubernetes_namespace.skillscan.metadata[0].name
  }
  spec {
    hard = {
      "limits.cpu"    = var.resource_quota.cpu_limit
      "limits.memory" = var.resource_quota.memory_limit
    }
  }
}

# SECURITY: NetworkPolicy/Kyverno manifests (deploy/networkpolicy/,
# deploy/kyverno/) are applied via kubectl/GitOps, not this Terraform module -
# they're plain Kubernetes-native resources with no Terraform-specific state
# to manage, and keeping them out of Terraform state avoids a drift-detection
# false-positive every time Kyverno's own admission webhook mutates them.
