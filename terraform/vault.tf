# Provisions the Transit engine/key/policy gate.signer.VaultTransitSigner
# depends on, WITHIN the enterprise's already-running Vault (reused, not
# self-built - same "int" convention as MySQL/Redis/MinIO). Mirrors exactly
# what was manually verified against a real local Vault dev instance during
# M6 development (transit secrets engine, rsa-2048 key, a policy scoping
# access to sign/read-key on that one key only). That dev instance was torn
# down afterwards and no live Vault has been re-authorized since, so the
# automated suite exercises the client against a fake - see
# apps/monolith/tests/test_gate_signer.py's `_FakeHvacTransit`.
resource "vault_mount" "transit" {
  path = "transit"
  type = "transit"
}

resource "vault_transit_secret_backend_key" "gate_signing" {
  backend = vault_mount.transit.path
  name    = var.vault_transit_key_name
  type    = "rsa-2048"
  # SECURITY: deletion_allowed stays false - a signing key backing already-
  # issued, still-valid verdict JWS must never be deletable by a routine
  # `terraform apply`/destroy; unwinding it is a deliberate, separate,
  # out-of-band operation.
  deletion_allowed = false
}

resource "vault_policy" "gate_signer" {
  name = "skillscan-gate-signer"
  policy = <<-EOT
    path "transit/sign/${var.vault_transit_key_name}" {
      capabilities = ["update"]
    }
    path "transit/keys/${var.vault_transit_key_name}" {
      capabilities = ["read"]
    }
  EOT
}

# SECURITY: the monolith authenticates to Vault via whatever auth method the
# enterprise's own Vault already uses for workload identity (Kubernetes auth,
# AppRole, etc.) - out of this module's scope, since it depends entirely on
# how THIS enterprise's Vault is already configured (reused, not self-built).
# `gate.signer.VaultTransitSigner` only needs a valid token bound to
# `vault_policy.gate_signer` above, however that token is obtained.
