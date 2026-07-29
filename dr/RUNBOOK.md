# Disaster Recovery Runbook

**Target:** RTO 4h / RPO 1h (coding spec §11.7 acceptance criterion).

## What actually needs to survive a disaster

Per the coding spec's own degradation matrix (§SAD, "降级矩阵"): Redis is a
**control-plane queue only** - if it's lost, in-flight work recovers from
MySQL + MinIO once Redis is back (new submissions get `503` in the meantime,
nothing is silently dropped). **Redis therefore has no backup/restore
procedure of its own** - it's rebuilt empty and the system self-heals.

The two systems that hold durable, non-reconstructible state are:

| System | Holds | Backup |
|---|---|---|
| MySQL | verdict/audit_entry/reconciliation/scan_job/... (every table in coding spec §7.1) | Point-in-time-recoverable dump, see below |
| MinIO | `artifacts/<content_hash>/pkg.tar` (submitted packages), `findings/<scan_id>/*.json` | Bucket mirror/replication, see below |

Vault holds the signing key and per-module credentials - it is the
enterprise's own already-running Vault (reused, not self-built per
terraform/vault.tf's own note), so **its own DR posture is the enterprise's,
not this project's** - this runbook only covers re-provisioning
`skillscan-gate-signing`'s Transit key policy (not its key MATERIAL, which
Vault itself is responsible for backing up) via `terraform apply` against
`terraform/vault.tf` if the Transit mount itself needs to be recreated.

## Backup (RPO 1h)

Run `dr/backup.sh` on a schedule (cron/K8s CronJob) at least hourly:

```bash
SKILLSCAN_DB_HOST=mysql.skillscan.svc.cluster.local \
SKILLSCAN_BACKUP_DEST=s3://internal-backup-bucket/skillscan/ \
  dr/backup.sh
```

It performs, in order:
1. `mysqldump --single-transaction` (consistent snapshot without locking
   writers - InnoDB, matches this project's own `ENGINE=InnoDB` DDL) of the
   `skillscan` database.
2. `mc mirror` of the MinIO `artifacts/` and `findings/` buckets to the
   backup destination.

Both are idempotent and safe to run more often than hourly if a tighter RPO
is ever needed - **not verified end-to-end in this environment** (no real
MinIO `mc` CLI target / backup bucket available here beyond the local dev
MinIO used for M3+ testing) - honestly labeled, same posture as this
project's other environment-blocked verification gaps.

## Restore (RTO 4h)

1. Provision a fresh MySQL instance (or confirm the existing one is healthy)
   and `mysql < latest_dump.sql` the most recent backup.
2. Provision/confirm MinIO and `mc mirror` the backup destination back into
   the `artifacts`/`findings` buckets.
3. Re-provision Vault Transit (`terraform apply` against `terraform/vault.tf`)
   if the Transit mount itself was lost - the signing key's own recoverability
   is the enterprise Vault's own backup/restore responsibility, not this
   project's.
4. Deploy the application (`helm install`/`upgrade`, `deploy/helm/skillscan`)
   pointed at the restored MySQL/MinIO/Vault.
5. Redis needs no restore step - it starts empty; in-flight scans that were
   queued but not yet decided at the time of the incident will need to be
   RESUBMITTED (their `scan_job` row may exist in the restored MySQL dump in
   `state='queued'`/`'running'` with no corresponding live Redis Streams
   message - operators should re-check for state='queued'/'running' rows
   older than the incident and resubmit or explicitly mark them failed).
6. Verify: `GET /healthz`/`/readyz`, submit a known-benign test Skill package
   end-to-end, confirm a PASS verdict is issued and signed correctly
   (`GET /.well-known/jwks.json` resolves, the issued JWS verifies against it).

## Drill cadence

Coding spec's own acceptance criterion is a DR drill, not merely a written
runbook - schedule and execute this restore procedure against a non-production
environment at least once per quarter, and record actual elapsed time against
the 4h RTO target (this runbook has not itself been drilled in this
development environment - no real MySQL/MinIO/Vault-backed production
environment is available here to drill against).
