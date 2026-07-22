#!/bin/bash
# Backup MySQL (mysqldump, consistent snapshot) + MinIO (artifacts/findings
# buckets, mc mirror) for disaster recovery (coding spec §11.7, RPO 1h).
# See dr/RUNBOOK.md for the full restore procedure and DR posture rationale.
#
# SECURITY: no credentials are hardcoded here - every value comes from the
# environment, matching this project's own "no hardcoded secrets" convention
# (see project coding conventions). Requires SKILLSCAN_DB_HOST, SKILLSCAN_DB_PASSWORD_BACKUP (a
# read-only MySQL user - see policies/grants/manifest.yaml's own per-module
# least-privilege convention; a dedicated svc_backup user with SELECT-only
# across all tables is the intended credential here, distinct from any
# module's own least-privilege user), SKILLSCAN_BACKUP_DEST (mc alias/path).
set -euo pipefail

: "${SKILLSCAN_DB_HOST:?SKILLSCAN_DB_HOST is required}"
: "${SKILLSCAN_DB_NAME:=skillscan}"
: "${SKILLSCAN_DB_USER_BACKUP:=svc_backup}"
: "${SKILLSCAN_DB_PASSWORD_BACKUP:?SKILLSCAN_DB_PASSWORD_BACKUP is required}"
: "${SKILLSCAN_BACKUP_DEST:?SKILLSCAN_BACKUP_DEST is required (e.g. s3://bucket/skillscan/)}"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
dump_file="/tmp/skillscan-${timestamp}.sql.gz"

echo "==> Dumping MySQL database '${SKILLSCAN_DB_NAME}' (consistent snapshot)..."
MYSQL_PWD="${SKILLSCAN_DB_PASSWORD_BACKUP}" mysqldump \
  --host="${SKILLSCAN_DB_HOST}" \
  --user="${SKILLSCAN_DB_USER_BACKUP}" \
  --single-transaction \
  --routines \
  --triggers \
  "${SKILLSCAN_DB_NAME}" | gzip > "${dump_file}"

echo "==> Uploading MySQL dump to ${SKILLSCAN_BACKUP_DEST}..."
mc cp "${dump_file}" "${SKILLSCAN_BACKUP_DEST%/}/mysql/skillscan-${timestamp}.sql.gz"
rm -f "${dump_file}"

echo "==> Mirroring MinIO artifacts/findings buckets to ${SKILLSCAN_BACKUP_DEST}..."
mc mirror --overwrite "skillscan-minio/artifacts" "${SKILLSCAN_BACKUP_DEST%/}/minio/artifacts"
mc mirror --overwrite "skillscan-minio/findings" "${SKILLSCAN_BACKUP_DEST%/}/minio/findings"

echo "==> Backup complete: ${timestamp}"
