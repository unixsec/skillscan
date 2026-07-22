"""initial core schema

Transcribed verbatim from coding spec §7.1 (authoritative DDL). Raw SQL rather
than SQLAlchemy metadata/autogenerate, specifically so the migration matches
the spec byte-for-byte and stays auditable against it.

Revision ID: 1d6112d0e997
Revises:
Create Date: 2026-07-05 16:32:39.683982

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "1d6112d0e997"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # -- inventory module -------------------------------------------------
    op.execute("""
        CREATE TABLE skill (
          skill_id        VARCHAR(128) PRIMARY KEY,
          source          VARCHAR(255) NOT NULL,
          trust_tier      ENUM('internal','partner','public') NOT NULL,
          scope           VARCHAR(128) NULL,
          created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
    """)
    op.execute("""
        CREATE TABLE skill_version (
          content_hash    CHAR(64) PRIMARY KEY,
          skill_id        VARCHAR(128) NOT NULL,
          toolchain_digest CHAR(64) NOT NULL,
          declared_perms  JSON NULL,
          created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
          INDEX idx_skill (skill_id),
          CONSTRAINT fk_sv_skill FOREIGN KEY (skill_id) REFERENCES skill(skill_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
    """)
    op.execute("""
        CREATE TABLE baseline (
          skill_id        VARCHAR(128) PRIMARY KEY,
          content_hash    CHAR(64) NOT NULL,
          approved_at     DATETIME(6) NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
    """)

    # -- orchestration module ----------------------------------------------
    op.execute("""
        CREATE TABLE scan_job (
          scan_id         CHAR(36) PRIMARY KEY,
          content_hash    CHAR(64) NOT NULL,
          toolchain_digest CHAR(64) NOT NULL,
          cache_key       CHAR(64) NOT NULL,
          state           ENUM('queued','running','scored','decided','failed') NOT NULL,
          submitter       VARCHAR(255) NOT NULL,
          created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
          UNIQUE KEY uq_cache (cache_key),
          INDEX idx_state (state)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
    """)
    op.execute("""
        CREATE TABLE scan_result (
          scan_id         CHAR(36) PRIMARY KEY,
          content_hash    CHAR(64) NOT NULL,
          severity        TINYINT NOT NULL,
          confidence_at_max DOUBLE NOT NULL,
          trifecta_present BOOL NOT NULL,
          findings_capped BOOL NOT NULL,
          required_ok     BOOL NOT NULL,
          findings        JSON NOT NULL,
          provenance      JSON NOT NULL,
          hard_gate_hits  JSON NOT NULL,
          sev_gen         TINYINT AS (severity) STORED,
          INDEX idx_sev (sev_gen)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
    """)

    # -- gate module (verdict + outbox + audit_intent same-tx, §8/§12) ----
    op.execute("""
        CREATE TABLE verdict (
          scan_id         CHAR(36) PRIMARY KEY,
          content_hash    CHAR(64) NOT NULL,
          verdict         ENUM('PASS','REVIEW','BLOCK') NOT NULL,
          policy_version  VARCHAR(64) NOT NULL,
          jti             CHAR(36) NOT NULL,
          jws_signature   TEXT NOT NULL,
          effective_severity TINYINT NOT NULL,
          reasons         JSON NOT NULL,
          issued_at       DATETIME(6) NOT NULL,
          UNIQUE KEY uq_jti (jti)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
    """)
    op.execute("""
        CREATE TABLE allowlist (
          id              CHAR(36) PRIMARY KEY,
          scope_type      ENUM('content_hash','skill_id','rule_global') NOT NULL,
          scope_value     VARCHAR(255) NOT NULL,
          rule_id         VARCHAR(128) NOT NULL,
          expires_at      DATETIME(6) NOT NULL,
          approved_by     VARCHAR(255) NOT NULL,
          requested_by    VARCHAR(255) NOT NULL,
          reason          TEXT NULL,
          CONSTRAINT chk_four_eyes CHECK (approved_by <> requested_by),
          INDEX idx_scope (scope_type, scope_value)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
    """)
    op.execute("""
        CREATE TABLE gate_outbox (
          id              BIGINT AUTO_INCREMENT PRIMARY KEY,
          aggregate_id    CHAR(36) NOT NULL,
          event_type      VARCHAR(64) NOT NULL,
          payload         JSON NOT NULL,
          dispatched      BOOL NOT NULL DEFAULT FALSE,
          created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
          INDEX idx_undispatched (dispatched, id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
    """)

    # -- audit module (INV-12) ---------------------------------------------
    op.execute("""
        CREATE TABLE audit_intent (
          id              BIGINT AUTO_INCREMENT PRIMARY KEY,
          operator        VARCHAR(255) NOT NULL,
          action          VARCHAR(64) NOT NULL,
          payload         JSON NOT NULL,
          chained         BOOL NOT NULL DEFAULT FALSE,
          created_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
          INDEX idx_unchained (chained, id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
    """)
    op.execute("""
        CREATE TABLE audit_entry (
          seq             BIGINT AUTO_INCREMENT PRIMARY KEY,
          prev_hash       CHAR(64) NOT NULL,
          entry_hash      CHAR(64) NOT NULL,
          operator        VARCHAR(255) NOT NULL,
          action          VARCHAR(64) NOT NULL,
          payload         JSON NOT NULL,
          chained_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
    """)

    # -- reeval module -------------------------------------------------------
    op.execute("""
        CREATE TABLE reconciliation (
          id              BIGINT AUTO_INCREMENT PRIMARY KEY,
          content_hash    CHAR(64) NULL,
          skill_id        VARCHAR(128) NULL,
          result          ENUM('MATCH','ORPHAN','MISMATCH') NOT NULL,
          source          ENUM('poll','push') NOT NULL,
          detected_at     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
    """)

    # -- intel module --------------------------------------------------------
    op.execute("""
        CREATE TABLE threat_indicator (
          id              BIGINT AUTO_INCREMENT PRIMARY KEY,
          ioc_type        ENUM('domain','ip','md5') NOT NULL,
          ioc_value       VARCHAR(255) NOT NULL,
          source          VARCHAR(128) NOT NULL,
          imported_at     DATETIME(6) NOT NULL,
          UNIQUE KEY uq_ioc (ioc_type, ioc_value)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
    """)

    # -- audit hash-chain genesis row (§7.3: SELECT ... ORDER BY seq DESC
    # LIMIT 1 needs a row to exist the first time gate signs a verdict) -----
    op.execute("""
        INSERT INTO audit_entry (prev_hash, entry_hash, operator, action, payload)
        VALUES (
            REPEAT('0', 64),
            SHA2(CONCAT(REPEAT('0', 64), '{"action":"genesis"}'), 256),
            'system',
            'chain_genesis',
            JSON_OBJECT('note', 'audit hash-chain genesis entry')
        )
    """)


def downgrade() -> None:
    for table in (
        "threat_indicator",
        "reconciliation",
        "audit_entry",
        "audit_intent",
        "gate_outbox",
        "allowlist",
        "verdict",
        "scan_result",
        "scan_job",
        "baseline",
        "skill_version",
        "skill",
    ):
        op.execute(sa.text(f"DROP TABLE IF EXISTS {table}"))
