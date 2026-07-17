-- Stage 1: initial schema
-- Creates the five durable tables for the policy/risk engine.
-- Conventions: UUID PKs (app-generated UUIDv7, no DB default), UPPER_CASE enum
-- TEXT (no CHECK), created_at + updated_at on every table, no DB triggers.

BEGIN;

-- policies: one row per logical policy scope; active_version points to policy_versions.id.
CREATE TABLE IF NOT EXISTS policies (
    id             UUID PRIMARY KEY,
    scope          TEXT NOT NULL,
    active_version UUID,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- policy_versions: immutable versioned Rego bundles.
CREATE TABLE IF NOT EXISTS policy_versions (
    id          UUID PRIMARY KEY,
    policy_id   UUID NOT NULL REFERENCES policies (id) ON DELETE CASCADE,
    version     INTEGER NOT NULL,
    rego_hash   TEXT NOT NULL,
    rego_source TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by  TEXT NOT NULL,
    UNIQUE (policy_id, version)
);

-- Back-reference: policies.active_version -> policy_versions.id.
-- Guarded with DO $$ ... IF NOT EXISTS so the migration is idempotent and
-- survives re-runs after `make reset-db` (which truncates schema_migrations).
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'policies_active_version_fk') THEN
        ALTER TABLE policies
            ADD CONSTRAINT policies_active_version_fk
            FOREIGN KEY (active_version) REFERENCES policy_versions (id) ON DELETE SET NULL;
    END IF;
END $$;

DROP INDEX IF EXISTS idx_policy_versions_version;
CREATE INDEX IF NOT EXISTS idx_policy_versions_version ON policy_versions (version);
CREATE INDEX IF NOT EXISTS idx_policy_versions_policy_id ON policy_versions (policy_id);

-- policy_decisions: append-only audit of every evaluation.
CREATE TABLE IF NOT EXISTS policy_decisions (
    decision_id     TEXT PRIMARY KEY,
    policy_version  UUID NOT NULL REFERENCES policy_versions (id) ON DELETE RESTRICT,
    request_hash    TEXT NOT NULL,
    decision        TEXT NOT NULL,
    reasons         TEXT[] NOT NULL DEFAULT '{}',
    applied_rules   TEXT[] NOT NULL DEFAULT '{}',
    score           DOUBLE PRECISION,
    signature       BYTEA,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_policy_decisions_decision_id ON policy_decisions (decision_id);
CREATE INDEX IF NOT EXISTS idx_policy_decisions_created_at ON policy_decisions (created_at);

-- whitelist_addresses: user-verified destination addresses.
CREATE TABLE IF NOT EXISTS whitelist_addresses (
    id          UUID PRIMARY KEY,
    user_id     TEXT NOT NULL,
    chain       TEXT NOT NULL,
    address     TEXT NOT NULL,
    label       TEXT,
    verified_at TIMESTAMPTZ,
    status      TEXT NOT NULL DEFAULT 'PENDING',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, chain, address)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_whitelist_addresses_user_chain_address
    ON whitelist_addresses (user_id, chain, address);
CREATE INDEX IF NOT EXISTS idx_whitelist_addresses_user_id ON whitelist_addresses (user_id);
CREATE INDEX IF NOT EXISTS idx_whitelist_addresses_status ON whitelist_addresses (status);

-- review_queue: parked manual_review decisions awaiting resolution.
CREATE TABLE IF NOT EXISTS review_queue (
    id          UUID PRIMARY KEY,
    decision_id TEXT NOT NULL REFERENCES policy_decisions (decision_id) ON DELETE CASCADE,
    tx_id       TEXT,
    status      TEXT NOT NULL DEFAULT 'PENDING',
    assigned_to TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ,
    resolution  TEXT
);

CREATE INDEX IF NOT EXISTS idx_review_queue_status ON review_queue (status);
CREATE INDEX IF NOT EXISTS idx_review_queue_decision_id ON review_queue (decision_id);
CREATE INDEX IF NOT EXISTS idx_review_queue_assigned_to ON review_queue (assigned_to);

COMMIT;