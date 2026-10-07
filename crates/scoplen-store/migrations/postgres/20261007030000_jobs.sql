-- SPDX-License-Identifier: AGPL-3.0-only

CREATE TABLE jobs (
    id BYTEA PRIMARY KEY NOT NULL CHECK (octet_length(id) = 16),
    kind TEXT NOT NULL CHECK (length(kind) > 0 AND length(kind) <= 128),
    payload BYTEA NOT NULL CHECK (octet_length(payload) <= 1048576),
    available_at_ms BIGINT NOT NULL CHECK (available_at_ms >= 0),
    attempts BIGINT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    lease_owner TEXT CHECK (lease_owner IS NULL OR (length(lease_owner) > 0 AND length(lease_owner) <= 128)),
    lease_until_ms BIGINT CHECK (lease_until_ms IS NULL OR lease_until_ms >= 0),
    created_at_ms BIGINT NOT NULL CHECK (created_at_ms >= 0),
    finished_at_ms BIGINT,
    last_error TEXT CHECK (last_error IS NULL OR length(last_error) <= 4096),
    CHECK ((lease_owner IS NULL) = (lease_until_ms IS NULL)),
    CHECK (finished_at_ms IS NULL OR finished_at_ms >= created_at_ms)
);

CREATE INDEX jobs_claim_order
    ON jobs (finished_at_ms, available_at_ms, lease_until_ms, created_at_ms, id);
