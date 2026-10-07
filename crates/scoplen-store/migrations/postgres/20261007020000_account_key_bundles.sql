-- SPDX-License-Identifier: AGPL-3.0-only

-- Account key artifacts are already encrypted for the account and remain opaque to the
-- persistence layer. These constraints enforce wire-level size and identity bounds.
CREATE TABLE sync_account_key_bundles (
    account_id BYTEA PRIMARY KEY NOT NULL CHECK (octet_length(account_id) = 16),
    revision BIGINT NOT NULL CHECK (revision > 0),
    account_signing_key BYTEA NOT NULL CHECK (octet_length(account_signing_key) > 0 AND octet_length(account_signing_key) <= 65536),
    account_kem_key BYTEA NOT NULL CHECK (octet_length(account_kem_key) > 0 AND octet_length(account_kem_key) <= 65536),
    recovery_blob BYTEA NOT NULL CHECK (octet_length(recovery_blob) > 0 AND octet_length(recovery_blob) <= 65536),
    signature BYTEA NOT NULL CHECK (octet_length(signature) = 64),
    updated_at_ms BIGINT NOT NULL CHECK (updated_at_ms >= 0)
);

CREATE TABLE sync_account_key_device_wraps (
    account_id BYTEA NOT NULL CHECK (octet_length(account_id) = 16),
    device_id BYTEA NOT NULL CHECK (octet_length(device_id) = 16),
    wrapped_ark BYTEA NOT NULL CHECK (octet_length(wrapped_ark) > 0 AND octet_length(wrapped_ark) <= 65536),
    PRIMARY KEY (account_id, device_id),
    FOREIGN KEY (account_id) REFERENCES sync_account_key_bundles (account_id) ON DELETE CASCADE
);

CREATE INDEX sync_account_key_device_wraps_by_account
    ON sync_account_key_device_wraps (account_id, device_id);

CREATE TABLE sync_account_key_certificates (
    account_id BYTEA NOT NULL CHECK (octet_length(account_id) = 16),
    certificate BYTEA NOT NULL CHECK (octet_length(certificate) > 0 AND octet_length(certificate) <= 65536),
    PRIMARY KEY (account_id, certificate)
);

CREATE TABLE sync_account_key_revocations (
    account_id BYTEA NOT NULL CHECK (octet_length(account_id) = 16),
    revocation BYTEA NOT NULL CHECK (octet_length(revocation) > 0 AND octet_length(revocation) <= 65536),
    PRIMARY KEY (account_id, revocation)
);

CREATE INDEX sync_account_key_certificates_by_account
    ON sync_account_key_certificates (account_id);
CREATE INDEX sync_account_key_revocations_by_account
    ON sync_account_key_revocations (account_id);
