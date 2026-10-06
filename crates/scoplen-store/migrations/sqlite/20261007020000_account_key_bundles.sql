-- SPDX-License-Identifier: AGPL-3.0-only

-- Account key artifacts are already encrypted for the account and remain opaque to the
-- persistence layer.  The service validates their cryptographic envelopes before calling this
-- store; these constraints only enforce the wire-level size and identity bounds.
CREATE TABLE sync_account_key_bundles (
    account_id BLOB PRIMARY KEY NOT NULL CHECK (length(account_id) = 16),
    revision INTEGER NOT NULL CHECK (revision > 0),
    account_signing_key BLOB NOT NULL CHECK (length(account_signing_key) > 0 AND length(account_signing_key) <= 65536),
    account_kem_key BLOB NOT NULL CHECK (length(account_kem_key) > 0 AND length(account_kem_key) <= 65536),
    recovery_blob BLOB NOT NULL CHECK (length(recovery_blob) > 0 AND length(recovery_blob) <= 65536),
    signature BLOB NOT NULL CHECK (length(signature) = 64),
    updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0)
);

CREATE TABLE sync_account_key_device_wraps (
    account_id BLOB NOT NULL CHECK (length(account_id) = 16),
    device_id BLOB NOT NULL CHECK (length(device_id) = 16),
    wrapped_ark BLOB NOT NULL CHECK (length(wrapped_ark) > 0 AND length(wrapped_ark) <= 65536),
    PRIMARY KEY (account_id, device_id),
    FOREIGN KEY (account_id) REFERENCES sync_account_key_bundles (account_id) ON DELETE CASCADE
);

CREATE INDEX sync_account_key_device_wraps_by_account
    ON sync_account_key_device_wraps (account_id, device_id);

-- Certificates and revocations are signed opaque statements.  They are kept separately so
-- identity enrollment can publish a device-list change without rewriting the encrypted bundle.
CREATE TABLE sync_account_key_certificates (
    account_id BLOB NOT NULL CHECK (length(account_id) = 16),
    certificate BLOB NOT NULL CHECK (length(certificate) > 0 AND length(certificate) <= 65536),
    PRIMARY KEY (account_id, certificate)
);

CREATE TABLE sync_account_key_revocations (
    account_id BLOB NOT NULL CHECK (length(account_id) = 16),
    revocation BLOB NOT NULL CHECK (length(revocation) > 0 AND length(revocation) <= 65536),
    PRIMARY KEY (account_id, revocation)
);

CREATE INDEX sync_account_key_certificates_by_account
    ON sync_account_key_certificates (account_id);
CREATE INDEX sync_account_key_revocations_by_account
    ON sync_account_key_revocations (account_id);
