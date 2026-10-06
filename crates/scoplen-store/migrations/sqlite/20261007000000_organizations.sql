-- SPDX-License-Identifier: AGPL-3.0-only
CREATE TABLE organizations (
    id BLOB PRIMARY KEY NOT NULL CHECK (length(id) = 16),
    name TEXT NOT NULL CHECK (length(name) > 0),
    created_at_ms INTEGER NOT NULL CHECK (created_at_ms >= 0)
);
