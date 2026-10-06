# Scoplen server principles

Scoplen is a Plystra project. This record applies the shared adoption record in
[`../scoplen-docs/PROJECT_PRINCIPLES.md`](../scoplen-docs/PROJECT_PRINCIPLES.md) to the
self-hosted server, host agent, administration CLI, and web console.

## Current boundary

- The server owns durable service behavior, role supervision, operator configuration, and the
  web console. It does not own client source or shared wire contracts.
- The vendor does not receive deployment data. Operators control the server's data directory,
  keys, logs, backups, and retention.
- The repository is Exploration maturity until the roadmap evidence is complete. The baseline
  listener is useful for local development and reverse-proxy integration; it is not a complete
  production server.

## Open gaps

- ACME TLS-ALPN-01 issuance and renewal are not implemented.
- SQLite migration, transaction, initial sync storage, and an atomic retention primitive exist.
  Public sync endpoints, authentication, membership-aware purge scheduling, PostgreSQL, object
  storage, identity, policy, certificate, gateway, audit, agent, CLI, and console behavior remain
  on the roadmap.
- Deployment, backup/restore, upgrade, and release artifacts require their own validated gates.

## Review

Review this record with the project record before a new public surface or a maturity change.
