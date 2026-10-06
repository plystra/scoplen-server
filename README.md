# scoplen-server

The self-hosted Scoplen server, host agent, administration CLI, and web-console workspace.
Scoplen is a Plystra project. This repository is licensed under AGPL-3.0-only.

## Status

Maturity: Exploration. Maintenance: Active. The repository baseline is under development. The
current binary provides role selection, validated TOML and `SPL_` environment configuration,
first-run deployment material, a single public listener, health/readiness/metrics endpoints, and
plain or file-based TLS. It now opens a durable SQLite database in WAL mode and applies forward
migrations for `api`, `worker`, and `edge` roles; readiness checks that database. The storage layer
also has the first sync foundation: per-vault gap-free sequence allocation, atomic compare-and-swap
batches, current change and snapshot paging, acknowledgement cursors, and bounded version reads.
Standalone `ca` and `gateway` roles do not open SQLite or generate Personal setup material.
PostgreSQL, object storage, public sync endpoints and authentication, envelope validation, retention
and purge jobs, audit, identity, control, gateway, and console behavior are still roadmap work.
ACME TLS-ALPN-01 issuance remains unavailable.

## Repository shape

The Cargo workspace contains the server supervisor and one crate boundary for each server role.
`web/console` is a strict TypeScript package for the future web console. `deploy/` and `docs/`
hold deployment and operational material as those roadmap gates become implementable.

## Development

```text
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
pnpm --dir web/console install --frozen-lockfile
pnpm --dir web/console lint
pnpm --dir web/console typecheck
```

For a local configuration check:

```text
cargo run -p scoplen-server -- --validate-config
```

Run `cargo run -p scoplen-server -- --help` for role selection and configuration options. The
Personal defaults bind to `127.0.0.1:8443` and use a local data directory. A reverse proxy may
terminate TLS and select `tls.mode = "plain"`; direct TLS uses `tls.mode = "files"` with a PEM
certificate and key. `tls.mode = "acme"` is reserved until the ACME implementation lands.
The SQLite database is `scoplen.sqlite` in `server.data_dir`; migrations run before database-backed
roles start, and a migration failure stops startup. These roles currently require
`storage.backend = "sqlite"`.

## Security

See [SECURITY.md](SECURITY.md). The SQLite database, generated deployment keys, CA keys, and setup
links are private deployment material; keep the data directory out of source control and unprotected
backups. Copying only `scoplen.sqlite` while the server is running is not a consistent backup in WAL
mode. Built-in backup and restore are still roadmap work.
