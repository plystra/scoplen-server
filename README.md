# scoplen-server

The self-hosted Scoplen server, host agent, administration CLI, and web-console workspace.
Scoplen is a Plystra project. This repository is licensed under AGPL-3.0-only.

## Status

Maturity: Exploration. Maintenance: Active. The repository baseline is under development. The
current binary provides role selection, validated TOML and `SPL_` environment configuration,
first-run deployment material, a single public listener, health/readiness/metrics endpoints, and
plain or file-based TLS. ACME TLS-ALPN-01 issuance and the storage, identity, sync, control,
gateway, and console product behavior are planned roadmap work and are not implied by this
baseline.

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

## Security

See [SECURITY.md](SECURITY.md). Generated deployment keys, CA keys, and setup links are private
deployment material; keep the data directory out of source control and backups that are not
protected by the operator.
\n