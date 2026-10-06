# Server architecture

`spl-server` is a single process with role selection. The role names are `api`, `worker`, `ca`,
`edge`, and `gateway`; `all` expands to those roles in a stable order. The process loads one TOML
configuration, applies non-empty `SPL_` environment overrides, validates local invariants, and
then creates first-run material before starting the selected roles.

The public listener is one TCP port. In `plain` mode it is intended to sit behind a trusted TLS
terminator. In `files` mode it terminates TLS itself and advertises `h2`, `http/1.1`, and
`spl-gw/1` through ALPN. The gateway protocol is reserved for the managed data-path gate and is
not accepted by the baseline listener yet. `acme` is parsed and validated but deliberately fails
at startup until TLS-ALPN-01 is implemented.

The baseline exposes `/healthz`, `/readyz`, and `/metrics`. Logs are JSON tracing events; secret
material is written only under the configured data directory and is never included in request
responses or logs.

The relational storage boundary currently supports SQLite only. Startup opens
`server.data_dir/scoplen.sqlite`, enables WAL and foreign keys on pooled connections, and applies
embedded forward migrations before generating first-run material. The first migration establishes
the organization table with
identifier, nonempty name, and creation-time constraints. A migration error prevents roles from
starting. `/readyz` queries the database and returns 503 when the query fails. PostgreSQL,
parallel migration equivalence, application-level column encryption, object storage, audit,
and worker jobs remain V2 work.
