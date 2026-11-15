# Operations

## PostgreSQL development

Set `DATABASE_URL`, `PEPE_SERVER`, `PEPE_ADMIN_TOKEN`, and
`PEPE_GITHUB_WEBHOOK_SECRET` in Doppler `pepe/dev`. Then run:

```sh
make migrate
make dev PEPE_STORAGE=postgres
```

`make migrate` plans and applies only `schema/tables/` through SchemaHero.
These manifests define `pepe_namespaces`, `pepe_sessions`, `pepe_routes`,
`pepe_events`, and `pepe_oauth`, with no foreign keys. The application never
applies PostgreSQL schema changes during startup. Keep the connection string in
Doppler; the development command receives it through the environment.

`pepe serve --storage postgres` reads `DATABASE_URL`. The optional
`--database-url` flag or `database_url` JSON config field can also supply it.
SQLite remains the default storage backend. PostgreSQL namespace stores share
the configured database, with namespace-scoped keys and queries. Use PostgreSQL
backup tools for this backend.

## Configuration

`pepe serve` accepts flags and `PEPE_ADMIN_TOKEN` / `PEPE_GITHUB_WEBHOOK_SECRET`. With `--config`, a JSON file replaces those settings:

```json
{
  "listen": "127.0.0.1:8080",
  "public_url": "https://pepe.example.com",
  "database": "/var/lib/pepe/pepe.sqlite",
  "admin_token": "REPLACE_WITH_AT_LEAST_32_RANDOM_CHARACTERS",
  "webhook_secret": "REPLACE_WITH_ANOTHER_RANDOM_SECRET_AT_LEAST_32_CHARS"
}
```

Keep this file private. The Linux installer uses mode 0600 and assigns it to the unprivileged `pepe` service account. SQLite uses WAL, full synchronization, foreign keys, and a busy timeout. It is intended for a single relay instance on local persistent storage, not a shared network filesystem.

Pepe does not trust forwarded headers to construct callback URLs: `public_url` is explicit. It has no IP-based authorization decisions. Keep its listener private behind a proxy; terminate TLS at that proxy.

## systemd and TLS

```sh
sudo pepe install --domain pepe.example.com --proxy caddy --dry-run
sudo pepe install --domain pepe.example.com --proxy caddy
sudo systemctl status pepe
sudo journalctl -u pepe -f
```

Install Caddy first from its official package. If a Caddyfile already exists, explicitly add `import /etc/caddy/pepe.caddy`; the installer will not replace it. It writes only the dedicated `/etc/caddy/pepe.caddy` fragment, validates Caddy configuration, and reloads Caddy. DNS and ports 80/443 must allow certificate issuance. Caddy handles certificate storage and renewal. See [Caddy documentation](https://caddyserver.com/docs/automatic-https).

Without `--proxy caddy`, configure your existing proxy to forward to `127.0.0.1:8080`. For example:

```caddyfile
pepe.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Repeated installation preserves existing credentials and configuration. Use the same public URL on reinstall. Edit `/etc/pepe/pepe.json` deliberately if changing the deployment, then restart the service. The installer does not set firewall rules, install OS packages, or register provider webhooks on your behalf.

```sh
sudo pepe uninstall          # preserves configuration and state
sudo pepe uninstall --purge  # deletes configuration, credentials and queues
```

Uninstall leaves Caddy and its route in place so it cannot accidentally disturb other sites. Remove `/etc/caddy/pepe.caddy` and its import when decommissioning the endpoint. The service account is preserved for ownership of retained data.

## Backups and retention

Stop the service before making a simple filesystem copy of the database. For online backups use SQLite's backup API or `VACUUM INTO`; do not copy only the main SQLite file while WAL writes are active.

Automatic upgrade backups are retained next to the database. Store off-host backups separately. Events, including acknowledged and unclaimed events, have no automatic retention during development. Monitor disk usage. Deleting acknowledged records also removes their deduplication history. Deleting a session removes all its routing and delivery state.

## Development versions and updates

Pepe is v0.0 and pre-release. Do not create tags or publish releases until the maintainer explicitly authorizes v0.1. Track builds by source commit; no backward compatibility is promised for the API or SQLite schema.

Build current source and pass the resulting executable to `pepe upgrade --binary /path/to/pepe`. `--check` inspects the candidate without replacing the installation. No binary is downloaded automatically. Use only builds you trust.

Installed service updates retain a database backup, replace the executable atomically, restart the service, and verify health. Caddy and configuration are preserved. Development schema changes may require a deliberate state reset; no migration framework is maintained yet.
