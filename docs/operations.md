# Operations

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

Automatic upgrade backups are retained next to the database. Store off-host backups separately. Events, including acknowledged and unclaimed events, have no automatic retention in v0.2. Monitor disk usage. Deleting acknowledged records also removes their deduplication history. Deleting a session removes all its routing and delivery state.

## Release verification

Official release assets are plain executables, plus `manifest.json` and its raw Ed25519 signature `manifest.sig`. The signed manifest binds a version and SHA-256 digest to each platform binary. `pepe upgrade` embeds this public key:

```text
Pb/DI60gEUsD/KSlfSnSlSwix84CU5a99EiHt2dL32k=
```

The public key is the base64-encoded 32-byte Ed25519 public key. Verify the raw manifest bytes against `manifest.sig`, then compare the selected executable's SHA-256 with the signed entry. Bootstrap trust comes from obtaining the initial binary or source from a trusted channel. Later upgrades require both a valid signature and matching binary hash.

`pepe upgrade --check` verifies the manifest without replacing anything. `--version vX.Y.Z` selects an explicit stable version, including a deliberate downgrade. Database schema support still applies; keep backups. For service upgrades, Pepe stops traffic before backup and migration; OAuth requests can fail during this short downtime and should be restarted by the user. Queued webhooks survive. A failed new service restores the previous executable and pre-upgrade database before restarting.

## Publishing a release

No CI is required. Keep the signing key outside the repository. With Go installed:

```sh
go test -race ./...
go vet ./...
go run ./scripts/release v0.2.0 /private/path/to/signing-key
git tag v0.2.0
git push origin v0.2.0
gh release create v0.2.0 dist/pepe_* dist/manifest.json dist/manifest.sig --title v0.2.0 --notes-file release-notes.md
```

The release helper expects a base64-encoded 64-byte Ed25519 private key matching the embedded public key. It builds Linux/macOS on amd64/arm64 with CGO disabled, then signs a manifest of the exact binaries. Never commit or attach the private key. Pin and audit release dependencies before signing.

## v0.2 upgrade notes

v0.2 changes the wire protocol: poll returns metadata; payloads are fetched as raw HTTP bodies. Acknowledgements require `attempt`; replays increment it. Upgrade agents with the relay. `dev/` branch prefixes are no longer accepted. Existing pinned PR routes and stored events survive the upgrade. SQLite schema v2 adds the attempt counter transactionally, defaulting existing events to attempt 1. Back up before upgrading. Old binaries cannot directly open the migrated schema; use a matching pre-upgrade backup when rolling back to v0.1.
