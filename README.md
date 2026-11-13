# Pepe

**Stable callbacks for disposable development environments.**

Run Pepe next to your app. GitHub webhooks and OAuth callbacks find the right workspace, even as branches and development machines change.

[runpepe.dev](https://runpepe.dev) · [Documentation](docs/protocol.md) · Apache-2.0

Pepe is one Go binary with two roles:

- `pepe serve` is a public relay backed by SQLite.
- `pepe run` connects a workspace over outbound HTTPS and forwards its webhooks to your app.

The relay remembers which workspace owns each PR. Comments and reviews follow that binding. Offline workspaces keep their queued events; restarting the relay preserves state.

## Install the binary

Download `pepe_<os>_<arch>` from [Releases](https://github.com/marccampbell/pepe/releases), make it executable, and place it on your PATH as `pepe`. Releases include Linux and macOS binaries for amd64 and arm64; no additional runtime is required. See [release verification](docs/operations.md#release-verification).

Or build with Go 1.25 or newer:

```sh
go install github.com/marccampbell/pepe/cmd/pepe@latest
```

## Start a relay

For local development, generate two independent secrets (at least 32 characters each):

```sh
export PEPE_ADMIN_TOKEN="$(openssl rand -hex 32)"
export PEPE_GITHUB_WEBHOOK_SECRET="$(openssl rand -hex 32)"
pepe serve --public-url http://localhost:8080 --db ./pepe.sqlite
```

For a Linux server behind your existing HTTPS proxy:

```sh
sudo pepe install --public-url https://pepe.example.com
```

Or use Caddy, installed from its official OS package, for automatic HTTPS:

```sh
sudo pepe install --domain pepe.example.com --proxy caddy
```

Point DNS at the server and allow inbound ports 80/443. Pepe listens on `127.0.0.1:8080`. If you already have a Caddyfile, add `import /etc/caddy/pepe.caddy` before running the installer. Pepe preserves existing proxy configuration. `--dry-run` previews installation without changing the host.

The installer generates credentials in `/etc/pepe/pepe.json`, installs `pepe.service`, and puts state in `/var/lib/pepe/`. Credentials are not printed. See [operations](docs/operations.md).

## Connect a workspace

Set your relay URL and its admin token in the workspace's environment:

```sh
export PEPE_SERVER=https://pepe.example.com
export PEPE_ADMIN_TOKEN='<your relay admin token>'
pepe run --target http://127.0.0.1:3000/api/github/webhook
```

The first run saves a private identity in `.pepe/identity.json`. Add `.pepe/` to your application's `.gitignore`. Keep this identity across restarts; use a separate identity for each independent workspace. The command prints its branch prefix, for example:

```text
Pepe connected · p_24b3a4c5d6e7
Branch prefix: pepe/p_24b3a4c5d6e7/
```

Create branches under that prefix. When a PR event arrives, Pepe pins `(repository ID, PR number)` to that workspace. Reviews and comments continue to route there after a branch rename. Fork-origin PRs cannot establish a route by copying a prefix. Unknown events remain unclaimed rather than being broadcast.

For an existing branch, explicitly claim its PR before sending events:

```sh
pepe claim --repo 12345678 --pr 42
pepe status
```

`--repo` is GitHub's numeric repository ID, not `owner/name`. Claiming cannot overwrite another workspace's binding. Unclaimed deliveries are retained. After establishing ownership, use `pepe replay --delivery <delivery-id>` to route a stored event to its current owner. A claim by itself does not dispatch old events.

Configure your GitHub App or repository webhook:

- URL: `https://pepe.example.com/github`
- Content type: `application/json`
- Secret: the relay's `webhook_secret`
- Events: pull requests, pull request reviews, pull request review comments, and issue comments

Pepe verifies GitHub's signature and preserves payload bytes, delivery IDs, and event names. By default it forwards the original signature. If your local app uses a different secret, set `PEPE_LOCAL_WEBHOOK_SECRET`; the agent re-signs the original bytes with that secret. Only a successful local 2xx response acknowledges a delivery. Delivery is **at least once** within each attempt. Your app should deduplicate `(X-GitHub-Delivery, X-Pepe-Attempt)` and keep business operations idempotent. Automatic retries keep the same attempt; an explicit replay increments it.

## Route Google OAuth callbacks

Run your workspace with its exact application callback:

```sh
pepe run --callback https://workspace.example.com/auth/callback/google
```

Register `https://pepe.example.com/oauth/google/callback` with Google. Before redirecting the browser to Google, your app calls the authenticated Pepe transaction endpoint, passing its original OAuth state. Use the returned opaque state in the provider request. Pepe consumes it once, restores your application's original state, and redirects to the workspace callback.

Your app still validates its state cookie and exchanges the code using the **same stable redirect URI** supplied to Google. See the complete [OAuth integration contract](docs/protocol.md#oauth).

OAuth requires this application integration; `pepe run` alone cannot intercept your login flow. A browser must be able to reach the workspace callback. Pepe does not currently provide a public HTTP tunnel. A localhost callback works only for a browser on that same machine.

## Upgrade

```sh
pepe upgrade --check
sudo pepe upgrade
sudo pepe upgrade --version v0.2.0
```

Upgrades verify an Ed25519-signed release manifest and binary checksum. On an installed Linux relay, Pepe stops the service, backs up SQLite, replaces the executable, and verifies health. Failed startup triggers restoration of the prior binary and database. Configuration and Caddy remain independent. Package-manager installations should be upgraded through their package manager.

## Replay a stored delivery

```sh
pepe replay --delivery <upstream-delivery-id>
```

Pepe requeues the saved bytes without asking GitHub to resend. Already routed events retain their owner. An unclaimed event must resolve to this workspace under current routing rules (use `pepe claim` first if needed). Replays preserve the upstream delivery ID and increment `X-Pepe-Attempt`. Acknowledgements for older attempts cannot clear the replay.

## Scope of v0.2

This is a self-hosted, single-operator relay. Anyone holding its admin token is trusted to register workspaces and inspect queue counts. Use separate relay instances and secrets for mutually untrusted teams. Project-scoped membership, a hosted service, a browser inspector, generic provider plugins, automatic retention, and a public tunnel are not implemented.

The initial routing behavior is adapted from the Doomer development router, with portable workspace IDs and opaque, single-use OAuth transactions. Only `pepe/<session-id>/<branch>` establishes a route; legacy `dev/` prefixes are not supported. Polling returns metadata, and a separate authenticated endpoint returns the exact original payload as its HTTP body. It does not migrate a running Doomer router or alter its deployment. There is no CI yet.

## Development

```sh
go test -race ./...
go vet ./...
go build -o pepe ./cmd/pepe
```

Tests cover signature validation, exact payload preservation, routing, deduplication, acknowledgements, isolation, persistence, OAuth expiry/replay protection, local forwarding failures, installer planning, and release verification rejection.

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).
