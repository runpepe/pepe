# Protocol

All API endpoints except `/healthz`, `/github`, and the OAuth callback require `Authorization: Bearer <token>`. Use HTTPS outside loopback. The API supports operator-managed namespaces.

## Sessions

`POST /sessions` with the admin token:

```json
{"id":"p_example","token":"a-random-secret-of-at-least-32-characters","callback":"https://workspace.example/auth/callback/google"}
```

IDs contain 3–64 ASCII letters, digits, underscores or hyphens, beginning with a letter or digit. Tokens are hashed before storage. Re-registering the same ID requires the same token; it can update the callback. The callback is optional, exact, and has no query, fragment, or embedded credentials. HTTPS is required except for loopback addresses.

`POST /sessions/{id}/remove` with the admin token deletes that session, its routes, its queued events, and its OAuth transactions.

## Webhooks

`POST /github` accepts GitHub JSON and verifies `X-Hub-Signature-256` over the exact request bytes. Maximum body size is 5 MB. Supported events: `pull_request`, `pull_request_review`, `pull_request_review_comment`, and PR `issue_comment` events. Unsupported events return 202 without queueing.

A branch `pepe/{session-id}/{branch}` establishes a route only when the PR head repository ID matches the event's repository ID. Legacy `dev/` prefixes are not recognized. Existing PR bindings win over subsequent branch changes. No event is broadcast. A delivery ID is unique within the relay; duplicates are ignored.

`POST /sessions/{id}/poll` with the session token and `{}` returns at most ten pending deliveries in arrival order. This is metadata only:

```json
{"events":[{"delivery":"github-delivery-id","event":"pull_request","signature":"sha256=...","attempt":1}]}
```

`GET /sessions/{id}/events/{delivery-id}?attempt=1` with the session token returns the **exact original upstream bytes as the HTTP response body**, with `Content-Type: application/json`. There is no envelope, base64 encoding, or JSON reserialization. URL-encode the delivery ID. Response headers include `X-GitHub-Delivery`, `X-GitHub-Event`, `X-Hub-Signature-256`, and `X-Pepe-Attempt`. A stale attempt returns 409. Another session cannot fetch the event.

Forward these bytes unchanged to your application's webhook endpoint. The bundled agent forwards the upstream headers plus `X-Pepe-Attempt`; it can optionally re-sign the unchanged body using `PEPE_LOCAL_WEBHOOK_SECRET` when your application uses a different secret.

`POST /sessions/{id}/ack` with `{"delivery":"github-delivery-id","attempt":1}` acknowledges only that session's current attempt. A stale or mismatched attempt returns 409. Acknowledged records remain available for deduplication and explicit replay. Polling does not lease messages: run one agent per identity; concurrent agents can deliver duplicates.

`POST /sessions/{id}/replay` with `{"delivery":"github-delivery-id"}` requeues the saved payload. The response includes `delivery`, the incremented `attempt`, and `queued: true`. The upstream delivery ID and raw bytes remain unchanged. The same workspace must own the event. For an unclaimed event, Pepe reevaluates routing from the stored payload; a current route to the requesting workspace is required. Use `claim` first if necessary. Missing/other-owner deliveries return 404; an unresolved route returns 409. Upstream redeliveries still deduplicate; explicit replay is how to request another delivery attempt.

Consumers should deduplicate `(X-GitHub-Delivery, X-Pepe-Attempt)` after successful processing, and maintain idempotent business operations. Ordinary retries use the same attempt. Explicit replay creates a new attempt and may intentionally reprocess an event.

`POST /sessions/{id}/claim` with `{"repo":123456,"pr":42}` pins a PR explicitly. A claim cannot replace another session's binding. This is an operator-trusted API, not a GitHub permission check. It does not automatically dispatch old events. Replay a stored unclaimed delivery after establishing ownership.

`POST /status` with the admin token returns session, pending-delivery, and unclaimed-delivery counts. `GET /healthz` checks database connectivity.

## OAuth

Only Google query-mode authorization-code callbacks are supported. Legacy Doomer signed routing-state payloads are not supported.

1. Your app generates and stores its usual state and PKCE verifier, if applicable.
2. From the app's backend, call `POST /sessions/{id}/oauth` using the session token:

   ```json
   {"provider":"google","state":"original-app-state"}
   ```

3. Pepe responds:

   ```json
   {"state":"opaque-pepe-transaction-token","redirect_uri":"https://pepe.example.com/oauth/google/callback"}
   ```

4. Send the browser to Google's authorization endpoint with the returned `state` and `redirect_uri`. Preserve your normal client ID, scopes, and PKCE parameters.
5. Google calls the stable Pepe callback. Pepe rejects duplicate query parameters, invalid tokens, expired transactions, and replay. Transactions expire after ten minutes.
6. Pepe redirects to the session's registered callback, forwarding `code` or `error` and restoring the original app state. Your app verifies its original state cookie and performs the code exchange with the stable redirect URI from step 3.

Each transaction snapshots the exact registered callback at creation. Later registration changes cannot redirect an in-progress login to another destination.

OAuth codes and states are excluded from server access logs. Original app state is stored until redemption or expiry cleanup; expired transactions are cleaned when new ones are created. Provider credentials and tokens stay with the app. Browser reachability and cookie behavior remain the application's responsibility.

## Namespaces

Requests without a namespace use `default`. Existing self-hosted commands and
URLs continue to work without extra configuration. `/namespaces/default/` also
addresses that namespace explicitly.

Create a named namespace with the relay administrator credential using
`POST /namespaces` and a JSON body containing `id`, `token`, and `webhook_secret`.
IDs use the session ID format above. Both secrets must be at least 32 characters.
The namespace management token is hashed at rest. The webhook signing secret is
stored privately because signature verification requires the original secret.
Retrying creation requires the same credentials. Creating `default` is rejected.

The response contains the namespace's `url`, for example
`https://pepe.example.com/namespaces/my-team`. All session, webhook, status, and
OAuth endpoints for that namespace are relative to this URL. Register the
namespace-specific Google callback and GitHub webhook URL with those providers.
SQLite gives each namespace an independent store. PostgreSQL uses namespace-scoped
keys in shared tables. Both isolate session IDs, PR routes, delivery IDs, and OAuth transactions. Tokens and signing secrets from another
namespace do not grant access. Namespace selection comes from the URL, never an
incoming identity header. The relay administrator can manage all namespaces.

CLI clients can use `--namespace my-team` or `PEPE_NAMESPACE=my-team` with the
relay origin in `PEPE_SERVER`. Use the namespace management token as
`PEPE_ADMIN_TOKEN` for registration and status. Use a separate identity file for
each environment/namespace. Session tokens continue to authorize only their own
session. A namespace management token cannot create other namespaces.

Namespace boundaries establish isolation between operator-provisioned groups.
Within a namespace, PR claims remain operator-trusted. Namespace creation and
GitHub webhook provisioning should only be granted to an authorized controller.

The default database remains at the configured `--db` path. Named stores are in
`<db>.namespaces/<namespace>.sqlite`, and their credential registry is in the
default database. Include both the default database and the namespace directory
in backups. The store-level backup operation covers its selected database only.
