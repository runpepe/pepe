# Protocol

All API endpoints except `/healthz`, `/github`, and the OAuth callback require `Authorization: Bearer <token>`. Use HTTPS outside loopback. The API is intentionally small and currently single-operator.

## Sessions

`POST /sessions` with the admin token:

```json
{"id":"p_example","token":"a-random-secret-of-at-least-32-characters","callback":"https://workspace.example/auth/callback/google"}
```

IDs contain 3–64 ASCII letters, digits, underscores or hyphens, beginning with a letter or digit. Tokens are hashed before storage. Re-registering the same ID requires the same token; it can update the callback. The callback is optional, exact, and has no query, fragment, or embedded credentials. HTTPS is required except for loopback addresses.

`POST /sessions/{id}/remove` with the admin token deletes that session, its routes, its queued events, and its OAuth transactions.

## Webhooks

`POST /github` accepts GitHub JSON and verifies `X-Hub-Signature-256` over the exact request bytes. Maximum body size is 5 MB. Supported events: `pull_request`, `pull_request_review`, `pull_request_review_comment`, and PR `issue_comment` events. Unsupported events return 202 without queueing.

A branch `pepe/{session-id}/{branch}` establishes a route only when the PR head repository ID matches the event's repository ID. The legacy `dev/{session-id}/{branch}` prefix is also recognized. Existing PR bindings win over subsequent branch changes. No event is broadcast. A delivery ID is unique within the relay; duplicates are ignored.

`POST /sessions/{id}/poll` with the session token and `{}` returns at most ten pending events in arrival order:

```json
{"events":[{"delivery":"github-delivery-id","event":"pull_request","body":"BASE64_OF_ORIGINAL_BYTES","signature":"sha256=..."}]}
```

The base64 representation preserves whitespace and exact bytes needed for signature verification. The agent decodes it before HTTP delivery.

`POST /sessions/{id}/ack` with `{"delivery":"github-delivery-id"}` acknowledges only that session's event. Acknowledged records remain for deduplication. Polling does not lease messages: run one agent per identity; concurrent agents can deliver duplicates.

`POST /sessions/{id}/claim` with `{"repo":123456,"pr":42}` pins a PR explicitly. A claim cannot replace another session's binding. This is an operator-trusted API, not a GitHub permission check. It affects future events. Unclaimed records remain unclaimed; inspect or redeliver them from GitHub after establishing ownership.

`POST /status` with the admin token returns session, pending-delivery, and unclaimed-delivery counts. `GET /healthz` checks database connectivity.

## OAuth

Only Google query-mode authorization-code callbacks are supported initially.

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
