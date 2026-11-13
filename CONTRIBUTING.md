# Contributing

Use Go 1.25 or newer. Keep changes focused and include tests for routing, persistence, or protocol changes.

```sh
go test -race ./...
go vet ./...
go build ./cmd/pepe
```

Do not commit credentials, workspace identities, SQLite databases, or signing keys. Avoid logging webhook payloads and OAuth query parameters. Protocol changes must document compatibility. Database changes need versioned migrations and backup/rollback tests.

Open an issue or pull request on GitHub. Contributions are provided under the Apache License 2.0. CI is intentionally deferred for the initial release.
