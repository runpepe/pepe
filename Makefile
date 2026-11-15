DOPPLER_PROJECT ?= pepe
DOPPLER_CONFIG ?= dev
PEPE_LISTEN ?= 0.0.0.0:8080
PEPE_STORAGE ?= sqlite
SCHEMAHERO ?= schemahero
export SCHEMAHERO
PEPE_DB ?= .pepe/relay.sqlite

.PHONY: dev migrate
dev:
	doppler run --project "$(DOPPLER_PROJECT)" --config "$(DOPPLER_CONFIG)" -- \
		sh -ec 'exec go run ./cmd/pepe serve \
			--storage "$$3" \
			--listen "$$1" \
			--db "$$2" \
			--public-url "$${PEPE_PUBLIC_URL:-$${PEPE_SERVER:?Set PEPE_PUBLIC_URL or PEPE_SERVER in Doppler}}"' \
		sh "$(PEPE_LISTEN)" "$(PEPE_DB)" "$(PEPE_STORAGE)"

migrate:
	doppler run --project "$(DOPPLER_PROJECT)" --config "$(DOPPLER_CONFIG)" -- sh scripts/migrate.sh
