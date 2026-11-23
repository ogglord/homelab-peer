# Everything runs in the flake's dev shell (Go 1.26, sqlc, gcc for -race).
SHELL := bash
DEV := nix develop --quiet -c

.PHONY: help build vet test gen check stack
help:
	@echo "make build | vet | test | gen | check | stack"

build:
	$(DEV) go build ./...

vet:
	$(DEV) go vet ./...

# The whole suite, uncached, with the race detector: under 30 s.
test:
	$(DEV) go test -race -count=1 ./...

# Regenerate internal/store from db/schema.sql and db/queries.
gen:
	$(DEV) sqlc generate

# What to run before a commit that touches Go or SQL: formatting, generated
# code in step with the SQL, vet and the suite.
check:
	$(DEV) gofmt -l cmd internal db | (! grep .)
	$(DEV) sqlc diff
	$(DEV) go vet ./...
	$(DEV) go test -race -count=1 ./...

# The stack's system, as the homelab daemon builds it.
stack:
	nix build .#nixosConfigurations.peer.config.system.build.toplevel
