## tokyo3-ssh-proxy — build targets
##
## Usage:
##   make build           Build ssh-proxyd + ssh-tunneld binaries to ./bin/
##   make test            Run all tests
##   make check           Full pre-commit sequence (gofmt + test + vet + staticcheck + gopls + govulncheck + deadcode)
##   make tidy            Run go mod tidy
##   make gen-certs       Generate dev TLS material + SSH keys in ./certs/ via mkcert (host-side)
##   make docker-build    Build the proxy Docker image (linux/arm64, default)
##   make docker-up       Run gen-certs (if needed) and bring up the compose rig
##   make docker-down     Stop the compose rig (preserves nats-data + ./certs/)
##   make install         Install both binaries to GOPATH/bin
##   make clean           Remove ./bin/
##   make clean-all       Remove ./bin/ AND ./certs/ (full reset)
##   make help            Show this help

# ── Variables ─────────────────────────────────────────────────────────────────

MODULE          := github.com/abagile/tokyo3-ssh-proxy
CMD_PROXYD      := ./cmd/ssh-proxyd
CMD_TUNNELD     := ./cmd/ssh-tunneld

BIN_DIR         := bin
PROXYD_BIN      := $(BIN_DIR)/ssh-proxyd
TUNNELD_BIN     := $(BIN_DIR)/ssh-tunneld

GIT_TAG    := $(shell git describe --tags --exact-match 2>/dev/null || true)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
VERSION    := $(if $(GIT_TAG),$(GIT_TAG),dev-$(GIT_COMMIT))

LDFLAGS := -s -w -X main.Version=$(VERSION)

GO      := go
GOFLAGS :=

IMAGE_NAME ?= abagile/tokyo3-ssh-proxy
IMAGE_TAG  ?= $(VERSION)

# ── Phony targets ─────────────────────────────────────────────────────────────

.PHONY: all build build-linux build-linux-amd64 build-darwin \
        test test-verbose tidy vet lint check \
        gen-certs _sync-shared \
        docker-build docker-build-amd64 docker-push \
        docker-up docker-down \
        install clean clean-all help

# ── shared_data volume ────────────────────────────────────────────────────────
# shared_data is declared `external` in docker-compose.yml because the
# Makefile (not compose) owns it: _sync-shared creates and populates it
# before compose runs. The external volume's name is pinned to
# <project>_shared_data, so COMPOSE_PROJECT_NAME must reach the compose
# subprocess for both project namespacing and the ${COMPOSE_PROJECT_NAME}
# interpolation in the volume `name:` — hence the `export` below. Default
# is "ssh-proxy" (the directory name); override it if you run with -p.
COMPOSE_PROJECT_NAME ?= ssh-proxy
export COMPOSE_PROJECT_NAME
SHARED_VOLUME        := $(COMPOSE_PROJECT_NAME)_shared_data

all: build

# ── Build ─────────────────────────────────────────────────────────────────────

## build: Compile ssh-proxyd + ssh-tunneld into ./bin/
build: $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(PROXYD_BIN) $(CMD_PROXYD)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(TUNNELD_BIN) $(CMD_TUNNELD)
	@echo "  built $(PROXYD_BIN) + $(TUNNELD_BIN) ($(VERSION))"

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

## build-linux: Cross-compile for Linux arm64 (Graviton, default)
build-linux: $(BIN_DIR)
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/ssh-proxyd-linux-arm64 $(CMD_PROXYD)
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/ssh-tunneld-linux-arm64 $(CMD_TUNNELD)
	@echo "  built ssh-proxyd-linux-arm64 + ssh-tunneld-linux-arm64"

## build-linux-amd64: Cross-compile for Linux amd64
build-linux-amd64: $(BIN_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/ssh-proxyd-linux-amd64 $(CMD_PROXYD)
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/ssh-tunneld-linux-amd64 $(CMD_TUNNELD)
	@echo "  built ssh-proxyd-linux-amd64 + ssh-tunneld-linux-amd64"

## build-darwin: Cross-compile for macOS arm64
build-darwin: $(BIN_DIR)
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/ssh-proxyd-darwin-arm64 $(CMD_PROXYD)
	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/ssh-tunneld-darwin-arm64 $(CMD_TUNNELD)
	@echo "  built ssh-proxyd-darwin-arm64 + ssh-tunneld-darwin-arm64"

# ── Quality ───────────────────────────────────────────────────────────────────

## test: Run all tests
test:
	$(GO) test ./... -count=1

## test-verbose: Run all tests with verbose output
test-verbose:
	$(GO) test ./... -count=1 -v

## tidy: Run go mod tidy
tidy:
	$(GO) mod tidy

## vet: Run go vet
vet:
	$(GO) vet ./...

## lint: Run staticcheck
lint:
	staticcheck ./...

## check: Full pre-commit sequence (gofmt + test + vet + staticcheck + gopls + govulncheck + deadcode)
check:
	gofmt -s -w .
	$(GO) test ./... -count=1
	$(GO) vet ./...
	staticcheck ./...
	find . -type f -name "*.go" -print0 | xargs -0 -n 100 gopls check -severity=hint
	govulncheck ./...
	@out=$$(deadcode -test ./...); if [ -n "$$out" ]; then echo "$$out"; echo "deadcode: unreachable functions found (above)"; exit 1; fi

# ── Docker ────────────────────────────────────────────────────────────────────

## docker-build: Build the proxy Docker image (linux/arm64, default)
docker-build:
	docker build \
	  --platform linux/arm64 \
	  --build-arg TARGETARCH=arm64 \
	  --target proxy \
	  -t $(IMAGE_NAME):$(IMAGE_TAG) \
	  -t $(IMAGE_NAME):latest \
	  .
	@echo "  built $(IMAGE_NAME):$(IMAGE_TAG)"

## docker-build-amd64: Build the proxy Docker image for linux/amd64
docker-build-amd64:
	docker build \
	  --platform linux/amd64 \
	  --build-arg TARGETARCH=amd64 \
	  --target proxy \
	  -t $(IMAGE_NAME):$(IMAGE_TAG)-amd64 \
	  .

## docker-push: Push image to registry (set IMAGE_NAME to your registry repo)
docker-push: docker-build
	docker push $(IMAGE_NAME):$(IMAGE_TAG)
	docker push $(IMAGE_NAME):latest

# ── Dev rig (docker compose) ──────────────────────────────────────────────────

## gen-certs: Generate dev TLS material + SSH keys in ./shared/certs/ via mkcert (host-side).
## Pre-flight for `make docker-up`: mints the dev CA (via mkcert),
## the certd HTTPS cert, ssh-proxyd's tunnel-listener cert, the
## ssh-proxyd/ssh-tunneld workload certs, certd's SSH user CA
## (certd-signing.key/.pub), and the demo user keypair. Idempotent —
## re-runs regenerate X.509 leaves but preserve the SSH keys.
gen-certs:
	@bash shared/certs/gen.sh

## _sync-shared: Tar-pipe ./shared/ into the shared_data named volume.
## Containers see the directory at /shared/. Runs gen-certs first if
## ./shared/certs/ca.crt is missing.
_sync-shared:
	@if [ ! -f shared/certs/ca.crt ]; then $(MAKE) gen-certs; fi
	@docker volume create $(SHARED_VOLUME) >/dev/null
	@tar -cf - -C shared . | docker run --rm -i -v $(SHARED_VOLUME):/shared alpine:3.21 sh -c "tar -xf - -C /shared"
	@echo "  synced ./shared/ → docker volume $(SHARED_VOLUME)"

## docker-up: Sync shared/ into shared_data and bring up the compose rig.
## Requires a sibling tokyo3-ca checkout at ../ca/ (certd builds from there).
docker-up: _sync-shared
	docker compose up -d --build --wait

## docker-down: Stop the compose rig (preserves volumes)
docker-down:
	docker compose down

# ── Install / Clean ───────────────────────────────────────────────────────────

## install: Install both binaries to GOPATH/bin
install:
	$(GO) install $(CMD_PROXYD)
	$(GO) install $(CMD_TUNNELD)

## clean: Remove ./bin/
clean:
	rm -rf $(BIN_DIR)

## clean-all: Full reset — wipes ./bin/, generated material under
## ./shared/certs/, AND the compose-managed named volumes
## (shared_data, nats-data). Next `make docker-up` starts from scratch.
clean-all: clean
	docker compose down -v --remove-orphans 2>/dev/null || true
	docker volume rm $(SHARED_VOLUME) 2>/dev/null || true
	rm -f shared/certs/*.crt shared/certs/*.key shared/certs/*.pub shared/certs/*.srl
	rm -f shared/certs/user shared/certs/user-cert.pub
	@echo "  removed shared/certs/*.{crt,key,pub,srl} + user keys + named volumes"

# ── Help ──────────────────────────────────────────────────────────────────────

## help: Show this help
help:
	@grep -h '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
