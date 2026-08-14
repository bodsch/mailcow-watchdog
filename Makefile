# mailcow-watchdog Makefile
#
# All build/test/quality logic lives here so CI configs stay thin wrappers that
# only invoke `make` targets.
#
# Everything below the variable block is identical to the Makefile in
# mailcow-dockerapi, apart from the service-specific targets at the very bottom.
# Change it in one repository, then copy it to the other — see CONVENTIONS.md.

BINARY   := watchdog
CMD_PKG  := ./cmd/watchdog/
IMAGE    := mailcow/watchdog

# --- shared from here on ------------------------------------------------------

BIN_DIR  := bin
DIST_DIR := dist

# Version metadata, overridable from the environment / CI.
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

LDFLAGS := -s -w -X main.version=$(VERSION)

# Static binaries: the runtime image is distroless, there is nothing to link
# against. The race detector is the exception — see the test target.
export CGO_ENABLED := 0

# The container only ever runs on Linux; the others are for local development.
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

GO       := go
GOLANGCI := golangci-lint

.DEFAULT_GOAL := build

.PHONY: help
help: ## Show this help.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the binary into bin/.
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$(BINARY) $(CMD_PKG)

# The race detector requires cgo and a C compiler on every platform except
# darwin, where it also links without one. Overriding CGO_ENABLED here rather
# than dropping the export above keeps the binaries static while letting the
# tests run: without it, `go test -race` fails on Linux with
# "-race requires cgo; enable cgo by setting CGO_ENABLED=1".
.PHONY: test
test: ## Run the test suite with the race detector (needs a C compiler).
	CGO_ENABLED=1 $(GO) test -race -count=1 ./...

.PHONY: cover
cover: ## Run tests and write a coverage profile.
	CGO_ENABLED=1 $(GO) test -race -count=1 -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -n 1

.PHONY: bench
bench: ## Run micro-benchmarks (no tests) with allocation stats.
	CGO_ENABLED=1 $(GO) test -run '^$$' -bench . -benchmem ./...

.PHONY: fmt
fmt: ## Fail if anything is not gofmt-clean.
	@out="$$(gofmt -l cmd internal)"; \
	if [ -n "$$out" ]; then echo "not gofmt-clean:"; echo "$$out"; echo "run 'gofmt -w cmd internal'."; exit 1; fi

.PHONY: vet
vet: ## Run go vet.
	$(GO) vet ./...

.PHONY: lint
lint: ## Run golangci-lint (uses .golangci.yml if present).
	@command -v $(GOLANGCI) >/dev/null 2>&1 || { \
		echo "$(GOLANGCI) not found — install it from https://golangci-lint.run/welcome/install/"; \
		exit 1; \
	}
	$(GOLANGCI) run ./...

.PHONY: vuln
vuln: ## Scan deps and reachable code for known vulnerabilities (govulncheck).
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

.PHONY: sec
sec: lint vuln ## Security checks: golangci-lint (incl. gosec) + govulncheck.

.PHONY: tidy
tidy: ## Tidy and verify go.mod/go.sum.
	$(GO) mod tidy
	$(GO) mod verify

.PHONY: ci
ci: fmt vet lint vuln test build ## Full CI pipeline: fmt, vet, lint, vuln, test (race), build.

.PHONY: image
image: ## Build the container image.
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

.PHONY: release
release: ## Cross-compile static release binaries into dist/.
	@mkdir -p $(DIST_DIR)
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		out=$(DIST_DIR)/$(BINARY)-$$os-$$arch; \
		echo "building $$out"; \
		GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $$out $(CMD_PKG) || exit 1; \
	done

.PHONY: clean
clean: ## Remove build artefacts.
	rm -rf $(BIN_DIR) $(DIST_DIR) coverage.out
