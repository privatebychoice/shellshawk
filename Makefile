# Makefile — build and local quality gate. Requires Go 1.27+.
#
# Run `make check` before pushing.
#
# Versioning: VERSION holds 1.0.x where x is the build number. Run
# `make bump` before each deployment.

GO ?= go
# govulncheck runs via `go run pkg@version`; it is never added to go.mod.
GOVULNCHECK ?= golang.org/x/vuln/cmd/govulncheck@latest

BIN       := bin/shellshawk
PKG       := go.privatebychoice.com/shellshawk
VERSION   := $(shell cat VERSION)
COMMIT    := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILDDATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS   := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.BuildDate=$(BUILDDATE)
# CGO off: modernc.org/sqlite is pure Go, so builds are static and
# cross-compile cleanly from macOS to Linux.
BUILDENV  := CGO_ENABLED=0

.DEFAULT_GOAL := help
.PHONY: build build-linux bump check fmt fmt-check vet test race cover vuln tidy clean help

## build: build for the host platform into bin/
build:
	$(BUILDENV) $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/shellshawk

## build-linux: cross-compile for linux/amd64 and linux/arm64 into bin/
build-linux:
	$(BUILDENV) GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)-linux-amd64 ./cmd/shellshawk
	$(BUILDENV) GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)-linux-arm64 ./cmd/shellshawk

## bump: increment the build number in VERSION (1.0.x -> 1.0.x+1)
bump:
	@awk -F. -v OFS=. '{ $$3 = $$3 + 1; print }' VERSION > VERSION.tmp && mv VERSION.tmp VERSION
	@echo "VERSION is now $$(cat VERSION)"

## check: full local gate — fmt-check, vet, test, vuln
check: fmt-check vet test vuln

## fmt: format all Go code in place
fmt:
	gofmt -w .

## fmt-check: fail if any Go code is not gofmt-clean
fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then \
		echo "gofmt: these files need formatting:"; echo "$$out"; exit 1; fi

## vet: run go vet
vet:
	$(GO) vet ./...

## test: run the test suite
test:
	$(GO) test ./...

## race: run tests with the race detector (needs a C toolchain)
race:
	$(GO) test -race ./...

## cover: run tests and print coverage
cover:
	$(GO) test -cover ./...

## vuln: scan for known vulnerabilities (Go vuln DB; needs network)
vuln:
	$(GO) run $(GOVULNCHECK) ./...

## tidy: sync go.mod / go.sum
tidy:
	$(GO) mod tidy

## clean: remove build output
clean:
	rm -rf bin

## help: list available targets
help:
	@echo "Targets:"; grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
