BINARY  := midwatch
PKG     := ./cmd/midwatch
# No --always: an untagged checkout should stamp "dev" and let the version
# package name the build after its commit, rather than passing a bare sha off
# as a release number.
VERSION ?= $(shell git describe --tags --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X github.com/securqbit/midwatch/internal/version.Version=$(VERSION) \
	-X github.com/securqbit/midwatch/internal/version.Commit=$(COMMIT) \
	-X github.com/securqbit/midwatch/internal/version.Date=$(DATE)

.PHONY: build test lint fmt vet cover install clean run all vulncheck headers check

all: fmt vet test build

# What CI enforces, runnable before you push.
check: fmt vet headers test vulncheck

build:
	@mkdir -p bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)
	@echo "built bin/$(BINARY) $(VERSION)"

install:
	go install -trimpath -ldflags "$(LDFLAGS)" $(PKG)

test:
	go test -race ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

fmt:
	gofmt -l -w ./cmd ./internal

vet:
	go vet ./...

# Optional: requires golangci-lint on PATH.
lint:
	golangci-lint run ./...

# Zero dependencies is not zero exposure: the standard library ships security
# fixes too, and midwatch leans on crypto/tls, crypto/x509 and encoding/asn1.
vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# MPL-2.0 is file-level copyleft, so every file needs the notice.
headers:
	@missing=$$(for f in $$(find ./cmd ./internal -name '*.go'); do \
		head -3 $$f | grep -q 'Mozilla Public' || echo $$f; \
	done); \
	if [ -n "$$missing" ]; then \
		echo "missing the MPL-2.0 header:"; echo "$$missing"; exit 1; \
	fi; \
	echo "all source files carry the MPL header"

run: build
	./bin/$(BINARY) scan

clean:
	rm -rf bin coverage.out
