.PHONY: all build test test-e2e test-e2e-staging test-smoke-brew lint vet clean

BINARY := cbx
CMD := ./cmd/cbx

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

all: build

build:
	go build $(LDFLAGS) -o bin/$(BINARY) $(CMD)

test:
	go test ./...

test-e2e:
	go test -v ./e2e/...

test-e2e-staging:
	CB_API_URL=$${CB_API_URL:-https://api.staging.cloudbooster.io} go test -v ./e2e/... -tags=e2e_staging

test-smoke-brew:
	./scripts/smoke-brew.sh

lint:
	golangci-lint run ./...

vet:
	go vet ./...

clean:
	rm -rf bin/
