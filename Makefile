.PHONY: all build test test-e2e test-e2e-staging test-smoke-brew lint vet codegen codegen-check codegen-primitives codegen-primitives-check clean

# Path to platform-app primitive docs — override when the sibling checkout
# lives somewhere other than ../platform-app (e.g. CI runners with a
# different layout): `make codegen-primitives PRIMITIVES_SRC=/path/to/primitives`.
PRIMITIVES_SRC ?= ../platform-app/be/app/knowledge/resources/aws/primitives

BINARY := cbx
CMD := ./cmd/cbx

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Sentry DSN injected into the binary at build time. Empty by default, so a
# source build ships no telemetry endpoint; release builds receive the real
# DSN from CI / GoReleaser (which sets SENTRY_DSN here). Override locally with
# `make build SENTRY_DSN=https://...`.
SENTRY_DSN ?=

LDFLAGS := -ldflags "\
  -X github.com/cloudbooster-io/cbx-cli/pkg/cmd.Version=$(VERSION) \
  -X github.com/cloudbooster-io/cbx-cli/pkg/cmd.Commit=$(COMMIT) \
  -X github.com/cloudbooster-io/cbx-cli/pkg/cmd.Date=$(DATE) \
  -X github.com/cloudbooster-io/cbx-cli/internal/telemetry.defaultDSN=$(SENTRY_DSN)"

all: build

build:
	go build $(LDFLAGS) -o bin/$(BINARY) $(CMD)

test:
	go test ./...

test-e2e:
	go test -v ./e2e/...

# Maintainer-only: targets CloudBooster's internal staging API.
# CB_E2E_STAGING=1 opts in to TestStagingConnectivity (interactive device-code
# login); without it that test skips so the e2e-staging CI job never blocks MRs.
test-e2e-staging:
	CB_E2E_STAGING=1 CB_API_URL=$${CB_API_URL:-https://api.staging.cloudbooster.io} go test -v ./e2e/... -tags=e2e_staging

test-smoke-brew:
	./scripts/smoke-brew.sh

lint:
	golangci-lint run ./...

vet:
	go vet ./...

codegen:
	./tools/codegen/generate.sh

codegen-check: codegen
	@echo "Checking for generated code drift..."
	git diff --exit-code core/api/v1/client.gen.go

# Primitive-map drift (internal/audit/primitives_aws.go) is checked manually
# via codegen-primitives-check — CI cannot gate it because runners lack the
# platform-app sibling checkout that PRIMITIVES_SRC points at.
codegen-primitives:
	go run ./tools/genprimitives -src $(PRIMITIVES_SRC) -out internal/audit/primitives_aws.go

codegen-primitives-check: codegen-primitives
	@echo "Checking for primitive-map drift..."
	git diff --exit-code internal/audit/primitives_aws.go

clean:
	rm -rf bin/
