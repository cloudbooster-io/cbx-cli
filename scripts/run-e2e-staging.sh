#!/usr/bin/env bash
set -euo pipefail

CB_API_URL="${CB_API_URL:-https://api.staging.cloudbooster.io}"
export CB_API_URL

echo "=== Running E2E tests against staging: $CB_API_URL ==="

go test -v ./e2e/... -tags=e2e_staging

echo "=== Staging E2E tests PASSED ==="
