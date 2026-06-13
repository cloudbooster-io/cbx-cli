#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

echo "=== Generating API client from OpenAPI spec ==="
go tool oapi-codegen -config tools/codegen/oapi-codegen.yaml api/openapi.yaml
echo "=== Done ==="
