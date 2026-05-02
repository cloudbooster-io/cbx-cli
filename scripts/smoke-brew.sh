#!/usr/bin/env bash
set -euo pipefail

echo "=== Brew smoke test ==="

# Tap and install
echo "--> Tapping cloudbooster/tap..."
brew tap cloudbooster/tap || true

echo "--> Installing cbx-cli..."
brew install cbx-cli

echo "--> Running cbx version..."
cbx version

echo "--> Running cbx doctor..."
cbx doctor

echo "=== Brew smoke test PASSED ==="
