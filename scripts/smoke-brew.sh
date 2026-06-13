#!/usr/bin/env bash
set -euo pipefail

echo "=== Brew smoke test ==="

# Tap and install
echo "--> Tapping cloudbooster-io/tap..."
brew tap cloudbooster-io/tap || true

# cbx-cli ships as a Homebrew **cask** (GoReleaser dropped formulas for
# pre-built binaries). Casks are macOS-only — this smoke test must run on a
# macOS runner. Linux installs via the .deb/.rpm or release tarball instead.
echo "--> Installing cbx-cli (cask)..."
brew install --cask cbx-cli

echo "--> Running cbx version..."
cbx version

echo "--> Running cbx doctor..."
cbx doctor

echo "=== Brew smoke test PASSED ==="
