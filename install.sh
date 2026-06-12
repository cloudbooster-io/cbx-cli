#!/bin/sh
# cbx-cli installer.
#
#   curl -sSL https://install.cloudbooster.io/cbx | sh
#
# Downloads the GoReleaser release archive for this OS/arch from GitHub
# Releases, verifies it against the release's checksums.txt, and installs
# the `cbx` binary. No telemetry, no account, nothing else touched.
#
# Defaults install to /usr/local/bin when writable (e.g. piped through
# `sudo sh`), otherwise ~/.local/bin. There is deliberately no implicit
# sudo escalation.
#
# Environment overrides:
#   CBX_VERSION      release tag to install, e.g. v0.1.0 (default: latest)
#   CBX_INSTALL_DIR  target directory (default: /usr/local/bin or ~/.local/bin)
#   CBX_BASE_URL     releases base URL, for mirrors/tests
#                    (default: https://github.com/cloudbooster-io/cbx-cli/releases)
#
# Windows is not served here — use Scoop:
#   scoop bucket add cloudbooster https://github.com/cloudbooster-io/scoop-bucket
#   scoop install cbx-cli

set -eu

BASE_URL="${CBX_BASE_URL:-https://github.com/cloudbooster-io/cbx-cli/releases}"

say() { printf '%s\n' "$*" >&2; }
fail() {
	say "cbx install: error: $*"
	exit 1
}

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"

# --- resolve the release asset for this platform -------------------------
# Archive naming must match .goreleaser.yaml / internal/update/update.go:
#   cbx-cli_<TitleOs>_<Arch>.tar.gz   (amd64 -> x86_64, arm64 unchanged)
case "$(uname -s)" in
Linux) os="Linux" ;;
Darwin) os="Darwin" ;;
*) fail "unsupported OS '$(uname -s)' — on Windows use Scoop (see header of this script), otherwise grab an archive from $BASE_URL" ;;
esac

case "$(uname -m)" in
x86_64 | amd64) arch="x86_64" ;;
arm64 | aarch64) arch="arm64" ;;
*) fail "unsupported architecture '$(uname -m)' (need x86_64 or arm64)" ;;
esac

asset="cbx-cli_${os}_${arch}.tar.gz"

if [ -n "${CBX_VERSION:-}" ]; then
	# Accept "0.1.0" as well as the canonical "v0.1.0" tag form.
	case "$CBX_VERSION" in
	v*) tag="$CBX_VERSION" ;;
	*) tag="v$CBX_VERSION" ;;
	esac
	download_base="$BASE_URL/download/$tag"
else
	tag="latest"
	download_base="$BASE_URL/latest/download"
fi

# --- download + verify ----------------------------------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "cbx install: downloading $asset ($tag)"
curl -fsSL -o "$tmp/$asset" "$download_base/$asset" ||
	fail "download failed: $download_base/$asset"
curl -fsSL -o "$tmp/checksums.txt" "$download_base/checksums.txt" ||
	fail "download failed: $download_base/checksums.txt"

if command -v sha256sum >/dev/null 2>&1; then
	sha_tool="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
	sha_tool="shasum -a 256"
else
	fail "neither sha256sum nor shasum found — cannot verify the download"
fi
(cd "$tmp" && grep " $asset\$" checksums.txt | $sha_tool -c - >/dev/null 2>&1) ||
	fail "checksum verification failed for $asset"
say "cbx install: checksum verified"

tar -xzf "$tmp/$asset" -C "$tmp" cbx ||
	fail "archive did not contain the cbx binary"

# --- install ---------------------------------------------------------------
install_dir="${CBX_INSTALL_DIR:-}"
if [ -z "$install_dir" ]; then
	if [ -w /usr/local/bin ]; then
		install_dir="/usr/local/bin"
	else
		install_dir="$HOME/.local/bin"
	fi
fi

mkdir -p "$install_dir" || fail "cannot create $install_dir"
install -m 0755 "$tmp/cbx" "$install_dir/cbx" ||
	fail "cannot write to $install_dir (set CBX_INSTALL_DIR, or pipe through 'sudo sh' for /usr/local/bin)"

say "cbx install: installed $install_dir/cbx"
"$install_dir/cbx" version >&2 2>/dev/null || true

case ":$PATH:" in
*":$install_dir:"*) ;;
*)
	say ""
	say "note: $install_dir is not on your PATH. Add it with:"
	say "  export PATH=\"$install_dir:\$PATH\""
	;;
esac
