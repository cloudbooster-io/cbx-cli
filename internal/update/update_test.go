package update

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSemverGreaterThan(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"v1.2.0", "v1.1.0", true},
		{"v1.1.0", "v1.2.0", false},
		{"v1.2.0", "v1.2.0", false},
		{"v2.0.0", "v1.9.9", true},
		{"v1.0.0", "dev", true},
		{"dev", "v1.0.0", false},
		{"v1.0.0", "unknown", true},
		{"", "v1.0.0", false},
		{"v1.2.3", "v1.2.3", false},
		{"v1.10.0", "v1.9.0", true},
		// Pre-release handling (deliberately simplified — see the
		// semverGreaterThan doc comment): the numeric core is compared
		// first, and on a tie a release beats a pre-release of the same
		// core. Two pre-releases of the same core are not ordered.
		{"v1.2.1", "v1.2.1-rc.1", true},
		{"v1.2.0-rc.1", "v1.2.0", false},
		{"v1.2.0-rc.1", "v1.1.0", true},
		{"v1.3.0", "v1.2.99-rc.1", true},
		{"v1.2.0-rc.2", "v1.2.0-rc.1", false},
		{"v1.2.0-rc.1", "v1.2.0-rc.2", false},
		// Build metadata is ignored for precedence (semver §10).
		{"v1.2.1+build.5", "v1.2.1", false},
		{"v1.2.1", "v1.2.1+build.5", false},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s_vs_%s", tc.a, tc.b), func(t *testing.T) {
			got := semverGreaterThan(tc.a, tc.b)
			if got != tc.want {
				t.Fatalf("semverGreaterThan(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestCheckerCheck_CacheHit(t *testing.T) {
	tmp := t.TempDir()
	os.Setenv("HOME", tmp)
	defer os.Unsetenv("HOME")

	entry := &cacheEntry{
		CheckedAt:     time.Now().UTC(),
		LatestVersion: "v2.0.0",
		ReleaseURL:    "https://example.com/v2.0.0",
	}
	_ = writeCache(entry)

	checker := NewChecker("v1.0.0")
	result, err := checker.Check(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.LatestVersion != "v2.0.0" {
		t.Fatalf("expected v2.0.0, got %s", result.LatestVersion)
	}
	if !result.HasUpdate {
		t.Fatal("expected HasUpdate=true")
	}
}

func TestCheckerCheck_CacheMiss(t *testing.T) {
	tmp := t.TempDir()
	os.Setenv("HOME", tmp)
	defer os.Unsetenv("HOME")

	mockAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// GitHub releases endpoint: /repos/<owner>/<repo>/releases/latest.
		const wantPath = "/cloudbooster-io/cbx-cli/releases/latest"
		if r.URL.EscapedPath() != wantPath {
			t.Fatalf("unexpected path: %s", r.URL.EscapedPath())
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name": "v1.5.0",
			"html_url": "https://github.com/cloudbooster-io/cbx-cli/releases/tag/v1.5.0",
		})
	}))
	defer mockAPI.Close()
	t.Setenv("CBX_RELEASES_URL", mockAPI.URL)

	checker := NewChecker("v1.0.0")
	checker.HTTPClient = mockAPI.Client()

	result, err := checker.Check(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.LatestVersion != "v1.5.0" {
		t.Fatalf("expected v1.5.0, got %s", result.LatestVersion)
	}
	if !result.HasUpdate {
		t.Fatal("expected HasUpdate=true")
	}
}

func TestIsDisabled(t *testing.T) {
	tests := []struct {
		name       string
		ci         string
		cbxNoCheck string
		cbNoCheck  string
		want       bool
	}{
		{"none", "", "", "", false},
		{"ci_only", "true", "", "", true},
		{"cbx_no_check", "", "1", "", true},
		{"legacy_cb_no_check", "", "", "1", true},
		{"both", "true", "1", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CI", tc.ci)
			t.Setenv("CBX_NO_UPDATE_CHECK", tc.cbxNoCheck)
			t.Setenv("CB_NO_UPDATE_CHECK", tc.cbNoCheck)
			if got := IsDisabled(); got != tc.want {
				t.Fatalf("IsDisabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCacheReadWrite(t *testing.T) {
	tmp := t.TempDir()
	os.Setenv("HOME", tmp)
	defer os.Unsetenv("HOME")

	_, ok := readCache()
	if ok {
		t.Fatal("expected cache miss on empty home")
	}

	entry := &cacheEntry{
		CheckedAt:     time.Now().UTC(),
		LatestVersion: "v3.0.0",
		ReleaseURL:    "https://example.com",
	}
	if err := writeCache(entry); err != nil {
		t.Fatalf("writeCache failed: %v", err)
	}

	read, ok := readCache()
	if !ok {
		t.Fatal("expected cache hit after write")
	}
	if read.LatestVersion != "v3.0.0" {
		t.Fatalf("expected v3.0.0, got %s", read.LatestVersion)
	}

	// Verify cache expiry
	stale := &cacheEntry{
		CheckedAt:     time.Now().UTC().Add(-25 * time.Hour),
		LatestVersion: "v99.0.0",
		ReleaseURL:    "https://example.com",
	}
	_ = writeCache(stale)
	_, ok = readCache()
	if ok {
		t.Fatal("expected stale cache to be ignored")
	}
}

func TestCachePath(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CACHE_HOME", "")

	want := filepath.Join(tmp, ".cache", "cbx", "update-check.json")
	if got := cachePath(); got != want {
		t.Fatalf("cachePath() = %q, want %q", got, want)
	}
}

func TestCachePathXDG(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmp)

	want := filepath.Join(tmp, "cbx", "update-check.json")
	if got := cachePath(); got != want {
		t.Fatalf("cachePath() = %q, want %q", got, want)
	}
}

func TestDirectAssetURL(t *testing.T) {
	// Locks the GoReleaser archive name contract: .goreleaser.yml's
	// archives name_template produces cbx-cli_<TitleOs>_<arch> with
	// amd64 -> x86_64 and arm64 passing through, and format_overrides
	// ships windows as .zip (everything else tar.gz). The direct-upgrade
	// download path breaks if the two ever drift apart.
	tests := []struct {
		goos, goarch string
		want         string
	}{
		{"darwin", "arm64", "https://github.com/cloudbooster-io/cbx-cli/releases/download/v1.2.3/cbx-cli_Darwin_arm64.tar.gz"},
		{"darwin", "amd64", "https://github.com/cloudbooster-io/cbx-cli/releases/download/v1.2.3/cbx-cli_Darwin_x86_64.tar.gz"},
		{"linux", "amd64", "https://github.com/cloudbooster-io/cbx-cli/releases/download/v1.2.3/cbx-cli_Linux_x86_64.tar.gz"},
		{"linux", "arm64", "https://github.com/cloudbooster-io/cbx-cli/releases/download/v1.2.3/cbx-cli_Linux_arm64.tar.gz"},
		{"windows", "amd64", "https://github.com/cloudbooster-io/cbx-cli/releases/download/v1.2.3/cbx-cli_Windows_x86_64.zip"},
		{"windows", "arm64", "https://github.com/cloudbooster-io/cbx-cli/releases/download/v1.2.3/cbx-cli_Windows_arm64.zip"},
	}

	origGoos, origGoarch := goos, goarch
	t.Cleanup(func() { goos, goarch = origGoos, origGoarch })

	for _, tc := range tests {
		t.Run(tc.goos+"_"+tc.goarch, func(t *testing.T) {
			goos, goarch = tc.goos, tc.goarch
			got := directAssetURL(&Result{LatestVersion: "v1.2.3"})
			if got != tc.want {
				t.Fatalf("directAssetURL(%s/%s) = %q, want %q", tc.goos, tc.goarch, got, tc.want)
			}
		})
	}
}

func TestUpgradeCommand(t *testing.T) {
	origGoos, origGoarch := goos, goarch
	t.Cleanup(func() { goos, goarch = origGoos, origGoarch })
	goos, goarch = "linux", "amd64"

	tests := []struct {
		method InstallMethod
		want   string
	}{
		{InstallBrew, "brew upgrade cbx-cli"},
		{InstallScoop, "scoop update cbx-cli"},
		{InstallDeb, "sudo apt-get install --only-upgrade cbx-cli"},
		{InstallRPM, "sudo dnf upgrade cbx-cli"},
		// The direct path downloads to disk so the artifact can be
		// verified against the GoReleaser checksums.txt before install.
		{InstallDirect, "curl -fsSLO https://github.com/cloudbooster-io/cbx-cli/releases/download/v1.2.3/cbx-cli_Linux_x86_64.tar.gz && " +
			"curl -fsSL https://github.com/cloudbooster-io/cbx-cli/releases/download/v1.2.3/checksums.txt | grep cbx-cli_Linux_x86_64.tar.gz | sha256sum -c && " +
			"tar -xzf cbx-cli_Linux_x86_64.tar.gz cbx && mv cbx $(which cbx)"},
	}
	for _, tc := range tests {
		t.Run(string(tc.method), func(t *testing.T) {
			result := &Result{LatestVersion: "v1.2.3", InstallMethod: tc.method}
			if got := UpgradeCommand(result); got != tc.want {
				t.Fatalf("UpgradeCommand(%s) = %q, want %q", tc.method, got, tc.want)
			}
		})
	}
}

func TestDetectLinuxPackage(t *testing.T) {
	origDpkg, origRPMDirs, origRPMQuery := dpkgInfoGlobs, rpmDBDirs, rpmQuery
	t.Cleanup(func() { dpkgInfoGlobs, rpmDBDirs, rpmQuery = origDpkg, origRPMDirs, origRPMQuery })

	// missingGlob points at an empty fixture dir, i.e. dpkg does not know
	// the package.
	missingGlob := func(t *testing.T) []string {
		t.Helper()
		return []string{filepath.Join(t.TempDir(), "cbx-cli.*")}
	}

	t.Run("deb_owned", func(t *testing.T) {
		tmp := t.TempDir()
		if err := os.WriteFile(filepath.Join(tmp, "cbx-cli.list"), []byte("/usr/bin/cbx\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		dpkgInfoGlobs = []string{filepath.Join(tmp, "cbx-cli.*")}
		rpmDBDirs = nil
		method, ok := detectLinuxPackage()
		if !ok || method != InstallDeb {
			t.Fatalf("detectLinuxPackage() = (%s, %v), want (%s, true)", method, ok, InstallDeb)
		}
	})

	t.Run("rpm_owned", func(t *testing.T) {
		dpkgInfoGlobs = missingGlob(t)
		rpmDBDirs = []string{t.TempDir()}
		rpmQuery = func() bool { return true }
		method, ok := detectLinuxPackage()
		if !ok || method != InstallRPM {
			t.Fatalf("detectLinuxPackage() = (%s, %v), want (%s, true)", method, ok, InstallRPM)
		}
	})

	t.Run("rpm_db_present_not_owned", func(t *testing.T) {
		dpkgInfoGlobs = missingGlob(t)
		rpmDBDirs = []string{t.TempDir()}
		rpmQuery = func() bool { return false }
		if method, ok := detectLinuxPackage(); ok {
			t.Fatalf("detectLinuxPackage() = (%s, true), want not-owned", method)
		}
	})

	t.Run("no_package_db", func(t *testing.T) {
		dpkgInfoGlobs = missingGlob(t)
		rpmDBDirs = []string{filepath.Join(t.TempDir(), "missing")}
		rpmQuery = func() bool { t.Fatal("rpmQuery must not run without an rpm db"); return false }
		if method, ok := detectLinuxPackage(); ok {
			t.Fatalf("detectLinuxPackage() = (%s, true), want not-owned", method)
		}
	})
}

func TestDetectInstallMethodFor_LinuxPackagedBindirs(t *testing.T) {
	origGoos := goos
	origDpkg, origRPMDirs, origRPMQuery := dpkgInfoGlobs, rpmDBDirs, rpmQuery
	t.Cleanup(func() {
		goos = origGoos
		dpkgInfoGlobs, rpmDBDirs, rpmQuery = origDpkg, origRPMDirs, origRPMQuery
	})

	goos = "linux"
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "cbx-cli.list"), []byte("/usr/bin/cbx\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dpkgInfoGlobs = []string{filepath.Join(tmp, "cbx-cli.*")}
	rpmDBDirs = nil

	// Packaged bindir + dpkg ownership → deb.
	if got := detectInstallMethodFor("/usr/bin/cbx"); got != InstallDeb {
		t.Fatalf("detectInstallMethodFor(/usr/bin/cbx) = %s, want %s", got, InstallDeb)
	}
	// Outside the packaged bindirs the dpkg record is irrelevant → direct.
	if got := detectInstallMethodFor("/home/user/bin/cbx"); got != InstallDirect {
		t.Fatalf("detectInstallMethodFor(/home/user/bin/cbx) = %s, want %s", got, InstallDirect)
	}
}
