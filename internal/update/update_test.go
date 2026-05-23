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
		// GitLab releases endpoint, path-escaped project id.
		const wantPath = "/cloudbooster.io%2Fplatform%2Fcbx-cli/releases/permalink/latest"
		if r.URL.EscapedPath() != wantPath {
			t.Fatalf("unexpected path: %s", r.URL.EscapedPath())
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name": "v1.5.0",
			"_links": map[string]string{
				"self": "https://gitlab.com/cloudbooster.io/platform/cbx-cli/-/releases/v1.5.0",
			},
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

