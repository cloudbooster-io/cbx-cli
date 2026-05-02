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
		if r.URL.Path != "/repos/cloudbooster/cbx-cli/releases/latest" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"tag_name": "v1.5.0",
			"html_url": "https://github.com/cloudbooster/cbx-cli/releases/tag/v1.5.0",
		})
	}))
	defer mockAPI.Close()

	checker := NewChecker("v1.0.0")
	// Override the HTTP transport to point at the mock server.
	checker.HTTPClient = mockAPI.Client()
	// We need to intercept the request URL. Since Checker builds the URL internally,
	// we test the full path via a small helper that rewrites the request host.
	originalTransport := checker.HTTPClient.Transport
	checker.HTTPClient.Transport = &rewriteHostTransport{
		base: originalTransport,
		host: mockAPI.URL,
	}

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
		ci      string
		noCheck string
		want    bool
	}{
		{"", "", false},
		{"true", "", true},
		{"", "1", true},
		{"true", "1", true},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("ci_%s_no_%s", tc.ci, tc.noCheck), func(t *testing.T) {
			t.Setenv("CI", tc.ci)
			t.Setenv("CB_NO_UPDATE_CHECK", tc.noCheck)
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
	os.Setenv("HOME", tmp)
	defer os.Unsetenv("HOME")

	want := filepath.Join(tmp, ".cache", "cb", "version-check")
	if got := cachePath(); got != want {
		t.Fatalf("cachePath() = %q, want %q", got, want)
	}
}

type rewriteHostTransport struct {
	base http.RoundTripper
	host string
}

func (t *rewriteHostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = t.host[len("http://"):]
	return t.base.RoundTrip(req)
}
