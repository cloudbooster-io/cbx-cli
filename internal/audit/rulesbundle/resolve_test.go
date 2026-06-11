package rulesbundle

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixedNow pins timeNow for a test and restores it afterwards.
func fixedNow(t *testing.T, at time.Time) {
	t.Helper()
	restore := timeNow
	timeNow = func() time.Time { return at }
	t.Cleanup(func() { timeNow = restore })
}

// isolatedCache points the XDG cache at a temp dir.
func isolatedCache(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", dir)
	return dir
}

// mutatedEmbedded returns the embedded artifact bytes with manifest
// fields tweaked — the canonical content hash covers only the rendered
// prose, so manifest-level mutations still Parse/Validate.
func mutatedEmbedded(t *testing.T, mutate func(manifest map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(EmbeddedBytes(), &doc); err != nil {
		t.Fatalf("unmarshal embedded: %v", err)
	}
	mutate(doc["manifest"].(map[string]any))
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal mutated: %v", err)
	}
	return out
}

func staticFetch(raw []byte, etag string, err error) FetchFunc {
	return func(context.Context, string, string, int) ([]byte, string, error) {
		return raw, etag, err
	}
}

func TestResolve_NoNetworkFallsToEmbedded(t *testing.T) {
	isolatedCache(t)
	pack, prov, err := Resolve(context.Background(), ResolveOptions{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if pack != Embedded() {
		t.Error("pack is not the embedded singleton")
	}
	if prov.Source != "embedded" || prov.Degraded || prov.Stale {
		t.Errorf("provenance = %+v, want clean embedded", prov)
	}
	if prov.ContentSHA256 != Embedded().Manifest.ContentSHA256 {
		t.Error("provenance hash does not match the served pack")
	}
}

func TestResolve_NetworkSuccessCachesAndReports(t *testing.T) {
	cacheRoot := isolatedCache(t)
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	fixedNow(t, now)

	raw := mutatedEmbedded(t, func(m map[string]any) { m["pack_version"] = 2.0 })
	pack, prov, err := Resolve(context.Background(), ResolveOptions{Fetch: staticFetch(raw, `"e2"`, nil)})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if prov.Source != "network" || prov.PackVersion != 2 || prov.Degraded {
		t.Errorf("provenance = %+v, want network v2", prov)
	}
	if pack.Manifest.PackVersion != 2 {
		t.Errorf("pack version = %d", pack.Manifest.PackVersion)
	}
	if prov.FetchedAt != now.Format(time.RFC3339) {
		t.Errorf("FetchedAt = %q", prov.FetchedAt)
	}

	// Cache written verbatim + sidecar carries etag/version.
	artifact, err := os.ReadFile(filepath.Join(cacheRoot, "cbx", "rulepack", "aws-stable-schema1.json"))
	if err != nil {
		t.Fatalf("cached artifact: %v", err)
	}
	if string(artifact) != string(raw) {
		t.Error("cached artifact is not byte-identical to the served bytes")
	}
	metaRaw, err := os.ReadFile(filepath.Join(cacheRoot, "cbx", "rulepack", "aws-stable-schema1.meta.json"))
	if err != nil {
		t.Fatalf("cached meta: %v", err)
	}
	var meta cacheMeta
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		t.Fatalf("meta: %v", err)
	}
	if meta.ETag != `"e2"` || meta.PackVersion != 2 || !meta.FetchedAt.Equal(now) {
		t.Errorf("meta = %+v", meta)
	}
}

func TestResolve_404FallsToEmbeddedNotDegraded(t *testing.T) {
	isolatedCache(t)
	_, prov, err := Resolve(context.Background(), ResolveOptions{
		Fetch: staticFetch(nil, "", ErrNotAuthored),
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if prov.Source != "embedded" {
		t.Errorf("source = %q", prov.Source)
	}
	if prov.Degraded {
		t.Error("404 marked Degraded — a not-yet-deployed endpoint is the expected pre-P2 state")
	}
	if prov.FetchError == "" {
		t.Error("404 fall-through should still be noted in FetchError")
	}
}

func TestResolve_TransientFailureUsesCacheDegraded(t *testing.T) {
	isolatedCache(t)
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	fixedNow(t, now)

	// Seed the cache via a successful run.
	raw := mutatedEmbedded(t, func(m map[string]any) { m["pack_version"] = 3.0 })
	if _, _, err := Resolve(context.Background(), ResolveOptions{Fetch: staticFetch(raw, `"e3"`, nil)}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Fresh cache → Degraded but not Stale.
	fixedNow(t, now.Add(time.Hour))
	pack, prov, err := Resolve(context.Background(), ResolveOptions{
		Fetch: staticFetch(nil, "", errors.New("dial tcp: connection refused")),
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if prov.Source != "cache" || !prov.Degraded || prov.Stale {
		t.Errorf("provenance = %+v, want degraded fresh cache", prov)
	}
	if pack.Manifest.PackVersion != 3 {
		t.Errorf("pack version = %d, want cached v3", pack.Manifest.PackVersion)
	}
	if !strings.Contains(prov.FetchError, "connection refused") {
		t.Errorf("FetchError = %q", prov.FetchError)
	}

	// Past the grace window → Stale escalates.
	fixedNow(t, now.Add(8*24*time.Hour))
	_, prov, err = Resolve(context.Background(), ResolveOptions{
		Fetch: staticFetch(nil, "", errors.New("dial tcp: connection refused")),
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if prov.Source != "cache" || !prov.Stale {
		t.Errorf("provenance = %+v, want stale cache", prov)
	}
}

func TestResolve_304ServesCacheAndRefreshesMeta(t *testing.T) {
	cacheRoot := isolatedCache(t)
	seedTime := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	fixedNow(t, seedTime)
	raw := mutatedEmbedded(t, func(m map[string]any) { m["pack_version"] = 4.0 })
	if _, _, err := Resolve(context.Background(), ResolveOptions{Fetch: staticFetch(raw, `"e4"`, nil)}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// 10 days later (past grace) the registry answers 304: the cache is
	// revalidated-current — NOT stale — and the meta stamp refreshes.
	revalTime := seedTime.Add(10 * 24 * time.Hour)
	fixedNow(t, revalTime)
	var gotETag string
	fetch := func(_ context.Context, _ string, etag string, _ int) ([]byte, string, error) {
		gotETag = etag
		return nil, etag, ErrNotModified
	}
	pack, prov, err := Resolve(context.Background(), ResolveOptions{Fetch: fetch})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if gotETag != `"e4"` {
		t.Errorf("If-None-Match etag = %q, want the cached one", gotETag)
	}
	if prov.Source != "cache" || prov.Stale || prov.Degraded {
		t.Errorf("provenance = %+v, want revalidated cache", prov)
	}
	if pack.Manifest.PackVersion != 4 {
		t.Errorf("pack version = %d", pack.Manifest.PackVersion)
	}
	metaRaw, _ := os.ReadFile(filepath.Join(cacheRoot, "cbx", "rulepack", "aws-stable-schema1.meta.json"))
	var meta cacheMeta
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		t.Fatalf("meta: %v", err)
	}
	if !meta.FetchedAt.Equal(revalTime) {
		t.Errorf("meta.FetchedAt = %v, want refreshed to %v", meta.FetchedAt, revalTime)
	}
}

func TestResolve_InvalidNetworkPayloadDegradesToEmbedded(t *testing.T) {
	isolatedCache(t)
	_, prov, err := Resolve(context.Background(), ResolveOptions{
		Fetch: staticFetch([]byte(`{"manifest":{"pack":"evil"}}`), `"x"`, nil),
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if prov.Source != "embedded" || !prov.Degraded {
		t.Errorf("provenance = %+v, want degraded embedded", prov)
	}
}

func TestResolve_OverrideFile(t *testing.T) {
	isolatedCache(t)
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, EmbeddedBytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	fetchCalled := false
	pack, prov, err := Resolve(context.Background(), ResolveOptions{
		OverrideFile: path,
		Fetch: func(context.Context, string, string, int) ([]byte, string, error) {
			fetchCalled = true
			return nil, "", errors.New("must not be called")
		},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if fetchCalled {
		t.Error("override file did not bypass the network")
	}
	if prov.Source != "file" || pack.Manifest.PackVersion != 1 {
		t.Errorf("provenance = %+v", prov)
	}

	// A broken override fails LOUD — silent fallback would invalidate
	// the dev/sweep lever it exists for.
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Resolve(context.Background(), ResolveOptions{OverrideFile: path}); err == nil {
		t.Fatal("broken CBX_AUDIT_RULES_FILE did not error")
	}
	if _, _, err := Resolve(context.Background(), ResolveOptions{OverrideFile: filepath.Join(t.TempDir(), "missing.json")}); err == nil {
		t.Fatal("missing CBX_AUDIT_RULES_FILE did not error")
	}
}

func TestResolve_PinSemantics(t *testing.T) {
	isolatedCache(t)

	// Pin satisfiable by the embedded pack (version 1) without network.
	pack, prov, err := Resolve(context.Background(), ResolveOptions{PinVersion: 1})
	if err != nil {
		t.Fatalf("pin=1: %v", err)
	}
	if prov.Source != "embedded" || prov.PinnedVersion != 1 || pack.Manifest.PackVersion != 1 {
		t.Errorf("provenance = %+v", prov)
	}

	// Unsatisfiable pin is an abort, not a silent unpinned run.
	if _, _, err := Resolve(context.Background(), ResolveOptions{PinVersion: 99}); err == nil {
		t.Fatal("pin=99 resolved — a sweep would be running unpinned rules silently")
	}

	// Registry serving the wrong version for a pin degrades, then the
	// embedded mismatch aborts.
	raw := mutatedEmbedded(t, func(m map[string]any) { m["pack_version"] = 5.0 })
	_, _, err = Resolve(context.Background(), ResolveOptions{PinVersion: 99, Fetch: staticFetch(raw, `"e5"`, nil)})
	if err == nil || !strings.Contains(err.Error(), "pinned rulepack version 99") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolve_MinEngineVersionHandshake(t *testing.T) {
	isolatedCache(t)
	raw := mutatedEmbedded(t, func(m map[string]any) {
		m["pack_version"] = 6.0
		m["min_engine_version"] = "v99.0.0"
	})

	// Released engine older than the requirement → abort with upgrade hint.
	_, _, err := Resolve(context.Background(), ResolveOptions{
		EngineVersion: "v0.5.0",
		Fetch:         staticFetch(raw, `"e6"`, nil),
	})
	if err == nil || !strings.Contains(err.Error(), "cbx upgrade") {
		t.Fatalf("err = %v, want upgrade-cbx abort", err)
	}

	// Dev builds satisfy every constraint.
	pack, prov, err := Resolve(context.Background(), ResolveOptions{
		EngineVersion: "dev",
		Fetch:         staticFetch(raw, `"e6"`, nil),
	})
	if err != nil {
		t.Fatalf("dev engine: %v", err)
	}
	if prov.Source != "network" || pack.Manifest.PackVersion != 6 {
		t.Errorf("provenance = %+v", prov)
	}

	// Engine at/above the requirement passes.
	if _, _, err := Resolve(context.Background(), ResolveOptions{
		EngineVersion: "v99.0.0",
		Fetch:         staticFetch(raw, `"e6"`, nil),
	}); err != nil {
		t.Fatalf("equal engine: %v", err)
	}
}

func TestValidate_RejectsMalformedMinEngineVersion(t *testing.T) {
	raw := mutatedEmbedded(t, func(m map[string]any) { m["min_engine_version"] = "latest" })
	if _, err := Parse(raw); err == nil || !strings.Contains(err.Error(), "min_engine_version") {
		t.Fatalf("err = %v, want min_engine_version rejection", err)
	}
}

func TestResolve_CorruptCacheIsAMiss(t *testing.T) {
	cacheRoot := isolatedCache(t)
	dir := filepath.Join(cacheRoot, "cbx", "rulepack")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "aws-stable-schema1.json"), []byte("torn"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "aws-stable-schema1.meta.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, prov, err := Resolve(context.Background(), ResolveOptions{
		Fetch: staticFetch(nil, "", errors.New("offline")),
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if prov.Source != "embedded" || !prov.Degraded {
		t.Errorf("provenance = %+v, want degraded embedded (corrupt cache must be a miss, never a crash)", prov)
	}
}
