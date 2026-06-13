package rulesbundle_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle"
	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle/rulesbundletest"
)

// fixedNow pins the package clock for a test and restores it afterwards.
func fixedNow(t *testing.T, at time.Time) {
	t.Helper()
	t.Cleanup(rulesbundle.SetTimeNowForTest(func() time.Time { return at }))
}

// isolatedCache points the XDG cache at a temp dir — every test starts
// cold unless it explicitly warms its own cache.
func isolatedCache(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", dir)
	return dir
}

// packArtifact is the typed replacement for the old manifest JSON
// surgery: Build applies the mutation, recomputes the content hash, and
// re-validates, so the bytes are always a well-formed registry artifact.
func packArtifact(t *testing.T, mutate func(p *rulesbundle.RulePack)) []byte {
	t.Helper()
	return rulesbundletest.MarshalArtifact(t, rulesbundletest.Build(t, mutate))
}

func withVersion(v int) func(p *rulesbundle.RulePack) {
	return func(p *rulesbundle.RulePack) { p.Manifest.PackVersion = v }
}

func staticFetch(raw []byte, etag string, err error) rulesbundle.FetchFunc {
	return func(context.Context, string, string, int) ([]byte, string, error) {
		return raw, etag, err
	}
}

// cacheMetaFile mirrors the revalidation sidecar's JSON shape. Asserted
// from outside the package on purpose — the on-disk layout is a
// contract (P3 signature verification reads these same files).
type cacheMetaFile struct {
	ETag        string    `json:"etag"`
	FetchedAt   time.Time `json:"fetched_at"`
	PackVersion int       `json:"pack_version"`
}

func readCacheMeta(t *testing.T, cacheRoot string) cacheMetaFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(cacheRoot, "cbx", "rulepack", "aws-stable-schema1.meta.json"))
	if err != nil {
		t.Fatalf("cached meta: %v", err)
	}
	var meta cacheMetaFile
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("meta: %v", err)
	}
	return meta
}

// warmCache seeds the on-disk cache through a real network resolve, so
// later rungs are exercised against bytes the ladder itself wrote.
func warmCache(t *testing.T, raw []byte, etag string) {
	t.Helper()
	if _, _, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{Fetch: staticFetch(raw, etag, nil)}); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
}

// TestResolve_NoNetworkColdCacheErrors: with the embedded floor gone,
// no network + cold cache is the exhausted ladder — Resolve must abort
// with ErrNoRulePack and name the override lever, never run rule-less
// (a rule-less grounded prompt still produces plausible findings — the
// false-green failure mode).
func TestResolve_NoNetworkColdCacheErrors(t *testing.T) {
	isolatedCache(t)
	_, _, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{})
	if !errors.Is(err, rulesbundle.ErrNoRulePack) {
		t.Fatalf("err = %v, want ErrNoRulePack", err)
	}
	if !strings.Contains(err.Error(), "CBX_AUDIT_RULES_FILE") {
		t.Errorf("err = %q, should name the CBX_AUDIT_RULES_FILE way out", err)
	}
}

func TestResolve_NetworkSuccessCachesAndReports(t *testing.T) {
	cacheRoot := isolatedCache(t)
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	fixedNow(t, now)

	raw := packArtifact(t, withVersion(2))
	pack, prov, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{Fetch: staticFetch(raw, `"e2"`, nil)})
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

	// Cache written verbatim (P3 signature verification must run over
	// the same bytes the server signed) + sidecar carries etag/version.
	artifact, err := os.ReadFile(filepath.Join(cacheRoot, "cbx", "rulepack", "aws-stable-schema1.json"))
	if err != nil {
		t.Fatalf("cached artifact: %v", err)
	}
	if string(artifact) != string(raw) {
		t.Error("cached artifact is not byte-identical to the served bytes")
	}
	meta := readCacheMeta(t, cacheRoot)
	if meta.ETag != `"e2"` || meta.PackVersion != 2 || !meta.FetchedAt.Equal(now) {
		t.Errorf("meta = %+v", meta)
	}
}

// TestResolve_404WithWarmCacheServesCache: a 404 is a deterministic
// registry answer (unknown channel / not-yet-authored), not degradation
// — the cache serves with Degraded=false, but the miss is still noted
// in FetchError so provenance never hides the fall-through.
func TestResolve_404WithWarmCacheServesCache(t *testing.T) {
	isolatedCache(t)
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	fixedNow(t, now)
	warmCache(t, packArtifact(t, withVersion(2)), `"e2"`)

	pack, prov, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{
		Fetch: staticFetch(nil, "", rulesbundle.ErrNotAuthored),
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if prov.Source != "cache" || pack.Manifest.PackVersion != 2 {
		t.Errorf("provenance = %+v, want cache v2", prov)
	}
	if prov.Degraded {
		t.Error("404 marked Degraded — a not-yet-authored pack is the registry answering, not failing")
	}
	if prov.FetchError == "" {
		t.Error("404 fall-through should still be noted in FetchError")
	}
}

// TestResolve_404ColdCacheErrors: the same 404 with nothing to fall to
// is the exhausted ladder — not a softer degradation.
func TestResolve_404ColdCacheErrors(t *testing.T) {
	isolatedCache(t)
	_, _, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{
		Fetch: staticFetch(nil, "", rulesbundle.ErrNotAuthored),
	})
	if !errors.Is(err, rulesbundle.ErrNoRulePack) {
		t.Fatalf("err = %v, want ErrNoRulePack", err)
	}
	if !strings.Contains(err.Error(), "not authored") {
		t.Errorf("err = %q, should carry the registry's 404 reason", err)
	}
}

func TestResolve_TransientFailureUsesCacheDegraded(t *testing.T) {
	isolatedCache(t)
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	fixedNow(t, now)
	warmCache(t, packArtifact(t, withVersion(3)), `"e3"`)

	// Fresh cache → Degraded but not Stale.
	fixedNow(t, now.Add(time.Hour))
	pack, prov, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{
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
	_, prov, err = rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{
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
	warmCache(t, packArtifact(t, withVersion(4)), `"e4"`)

	// 10 days later (past grace) the registry answers 304: the cache is
	// revalidated-current — NOT stale — and the meta stamp refreshes.
	revalTime := seedTime.Add(10 * 24 * time.Hour)
	fixedNow(t, revalTime)
	var gotETag string
	fetch := func(_ context.Context, _ string, etag string, _ int) ([]byte, string, error) {
		gotETag = etag
		return nil, etag, rulesbundle.ErrNotModified
	}
	pack, prov, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{Fetch: fetch})
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
	meta := readCacheMeta(t, cacheRoot)
	if !meta.FetchedAt.Equal(revalTime) {
		t.Errorf("meta.FetchedAt = %v, want refreshed to %v", meta.FetchedAt, revalTime)
	}
}

// TestResolve_304WithVanishedCacheRefetches: a 304 promises "your copy
// is current", but if the copy has vanished there is nothing to serve —
// the ladder must refetch once unconditionally instead of falling
// through to a guaranteed miss.
func TestResolve_304WithVanishedCacheRefetches(t *testing.T) {
	isolatedCache(t)
	fixedNow(t, time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC))
	raw := packArtifact(t, withVersion(4))
	calls := 0
	fetch := func(_ context.Context, _ string, etag string, _ int) ([]byte, string, error) {
		calls++
		if calls == 1 {
			return nil, "", rulesbundle.ErrNotModified
		}
		if etag != "" {
			t.Errorf("refetch sent If-None-Match %q, want unconditional", etag)
		}
		return raw, `"e4"`, nil
	}
	pack, prov, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{Fetch: fetch})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if calls != 2 {
		t.Errorf("fetch called %d times, want a refetch after the 304", calls)
	}
	if prov.Source != "network" || pack.Manifest.PackVersion != 4 {
		t.Errorf("provenance = %+v, want network v4", prov)
	}
}

// TestResolve_304WithPinMismatchedCacheRefetches: the 304 arm must
// enforce the version pin exactly like rung 2 does. A conforming
// fetcher never 304s here (the ETag is withheld when the cache misses
// the pin), but a FetchFunc that ignores the etag argument must not be
// able to smuggle the cached version past the pin — the ladder
// refetches unconditionally instead.
func TestResolve_304WithPinMismatchedCacheRefetches(t *testing.T) {
	isolatedCache(t)
	fixedNow(t, time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC))
	warmCache(t, packArtifact(t, withVersion(7)), `"e7"`)

	pinned := packArtifact(t, withVersion(9))
	calls := 0
	fetch := func(_ context.Context, _ string, etag string, _ int) ([]byte, string, error) {
		calls++
		if calls == 1 {
			return nil, etag, rulesbundle.ErrNotModified
		}
		if etag != "" {
			t.Errorf("refetch sent If-None-Match %q, want unconditional", etag)
		}
		return pinned, `"e9"`, nil
	}

	pack, prov, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{PinVersion: 9, Fetch: fetch})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if pack.Manifest.PackVersion != 9 || prov.Source != "network" {
		t.Errorf("served pack_version %d from %q, want pinned 9 from network", pack.Manifest.PackVersion, prov.Source)
	}
}

// TestResolve_InvalidNetworkPayloadWarmCacheDegrades: a served-but-
// invalid artifact is degradation (the registry is up but lying), not a
// 404 — fall to the cache, flag Degraded, carry the parse error.
func TestResolve_InvalidNetworkPayloadWarmCacheDegrades(t *testing.T) {
	isolatedCache(t)
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	fixedNow(t, now)
	warmCache(t, packArtifact(t, withVersion(2)), `"e2"`)

	pack, prov, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{
		Fetch: staticFetch([]byte(`{"manifest":{"pack":"evil"}}`), `"x"`, nil),
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if prov.Source != "cache" || !prov.Degraded || pack.Manifest.PackVersion != 2 {
		t.Errorf("provenance = %+v, want degraded cache v2", prov)
	}
	if !strings.Contains(prov.FetchError, "schema_version") {
		t.Errorf("FetchError = %q, should carry the parse failure", prov.FetchError)
	}
}

// TestResolve_InvalidNetworkPayloadColdCacheErrors: invalid payload +
// nothing cached exhausts the ladder; the parse failure must surface in
// the abort so the operator sees WHY the network rung didn't serve.
func TestResolve_InvalidNetworkPayloadColdCacheErrors(t *testing.T) {
	isolatedCache(t)
	_, _, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{
		Fetch: staticFetch([]byte(`{"manifest":{"pack":"evil"}}`), `"x"`, nil),
	})
	if !errors.Is(err, rulesbundle.ErrNoRulePack) {
		t.Fatalf("err = %v, want ErrNoRulePack", err)
	}
	if !strings.Contains(err.Error(), "schema_version") {
		t.Errorf("err = %q, should carry the parse failure", err)
	}
}

func TestResolve_OverrideFile(t *testing.T) {
	isolatedCache(t)
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, packArtifact(t, nil), 0o644); err != nil {
		t.Fatal(err)
	}

	fetchCalled := false
	pack, prov, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{
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
	if _, _, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{OverrideFile: path}); err == nil {
		t.Fatal("broken CBX_AUDIT_RULES_FILE did not error")
	}
	if _, _, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{OverrideFile: filepath.Join(t.TempDir(), "missing.json")}); err == nil {
		t.Fatal("missing CBX_AUDIT_RULES_FILE did not error")
	}
}

func TestResolve_PinSemantics(t *testing.T) {
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)

	t.Run("network-satisfies", func(t *testing.T) {
		isolatedCache(t)
		fixedNow(t, now)
		pack, prov, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{
			PinVersion: 7,
			Fetch:      staticFetch(packArtifact(t, withVersion(7)), `"e7"`, nil),
		})
		if err != nil {
			t.Fatalf("pin=7 via network: %v", err)
		}
		if prov.Source != "network" || prov.PinnedVersion != 7 || pack.Manifest.PackVersion != 7 {
			t.Errorf("provenance = %+v", prov)
		}
	})

	t.Run("cache-satisfies", func(t *testing.T) {
		isolatedCache(t)
		fixedNow(t, now)
		warmCache(t, packArtifact(t, withVersion(7)), `"e7"`)
		pack, prov, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{PinVersion: 7})
		if err != nil {
			t.Fatalf("pin=7 via cache: %v", err)
		}
		if prov.Source != "cache" || prov.PinnedVersion != 7 || pack.Manifest.PackVersion != 7 {
			t.Errorf("provenance = %+v", prov)
		}
	})

	// Unsatisfiable pin is an abort, not a silent unpinned run — a sweep
	// scoring rules it didn't pin is unscoreable.
	t.Run("unsatisfiable-aborts", func(t *testing.T) {
		isolatedCache(t)
		fixedNow(t, now)
		warmCache(t, packArtifact(t, withVersion(7)), `"e7"`)
		_, _, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{PinVersion: 99})
		if !errors.Is(err, rulesbundle.ErrNoRulePack) {
			t.Fatalf("err = %v, want ErrNoRulePack", err)
		}
		for _, frag := range []string{"99", "cache holds pack_version 7"} {
			if !strings.Contains(err.Error(), frag) {
				t.Errorf("err = %q, should mention %q", err, frag)
			}
		}
	})

	// A registry serving the wrong version for a pin is degradation, and
	// with no other source holding the pin the ladder exhausts.
	t.Run("registry-wrong-version", func(t *testing.T) {
		isolatedCache(t)
		fixedNow(t, now)
		_, _, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{
			PinVersion: 99,
			Fetch:      staticFetch(packArtifact(t, withVersion(5)), `"e5"`, nil),
		})
		if !errors.Is(err, rulesbundle.ErrNoRulePack) {
			t.Fatalf("err = %v, want ErrNoRulePack", err)
		}
		if !strings.Contains(err.Error(), "pinned version 99") {
			t.Errorf("err = %q, should carry the registry version mismatch", err)
		}
	})

	// The override file is the dev/sweep lever — a pin it can't satisfy
	// keeps its dedicated checkPin error (loud, names the file), not the
	// exhausted-ladder sentinel: the file was found, it's just wrong.
	t.Run("override-mismatch", func(t *testing.T) {
		isolatedCache(t)
		path := filepath.Join(t.TempDir(), "rules.json")
		if err := os.WriteFile(path, packArtifact(t, nil), 0o644); err != nil {
			t.Fatal(err)
		}
		_, _, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{OverrideFile: path, PinVersion: 99})
		if err == nil || !strings.Contains(err.Error(), "pinned rulepack version 99") {
			t.Fatalf("err = %v, want the override checkPin error", err)
		}
		if errors.Is(err, rulesbundle.ErrNoRulePack) {
			t.Error("override pin mismatch collapsed into ErrNoRulePack — it must stay its own error")
		}
	})
}

func TestResolve_MinEngineVersionHandshake(t *testing.T) {
	isolatedCache(t)
	raw := packArtifact(t, func(p *rulesbundle.RulePack) {
		p.Manifest.PackVersion = 6
		p.Manifest.MinEngineVersion = "v99.0.0"
	})

	// Released engine older than the requirement → abort with upgrade hint.
	_, _, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{
		EngineVersion: "v0.5.0",
		Fetch:         staticFetch(raw, `"e6"`, nil),
	})
	if err == nil || !strings.Contains(err.Error(), "cbx upgrade") {
		t.Fatalf("err = %v, want upgrade-cbx abort", err)
	}

	// Dev builds satisfy every constraint.
	pack, prov, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{
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
	if _, _, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{
		EngineVersion: "v99.0.0",
		Fetch:         staticFetch(raw, `"e6"`, nil),
	}); err != nil {
		t.Fatalf("equal engine: %v", err)
	}
}

// Build re-validates its result, so an artifact with a malformed
// min_engine_version can only be produced by corrupting the bytes — the
// map round-trip below is the registry-served-garbage simulation.
func TestValidate_RejectsMalformedMinEngineVersion(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(rulesbundletest.MarshalArtifact(t, rulesbundletest.Pack(t)), &doc); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	doc["manifest"].(map[string]any)["min_engine_version"] = "latest"
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal corrupted: %v", err)
	}
	if _, err := rulesbundle.Parse(raw); err == nil || !strings.Contains(err.Error(), "min_engine_version") {
		t.Fatalf("err = %v, want min_engine_version rejection", err)
	}
}

// TestResolve_CorruptCacheIsAMiss: a torn cache must read as a plain
// miss — never a crash, and never a served-but-invalid pack.
func TestResolve_CorruptCacheIsAMiss(t *testing.T) {
	seedCorrupt := func(t *testing.T) {
		t.Helper()
		dir := filepath.Join(isolatedCache(t), "cbx", "rulepack")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "aws-stable-schema1.json"), []byte("torn"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "aws-stable-schema1.meta.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Miss + no other rung = the exhausted-ladder abort, not a crash.
	t.Run("no-network", func(t *testing.T) {
		seedCorrupt(t)
		_, _, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{})
		if !errors.Is(err, rulesbundle.ErrNoRulePack) {
			t.Fatalf("err = %v, want ErrNoRulePack (corrupt cache must be a miss, never a crash)", err)
		}
	})

	// Miss + working network = the fetch serves (and rewrites the cache).
	t.Run("network-recovers", func(t *testing.T) {
		seedCorrupt(t)
		fixedNow(t, time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC))
		pack, prov, err := rulesbundle.Resolve(context.Background(), rulesbundle.ResolveOptions{
			Fetch: staticFetch(packArtifact(t, withVersion(2)), `"e2"`, nil),
		})
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if prov.Source != "network" || pack.Manifest.PackVersion != 2 {
			t.Errorf("provenance = %+v, want network v2 (corrupt cache must not block the fetch)", prov)
		}
	})
}
