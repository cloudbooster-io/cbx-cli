package audit

// Offline-guarantee tests (invariant 2 of docs/REVIEW_2026-06-11.md):
// state-file audits through the pkg/audit library path must perform ZERO
// network calls — both with a zero-value scanner selection (which resolves
// to the built-in mock set) and with an explicit MockScanners: true.
//
// These replace the legacy-tagged e2e audit_zero_outbound_http test (the
// deleted e2e/audit_test.go behind //go:build legacy_iac_audit), which
// exercised CLI flags that no longer exist and therefore never ran. Here
// the guarantee is enforced tag-free at the library layer: a trap
// RoundTripper is installed as http.DefaultTransport, so any code path
// that reaches Go's default HTTP stack fails the run and is recorded.

import (
	"errors"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
)

// trapTransport records and fails every request routed through it.
type trapTransport struct {
	mu   sync.Mutex
	hits []string
}

func (tt *trapTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	tt.mu.Lock()
	tt.hits = append(tt.hits, req.URL.String())
	tt.mu.Unlock()
	return nil, errors.New("offline-guarantee violation: outbound HTTP attempted")
}

func (tt *trapTransport) requests() []string {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	return append([]string(nil), tt.hits...)
}

// installTrapTransport swaps http.DefaultTransport for a trapTransport and
// restores the original on cleanup. Tests using it must NOT call
// t.Parallel() — it mutates process-global state.
func installTrapTransport(t *testing.T) *trapTransport {
	t.Helper()
	trap := &trapTransport{}
	orig := http.DefaultTransport
	http.DefaultTransport = trap
	t.Cleanup(func() { http.DefaultTransport = orig })
	return trap
}

// offlineStateFile writes the minimal Pulumi state fixture used by the
// runner tests (one S3 bucket → the static mock scanner emits findings).
func offlineStateFile(t *testing.T) string {
	t.Helper()
	statePath := filepath.Join(t.TempDir(), "state.json")
	writeJSON(t, statePath, map[string]interface{}{
		"version": 3,
		"deployment": map[string]interface{}{
			"resources": []interface{}{
				map[string]interface{}{
					"urn":  "urn:pulumi:dev::stack::aws:s3/bucket:Bucket::my-bucket",
					"type": "aws:s3/bucket:Bucket",
				},
			},
		},
	})
	return statePath
}

func assertOffline(t *testing.T, trap *trapTransport, findings []Finding, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("expected offline state-file audit to succeed, got: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from the static mock scanner")
	}
	if hits := trap.requests(); len(hits) != 0 {
		t.Fatalf("offline guarantee violated: %d outbound HTTP request(s): %v", len(hits), hits)
	}
}

func TestCollect_OfflineGuarantee_ZeroValueScannerDefault(t *testing.T) {
	// No t.Parallel: installTrapTransport mutates http.DefaultTransport.
	trap := installTrapTransport(t)

	findings, err := Collect(Options{StateFile: offlineStateFile(t)})
	assertOffline(t, trap, findings, err)
}

func TestCollect_OfflineGuarantee_ExplicitMockScanners(t *testing.T) {
	// No t.Parallel: installTrapTransport mutates http.DefaultTransport.
	trap := installTrapTransport(t)

	findings, err := Collect(Options{
		StateFile:    offlineStateFile(t),
		MockScanners: true,
	})
	assertOffline(t, trap, findings, err)
}
