package audit

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPreservesPartialFindingsOnScannerError(t *testing.T) {
	// This test asserts the failure path when tfsec is missing. Skip when
	// tfsec is installed locally — it then runs successfully and the
	// premise no longer holds. CI's golang:1.25 image has no scanners on
	// PATH so the assertion still runs there.
	if _, lookErr := exec.LookPath("tfsec"); lookErr == nil {
		t.Skip("tfsec is installed locally; this test asserts the missing-binary path")
	}

	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
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

	opts := Options{
		StateFile: statePath,
		Scanners:  []string{"static", "tfsec"},
	}

	result, err := Run(opts)
	if err == nil {
		t.Fatal("expected error because tfsec is not installed")
	}
	if result == nil {
		t.Fatal("expected non-nil result with partial findings from static scanner")
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings from static scanner despite tfsec failure")
	}
	if !strings.Contains(err.Error(), "tfsec") {
		t.Errorf("expected error to mention tfsec, got: %v", err)
	}
}

func TestCollectContext_PreCancelledReturnsCtxErr(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
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

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	findings, err := CollectContext(ctx, Options{StateFile: statePath, MockScanners: true})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from a pre-cancelled ctx, got %v", err)
	}
	if findings != nil {
		t.Fatalf("expected no findings from a pre-cancelled ctx, got %d", len(findings))
	}
}

func TestSelectProviders_ExternalScannersAreOptInByName(t *testing.T) {
	mockOnly := func(t *testing.T, providers []FindingProvider) {
		t.Helper()
		for _, p := range providers {
			switch p.Name() {
			case "static", "orphan":
			default:
				t.Fatalf("expected only the zero-network mock set, got scanner %q", p.Name())
			}
		}
	}

	// The library-mode guarantee: a zero-value Options (MockScanners false,
	// Scanners empty) must resolve to the mock set, never AllScanners.
	mockOnly(t, selectProviders(Options{}))

	// MockScanners overrides an explicit external selection.
	mockOnly(t, selectProviders(Options{MockScanners: true, Scanners: []string{"prowler", "trivy"}}))

	// Explicitly named external scanners still resolve (the --scanners path).
	named := selectProviders(Options{Scanners: []string{"static", "tfsec"}})
	if len(named) != 2 {
		t.Fatalf("expected 2 named providers, got %d", len(named))
	}
	var hasTfsec bool
	for _, p := range named {
		if p.Name() == "tfsec" {
			hasTfsec = true
		}
	}
	if !hasTfsec {
		t.Fatal("expected explicitly named tfsec adapter to be selected")
	}
}

func TestCollect_EmptyScannersDefaultsToMockSet(t *testing.T) {
	// Regression test for the library-scanner trap: with MockScanners false
	// AND Scanners empty, Collect must run the built-in zero-network mock
	// set. Before the fix this fell through to AllScanners() — on a machine
	// without the external binaries the missing-binary errors would surface
	// here (and with them installed, prowler would touch live AWS).
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")
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

	findings, err := Collect(Options{StateFile: statePath})
	if err != nil {
		t.Fatalf("expected zero-value scanner selection to run the mock set without error, got: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from the static mock scanner")
	}
}
