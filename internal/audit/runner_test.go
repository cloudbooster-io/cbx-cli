package audit

import (
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
