package audit

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPreservesPartialFindingsOnScannerError(t *testing.T) {
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
