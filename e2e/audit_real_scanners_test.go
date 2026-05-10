//go:build e2e_real_scanners

// Real-scanner e2e tests. Opt-in only — these invoke the real tfsec binary
// and require it to be installed on PATH. Run with:
//
//   go test -tags e2e_real_scanners ./e2e -run TestAuditSource_Real
//
// Not part of the default CI matrix to keep the offline guarantee on the
// fast `e2e-matrix` job.

package e2e

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditSource_RealTfsec(t *testing.T) {
	if _, err := exec.LookPath("tfsec"); err != nil {
		t.Skip("tfsec not installed on PATH")
	}

	sourceFixture, err := filepath.Abs("fixtures/terraform-sample-source")
	if err != nil {
		t.Fatalf("resolving fixture path: %v", err)
	}

	tmpDir := t.TempDir()
	stdout, stderr, code := runCBXInDir(t, tmpDir, nil,
		"audit", "--source", sourceFixture, "--scanners", "tfsec", "--output", "json")

	if code == 0 {
		t.Fatalf("expected non-zero exit code (fixture has misconfigured resources), got %d\nstderr: %s", code, stderr)
	}

	requireJSONValid(t, stdout)

	var envelope struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
		t.Fatalf("parsing JSON envelope: %v", err)
	}
	if len(envelope.Data) == 0 {
		t.Fatal("expected real tfsec to produce at least one finding for the fixture")
	}

	// Real tfsec rule IDs follow the AVD-AWS-XXXX pattern. If we somehow
	// got mock findings here the MockScanners gate regressed.
	for _, f := range envelope.Data {
		rid, _ := f["rule_id"].(string)
		if strings.HasPrefix(rid, "MOCK-") {
			t.Fatalf("got mock finding %q; expected real tfsec output", rid)
		}
	}
}
