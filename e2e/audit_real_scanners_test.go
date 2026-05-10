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
	runRealSourceScanner(t, "tfsec", "fixtures/terraform-sample-source")
}

func TestAuditSource_RealCheckov(t *testing.T) {
	runRealSourceScanner(t, "checkov", "fixtures/terraform-sample-source")
}

func TestAuditSource_RealTrivy(t *testing.T) {
	runRealSourceScanner(t, "trivy", "fixtures/terraform-sample-source")
}

func TestAuditSource_RealCheckov_CFN(t *testing.T) {
	runRealSourceScanner(t, "checkov", "fixtures/cloudformation-sample-source")
}

func TestAuditSource_RealTrivy_CFN(t *testing.T) {
	runRealSourceScanner(t, "trivy", "fixtures/cloudformation-sample-source")
}

func TestAuditSource_RealCheckov_K8s(t *testing.T) {
	runRealSourceScanner(t, "checkov", "fixtures/kubernetes-sample-source")
}

func TestAuditSource_RealTrivy_K8s(t *testing.T) {
	runRealSourceScanner(t, "trivy", "fixtures/kubernetes-sample-source")
}

// Helm: no real-scanner test. checkov's Helm framework needs the `helm`
// binary on PATH to render the chart, and `trivy config` skips Go template
// directives. Both produce zero findings against raw template files, which
// would fail runRealSourceScanner's len(findings) > 0 assertion. The mock
// path covers Helm dispatch in audit_test.go; revisit when we want a true
// Helm pipeline (likely involves rendering with helm template before scan).

// runRealSourceScanner executes `cbx audit --source <fixture> --scanners <name>`
// against a real scanner binary and asserts the JSON envelope is valid and
// the findings did not fall back to the mock implementation. Skips if the
// requested binary is not on PATH.
func runRealSourceScanner(t *testing.T, scanner, fixtureRel string) {
	t.Helper()

	if _, err := exec.LookPath(scanner); err != nil {
		t.Skipf("%s not installed on PATH", scanner)
	}

	sourceFixture, err := filepath.Abs(fixtureRel)
	if err != nil {
		t.Fatalf("resolving fixture path: %v", err)
	}

	tmpDir := t.TempDir()
	stdout, stderr, code := runCBXInDir(t, tmpDir, nil,
		"audit", "--source", sourceFixture, "--scanners", scanner, "--output", "json")

	// Real scanners against the misconfigured fixture must produce findings,
	// which surfaces as a non-zero exit. Code is severity-driven — anywhere
	// in 1..3 is acceptable depending on the scanner's severity mapping.
	if code == 0 {
		t.Fatalf("expected non-zero exit (%s findings), got 0\nstderr: %s\nstdout: %s", scanner, stderr, stdout)
	}

	requireJSONValid(t, stdout)

	var envelope struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
		t.Fatalf("parsing JSON envelope: %v", err)
	}
	if len(envelope.Data) == 0 {
		t.Fatalf("expected real %s to produce at least one finding for the fixture", scanner)
	}

	// If we got mock findings here, the MockScanners gate (which is keyed on
	// the absence of --scanners) regressed.
	for _, f := range envelope.Data {
		rid, _ := f["rule_id"].(string)
		if strings.HasPrefix(rid, "MOCK-") {
			t.Fatalf("got mock finding %q; expected real %s output", rid, scanner)
		}
	}
}
