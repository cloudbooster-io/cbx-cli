package audit_test

// Smoke test for the pkg/audit facade. downstream consumers depends on these type
// aliases and function vars resolving to the same symbols
// internal/audit exposes; if a re-export is renamed or dropped this
// test fails at compile time rather than silently breaking downstream consumers at
// import.

import (
	"testing"

	internalaudit "github.com/cloudbooster-io/cbx-cli/internal/audit"
	"github.com/cloudbooster-io/cbx-cli/internal/audit/group"
	pkgaudit "github.com/cloudbooster-io/cbx-cli/pkg/audit"
)

func TestFacade_TypeAliasesIdentical(t *testing.T) {
	// Type aliases are compile-time equivalent — assignability proves
	// the package's contract holds for downstream consumers.
	var (
		_ pkgaudit.Finding            = internalaudit.Finding{}
		_ pkgaudit.CBSource           = internalaudit.CBSource{}
		_ pkgaudit.Result             = internalaudit.Result{}
		_ pkgaudit.Options            = internalaudit.Options{}
		_ pkgaudit.DiscoveredResource = internalaudit.DiscoveredResource{}
		_ pkgaudit.Component          = group.Component{}
	)
}

func TestFacade_SeverityConstantsMatch(t *testing.T) {
	pairs := []struct {
		facade, internal string
	}{
		{pkgaudit.SeverityInfo, internalaudit.SeverityInfo},
		{pkgaudit.SeverityWarning, internalaudit.SeverityWarning},
		{pkgaudit.SeverityHigh, internalaudit.SeverityHigh},
		{pkgaudit.SeverityCritical, internalaudit.SeverityCritical},
	}
	for _, p := range pairs {
		if p.facade != p.internal {
			t.Errorf("severity constant drift: %q vs %q", p.facade, p.internal)
		}
	}
}

func TestFacade_IaCConstantsMatch(t *testing.T) {
	pairs := []struct {
		facade, internal string
	}{
		{pkgaudit.IaCTypeAuto, internalaudit.IaCTypeAuto},
		{pkgaudit.IaCTypeTerraform, internalaudit.IaCTypeTerraform},
		{pkgaudit.IaCTypeCloudFormation, internalaudit.IaCTypeCloudFormation},
		{pkgaudit.IaCTypeK8s, internalaudit.IaCTypeK8s},
		{pkgaudit.IaCTypeHelm, internalaudit.IaCTypeHelm},
	}
	for _, p := range pairs {
		if p.facade != p.internal {
			t.Errorf("iactype constant drift: %q vs %q", p.facade, p.internal)
		}
	}
}

func TestFacade_LookupHelpersMatchInternal(t *testing.T) {
	// Function vars compare by underlying pointer; we instead spot-
	// check a known mapping to prove the facade calls into the same
	// generated maps the internal package uses.
	if pkgaudit.CFNTypeToCBPrimitive("AWS::S3::Bucket") != "aws:s3/bucket@v1" {
		t.Error("facade.CFNTypeToCBPrimitive did not return the expected primitive id for AWS::S3::Bucket")
	}
	if pkgaudit.RDSPrimitiveFor("postgres") != "aws:db/postgres@v1" {
		t.Error("facade.RDSPrimitiveFor did not engine-resolve postgres")
	}
}
