package audit_test

// Smoke test for the pkg/audit facade. downstream consumers depends on these type
// aliases and function vars resolving to the same symbols
// internal/audit exposes; if a re-export is renamed or dropped this
// test fails at compile time rather than silently breaking downstream consumers at
// import.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	internalaudit "github.com/cloudbooster-io/cbx-cli/internal/audit"
	"github.com/cloudbooster-io/cbx-cli/internal/audit/group"
	"github.com/cloudbooster-io/cbx-cli/internal/audit/parsers"
	pkgaudit "github.com/cloudbooster-io/cbx-cli/pkg/audit"
)

func TestFacade_TypeAliasesIdentical(t *testing.T) {
	// Type aliases are compile-time equivalent — each conversion below
	// only compiles while the facade alias still resolves to its
	// internal counterpart. (Conversions rather than typed var
	// declarations keep staticcheck QF1011 quiet.)
	var (
		_ = pkgaudit.Finding(internalaudit.Finding{})
		_ = pkgaudit.CBSource(internalaudit.CBSource{})
		_ = pkgaudit.Result(internalaudit.Result{})
		_ = pkgaudit.Options(internalaudit.Options{})
		_ = pkgaudit.DiscoveredResource(internalaudit.DiscoveredResource{})
		_ = pkgaudit.Resource(internalaudit.Resource{})
		_ = pkgaudit.Component(group.Component{})
		_ = pkgaudit.AWSAuditContext(internalaudit.AWSAuditContext{})
		_ = pkgaudit.ExitCodeError(internalaudit.ExitCodeError{})
		_ = pkgaudit.ParseError(parsers.ParseError{})

		// Types that escape through exported fields of the aliases
		// above (review H3).
		_ = pkgaudit.LLMConnection(internalaudit.LLMConnection{})
		_ = pkgaudit.AccountPosture(internalaudit.AccountPosture{})
		_ = pkgaudit.ConfigRecorderState(internalaudit.ConfigRecorderState{})
		_ = pkgaudit.CredentialReportPosture(internalaudit.CredentialReportPosture{})
		_ = pkgaudit.GlueCatalogPolicy(internalaudit.GlueCatalogPolicy{})
		_ = pkgaudit.AuditState(internalaudit.AuditState{})

		// FindingProvider is an interface — the inner-to-outer
		// conversion only compiles while the internal contract still
		// satisfies the facade's.
		_ = pkgaudit.FindingProvider(internalaudit.FindingProvider(nil))
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

func TestFacade_CollectContextHonorsCancellation(t *testing.T) {
	// The facade var must resolve to the cancellable entry point: a
	// pre-cancelled ctx returns ctx.Err() before any scanner (or even the
	// state file) is touched, so no fixture is needed.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := pkgaudit.CollectContext(ctx, pkgaudit.Options{StateFile: "does-not-exist.json"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from a pre-cancelled ctx, got %v", err)
	}
}

func TestFacade_ParseErrorRoundTrip(t *testing.T) {
	// A real parse failure through the public entry point must come back
	// as a *ParseError extractable with errors.As — library consumers
	// branch on the typed error instead of string-matching the rendered
	// three-line message.
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"invalid`), 0o644); err != nil {
		t.Fatalf("writing state file: %v", err)
	}

	_, err := pkgaudit.Collect(pkgaudit.Options{StateFile: path, MockScanners: true})
	if err == nil {
		t.Fatal("expected a parse error for malformed JSON")
	}
	var pe *pkgaudit.ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("expected errors.As to extract *ParseError, got %T: %v", err, err)
	}
	if pe.What == "" || pe.Cause == "" || pe.Hint == "" {
		t.Fatalf("ParseError fields not populated: %+v", pe)
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
