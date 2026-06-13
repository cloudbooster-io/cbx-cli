//go:build e2e_staging

package e2e

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/semver"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/knowledge"
	"github.com/cloudbooster-io/cbx-cli/internal/audit/parsers"
	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle"
	pkgcmd "github.com/cloudbooster-io/cbx-cli/pkg/cmd"
)

// TestStagingRulePackContract validates the LIVE rule pack the registry
// serves on the stable channel. The pack is API-only (no embedded copy),
// so the production-content contract checks that used to run against the
// embedded artifact in the unit tier live here instead — unit tests
// ground against the synthetic pack in rulesbundletest and never see
// production rule content.
//
// Like TestStagingConnectivity above, this is opt-in (CB_E2E_STAGING):
// it depends on the live staging API. It needs no login — the rulepack
// endpoint is anonymous-tier — and no human interaction, but it stays
// behind the same maintainer gate so the e2e-staging CI job remains
// deterministic.
func TestStagingRulePackContract(t *testing.T) {
	if os.Getenv("CB_E2E_STAGING") == "" {
		t.Skip("staging E2E disabled: set CB_E2E_STAGING=1 to run (maintainer-only, talks to the live staging registry)")
	}

	t.Parallel()

	apiURL := os.Getenv("CB_API_URL")
	if apiURL == "" {
		t.Fatal("CB_API_URL is not set — required for staging E2E tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	kc := knowledge.New(apiURL)

	// First fetch: latest pack on the stable channel, no ETag. A 404
	// (ErrNotAuthored) here is a registry contract break — the stable
	// channel must always be authored.
	raw, etag, err := kc.RulePack(ctx, "stable", "", 0)
	if err != nil {
		t.Fatalf("GET /v1/knowledge/aws/rulepack (stable, latest) failed: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("registry served an empty rulepack artifact")
	}

	// Parse runs full validation: wire contract (severity vocabulary,
	// response_schema), meta blocks, and the manifest's content_sha256
	// self-check against the served bytes.
	pack, err := rulesbundle.Parse(raw)
	if err != nil {
		t.Fatalf("served rulepack failed Parse/Validate: %v", err)
	}
	if len(pack.Rules) == 0 {
		t.Fatal("served rulepack has no rules — a rule-less grounded audit is the false-green failure mode the registry exists to prevent")
	}
	t.Logf("stable pack: pack_version %d, schema %d, %d rules, content_sha256 %s",
		pack.Manifest.PackVersion, pack.Manifest.SchemaVersion, len(pack.Rules), pack.Manifest.ContentSHA256)

	// Ported from the unit tier's TestEmbeddedPackRequiresFieldsKnown:
	// every cb_describer_* field a rule declares in requires_fields must
	// exist in this engine's generated describer-field manifest. The
	// registry must never serve a stable-channel pack ahead of the
	// released engine without min_engine_version gating — if the pack
	// declares a min this build doesn't satisfy, the gate is doing its
	// job (released engines refuse the pack) and the check doesn't
	// apply to this build, so skip rather than fail.
	t.Run("requires_fields_known", func(t *testing.T) {
		if min := pack.Manifest.MinEngineVersion; !rulepackEngineSatisfies(pkgcmd.Version, min) {
			t.Skipf("pack_version %d declares min_engine_version %s and this test build is %s — the min_engine_version handshake gates it, requires_fields cannot be checked against this engine",
				pack.Manifest.PackVersion, min, pkgcmd.Version)
		}
		for _, r := range pack.Rules {
			for _, f := range r.RequiresFields {
				if !parsers.DescriberFieldKnown(f) {
					t.Errorf("rule %s requires_fields names %q, which no describer/lister/cross-ref in this engine emits — the registry is serving a pack ahead of the engine without min_engine_version gating", r.ID, f)
				}
			}
		}
	})

	// 304 contract: re-fetching with the ETag the registry just returned
	// must yield Not Modified — the resolve ladder's cache revalidation
	// depends on it.
	t.Run("etag_revalidation_304", func(t *testing.T) {
		if etag == "" {
			t.Fatal("registry returned no ETag — cache revalidation (If-None-Match → 304) cannot work")
		}
		_, _, err := kc.RulePack(ctx, "stable", etag, 0)
		if !errors.Is(err, knowledge.ErrNotModified) {
			t.Fatalf("re-fetch with ETag %q: want knowledge.ErrNotModified, got %v", etag, err)
		}
	})
}

// rulepackEngineSatisfies mirrors rulesbundle's min_engine_version
// handshake semantics: an empty min satisfies, and non-semver engine
// versions (e.g. the test binary's default "dev") satisfy every
// constraint.
func rulepackEngineSatisfies(engine, min string) bool {
	if min == "" {
		return true
	}
	e, m := rulepackEnsureV(engine), rulepackEnsureV(min)
	if !semver.IsValid(e) || !semver.IsValid(m) {
		return true
	}
	return semver.Compare(e, m) >= 0
}

func rulepackEnsureV(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}
