package audit

import (
	"strings"
	"testing"
)

// TestWriteAccountPosture_RendersGlueCatalogPolicy asserts the Glue
// Data Catalog resource-policy block lands in the posture render with a
// precomputed grants_wildcard_principal flag per present region, in
// sorted order, alongside the raw document for citation. Without the
// boolean the LLM has to parse the policy JSON itself — the S3
// describer learned that "policy present" alone wasn't enough signal.
func TestWriteAccountPosture_RendersGlueCatalogPolicy(t *testing.T) {
	posture := &AccountPosture{
		GlueCatalogPolicyByRegion: map[string]*GlueCatalogPolicy{
			"us-east-1": {
				GrantsWildcardPrincipal: true,
				Document:                `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"glue:GetTable"}]}`,
			},
			"eu-west-1": {
				GrantsWildcardPrincipal: false,
				Document:                `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::444455556666:root"}}]}`,
			},
		},
	}
	var sb strings.Builder
	writeAccountPosture(&sb, posture)
	out := sb.String()

	for _, want := range []string{
		"Glue Data Catalog resource policy",
		"us-east-1: grants_wildcard_principal=true",
		"eu-west-1: grants_wildcard_principal=false",
		`"Principal":"*"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("posture render missing %q\n---\n%s", want, out)
		}
	}

	// Sorted order: eu-west-1 must render before us-east-1.
	if strings.Index(out, "eu-west-1") > strings.Index(out, "us-east-1") {
		t.Errorf("Glue regions not rendered in sorted order:\n%s", out)
	}
}

// TestWriteAccountPosture_OmitsGlueWhenNoPolicies asserts the Glue
// block is suppressed entirely when no region carries a catalog
// resource policy (the common case) — present-only, no prompt bloat.
func TestWriteAccountPosture_OmitsGlueWhenNoPolicies(t *testing.T) {
	posture := &AccountPosture{
		GlueCatalogPolicyByRegion: map[string]*GlueCatalogPolicy{},
	}
	var sb strings.Builder
	writeAccountPosture(&sb, posture)
	if strings.Contains(sb.String(), "Glue Data Catalog resource policy") {
		t.Errorf("Glue block rendered for an account with no catalog policies:\n%s", sb.String())
	}
}

// TestBuildGroundedPrompt_HasGlueAndAthenaRules guards the baseline
// rule text so a rebase against the other rule-family branches can't
// silently drop the Athena workgroup (enforce/encryption) or Glue
// Data Catalog wildcard-principal guidance from rule #1.
func TestBuildGroundedPrompt_HasGlueAndAthenaRules(t *testing.T) {
	prompt := buildGroundedPrompt(IaCTypeCloudFormation, nil, nil, nil, nil)
	for _, want := range []string{
		"AWS::Athena::WorkGroup",
		"EnforceWorkGroupConfiguration",
		"EncryptionConfiguration",
		// The `primary`-workgroup carve-out must key on the describer
		// flag (computed deterministically in Go), not on the literal
		// name — otherwise the LLM is left re-deciding "is this the
		// default" and the false positive returns.
		"cb_describer_is_default_workgroup",
		"Glue Data Catalog exposure",
		"grants_wildcard_principal=true",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("grounded prompt missing rule text %q", want)
		}
	}
}
