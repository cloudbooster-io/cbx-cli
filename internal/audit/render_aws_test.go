package audit

import (
	"os"
	"strings"
	"testing"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit/group"
)

func TestRenderAWSMarkdown_HeaderIncludesAccountIdentityRegionsEvents(t *testing.T) {
	ctx := AWSAuditContext{
		AccountID:  "123456789012",
		Identity:   "arn:aws:iam::123456789012:user/alice",
		Regions:    []string{"us-east-1", "eu-west-1"},
		EventCount: 117,
	}
	result := &Result{Findings: nil, Components: nil}
	out := RenderAWSMarkdown(result, ctx)

	wants := []string{
		"# CloudBooster Audit Report — AWS",
		"## Audited Account",
		"123456789012",
		"arn:aws:iam::123456789012:user/alice",
		"us-east-1, eu-west-1",
		"~117",
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("output missing %q\n---\n%s", w, out)
		}
	}
}

func TestRenderAWSMarkdown_PerComponentSection(t *testing.T) {
	components := []group.Component{
		{
			Name:      "frontend",
			Kind:      "tag",
			Resources: []string{"aws://us-east-1/AWS::S3::Bucket/web"},
			Source:    map[string]string{"tag.Application": "frontend"},
		},
		{
			Name:      "cb:aws:db/postgres@v1:aws://us-east-1/AWS::RDS::DBInstance/prod-db",
			Kind:      "cb-primitive",
			Resources: []string{"aws://us-east-1/AWS::RDS::DBInstance/prod-db"},
			Source:    map[string]string{"primitive": "aws:db/postgres@v1"},
		},
	}
	findings := []Finding{
		{
			RuleID:   "ORPHAN-EBS-UNATTACHED",
			Title:    "Unattached EBS volume",
			Severity: SeverityInfo,
			Resource: "aws://us-east-1/AWS::S3::Bucket/web",
			Service:  "S3",
		},
		{
			RuleID:   "ORPHAN-IAM-ROLE-UNUSED",
			Title:    "IAM role unused",
			Severity: SeverityInfo,
			Resource: "aws://global/AWS::IAM::Role/unused-role", // no component → account-wide
			Service:  "IAM",
		},
	}
	result := &Result{Findings: findings, Components: components}
	out := RenderAWSMarkdown(result, AWSAuditContext{})

	if !strings.Contains(out, "## Components") {
		t.Errorf("missing ## Components section\n---\n%s", out)
	}
	if !strings.Contains(out, "### tag: frontend") {
		t.Errorf("tag component header missing")
	}
	if !strings.Contains(out, "### cb-primitive:") {
		t.Errorf("cb-primitive component header missing")
	}
	if !strings.Contains(out, "## Account-wide Findings") {
		t.Errorf("missing account-wide section")
	}
	// The IAM finding (no matching component) must land under account-wide;
	// the EBS finding (matched to frontend) must NOT.
	accountIdx := strings.Index(out, "## Account-wide Findings")
	if accountIdx == -1 {
		t.Fatal("account-wide marker missing")
	}
	if !strings.Contains(out[accountIdx:], "ORPHAN-IAM-ROLE-UNUSED") {
		t.Errorf("IAM finding not in account-wide section")
	}
	if strings.Contains(out[accountIdx:], "ORPHAN-EBS-UNATTACHED") {
		t.Errorf("EBS finding leaked into account-wide section (should be under frontend)")
	}
}

func TestPartitionFindings_FindingMatchedOnlyOnce(t *testing.T) {
	// A resource that's in two components (a tag-based AND a cb-primitive)
	// must have its finding placed under exactly one (the first by sorted
	// order) — not double-rendered.
	components := []group.Component{
		{Name: "frontend", Kind: "tag", Resources: []string{"urn-a"}},
		{Name: "cb:aws:s3/bucket@v1:urn-a", Kind: "cb-primitive", Resources: []string{"urn-a"}},
	}
	findings := []Finding{
		{RuleID: "X", Resource: "urn-a"},
	}
	placed, accountWide := partitionFindingsByComponent(findings, components)
	if len(accountWide) != 0 {
		t.Errorf("expected no account-wide findings; got %+v", accountWide)
	}
	total := 0
	for _, fs := range placed {
		total += len(fs)
	}
	if total != 1 {
		t.Errorf("finding rendered %d times; want 1", total)
	}
}

func TestPartitionFindings_NoComponentsKeepsAllFindingsAccountWide(t *testing.T) {
	findings := []Finding{{RuleID: "X", Resource: "urn-a"}, {RuleID: "Y", Resource: "urn-b"}}
	placed, accountWide := partitionFindingsByComponent(findings, nil)
	if placed != nil {
		t.Errorf("expected no per-component findings, got %+v", placed)
	}
	if len(accountWide) != 2 {
		t.Errorf("expected both findings account-wide, got %d", len(accountWide))
	}
}

func TestPartitionFindings_EmptyResourceFindingsAlwaysAccountWide(t *testing.T) {
	// Findings without a Resource (e.g. LLM-CB-COST-CAP) must never be
	// assigned to a component even if a component happens to share an
	// empty URN somehow.
	findings := []Finding{{RuleID: "LLM-CB-COST-CAP"}}
	components := []group.Component{{Name: "x", Resources: []string{""}}}
	placed, accountWide := partitionFindingsByComponent(findings, components)
	if len(placed) != 0 {
		t.Errorf("empty-resource finding leaked into component %+v", placed)
	}
	if len(accountWide) != 1 {
		t.Errorf("expected the finding account-wide, got %d", len(accountWide))
	}
}

func TestRunFromResources_AWSContextSelectsAWSRenderer(t *testing.T) {
	// Round-trip: when awsCtx is non-nil the on-disk report uses the
	// AWS shape ("# CloudBooster Audit Report — AWS"). When nil it
	// falls back to the generic header.
	dir := t.TempDir()
	resources := []DiscoveredResource{
		{
			Type: "AWS::S3::Bucket",
			URN:  "aws://us-east-1/AWS::S3::Bucket/web",
			ID:   "web",
			Tags: map[string]string{"Application": "frontend"},
		},
	}
	opts := Options{
		AWS:          true,
		AWSAccountID: "123",
		MockScanners: true,
		ReportFile:   dir + "/aws-report.md",
	}
	awsCtx := &AWSAuditContext{AccountID: "123", Identity: "arn:x", Regions: []string{"us-east-1"}, EventCount: 42}

	_, err := RunFromResources(opts, resources, awsCtx)
	if err != nil {
		t.Fatalf("RunFromResources: %v", err)
	}

	body, err := os.ReadFile(dir + "/aws-report.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "# CloudBooster Audit Report — AWS") {
		t.Errorf("AWS-mode header missing from report:\n%s", string(body))
	}
	if !strings.Contains(string(body), "~42") {
		t.Errorf("event count missing from report")
	}
}
