package group

import (
	"testing"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit/parsers"
)

func makeRes(urn, cfnType string, tags map[string]string) parsers.DiscoveredResource {
	return parsers.DiscoveredResource{URN: urn, Type: cfnType, Tags: tags}
}

func TestGroupByTags_PriorityFirstWins(t *testing.T) {
	resources := []parsers.DiscoveredResource{
		makeRes("a", "AWS::S3::Bucket", map[string]string{"Application": "frontend", "Service": "ignored"}),
		makeRes("b", "AWS::S3::Bucket", map[string]string{"Service": "api"}),
		makeRes("c", "AWS::S3::Bucket", map[string]string{}),
	}
	got := groupByTags(resources, []string{"Application", "Service"})

	want := map[string][]string{
		"<unassigned>": {"c"},
		"api":          {"b"},
		"frontend":     {"a"},
	}
	if len(got) != 3 {
		t.Fatalf("want 3 components, got %d", len(got))
	}
	for _, c := range got {
		w, ok := want[c.Name]
		if !ok {
			t.Errorf("unexpected component %q", c.Name)
			continue
		}
		if len(c.Resources) != len(w) || c.Resources[0] != w[0] {
			t.Errorf("component %q: got %v, want %v", c.Name, c.Resources, w)
		}
	}
}

func TestGroupByTags_NoUnassignedBucketWhenAllMatch(t *testing.T) {
	resources := []parsers.DiscoveredResource{
		makeRes("a", "AWS::S3::Bucket", map[string]string{"Application": "frontend"}),
		makeRes("b", "AWS::S3::Bucket", map[string]string{"Application": "frontend"}),
	}
	got := groupByTags(resources, []string{"Application"})
	if len(got) != 1 {
		t.Fatalf("want 1 component, got %d", len(got))
	}
	if got[0].Name != "frontend" {
		t.Errorf("got %q, want frontend", got[0].Name)
	}
	if len(got[0].Resources) != 2 {
		t.Errorf("want 2 resources, got %d", len(got[0].Resources))
	}
}

func TestGroupByTags_SourceCarriesWinningTag(t *testing.T) {
	resources := []parsers.DiscoveredResource{
		makeRes("a", "AWS::S3::Bucket", map[string]string{"Service": "api"}),
	}
	got := groupByTags(resources, []string{"Application", "Service"})
	if got[0].Source["tag.Service"] != "api" {
		t.Errorf("source should record the winning tag: got %v", got[0].Source)
	}
}

func TestGroupByCBPrimitive_OnePerMatchedResource(t *testing.T) {
	resources := []parsers.DiscoveredResource{
		makeRes("a", "AWS::S3::Bucket", nil),
		makeRes("b", "AWS::Lambda::Function", nil),
		makeRes("c", "AWS::Foo::Bar", nil), // unknown — skipped
	}
	lookup := func(cfn string) string {
		switch cfn {
		case "AWS::S3::Bucket":
			return "aws:s3/bucket@v1"
		case "AWS::Lambda::Function":
			return "aws:compute/lambda@v1"
		}
		return ""
	}
	got := groupByCBPrimitive(resources, lookup)
	if len(got) != 2 {
		t.Fatalf("want 2 components, got %d", len(got))
	}
	for _, c := range got {
		if c.Kind != "cb-primitive" {
			t.Errorf("kind: got %q", c.Kind)
		}
		if len(c.Resources) != 1 {
			t.Errorf("want component-of-one, got %d", len(c.Resources))
		}
	}
}

func TestGroupByCBPrimitive_NilLookupReturnsNil(t *testing.T) {
	got := groupByCBPrimitive([]parsers.DiscoveredResource{makeRes("a", "x", nil)}, func(string) string { return "" })
	if got != nil {
		t.Errorf("want nil, got %v", got)
	}
}

func TestGroup_CombinesLensesAndStableOrdering(t *testing.T) {
	resources := []parsers.DiscoveredResource{
		makeRes("a", "AWS::S3::Bucket", map[string]string{"Application": "frontend"}),
		makeRes("b", "AWS::Lambda::Function", map[string]string{"Application": "frontend"}),
	}
	lookup := func(cfn string) string {
		switch cfn {
		case "AWS::S3::Bucket":
			return "aws:s3/bucket@v1"
		case "AWS::Lambda::Function":
			return "aws:compute/lambda@v1"
		}
		return ""
	}
	got := Group(resources, Options{LookupPrimitive: lookup})

	// Should have: 1 tag component (frontend) + 2 cb-primitive components
	if len(got) != 3 {
		t.Fatalf("want 3 components, got %d", len(got))
	}

	// Kind sort: cb-primitive before tag
	if got[0].Kind != "cb-primitive" || got[1].Kind != "cb-primitive" || got[2].Kind != "tag" {
		t.Errorf("kinds in wrong order: %q %q %q", got[0].Kind, got[1].Kind, got[2].Kind)
	}
}

func TestGroup_EmptyReturnsNil(t *testing.T) {
	got := Group(nil, Options{})
	if got != nil {
		t.Errorf("want nil, got %v", got)
	}
}

func TestGroup_TagPriorityDefaults(t *testing.T) {
	resources := []parsers.DiscoveredResource{
		makeRes("a", "x", map[string]string{"Project": "alpha"}),
	}
	got := Group(resources, Options{}) // empty TagPriority → defaults kick in
	if len(got) != 1 || got[0].Name != "alpha" {
		t.Errorf("default priority should pick up Project tag; got %v", got)
	}
}
