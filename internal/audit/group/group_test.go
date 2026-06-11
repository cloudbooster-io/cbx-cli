package group

import (
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/parsers"
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

func TestGroupByCBPrimitive_ResolvedOverrideWinsOverStaticLookup(t *testing.T) {
	// AWS::RDS::DBInstance has no static CFN → primitive mapping (engine-split).
	// The RDS describer writes the resolved id into Inputs; grouping must
	// pick that up so the cb-primitive lens names the right primitive even
	// when the static lookup returns "".
	resources := []parsers.DiscoveredResource{
		{
			URN:  "aws://us-east-1/AWS::RDS::DBInstance/db-prod",
			Type: "AWS::RDS::DBInstance",
			Inputs: map[string]any{
				"cb_describer_primitive_resolved": "aws:db/postgres@v1",
			},
		},
	}
	lookup := func(string) string { return "" } // static map empty for DBInstance
	got := groupByCBPrimitive(resources, lookup)
	if len(got) != 1 {
		t.Fatalf("want 1 component, got %d", len(got))
	}
	if got[0].Name != "cb:aws:db/postgres@v1:aws://us-east-1/AWS::RDS::DBInstance/db-prod" {
		t.Errorf("component name = %q", got[0].Name)
	}
	if got[0].Source["primitive"] != "aws:db/postgres@v1" {
		t.Errorf("Source.primitive = %q", got[0].Source["primitive"])
	}
}

func TestGroupByCBPrimitive_OverrideTrumpsStaticEvenWhenBothSet(t *testing.T) {
	// Belt + suspenders: if a describer ever resolves a primitive for a
	// CFN type that ALSO has a static mapping, the resolved override
	// must win. This is the contract the RDS describer depends on.
	resources := []parsers.DiscoveredResource{
		{
			URN:  "aws://us-east-1/foo",
			Type: "AWS::S3::Bucket",
			Inputs: map[string]any{
				"cb_describer_primitive_resolved": "aws:override/test@v1",
			},
		},
	}
	lookup := func(string) string { return "aws:s3/bucket@v1" }
	got := groupByCBPrimitive(resources, lookup)
	if len(got) != 1 || got[0].Source["primitive"] != "aws:override/test@v1" {
		t.Fatalf("override did not win: %+v", got)
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
