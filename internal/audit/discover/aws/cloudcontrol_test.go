package aws

import (
	"testing"
)

func TestMapToDiscovered_S3Bucket(t *testing.T) {
	raw := rawResource{
		CFNType:    "AWS::S3::Bucket",
		Identifier: "my-bucket",
		Region:     "us-east-1",
		Properties: `{"BucketName":"my-bucket","Tags":[{"Key":"Application","Value":"frontend"},{"Key":"Env","Value":"prod"}]}`,
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dr.Type != "AWS::S3::Bucket" {
		t.Errorf("Type: got %q, want AWS::S3::Bucket", dr.Type)
	}
	if dr.ID != "my-bucket" {
		t.Errorf("ID: got %q, want my-bucket", dr.ID)
	}
	if dr.Region != "us-east-1" {
		t.Errorf("Region: got %q", dr.Region)
	}
	if dr.URN != "aws://us-east-1/AWS::S3::Bucket/my-bucket" {
		t.Errorf("URN: got %q", dr.URN)
	}
	if dr.Tags["Application"] != "frontend" || dr.Tags["Env"] != "prod" {
		t.Errorf("Tags: got %v", dr.Tags)
	}
	if dr.Inputs["BucketName"] != "my-bucket" {
		t.Errorf("Inputs lost BucketName: got %v", dr.Inputs)
	}
}

func TestMapToDiscovered_EmptyProperties(t *testing.T) {
	raw := rawResource{CFNType: "AWS::IAM::Role", Identifier: "Admins", Region: ""}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dr.Tags != nil {
		t.Errorf("Tags: expected nil, got %v", dr.Tags)
	}
	if dr.URN != "aws://global/AWS::IAM::Role/Admins" {
		t.Errorf("URN should fall back to 'global': got %q", dr.URN)
	}
}

func TestExtractTags_ListOfPairs(t *testing.T) {
	props := map[string]any{
		"Tags": []any{
			map[string]any{"Key": "a", "Value": "1"},
			map[string]any{"Key": "b", "Value": "2"},
		},
	}
	got := extractTags(props)
	if got["a"] != "1" || got["b"] != "2" {
		t.Errorf("got %v", got)
	}
}

func TestExtractTags_FlatMap(t *testing.T) {
	props := map[string]any{
		"Tags": map[string]any{"a": "1", "b": "2"},
	}
	got := extractTags(props)
	if got["a"] != "1" || got["b"] != "2" {
		t.Errorf("got %v", got)
	}
}

func TestExtractTags_None(t *testing.T) {
	if extractTags(nil) != nil {
		t.Error("nil props should return nil tags")
	}
	if extractTags(map[string]any{"Foo": "bar"}) != nil {
		t.Error("props without Tags should return nil")
	}
}

func TestDedupeByURN(t *testing.T) {
	in := []DiscoveredResource{
		{URN: "a", ID: "1"},
		{URN: "b", ID: "2"},
		{URN: "a", ID: "1-dup"}, // dup
		{URN: "c", ID: "3"},
	}
	out := dedupeByURN(in)
	if len(out) != 3 {
		t.Errorf("got %d, want 3", len(out))
	}
	// first-occurrence wins
	if out[0].ID != "1" {
		t.Errorf("first-write-wins violated: got ID %q", out[0].ID)
	}
}
