package aws

import (
	"context"
	"errors"
	"testing"
)

func TestResolveRegions_EmptyWithProfileDefault(t *testing.T) {
	c := awsCfg{}.withRegion("us-east-1")
	got, err := resolveRegionsImpl(context.Background(), c, nil, failingDescribe(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "us-east-1" {
		t.Errorf("got %v, want [us-east-1]", got)
	}
}

func TestResolveRegions_EmptyNoDefault(t *testing.T) {
	c := awsCfg{}
	_, err := resolveRegionsImpl(context.Background(), c, nil, failingDescribe(t))
	if !errors.Is(err, ErrNoRegion) {
		t.Errorf("got %v, want ErrNoRegion", err)
	}
}

func TestResolveRegions_ExplicitList(t *testing.T) {
	c := awsCfg{}.withRegion("us-east-1")
	got, err := resolveRegionsImpl(context.Background(), c, []string{"us-east-1", "eu-west-1"}, failingDescribe(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0] != "us-east-1" || got[1] != "eu-west-1" {
		t.Errorf("got %v, want [us-east-1 eu-west-1]", got)
	}
}

func TestResolveRegions_ExplicitListDedupesAndLowercases(t *testing.T) {
	c := awsCfg{}.withRegion("us-east-1")
	got, err := resolveRegionsImpl(context.Background(), c, []string{"US-EAST-1", "us-east-1", " eu-west-1 "}, failingDescribe(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"us-east-1", "eu-west-1"}
	if !equalSlices(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestResolveRegions_AllLiteralCallsDescribe(t *testing.T) {
	c := awsCfg{}.withRegion("us-east-1")
	called := false
	describe := func(ctx context.Context, c awsCfg) ([]string, error) {
		called = true
		return []string{"us-east-1", "eu-west-1", "ap-southeast-2"}, nil
	}
	got, err := resolveRegionsImpl(context.Background(), c, []string{"all"}, describe)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Errorf("describe not called")
	}
	if len(got) != 3 {
		t.Errorf("got %v, want 3 regions", got)
	}
}

func TestResolveRegions_InvalidRegionFormat(t *testing.T) {
	c := awsCfg{}.withRegion("us-east-1")
	_, err := resolveRegionsImpl(context.Background(), c, []string{"definitely-not-a-region"}, failingDescribe(t))
	if err == nil {
		t.Errorf("expected validation error for bogus region")
	}
}

func TestLooksLikeRegion(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"us-east-1", true},
		{"eu-west-3", true},
		{"ap-southeast-2", true},
		{"us-gov-east-1", true},
		{"cn-north-1", true},
		{"us", false},
		{"useast1", false},
		{"us-east", false},
		{"us-east-9999", false},
		{"", false},
	}
	for _, c := range cases {
		if got := looksLikeRegion(c.in); got != c.want {
			t.Errorf("looksLikeRegion(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestIsAllRegionsLiteral(t *testing.T) {
	if !IsAllRegionsLiteral([]string{"all"}) {
		t.Error("expected true for [all]")
	}
	if !IsAllRegionsLiteral([]string{"ALL"}) {
		t.Error("expected case-insensitive true for [ALL]")
	}
	if IsAllRegionsLiteral([]string{"all", "us-east-1"}) {
		t.Error("expected false for multi-element")
	}
	if IsAllRegionsLiteral(nil) {
		t.Error("expected false for nil")
	}
}

// failingDescribe returns a describeRegionsFn that fails the test if
// called — used to assert the empty/explicit branches don't hit the
// network.
func failingDescribe(t *testing.T) describeRegionsFn {
	return func(ctx context.Context, c awsCfg) ([]string, error) {
		t.Helper()
		t.Errorf("describe should not have been called")
		return nil, nil
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
