package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// ResolveRegions turns the user's --regions input into a concrete region
// list. Behaviour:
//
//   - explicit non-empty list (not "all")  → validated; passed through
//   - explicit ["all"]                     → enumerated via DescribeRegions
//   - empty list + profile has default     → single-element list of that
//   - empty list + no default              → returns ErrNoRegion; caller
//     decides whether to prompt
//
// `ec2DescribeRegions` is parameterised so tests can inject a fake.
func ResolveRegions(ctx context.Context, c awsCfg, requested []string) ([]string, error) {
	return resolveRegionsImpl(ctx, c, requested, describeRegionsLive)
}

// ErrNoRegion is returned by ResolveRegions when the user passed no
// --regions and the loaded AWS config has no region set. Surfaces a clean
// signal the caller can use to either prompt interactively or bail.
var ErrNoRegion = fmt.Errorf("no region configured in AWS profile and no --regions passed")

// describeRegionsFn is the signature ResolveRegions needs from EC2 so
// tests can substitute a fake without booting the SDK.
type describeRegionsFn func(ctx context.Context, c awsCfg) ([]string, error)

// describeRegionsLive enumerates enabled regions via ec2:DescribeRegions
// from whichever region c is currently pinned to. We require a working
// region on c for this call; ResolveRegions handles that by falling back
// to "us-east-1" only for this enumeration (the global EC2 service surface
// is reachable from any region, but the SDK still needs one set).
func describeRegionsLive(ctx context.Context, c awsCfg) ([]string, error) {
	if c.region() == "" {
		c = c.withRegion("us-east-1")
	}
	client := ec2.NewFromConfig(c.cfg)
	out, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: ptr(false), // opted-in only
	})
	if err != nil {
		return nil, &PermissionError{
			Service: "ec2",
			Action:  "ec2:DescribeRegions",
			Region:  c.region(),
			Cause:   err,
		}
	}
	var names []string
	for _, r := range out.Regions {
		if r.RegionName != nil {
			names = append(names, *r.RegionName)
		}
	}
	sort.Strings(names)
	return names, nil
}

func resolveRegionsImpl(ctx context.Context, c awsCfg, requested []string, describe describeRegionsFn) ([]string, error) {
	// Trim + drop empties before deciding which branch we're in.
	cleaned := cleanRegionList(requested)

	if len(cleaned) == 0 {
		if c.region() != "" {
			return []string{c.region()}, nil
		}
		return nil, ErrNoRegion
	}

	if IsAllRegionsLiteral(cleaned) {
		return describe(ctx, c)
	}

	// Explicit list — validate format only (lower-case, kebab-style).
	// We deliberately do NOT round-trip through DescribeRegions here:
	// that costs an API call for no real benefit, and a bogus region
	// will fail loudly on the first per-region client call anyway.
	for _, r := range cleaned {
		if !looksLikeRegion(r) {
			return nil, fmt.Errorf("invalid region %q (expected aws-style like us-east-1)", r)
		}
	}
	return cleaned, nil
}

func cleanRegionList(in []string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, r := range in {
		r = strings.TrimSpace(strings.ToLower(r))
		if r == "" {
			continue
		}
		if _, dup := seen[r]; dup {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	return out
}

// looksLikeRegion does a coarse syntax check: <prefix>-<area>-<digit>.
// Avoids a network call on obviously-bad input; the actual region is
// validated by the first SDK call that uses it.
func looksLikeRegion(r string) bool {
	if len(r) < 9 || len(r) > 30 {
		return false
	}
	parts := strings.Split(r, "-")
	if len(parts) < 3 {
		return false
	}
	last := parts[len(parts)-1]
	if len(last) != 1 || last[0] < '0' || last[0] > '9' {
		return false
	}
	return true
}

func ptr[T any](v T) *T { return &v }
