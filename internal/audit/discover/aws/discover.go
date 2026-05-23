package aws

import (
	"context"
	"fmt"
)

// DiscoverParams is the input to Discover. Kept as a struct so the
// signature stays stable as we add knobs in the next PR (concurrency,
// type filters, etc.) without touching call sites.
type DiscoverParams struct {
	Profile         string
	CredentialsFile string
	Regions         []string
	Concurrency     int
	Diagnose        bool

	// PromptForRegions is the hook for the interactive region picker.
	// When nil, ResolveRegions' ErrNoRegion propagates up unchanged.
	// Wired by the CLI layer so the discovery package doesn't pull
	// Bubble Tea into non-interactive callers.
	PromptForRegions func(ctx context.Context, enabled []string) ([]string, error)
}

// DiscoverResult is what Discover returns. In this PR resources is always
// empty — the actual CloudControl + per-service describer layer lands in
// the next PR. Identity + Regions are populated so the report header and
// runner can show what _would_ have been audited.
type DiscoverResult struct {
	Identity      Identity
	Regions       []string
	Resources     []DiscoveredResourceStub // placeholder; replaced by audit.DiscoveredResource in next PR
	PermissionErr []*PermissionError       // collected for --diagnose
}

// DiscoveredResourceStub is a placeholder shape kept inside this package
// until the next PR's discovery layer maps real AWS responses onto the
// shared audit.DiscoveredResource. Kept stub-local so package callers
// can still see a typed empty slice rather than `any`.
type DiscoveredResourceStub struct {
	ARN        string
	CFNType    string
	Region     string
	AccountID  string
	Tags       map[string]string
	RawConfig  map[string]any
}

// Discover runs the live-AWS discovery pipeline:
//  1. Load AWS config from the requested profile / credentials file
//  2. STS preflight (GetCallerIdentity) — fails closed on bad creds
//  3. Region resolution (with interactive prompt if no default)
//  4. Per-region inventory via CloudControl + curated describers
//     (NOT YET IMPLEMENTED — returns empty Resources in this PR)
func Discover(ctx context.Context, p DiscoverParams) (*DiscoverResult, error) {
	cfg, err := LoadAWSConfig(ctx, p.Profile, p.CredentialsFile)
	if err != nil {
		return nil, err
	}

	identity, err := Preflight(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("AWS preflight failed: %w", err)
	}

	regions, err := ResolveRegions(ctx, cfg, p.Regions)
	if err != nil {
		if err != ErrNoRegion {
			return nil, err
		}
		if p.PromptForRegions == nil {
			return nil, fmt.Errorf("%w (pass --regions or set AWS_REGION)", err)
		}
		// Enumerate enabled regions to feed the picker.
		enabled, listErr := describeRegionsLive(ctx, cfg)
		if listErr != nil {
			return nil, fmt.Errorf("enumerating regions for prompt: %w", listErr)
		}
		picked, pickErr := p.PromptForRegions(ctx, enabled)
		if pickErr != nil {
			return nil, pickErr
		}
		regions, err = ResolveRegions(ctx, cfg, picked)
		if err != nil {
			return nil, err
		}
	}

	// TODO(PR3 — CloudControl discovery): for each region, run CloudControl
	// list+get and the curated per-service describers, mapping AWS responses
	// onto audit.DiscoveredResource. Returns empty for now so the rest of
	// the audit pipeline can be wired end-to-end against a real account.
	return &DiscoverResult{
		Identity:  identity,
		Regions:   regions,
		Resources: nil,
	}, nil
}
