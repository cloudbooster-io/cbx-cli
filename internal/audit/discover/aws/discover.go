package aws

import (
	"context"
	"fmt"
	"sync"
)

// DiscoverParams is the input to Discover. Kept as a struct so the
// signature stays stable as we add knobs without touching call sites.
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

	// Types overrides the curated CFN type list (discoverableCFNTypes).
	// Used by tests; production callers leave this nil.
	Types []cfnTypeSpec
}

// DiscoverResult is what Discover returns. PermissionErr is collected
// across all per-type and per-region failures attributable to missing
// IAM permissions, for the --diagnose path to summarise at the end.
// OtherErrs collects non-permission failures (throttling, malformed
// responses) — these don't block the run but are surfaced as warnings.
type DiscoverResult struct {
	Identity      Identity
	Regions       []string
	Resources     []DiscoveredResource
	PermissionErr []*PermissionError
	OtherErrs     []error
}

// Discover runs the live-AWS discovery pipeline:
//  1. Load AWS config from the requested profile / credentials file
//  2. STS preflight (GetCallerIdentity) — fails closed on bad creds
//  3. Region resolution (with interactive prompt if no default)
//  4. Per-region × per-type CloudControl list+get fan-out
//  5. Map to DiscoveredResource + dedupe global services
//
// Per-resource failures collect into PermissionErr / OtherErrs without
// killing the run; only the preflight / region resolution / config-load
// failures cause Discover to return an error.
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

	types := p.Types
	if len(types) == 0 {
		types = discoverableCFNTypes
	}
	concurrency := p.Concurrency
	if concurrency < 1 {
		concurrency = 4
	}

	resources, permErrs, otherErrs := fanOutDiscovery(ctx, cfg, regions, types, concurrency)

	return &DiscoverResult{
		Identity:      identity,
		Regions:       regions,
		Resources:     dedupeByURN(resources),
		PermissionErr: permErrs,
		OtherErrs:     otherErrs,
	}, nil
}

// fanOutDiscovery runs (region, type) pairs through a worker pool of
// size `concurrency`. Global types are only queried once via
// pickRegionForGlobal so we don't N×-fan IAM / CloudFront / Route53.
// Per-job errors collect into the returned slices; the function never
// returns a non-nil error itself.
func fanOutDiscovery(ctx context.Context, c awsCfg, regions []string, types []cfnTypeSpec, concurrency int) (
	resources []DiscoveredResource, permErrs []*PermissionError, otherErrs []error,
) {
	type job struct {
		region string
		spec   cfnTypeSpec
	}
	type result struct {
		raws []rawResource
		err  error
	}

	var jobs []job
	for _, t := range types {
		if t.Global {
			jobs = append(jobs, job{region: pickRegionForGlobal, spec: t})
			continue
		}
		for _, r := range regions {
			jobs = append(jobs, job{region: r, spec: t})
		}
	}

	if len(jobs) == 0 {
		return nil, nil, nil
	}

	jobCh := make(chan job)
	resCh := make(chan result, len(jobs))

	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobCh {
				raws, err := listAndGet(ctx, c, j.region, j.spec.Type)
				resCh <- result{raws: raws, err: err}
			}
		}()
	}

	go func() {
		for _, j := range jobs {
			select {
			case <-ctx.Done():
				close(jobCh)
				return
			case jobCh <- j:
			}
		}
		close(jobCh)
	}()

	go func() {
		wg.Wait()
		close(resCh)
	}()

	for r := range resCh {
		for _, raw := range r.raws {
			dr, mapErr := raw.mapToDiscovered()
			if mapErr != nil {
				otherErrs = append(otherErrs, mapErr)
				continue
			}
			// Per-service enrichment: when a describer exists for this
			// CFN type, run it to backfill data CloudControl doesn't
			// expose. Failures collect into permErrs / otherErrs but
			// don't drop the resource — the baseline CC data is still
			// useful even when enrichment fails.
			if d := describerFor(dr.Type); d != nil {
				if eErr := d.Enrich(ctx, c, &dr); eErr != nil {
					if pe, ok := asPermissionError(eErr); ok {
						permErrs = append(permErrs, pe)
					} else {
						otherErrs = append(otherErrs, eErr)
					}
				}
			}
			resources = append(resources, dr)
		}
		if r.err != nil {
			if pe, ok := asPermissionError(r.err); ok {
				permErrs = append(permErrs, pe)
			} else {
				otherErrs = append(otherErrs, r.err)
			}
		}
	}
	return
}

// asPermissionError type-asserts err down to *PermissionError, returning
// false if the chain doesn't contain one. Convenience around errors.As
// so call sites stay tidy.
func asPermissionError(err error) (*PermissionError, bool) {
	var pe *PermissionError
	if aerrAs(err, &pe) {
		return pe, true
	}
	return nil, false
}
