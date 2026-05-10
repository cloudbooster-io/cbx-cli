package audit

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// RunProviders executes all given providers in parallel against the resources,
// respects per-provider timeouts, recovers from panics, and returns a
// deduplicated slice of findings.
func RunProviders(ctx context.Context, providers []FindingProvider, resources []Resource, timeoutPerProvider time.Duration) []Finding {
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := make(map[string]struct{})
	var findings []Finding

	for _, p := range providers {
		wg.Add(1)
		go func(provider FindingProvider) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					// A crashed provider must not abort the audit.
					// The panic is silently swallowed so other providers can finish.
					_ = r
				}
			}()

			pctx := ctx
			if timeoutPerProvider > 0 {
				var cancel context.CancelFunc
				pctx, cancel = context.WithTimeout(ctx, timeoutPerProvider)
				defer cancel()
			}

			ff, err := provider.Scan(pctx, resources)
			if err != nil {
				// A provider error must not abort the audit.
				return
			}

			mu.Lock()
			defer mu.Unlock()
			for _, f := range ff {
				key := f.RuleID + "|" + f.Resource
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				findings = append(findings, f)
			}
		}(p)
	}

	wg.Wait()
	return findings
}

// RunProvidersWithProgress executes providers in parallel and sends per-provider
// results through the returned channel. The channel is closed once all providers
// have finished. This is useful for TUI / interactive modes.
func RunProvidersWithProgress(ctx context.Context, providers []FindingProvider, resources []Resource, timeoutPerProvider time.Duration) <-chan ProviderResult {
	return runProvidersWithProgress(ctx, providers, timeoutPerProvider, func(pctx context.Context, p FindingProvider) ([]Finding, error) {
		return p.Scan(pctx, resources)
	})
}

// RunProvidersSourceWithProgress is the source-mode counterpart to
// RunProvidersWithProgress: each provider's ScanSource(dir) is invoked instead
// of Scan(resources). Providers that report SupportsSource() == false should
// be filtered out by the caller before this is invoked.
func RunProvidersSourceWithProgress(ctx context.Context, providers []FindingProvider, sourceDir string, timeoutPerProvider time.Duration) <-chan ProviderResult {
	return runProvidersWithProgress(ctx, providers, timeoutPerProvider, func(pctx context.Context, p FindingProvider) ([]Finding, error) {
		return p.ScanSource(pctx, sourceDir)
	})
}

// runProvidersWithProgress is the shared dispatcher: it owns the goroutine
// fan-out, per-provider timeout, and panic recovery. The caller supplies
// scanFn — the per-provider entrypoint that decides whether this is a state
// scan or a source scan.
func runProvidersWithProgress(ctx context.Context, providers []FindingProvider, timeoutPerProvider time.Duration, scanFn func(context.Context, FindingProvider) ([]Finding, error)) <-chan ProviderResult {
	ch := make(chan ProviderResult, len(providers))
	var wg sync.WaitGroup

	for _, p := range providers {
		wg.Add(1)
		go func(provider FindingProvider) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					ch <- ProviderResult{
						ProviderName: provider.Name(),
						Err:          fmt.Errorf("provider panic: %v", r),
					}
				}
			}()

			pctx := ctx
			if timeoutPerProvider > 0 {
				var cancel context.CancelFunc
				pctx, cancel = context.WithTimeout(ctx, timeoutPerProvider)
				defer cancel()
			}

			ff, err := scanFn(pctx, provider)
			ch <- ProviderResult{
				ProviderName: provider.Name(),
				Findings:     ff,
				Err:          err,
			}
		}(p)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	return ch
}

// ProviderResult carries the outcome of a single provider run.
type ProviderResult struct {
	ProviderName string
	Findings     []Finding
	Err          error
}
