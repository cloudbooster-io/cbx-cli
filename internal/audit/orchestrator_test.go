package audit

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---- mock providers ----

// noSourceProvider is embedded into each test mock to satisfy the source-mode
// half of FindingProvider without per-mock boilerplate. State-only mocks all
// share the same trivial behavior here.
type noSourceProvider struct{}

func (noSourceProvider) SupportsSource() bool { return false }
func (noSourceProvider) ScanSource(_ context.Context, _ string) ([]Finding, error) {
	return nil, ErrSourceModeUnsupported
}

type slowProvider struct{ noSourceProvider }

func (p *slowProvider) Name() string { return "slow" }

func (p *slowProvider) Scan(ctx context.Context, _ []Resource) ([]Finding, error) {
	select {
	case <-time.After(5 * time.Second):
		return []Finding{{RuleID: "SLOW-001", Resource: "r1", Severity: SeverityInfo}}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type panicProvider struct{ noSourceProvider }

func (p *panicProvider) Name() string { return "panic" }

func (p *panicProvider) Scan(_ context.Context, _ []Resource) ([]Finding, error) {
	panic("intentional provider panic")
}

type errorProvider struct{ noSourceProvider }

func (p *errorProvider) Name() string { return "error" }

func (p *errorProvider) Scan(_ context.Context, _ []Resource) ([]Finding, error) {
	return nil, errors.New("provider failed")
}

type emptyProvider struct{ noSourceProvider }

func (p *emptyProvider) Name() string { return "empty" }

func (p *emptyProvider) Scan(_ context.Context, _ []Resource) ([]Finding, error) {
	return nil, nil
}

type customProvider struct {
	noSourceProvider
	name     string
	findings []Finding
}

func (p *customProvider) Name() string { return p.name }

func (p *customProvider) Scan(_ context.Context, _ []Resource) ([]Finding, error) {
	return p.findings, nil
}

// ---- tests ----

// runProvidersCollected drains RunProvidersWithProgress into a deduplicated
// findings slice plus a joined error — the same collapsed view production
// callers get via collectFindings. It replaces the deleted legacy
// RunProviders entry point in these tests; unlike that helper it surfaces
// provider panics and scan errors instead of discarding them.
func runProvidersCollected(ctx context.Context, providers []FindingProvider, resources []Resource, timeoutPerProvider time.Duration) ([]Finding, error) {
	return collectFindings(RunProvidersWithProgress(ctx, providers, resources, timeoutPerProvider))
}

func TestRunProvidersTimeout(t *testing.T) {
	providers := []FindingProvider{&slowProvider{}}
	resources := []Resource{{Type: "aws:s3/bucket:Bucket", URN: "bucket-1"}}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The provider sleeps 5s; we give it 50ms per-provider so it times out.
	findings, err := runProvidersCollected(ctx, providers, resources, 50*time.Millisecond)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings after timeout, got %d", len(findings))
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected per-provider deadline error to surface, got %v", err)
	}
}

func TestRunProvidersPanicDoesNotAbort(t *testing.T) {
	providers := []FindingProvider{
		&panicProvider{},
		&customProvider{
			name: "good",
			findings: []Finding{
				{RuleID: "GOOD-001", Resource: "r1", Severity: SeverityHigh},
			},
		},
	}
	resources := []Resource{{Type: "aws:s3/bucket:Bucket", URN: "bucket-1"}}

	findings, err := runProvidersCollected(context.Background(), providers, resources, 0)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from non-panicking provider, got %d", len(findings))
	}
	if findings[0].RuleID != "GOOD-001" {
		t.Fatalf("expected GOOD-001, got %s", findings[0].RuleID)
	}
	if err == nil || !strings.Contains(err.Error(), "provider panic") {
		t.Fatalf("expected the panic to surface as a provider error, got %v", err)
	}
}

func TestRunProvidersErrorDoesNotAbort(t *testing.T) {
	providers := []FindingProvider{
		&errorProvider{},
		&customProvider{
			name: "good",
			findings: []Finding{
				{RuleID: "GOOD-001", Resource: "r1", Severity: SeverityInfo},
			},
		},
	}
	resources := []Resource{{Type: "aws:s3/bucket:Bucket", URN: "bucket-1"}}

	findings, err := runProvidersCollected(context.Background(), providers, resources, 0)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from non-error provider, got %d", len(findings))
	}
	if err == nil || !strings.Contains(err.Error(), "provider failed") {
		t.Fatalf("expected the scan error to surface, got %v", err)
	}
}

func TestRunProvidersEmptyFindings(t *testing.T) {
	providers := []FindingProvider{
		&emptyProvider{},
		&customProvider{
			name: "good",
			findings: []Finding{
				{RuleID: "GOOD-001", Resource: "r1", Severity: SeverityWarning},
			},
		},
	}
	resources := []Resource{{Type: "aws:s3/bucket:Bucket", URN: "bucket-1"}}

	findings, err := runProvidersCollected(context.Background(), providers, resources, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestRunProvidersMixedSeverities(t *testing.T) {
	providers := []FindingProvider{
		&customProvider{
			name: "info-provider",
			findings: []Finding{
				{RuleID: "INFO-001", Resource: "r1", Severity: SeverityInfo},
			},
		},
		&customProvider{
			name: "high-provider",
			findings: []Finding{
				{RuleID: "HIGH-001", Resource: "r2", Severity: SeverityHigh},
			},
		},
		&customProvider{
			name: "warning-provider",
			findings: []Finding{
				{RuleID: "WARN-001", Resource: "r3", Severity: SeverityWarning},
			},
		},
	}
	resources := []Resource{{Type: "aws:s3/bucket:Bucket", URN: "bucket-1"}}

	findings, err := runProvidersCollected(context.Background(), providers, resources, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	var hasInfo, hasWarning, hasHigh bool
	for _, f := range findings {
		switch f.Severity {
		case SeverityInfo:
			hasInfo = true
		case SeverityWarning:
			hasWarning = true
		case SeverityHigh:
			hasHigh = true
		}
	}
	if !hasInfo {
		t.Fatal("expected an info severity finding")
	}
	if !hasWarning {
		t.Fatal("expected a warning severity finding")
	}
	if !hasHigh {
		t.Fatal("expected a high severity finding")
	}
}

func TestRunProvidersDedupe(t *testing.T) {
	// Two providers return the same finding for the same rule+resource.
	providers := []FindingProvider{
		&customProvider{
			name: "p1",
			findings: []Finding{
				{RuleID: "DUP-001", Resource: "r1", Severity: SeverityHigh},
			},
		},
		&customProvider{
			name: "p2",
			findings: []Finding{
				{RuleID: "DUP-001", Resource: "r1", Severity: SeverityHigh},
			},
		},
	}
	resources := []Resource{{Type: "aws:s3/bucket:Bucket", URN: "bucket-1"}}

	findings, err := runProvidersCollected(context.Background(), providers, resources, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 deduplicated finding, got %d", len(findings))
	}
}

func TestRunProvidersParallelExecution(t *testing.T) {
	var counter atomic.Int32

	blocker := make(chan struct{})
	p1 := &customProvider{name: "p1", findings: nil}
	p2 := &customProvider{name: "p2", findings: nil}

	// Wrap providers so we can detect parallel execution.
	wrapped1 := &blockingProvider{inner: p1, blocker: blocker, counter: &counter}
	wrapped2 := &blockingProvider{inner: p2, blocker: blocker, counter: &counter}

	providers := []FindingProvider{wrapped1, wrapped2}
	resources := []Resource{{Type: "aws:s3/bucket:Bucket", URN: "bucket-1"}}

	go func() {
		// Give providers time to start, then unblock.
		time.Sleep(100 * time.Millisecond)
		close(blocker)
	}()

	findings, err := runProvidersCollected(context.Background(), providers, resources, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}

	// If both providers were running concurrently, counter should be 2 before unblock.
	if counter.Load() != 2 {
		t.Fatalf("expected both providers to start concurrently (counter=2), got %d", counter.Load())
	}
}

type blockingProvider struct {
	noSourceProvider
	inner   FindingProvider
	blocker <-chan struct{}
	counter *atomic.Int32
}

func (p *blockingProvider) Name() string { return p.inner.Name() }

func (p *blockingProvider) Scan(ctx context.Context, resources []Resource) ([]Finding, error) {
	p.counter.Add(1)
	select {
	case <-p.blocker:
	case <-ctx.Done():
	}
	return p.inner.Scan(ctx, resources)
}

func TestRunProvidersWithProgress(t *testing.T) {
	providers := []FindingProvider{
		&customProvider{
			name: "p1",
			findings: []Finding{
				{RuleID: "PROG-001", Resource: "r1", Severity: SeverityInfo},
			},
		},
		&customProvider{
			name: "p2",
			findings: []Finding{
				{RuleID: "PROG-002", Resource: "r2", Severity: SeverityWarning},
			},
		},
	}
	resources := []Resource{{Type: "aws:s3/bucket:Bucket", URN: "bucket-1"}}

	ch := RunProvidersWithProgress(context.Background(), providers, resources, 0)
	var total int
	var names []string
	for res := range ch {
		total += len(res.Findings)
		names = append(names, res.ProviderName)
		if res.Err != nil {
			t.Fatalf("unexpected error from %s: %v", res.ProviderName, res.Err)
		}
	}
	if total != 2 {
		t.Fatalf("expected 2 findings total, got %d", total)
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 provider results, got %d", len(names))
	}
}

func TestRunProvidersRespectsOverallTimeout(t *testing.T) {
	providers := []FindingProvider{&slowProvider{}}
	resources := []Resource{{Type: "aws:s3/bucket:Bucket", URN: "bucket-1"}}

	// Overall context expires in 50ms; per-provider timeout is generous (10s).
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	findings, err := runProvidersCollected(ctx, providers, resources, 10*time.Second)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings after overall timeout, got %d", len(findings))
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected the overall deadline error to surface, got %v", err)
	}
}

// NOTE: a former TestNoNetworkImports/_auditPackageNetHTTPGuard lived here but
// was vacuous (the guard always returned false, so it never asserted anything)
// and its premise no longer holds — the `cbx audit aws` grounded path
// legitimately imports net/http to fetch CB knowledge. The real dependency
// policy is enforced by the e2e suite's go-list-deps check.
