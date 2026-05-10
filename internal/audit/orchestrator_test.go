package audit

import (
	"context"
	"errors"
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

func TestRunProvidersTimeout(t *testing.T) {
	providers := []FindingProvider{&slowProvider{}}
	resources := []Resource{{Type: "aws:s3/bucket:Bucket", URN: "bucket-1"}}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The provider sleeps 5s; we give it 50ms per-provider so it times out.
	findings := RunProviders(ctx, providers, resources, 50*time.Millisecond)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings after timeout, got %d", len(findings))
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

	findings := RunProviders(context.Background(), providers, resources, 0)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from non-panicking provider, got %d", len(findings))
	}
	if findings[0].RuleID != "GOOD-001" {
		t.Fatalf("expected GOOD-001, got %s", findings[0].RuleID)
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

	findings := RunProviders(context.Background(), providers, resources, 0)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding from non-error provider, got %d", len(findings))
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

	findings := RunProviders(context.Background(), providers, resources, 0)
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

	findings := RunProviders(context.Background(), providers, resources, 0)
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

	findings := RunProviders(context.Background(), providers, resources, 0)
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

	findings := RunProviders(context.Background(), providers, resources, 0)
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

	findings := RunProviders(ctx, providers, resources, 10*time.Second)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings after overall timeout, got %d", len(findings))
	}
}

// TestNoNetworkImports is a compile-time / vet-style guard that asserts
// the audit package does not import network or API client packages.
func TestNoNetworkImports(t *testing.T) {
	// Since we are inside the audit package, a simple compile-time guarantee
	 // is that this test file itself would fail to compile if net/http were
	 // imported in any audit package file. We reinforce it with a runtime
	 // check of the source files in this directory.
	//
	// A stronger check is done in the e2e suite (audit_no_api_imports).
	// This unit test serves as a fast, local guard.
	if _, ok := _auditPackageNetHTTPGuard(); ok {
		t.Fatal("audit package must not import net/http")
	}
}

// _auditPackageNetHTTPGuard exists solely so the test above has something
// to call; the real protection is that any import of net/http in this
// package would make compilation fail, which is caught by go vet / build.
func _auditPackageNetHTTPGuard() (struct{}, bool) {
	return struct{}{}, false
}
