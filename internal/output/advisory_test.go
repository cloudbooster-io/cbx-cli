package output

import (
	"strings"
	"testing"
)

func TestAdvisoryDeduplicates(t *testing.T) {
	ResetAdvisories()
	defer ResetAdvisories()

	Advise(Advisory{Code: "x", Title: "first"})
	Advise(Advisory{Code: "x", Title: "second"}) // should be dropped
	Advise(Advisory{Code: "y", Title: "third"})

	got := Advisories()
	if len(got) != 2 {
		t.Fatalf("expected 2 advisories after dedup, got %d: %+v", len(got), got)
	}
	if got[0].Title != "first" || got[1].Title != "third" {
		t.Fatalf("unexpected advisory order: %+v", got)
	}
}

func TestFlushAdvisoriesClearsBuffer(t *testing.T) {
	ResetAdvisories()
	defer ResetAdvisories()

	Advise(Advisory{Code: "x", Title: "drained"})
	out := FlushAdvisories()
	if !strings.Contains(out, "drained") {
		t.Fatalf("expected rendered advisory to contain 'drained', got:\n%s", out)
	}
	if len(Advisories()) != 0 {
		t.Fatalf("expected buffer empty after Flush, got %+v", Advisories())
	}
}

func TestRenderAdvisoriesEmpty(t *testing.T) {
	ResetAdvisories()
	if got := RenderAdvisories(); got != "" {
		t.Fatalf("expected empty output for empty buffer, got %q", got)
	}
}
