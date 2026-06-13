package parsers

import (
	"errors"
	"fmt"
	"testing"
)

func TestThreeLineError_ExactFormat(t *testing.T) {
	// The rendered string is part of the CLI contract — it must stay
	// byte-identical to the pre-ParseError fmt.Errorf output.
	err := ThreeLineError("what failed", "why it failed", "how to fix it")
	want := "error: what failed\ncause: why it failed\nhint: how to fix it"
	if got := err.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

func TestThreeLineError_ErrorsAs(t *testing.T) {
	// ThreeLineError results must survive %w wrapping and come back out
	// via errors.As with the fields intact.
	wrapped := fmt.Errorf("outer context: %w", ThreeLineError("a", "b", "c"))

	var pe *ParseError
	if !errors.As(wrapped, &pe) {
		t.Fatalf("errors.As failed to extract *ParseError from %v", wrapped)
	}
	if pe.What != "a" || pe.Cause != "b" || pe.Hint != "c" {
		t.Fatalf("unexpected fields: %+v", pe)
	}
}
