package cmd

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/audit"
)

// TestExitCode covers the error → process-exit-code translation,
// including wrapped ExitCodeErrors: pkg/audit promises "wrap or unwrap
// with errors.As", so a fmt.Errorf("%w")-wrapped carrier must still
// surface its Code instead of falling back to the generic 1.
func TestExitCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "nil error", err: nil, want: 0},
		{name: "exit code 1", err: &audit.ExitCodeError{Code: 1}, want: 1},
		{name: "exit code 2", err: &audit.ExitCodeError{Code: 2}, want: 2},
		{name: "exit code 3", err: &audit.ExitCodeError{Code: 3}, want: 3},
		{name: "wrapped exit code", err: fmt.Errorf("ctx: %w", &audit.ExitCodeError{Code: 3}), want: 3},
		{name: "generic error", err: errors.New("x"), want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: non-ExitCodeError errors are printed to stderr by
			// ExitCode; only the return value is asserted here.
			if got := ExitCode(tt.err); got != tt.want {
				t.Fatalf("ExitCode(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}
