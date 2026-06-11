package audit

import "fmt"

// ExitCodeError is returned when a command wants to exit with a specific
// non-zero code. The error propagates to main() which calls os.Exit.
type ExitCodeError struct {
	Code int
}

func (e *ExitCodeError) Error() string {
	return fmt.Sprintf("exit code %d", e.Code)
}

// ExitWithSeverity returns an ExitCodeError reflecting the maximum
// severity among the given findings, or nil when there are no findings.
// Severity mapping: info → 1, warning → 2, high → 3, critical → 3.
func ExitWithSeverity(findings []Finding) error {
	maxSeverity := 0
	for _, f := range findings {
		switch f.Severity {
		case SeverityInfo:
			if maxSeverity < 1 {
				maxSeverity = 1
			}
		case SeverityWarning:
			if maxSeverity < 2 {
				maxSeverity = 2
			}
		case SeverityHigh, SeverityCritical:
			if maxSeverity < 3 {
				maxSeverity = 3
			}
		}
	}

	if maxSeverity > 0 {
		return &ExitCodeError{Code: maxSeverity}
	}
	return nil
}
