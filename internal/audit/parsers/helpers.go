package parsers

import "fmt"

func str(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func stringMap(m map[string]interface{}, key string) map[string]string {
	raw, ok := m[key].(map[string]interface{})
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ParseError is the structured form of the three-line errors the state /
// source parsers emit. It is re-exported through pkg/audit so library
// consumers can errors.As a parse failure and read the fields instead of
// string-matching the rendered message.
type ParseError struct {
	What  string // line 1: what failed
	Cause string // line 2: why it failed
	Hint  string // line 3: how to fix it
}

// Error renders the exact three-line format ThreeLineError has always
// produced — CLI output and tests depend on the string staying
// byte-identical.
func (e *ParseError) Error() string {
	return fmt.Sprintf("error: %s\ncause: %s\nhint: %s", e.What, e.Cause, e.Hint)
}

// ThreeLineError returns a *ParseError formatted as exactly three lines.
func ThreeLineError(line1, line2, line3 string) *ParseError {
	return &ParseError{What: line1, Cause: line2, Hint: line3}
}

func regionFromARN(arn string) string {
	// AWS ARN format: arn:partition:service:region:account-id:resource
	// e.g. arn:aws:s3:::bucket-name
	parts := splitARN(arn)
	if len(parts) >= 4 {
		return parts[3]
	}
	return ""
}

func splitARN(arn string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(arn); i++ {
		if arn[i] == ':' {
			parts = append(parts, arn[start:i])
			start = i + 1
		}
	}
	parts = append(parts, arn[start:])
	return parts
}
