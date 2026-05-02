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

// ThreeLineError returns an error formatted as exactly three lines.
func ThreeLineError(line1, line2, line3 string) error {
	return fmt.Errorf("error: %s\ncause: %s\nhint: %s", line1, line2, line3)
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
