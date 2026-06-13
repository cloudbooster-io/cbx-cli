package aws

// Small reader / copier helpers used by the per-service describers to
// lift CloudControl Properties fields into the cb_describer_* namespace.
// Kept in a single file because each describer would otherwise re-derive
// the same handful of nil-safe extractors.
//
// Type-assertion outcomes are deliberately conservative: the source map
// comes from a JSON unmarshal, so numbers are float64, integers may also
// arrive as json.Number depending on the decoder configuration, and a
// missing key is silently treated as "no value" — the describer's
// contract is "populate when known, skip when not."

// readStr returns the string value at key, or "" when missing / not a
// string. The CC properties JSON only emits string types here when the
// CFN schema declares the property as a string, so the lossy fallback
// is acceptable.
func readStr(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

// readBoolPtr returns (value, true) when the key is present AND the
// decoded type is bool. The two-value return distinguishes "false" from
// "absent" — which the RDS / EC2 normalizers must preserve so rule code
// can treat unread fields as "unknown" instead of "explicitly false".
func readBoolPtr(m map[string]any, key string) (bool, bool) {
	if m == nil {
		return false, false
	}
	raw, ok := m[key]
	if !ok {
		return false, false
	}
	b, ok := raw.(bool)
	return b, ok
}

// readNumericPtr unifies the two ways JSON unmarshal can hand us a
// numeric: float64 (default) and the json.Number-style string-coerced
// path. Returns the value as float64 plus a "present" flag.
func readNumericPtr(m map[string]any, key string) (float64, bool) {
	if m == nil {
		return 0, false
	}
	switch v := m[key].(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	}
	return 0, false
}

// copyStr copies the string at src into dst's slot under dstKey, when
// present. Empty / missing source leaves dst untouched.
func copyStr(m map[string]any, srcKey, dstKey string) {
	if v := readStr(m, srcKey); v != "" {
		m[dstKey] = v
	}
}

// copyBool copies the bool at srcKey into dstKey, only when the source
// is present AND decoded as bool. See readBoolPtr for the "unknown vs
// false" rationale.
func copyBool(m map[string]any, srcKey, dstKey string) {
	if v, ok := readBoolPtr(m, srcKey); ok {
		m[dstKey] = v
	}
}

// copyNumeric copies a numeric source key into dstKey as float64.
// Missing keys leave dst untouched.
func copyNumeric(m map[string]any, srcKey, dstKey string) {
	if v, ok := readNumericPtr(m, srcKey); ok {
		m[dstKey] = v
	}
}
