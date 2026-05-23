package output

// cfgFormat holds the requested output format. Empty means "default
// human-readable"; recognized values today are "json", "yaml", "table".
var cfgFormat string

// SetFormat records the requested output format. Call once at program
// startup (typically from cobra's PersistentPreRunE).
func SetFormat(f string) { cfgFormat = f }

// Format returns the requested output format, or "" if unset.
func Format() string { return cfgFormat }

// JSON is a convenience predicate: true iff the requested output format
// is JSON. Lets call sites read `output.JSON()` instead of comparing
// `output.Format() == "json"` every time.
func JSON() bool { return cfgFormat == "json" }
