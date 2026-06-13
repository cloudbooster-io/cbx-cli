package config

import (
	"fmt"
	"os"
	"sync"
)

var (
	deprecatedEnvSeen sync.Map // string → struct{}

	// DeprecatedEnvWarn is the sink for deprecation warnings. Tests and
	// the pkg/cmd init wire this to route through output.* / a custom
	// writer. The default writes a single line to stderr.
	DeprecatedEnvWarn = func(oldName, newName string) {
		fmt.Fprintf(os.Stderr,
			"warning: %s is deprecated, use %s instead (will be removed in a future release)\n",
			oldName, newName)
	}
)

// Env returns the value of CBX_<name>, falling back to CB_<name> with a
// one-time deprecation warning. Returns "" if neither is set.
func Env(name string) string {
	if v := os.Getenv("CBX_" + name); v != "" {
		return v
	}
	if v := os.Getenv("CB_" + name); v != "" {
		if _, seen := deprecatedEnvSeen.LoadOrStore(name, struct{}{}); !seen {
			if DeprecatedEnvWarn != nil {
				DeprecatedEnvWarn("CB_"+name, "CBX_"+name)
			}
		}
		return v
	}
	return ""
}

// resetDeprecationCacheForTest clears the one-shot guard. Test-only.
func resetDeprecationCacheForTest() {
	deprecatedEnvSeen = sync.Map{}
}
