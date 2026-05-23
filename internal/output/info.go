package output

import (
	"fmt"
	"os"
)

// Infof prints an informational line to stderr, no symbol prefix and no
// styling beyond what the caller embeds. Mirrors Successf for cases like
// "Already up to date" where the message is a status report rather than
// a positive confirmation. stderr keeps stdout clean for data.
func Infof(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}
