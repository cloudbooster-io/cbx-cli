package output

import (
	"fmt"
	"os"
)

// WarnRateLimit prints a soft warning to stderr when the API rate limit is low.
func WarnRateLimit(remaining int) {
	fmt.Fprintf(os.Stderr, "warning: API rate limit low (%d requests remaining)\n", remaining)
}
