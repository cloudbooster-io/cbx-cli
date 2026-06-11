package output

import (
	"fmt"
	"os"
)

// Successf prints a check-prefixed success line to stderr, styled when
// TTY+color enabled. Reserve stdout for data; success messages are
// decoration.
func Successf(format string, args ...any) {
	fmt.Fprintln(os.Stderr, Success.Render(Symbol("check"))+" "+fmt.Sprintf(format, args...))
}
