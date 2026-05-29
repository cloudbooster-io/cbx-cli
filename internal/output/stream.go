package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/cloudbooster-io/cbx-cli/internal/core/llm"
)

// WriteStream consumes an LLM token stream and writes each token to w.
// It returns the full accumulated text and any terminal error from the stream.
func WriteStream(w io.Writer, stream *llm.Stream) (string, error) {
	var full strings.Builder
	for {
		tok, err := stream.Next()
		if err != nil {
			if err.Error() == "EOF" {
				return full.String(), nil
			}
			return full.String(), err
		}
		if w != nil {
			fmt.Fprint(w, tok)
		}
		full.WriteString(tok)
	}
}
