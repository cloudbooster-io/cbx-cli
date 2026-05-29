package chat

import (
	"strings"

	"github.com/cloudbooster-io/cbx-cli/internal/core/llm"
)

// StreamAdapter wraps an llm.Stream so it can be consumed by the TUI stream
// renderer. It is the migration target for the old TokenStream interface.
type StreamAdapter struct {
	stream *llm.Stream
}

// NewStreamAdapter creates an adapter from a core/llm stream.
func NewStreamAdapter(stream *llm.Stream) *StreamAdapter {
	return &StreamAdapter{stream: stream}
}

// Next returns the next token or an error. An empty string signals EOF.
func (a *StreamAdapter) Next() (string, error) {
	return a.stream.Next()
}

// StreamRenderer incrementally renders a token stream into viewport content.
type StreamRenderer struct {
	content    strings.Builder
	autoScroll bool
}

// NewStreamRenderer creates a new stream renderer with auto-scroll enabled.
func NewStreamRenderer() *StreamRenderer {
	return &StreamRenderer{autoScroll: true}
}

// AppendToken appends a token to the accumulated content.
func (r *StreamRenderer) AppendToken(token string) {
	r.content.WriteString(token)
}

// Content returns the full rendered content so far.
func (r *StreamRenderer) Content() string {
	return r.content.String()
}

// SetAutoScroll enables or disables auto-scroll.
func (r *StreamRenderer) SetAutoScroll(auto bool) {
	r.autoScroll = auto
}

// AutoScroll reports whether auto-scroll is currently enabled.
func (r *StreamRenderer) AutoScroll() bool {
	return r.autoScroll
}

// Reset clears all accumulated content.
func (r *StreamRenderer) Reset() {
	r.content.Reset()
	r.autoScroll = true
}
