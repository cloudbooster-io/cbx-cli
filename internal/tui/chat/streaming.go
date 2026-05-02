package chat

import "strings"

// TokenStream is the interface consumed by the stream renderer.
// TODO(CB-398): migrate to core/llm/ streaming interface when available.
type TokenStream interface {
	// Next returns the next token or an error. An empty string signals EOF.
	Next() (string, error)
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
