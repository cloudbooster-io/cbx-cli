package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Envelope is the standard JSON response wrapper used when --json is set.
type Envelope struct {
	Data  any        `json:"data,omitempty"`
	Error *ErrDetail `json:"error,omitempty"`
}

// ErrDetail carries structured error information inside an Envelope.
type ErrDetail struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
}

// WriteJSON writes data wrapped in a standard Envelope to w.
// If errDetail is non-nil it is included in the envelope and Data is omitted.
func WriteJSON(w io.Writer, data any, errDetail *ErrDetail) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if errDetail != nil {
		return enc.Encode(Envelope{Error: errDetail})
	}
	return enc.Encode(Envelope{Data: data})
}

// PrintJSON is a convenience wrapper that writes to stdout followed by a newline.
func PrintJSON(data any, errDetail *ErrDetail) error {
	return WriteJSON(os.Stdout, data, errDetail)
}

// JSONError builds an ErrDetail from a Go error. If err is nil it returns nil.
func JSONError(err error) *ErrDetail {
	if err == nil {
		return nil
	}
	return &ErrDetail{Message: err.Error()}
}

// JSONErrorf builds an ErrDetail from a formatted string.
func JSONErrorf(format string, args ...any) *ErrDetail {
	return &ErrDetail{Message: fmt.Sprintf(format, args...)}
}
