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
	Why     string `json:"why,omitempty"`
	Fix     string `json:"fix,omitempty"`
}

// WriteJSON writes data wrapped in a standard Envelope to w.
// Both Data and Error are encoded; omitempty tags on Envelope keep nil
// fields out of the output. Callers can pass both when an operation
// produces a partial payload alongside a failure marker (e.g. doctor
// reporting checks plus an overall-failed signal).
func WriteJSON(w io.Writer, data any, errDetail *ErrDetail) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(Envelope{Data: data, Error: errDetail})
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
