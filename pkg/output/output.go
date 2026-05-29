// Package output re-exports terminal formatting helpers so that downstream
// modules (e.g. downstream consumers) can emit consistent JSON, tables, and styled text
// without reaching into cbx-cli/internal.
package output

import (
	"github.com/cloudbooster-io/cbx-cli/internal/output"
)

// Envelope is the standard JSON response wrapper used when --json is set.
type Envelope = output.Envelope

// ErrDetail carries structured error information inside an Envelope.
type ErrDetail = output.ErrDetail

// WriteJSON writes data wrapped in a standard Envelope to w.
var WriteJSON = output.WriteJSON

// PrintJSON is a convenience wrapper that writes to stdout followed by a newline.
var PrintJSON = output.PrintJSON

// JSONError builds an ErrDetail from a Go error.
var JSONError = output.JSONError

// JSONErrorf builds an ErrDetail from a formatted string.
var JSONErrorf = output.JSONErrorf

// Spinner is a simple terminal spinner.
type Spinner = output.Spinner

// NewSpinner creates a new Spinner with the given message.
var NewSpinner = output.NewSpinner

// Configure sets the global output mode.
var Configure = output.Configure

// Enabled reports whether styled output should be emitted.
var Enabled = output.Enabled

// IsQuiet reports whether quiet mode is active.
var IsQuiet = output.IsQuiet

// Success styles positive feedback.
var Success = output.Success

// Warning styles cautionary feedback.
var Warning = output.Warning

// Error styles negative feedback.
var Error = output.Error

// Info styles neutral informational feedback.
var Info = output.Info

// Dim styles low-emphasis text.
var Dim = output.Dim
