package aws

import "errors"

// aerrAs is the indirection point for errors.As that types.go uses to keep
// the standard-library import localised here. Splits cleanly for future
// alternative-error-tree experiments.
func aerrAs(err error, target any) bool {
	return errors.As(err, target)
}
