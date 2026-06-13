package rulesbundle

import "time"

// SetTimeNowForTest swaps the package clock for a test and returns the
// restore func.
func SetTimeNowForTest(f func() time.Time) (restore func()) {
	prev := timeNow
	timeNow = f
	return func() { timeNow = prev }
}
