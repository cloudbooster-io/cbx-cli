package config

import "os"

// Env returns the value of CBX_<name>, or "" if it is not set.
//
// The pre-1.0 CB_<name> fallback (honored with a one-time deprecation
// warning) has been removed; CBX_ is the only recognized prefix.
func Env(name string) string {
	return os.Getenv("CBX_" + name)
}
