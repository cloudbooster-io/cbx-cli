// Package auth re-exports authentication primitives so that downstream
// modules (e.g. downstream consumers) can verify login state without reaching into
// cbx-cli/internal/core/auth.
package auth

import (
	"github.com/cloudbooster-io/cbx-cli/internal/core/auth"
)

// Keyring abstracts OS-native credential storage.
type Keyring = auth.Keyring

// NewKeyring opens the best available keyring backend.
var NewKeyring = auth.NewKeyring

// LoadToken reads an OAuth2 token from the keyring.
var LoadToken = auth.LoadToken

// AccessToken returns the access token from the keyring, or "" if
// unauthenticated. Composition roots (e.g. downstream consumers) call this and inject the
// result into NewAPIClient via ClientOptions.Token, so library construction
// never touches the OS keychain directly.
var AccessToken = auth.AccessToken

// IsAuthenticated reports whether a token exists in the keyring.
var IsAuthenticated = auth.IsAuthenticated
