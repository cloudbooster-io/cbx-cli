// Package auth re-exports authentication primitives so that downstream
// modules (e.g. cb-cli) can verify login state without reaching into
// cbx-cli/internal/core/auth.
package auth

import (
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/core/auth"
)

// Keyring abstracts OS-native credential storage.
type Keyring = auth.Keyring

// NewKeyring opens the best available keyring backend.
var NewKeyring = auth.NewKeyring

// LoadToken reads an OAuth2 token from the keyring.
var LoadToken = auth.LoadToken

// IsAuthenticated reports whether a token exists in the keyring.
var IsAuthenticated = auth.IsAuthenticated
