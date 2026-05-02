// Package keychain provides OS-native secret storage for LLM provider tokens.
// It uses the OS keyring by default and can be switched to a mock in-memory
// store via UseMock() or the CBX_KEYCHAIN_MOCK=1 environment variable.
package keychain

import (
	"os"

	"github.com/zalando/go-keyring"
)

// Service is the keyring service name for LLM credentials.
// It is intentionally distinct from the CloudBooster auth namespace.
const Service = "cloudbooster-llm"

func init() {
	if os.Getenv("CBX_KEYCHAIN_MOCK") == "1" {
		keyring.MockInit()
	}
}

// UseMock switches the keyring backend to an in-memory mock.
// This is useful for tests and CI environments without a secret service.
func UseMock() {
	keyring.MockInit()
}

// Set stores a secret in the keyring.
func Set(account, secret string) error {
	return keyring.Set(Service, account, secret)
}

// Get retrieves a secret from the keyring.
func Get(account string) (string, error) {
	return keyring.Get(Service, account)
}

// Delete removes a secret from the keyring.
func Delete(account string) error {
	return keyring.Delete(Service, account)
}
