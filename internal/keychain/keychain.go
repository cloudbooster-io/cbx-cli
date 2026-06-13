// Package keychain provides OS-native secret storage for LLM provider tokens.
// It uses 99designs/keyring (the same library as internal/core/auth) with the
// OS backend by default and can be switched to an in-memory store via
// UseMock() or the CBX_KEYCHAIN_MOCK=1 environment variable. Like
// internal/core/auth, it honors CBX_KEYRING_BACKEND (file/keychain/
// secret-service/wincred) and CBX_KEYRING_FILE_DIR as escape hatches for
// headless environments.
package keychain

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/99designs/keyring"
	"github.com/cloudbooster-io/cbx-cli/internal/config"
)

// Service is the keyring service name for LLM credentials.
// It is intentionally distinct from the CloudBooster auth namespace.
//
// The value is load-bearing for migration: earlier releases stored keys via
// zalando/go-keyring, which on macOS creates generic-password Keychain items
// keyed by (service, account). 99designs/keyring's keychain backend looks
// items up by the same pair (ServiceName → service, Item.Key → account), so
// keeping this string stable means existing stored keys keep resolving.
const Service = "cloudbooster-llm"

// Legacy data-encoding prefixes written by zalando/go-keyring's macOS
// backend (used by earlier releases). It wrapped every secret before
// storing; Get transparently unwraps them so keys stored before the
// 99designs/keyring migration read back as plaintext.
const (
	legacyHexPrefix    = "go-keyring-encoded:"
	legacyBase64Prefix = "go-keyring-base64:"
)

// fileBackendObfuscationKey is the fixed, source-published passphrase the
// file keyring backend encrypts with — duplicated from internal/core/auth so
// both packages treat CBX_KEYRING_BACKEND=file identically. It is
// deliberately NOT a secret (obfuscation only, never protection; see
// SECURITY.md, "Known limitations"). Keep the value stable: changing it
// invalidates existing file-backend stores.
const fileBackendObfuscationKey = "cbx-test-passphrase"

var (
	mu     sync.Mutex
	active keyring.Keyring // resolved lazily; non-nil once opened or mocked
)

func init() {
	if os.Getenv("CBX_KEYCHAIN_MOCK") == "1" {
		active = keyring.NewArrayKeyring(nil)
	}
}

// UseMock switches the keyring backend to an in-memory mock.
// This is useful for tests and CI environments without a secret service.
func UseMock() {
	mu.Lock()
	defer mu.Unlock()
	active = keyring.NewArrayKeyring(nil)
}

// ring returns the active keyring, opening the best available backend on
// first use.
func ring() (keyring.Keyring, error) {
	mu.Lock()
	defer mu.Unlock()
	if active != nil {
		return active, nil
	}
	kr, err := openKeyring()
	if err != nil {
		return nil, err
	}
	active = kr
	return active, nil
}

// openKeyring opens the best available keyring backend. It mirrors
// internal/core/auth.NewKeyring (duplicated rather than shared so this
// package keeps its own service namespace without touching internal/core/auth):
// CBX_KEYRING_BACKEND forces a backend, otherwise the native OS backends are
// tried in preference order.
func openKeyring() (keyring.Keyring, error) {
	if backendEnv := config.Env("KEYRING_BACKEND"); backendEnv != "" {
		return openBackend(backendEnv)
	}

	preferred := []keyring.BackendType{
		keyring.KeychainBackend,
		keyring.SecretServiceBackend,
		keyring.WinCredBackend,
	}
	available := keyring.AvailableBackends()

	for _, p := range preferred {
		for _, a := range available {
			if a == p {
				kr, err := keyring.Open(backendConfig(p, ""))
				if err == nil {
					return kr, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("no supported OS keyring backend available; set CBX_KEYRING_BACKEND=file to use a file-based fallback")
}

func openBackend(name string) (keyring.Keyring, error) {
	var bt keyring.BackendType
	switch name {
	case "file":
		bt = keyring.FileBackend
	case "keychain":
		bt = keyring.KeychainBackend
	case "secret-service":
		bt = keyring.SecretServiceBackend
	case "wincred":
		bt = keyring.WinCredBackend
	default:
		return nil, fmt.Errorf("unknown keyring backend %q", name)
	}

	dir := config.Env("KEYRING_FILE_DIR")
	if dir == "" && bt == keyring.FileBackend {
		dir = defaultFileBackendDir()
	}
	return keyring.Open(backendConfig(bt, dir))
}

// backendConfig builds the keyring configuration for a backend. ServiceName
// is always Service so OS-keychain lookups hit the same items earlier
// (zalando/go-keyring based) releases wrote.
func backendConfig(bt keyring.BackendType, dir string) keyring.Config {
	cfg := keyring.Config{
		ServiceName:     Service,
		AllowedBackends: []keyring.BackendType{bt},
		FileDir:         dir,
		// macOS: trust the creating binary. Without this the keychain item
		// is written with an EMPTY trusted-app ACL, so every data read —
		// even by the binary that wrote it — triggers the Keychain
		// authorization prompt. Applies at item creation; existing items
		// keep their old ACL until rewritten (re-run `cbx llm api login`).
		KeychainTrustApplication: true,
	}
	if bt == keyring.FileBackend {
		// SECURITY (known limitation): the file backend encrypts stored
		// credentials with a fixed, source-published passphrase, so on-disk
		// tokens are effectively obfuscated rather than protected. Treat
		// CBX_KEYRING_BACKEND=file as a convenience fallback for throwaway or
		// headless contexts, NOT for long-lived real credentials. Hardening
		// (a user-supplied passphrase) is tracked — see SECURITY.md.
		cfg.FilePasswordFunc = func(_ string) (string, error) {
			return fileBackendObfuscationKey, nil
		}
	}
	return cfg
}

// defaultFileBackendDir returns the directory the file keyring backend uses
// when CBX_KEYRING_FILE_DIR is not set: a user-private (0700) directory under
// the OS user cache dir (shared with internal/core/auth; key names do not
// collide). Falls back to the world-readable os.TempDir() only when the
// cache dir cannot be resolved or created — the file backend remains usable
// there, just without the directory-permission layer.
func defaultFileBackendDir() string {
	cache, err := os.UserCacheDir()
	if err != nil {
		return os.TempDir()
	}
	dir := filepath.Join(cache, "cbx-keyring")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return os.TempDir()
	}
	return dir
}

// Set stores a secret in the keyring.
func Set(account, secret string) error {
	kr, err := ring()
	if err != nil {
		return err
	}
	return kr.Set(keyring.Item{
		Key:         account,
		Data:        []byte(secret),
		Label:       "CloudBooster CLI LLM (" + account + ")",
		Description: "LLM provider API key for cbx",
	})
}

// Get retrieves a secret from the keyring.
func Get(account string) (string, error) {
	kr, err := ring()
	if err != nil {
		return "", err
	}
	item, err := kr.Get(account)
	if err != nil {
		return "", err
	}
	return decodeLegacy(string(item.Data))
}

// Delete removes a secret from the keyring.
func Delete(account string) error {
	kr, err := ring()
	if err != nil {
		return err
	}
	return kr.Remove(account)
}

// decodeLegacy reverses the encoding zalando/go-keyring's macOS backend
// applied on write, so items stored by earlier releases read back as
// plaintext. Unprefixed data (everything written after the migration) is
// returned as-is. The prefix sniffing matches zalando's own Get behavior
// exactly, including its (vanishingly unlikely) misread of a genuine secret
// that starts with one of the prefixes.
func decodeLegacy(data string) (string, error) {
	switch {
	case strings.HasPrefix(data, legacyHexPrefix):
		dec, err := hex.DecodeString(strings.TrimPrefix(data, legacyHexPrefix))
		if err != nil {
			return "", fmt.Errorf("decoding legacy keychain entry: %w", err)
		}
		return string(dec), nil
	case strings.HasPrefix(data, legacyBase64Prefix):
		dec, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(data, legacyBase64Prefix))
		if err != nil {
			return "", fmt.Errorf("decoding legacy keychain entry: %w", err)
		}
		return string(dec), nil
	default:
		return data, nil
	}
}
