package auth

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/99designs/keyring"
	"github.com/cloudbooster-io/cbx-cli/internal/config"
)

// fileBackendObfuscationKey is the fixed, source-published passphrase the
// file keyring backend encrypts with. It is deliberately NOT a secret —
// anyone with this repository can decrypt the files — so it provides
// obfuscation only, never protection (see SECURITY.md, "Known limitations").
// Keep the value stable: changing it invalidates existing file-backend stores.
const fileBackendObfuscationKey = "cbx-test-passphrase"

// Keyring abstracts OS-native credential storage.
type Keyring interface {
	Store(key, secret string) error
	Retrieve(key string) (string, error)
	Delete(key string) error
	// Has reports whether a key exists without reading its secret data.
	// On macOS this queries Keychain metadata only, which does not trigger
	// the user-authorization prompt that Retrieve would.
	Has(key string) (bool, error)
}

// osKeyring wraps 99designs/keyring.
type osKeyring struct {
	kr keyring.Keyring
}

// NewKeyring opens the best available keyring backend.
// Set CBX_KEYRING_BACKEND=file (and optionally CBX_KEYRING_FILE_DIR) to
// force the file-based backend — useful in CI or headless environments.
// Legacy CB_KEYRING_BACKEND / CB_KEYRING_FILE_DIR are still honored with
// a one-time deprecation warning.
func NewKeyring() (Keyring, error) {
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
				kr, err := keyring.Open(keyring.Config{
					ServiceName:     serviceName,
					AllowedBackends: []keyring.BackendType{p},
					// macOS: trust the creating binary. Without this the
					// keychain item is written with an EMPTY trusted-app ACL,
					// so every data read — even by the binary that wrote it —
					// triggers the Keychain authorization prompt. Applies at
					// item creation; existing items keep their old ACL until
					// rewritten (logout + login).
					KeychainTrustApplication: true,
				})
				if err == nil {
					return &osKeyring{kr: kr}, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("no supported OS keyring backend available; set CBX_KEYRING_BACKEND=file to use a file-based fallback")
}

func openBackend(name string) (Keyring, error) {
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
	cfg := keyring.Config{
		ServiceName:     serviceName,
		AllowedBackends: []keyring.BackendType{bt},
		FileDir:         dir,
		// See NewKeyring: avoids the per-read macOS Keychain prompt for
		// items this binary creates (no-op for non-keychain backends).
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
	kr, err := keyring.Open(cfg)
	if err != nil {
		return nil, err
	}
	return &osKeyring{kr: kr}, nil
}

// defaultFileBackendDir returns the directory the file keyring backend uses
// when CBX_KEYRING_FILE_DIR is not set: a user-private (0700) directory under
// the OS user cache dir. Falls back to the world-readable os.TempDir() only
// when the cache dir cannot be resolved or created — the file backend remains
// usable there, just without the directory-permission layer.
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

func (k *osKeyring) Store(key, secret string) error {
	return k.kr.Set(keyring.Item{
		Key:         key,
		Data:        []byte(secret),
		Label:       "CloudBooster CLI (" + key + ")",
		Description: "OAuth credentials for cbx",
	})
}

func (k *osKeyring) Retrieve(key string) (string, error) {
	item, err := k.kr.Get(key)
	if err != nil {
		return "", err
	}
	return string(item.Data), nil
}

func (k *osKeyring) Delete(key string) error {
	return k.kr.Remove(key)
}

func (k *osKeyring) Has(key string) (bool, error) {
	// Use Keys() rather than Get/GetMetadata: on macOS, Keys() only
	// requests kSecReturnAttributes (no item ref, no data), which does
	// not trigger the per-item ACL prompt. GetMetadata sets ReturnRef,
	// which does.
	keys, err := k.kr.Keys()
	if err != nil {
		return false, err
	}
	for _, k := range keys {
		if k == key {
			return true, nil
		}
	}
	return false, nil
}
