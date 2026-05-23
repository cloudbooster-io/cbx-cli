package auth

import (
	"fmt"
	"os"

	"github.com/99designs/keyring"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
)

// Keyring abstracts OS-native credential storage.
type Keyring interface {
	Store(key, secret string) error
	Retrieve(key string) (string, error)
	Delete(key string) error
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
		dir = os.TempDir()
	}
	cfg := keyring.Config{
		ServiceName:     serviceName,
		AllowedBackends: []keyring.BackendType{bt},
		FileDir:         dir,
	}
	if bt == keyring.FileBackend {
		cfg.FilePasswordFunc = func(_ string) (string, error) {
			return "cbx-test-passphrase", nil
		}
	}
	kr, err := keyring.Open(cfg)
	if err != nil {
		return nil, err
	}
	return &osKeyring{kr: kr}, nil
}

func (k *osKeyring) Store(key, secret string) error {
	return k.kr.Set(keyring.Item{
		Key:  key,
		Data: []byte(secret),
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
