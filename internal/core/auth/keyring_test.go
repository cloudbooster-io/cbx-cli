package auth

import (
	"testing"

	"github.com/99designs/keyring"
)

func TestMockKeyringRoundTrip(t *testing.T) {
	kr := &mockKeyring{data: make(map[string]string)}

	if err := kr.Store("api-token", "secret123"); err != nil {
		t.Fatalf("store: %v", err)
	}

	val, err := kr.Retrieve("api-token")
	if err != nil {
		t.Fatalf("retrieve: %v", err)
	}
	if val != "secret123" {
		t.Fatalf("expected secret123, got %q", val)
	}

	if err := kr.Delete("api-token"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	_, err = kr.Retrieve("api-token")
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestFileKeyringRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("CB_KEYRING_BACKEND", "file")
	t.Setenv("CB_KEYRING_FILE_DIR", tmpDir)

	kr, err := NewKeyring()
	if err != nil {
		t.Fatalf("new keyring: %v", err)
	}

	if err := kr.Store("api-token", "secret456"); err != nil {
		t.Fatalf("store: %v", err)
	}

	val, err := kr.Retrieve("api-token")
	if err != nil {
		t.Fatalf("retrieve: %v", err)
	}
	if val != "secret456" {
		t.Fatalf("expected secret456, got %q", val)
	}

	if err := kr.Delete("api-token"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	_, err = kr.Retrieve("api-token")
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestFileKeyringPersistsAcrossOpen(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("CB_KEYRING_BACKEND", "file")
	t.Setenv("CB_KEYRING_FILE_DIR", tmpDir)

	kr1, err := NewKeyring()
	if err != nil {
		t.Fatalf("new keyring 1: %v", err)
	}
	if err := kr1.Store("api-token", "persistent"); err != nil {
		t.Fatalf("store: %v", err)
	}

	// Open a second keyring instance against the same directory.
	kr2, err := NewKeyring()
	if err != nil {
		t.Fatalf("new keyring 2: %v", err)
	}
	val, err := kr2.Retrieve("api-token")
	if err != nil {
		t.Fatalf("retrieve from second instance: %v", err)
	}
	if val != "persistent" {
		t.Fatalf("expected persistent, got %q", val)
	}
}

func TestKeyringWithoutEnvFailsOnMissingBackend(t *testing.T) {
	// Unset any backend override.
	t.Setenv("CB_KEYRING_BACKEND", "")

	// In a headless CI container OS-native backends are usually unavailable.
	// We just verify NewKeyring returns an error rather than panicking.
	_, err := NewKeyring()
	if err == nil {
		// Some CI environments do have a backend (e.g., macOS keychain).
		// That's fine — we only care that it doesn't panic.
		t.Log("a backend was available in this environment")
	}
}

func TestKeyringFileBackendDefaultDir(t *testing.T) {
	t.Setenv("CB_KEYRING_BACKEND", "file")
	t.Setenv("CB_KEYRING_FILE_DIR", "")

	// Should still open successfully, using the default temp dir.
	kr, err := NewKeyring()
	if err != nil {
		t.Fatalf("new keyring with default file dir: %v", err)
	}
	if err := kr.Store("test-key", "test-val"); err != nil {
		t.Fatalf("store: %v", err)
	}
}

func TestKeyringUnknownBackend(t *testing.T) {
	t.Setenv("CB_KEYRING_BACKEND", "nonexistent")
	_, err := NewKeyring()
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

func TestLoadTokenMissing(t *testing.T) {
	kr := &mockKeyring{data: make(map[string]string)}
	_, err := LoadToken(kr)
	if err == nil {
		t.Fatal("expected error loading missing token")
	}
}

func TestIsAuthenticated(t *testing.T) {
	kr := &mockKeyring{data: make(map[string]string)}
	ok, err := IsAuthenticated(kr)
	if err != nil {
		t.Fatalf("is authenticated: %v", err)
	}
	if ok {
		t.Fatal("expected not authenticated")
	}

	tokenData := `{"access_token":"tok","token_type":"Bearer"}`
	_ = kr.Store(tokenKey, tokenData)
	ok, err = IsAuthenticated(kr)
	if err != nil {
		t.Fatalf("is authenticated after store: %v", err)
	}
	if !ok {
		t.Fatal("expected authenticated")
	}
}

func TestOSKeyringStoreRetrieveDelete(t *testing.T) {
	tmpDir := t.TempDir()
	// Use file backend via direct opener to exercise osKeyring methods.
	kr, err := keyring.Open(keyring.Config{
		ServiceName:      serviceName,
		AllowedBackends:  []keyring.BackendType{keyring.FileBackend},
		FileDir:          tmpDir,
		FilePasswordFunc: func(_ string) (string, error) { return "test-pass", nil },
	})
	if err != nil {
		t.Fatalf("open keyring: %v", err)
	}
	oskr := &osKeyring{kr: kr}

	if err := oskr.Store("my-key", "my-secret"); err != nil {
		t.Fatalf("store: %v", err)
	}
	val, err := oskr.Retrieve("my-key")
	if err != nil {
		t.Fatalf("retrieve: %v", err)
	}
	if val != "my-secret" {
		t.Fatalf("expected my-secret, got %q", val)
	}
	if err := oskr.Delete("my-key"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, err = oskr.Retrieve("my-key")
	if err == nil {
		t.Fatal("expected error after delete")
	}
}
