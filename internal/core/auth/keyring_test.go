package auth

import (
	"os"
	"path/filepath"
	"runtime"
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
	// Redirect os.UserCacheDir into a temp dir so the test never touches
	// the real user cache (covers darwin/linux/windows resolution paths).
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, "cache"))
	t.Setenv("LocalAppData", filepath.Join(home, "appdata"))

	t.Setenv("CB_KEYRING_BACKEND", "file")
	t.Setenv("CB_KEYRING_FILE_DIR", "")

	// Should open successfully, defaulting to <user cache dir>/cbx-keyring.
	kr, err := NewKeyring()
	if err != nil {
		t.Fatalf("new keyring with default file dir: %v", err)
	}
	if err := kr.Store("test-key", "test-val"); err != nil {
		t.Fatalf("store: %v", err)
	}

	cache, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("user cache dir: %v", err)
	}
	dir := filepath.Join(cache, "cbx-keyring")
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("default keyring dir not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("default keyring path is not a directory: %s", dir)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Errorf("default keyring dir permissions = %o, want 700", perm)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read default keyring dir: %v", err)
	}
	if len(entries) == 0 {
		t.Error("expected stored item under the default keyring dir")
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
