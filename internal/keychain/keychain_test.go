package keychain

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/99designs/keyring"
)

// setRingForTest swaps the package-level keyring and restores the previous
// one when the test finishes.
func setRingForTest(t *testing.T, kr keyring.Keyring) {
	t.Helper()
	mu.Lock()
	prev := active
	active = kr
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		active = prev
		mu.Unlock()
	})
}

func TestKeychainRoundTrip(t *testing.T) {
	setRingForTest(t, keyring.NewArrayKeyring(nil))

	if err := Set("claude", "secret-token-123"); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	val, err := Get("claude")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if val != "secret-token-123" {
		t.Fatalf("expected secret-token-123, got %q", val)
	}

	if err := Delete("claude"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err = Get("claude")
	if !errors.Is(err, keyring.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound after delete, got: %v", err)
	}
}

func TestUseMockSwitchesToInMemory(t *testing.T) {
	setRingForTest(t, nil)
	UseMock()

	if err := Set("codex", "mock-secret"); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	val, err := Get("codex")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if val != "mock-secret" {
		t.Fatalf("expected mock-secret, got %q", val)
	}
}

func TestKeychainServiceName(t *testing.T) {
	// Ensure the service name is distinct from CloudBooster auth, and stable:
	// it must keep matching the macOS Keychain "service" attribute written by
	// the pre-migration zalando/go-keyring releases.
	if Service != "cloudbooster-llm" {
		t.Fatalf("expected service name cloudbooster-llm, got %q", Service)
	}
}

func TestBackendConfigServiceAndAccountMapping(t *testing.T) {
	// The OS-keychain lookup key is (service, account). ServiceName must be
	// Service for every backend so reads hit the items earlier releases wrote.
	cfg := backendConfig(keyring.KeychainBackend, "")
	if cfg.ServiceName != Service {
		t.Fatalf("ServiceName = %q, want %q", cfg.ServiceName, Service)
	}
	if len(cfg.AllowedBackends) != 1 || cfg.AllowedBackends[0] != keyring.KeychainBackend {
		t.Fatalf("AllowedBackends = %v, want [keychain]", cfg.AllowedBackends)
	}
	if cfg.FilePasswordFunc != nil {
		t.Fatal("non-file backend should not get a file passphrase func")
	}

	fcfg := backendConfig(keyring.FileBackend, "/tmp/unused")
	if fcfg.ServiceName != Service {
		t.Fatalf("file ServiceName = %q, want %q", fcfg.ServiceName, Service)
	}
	if fcfg.FileDir != "/tmp/unused" {
		t.Fatalf("FileDir = %q, want /tmp/unused", fcfg.FileDir)
	}
	if fcfg.FilePasswordFunc == nil {
		t.Fatal("file backend must have a passphrase func")
	}
	pass, err := fcfg.FilePasswordFunc("")
	if err != nil {
		t.Fatalf("passphrase func: %v", err)
	}
	if pass != fileBackendObfuscationKey {
		t.Fatalf("passphrase = %q, want the shared obfuscation key", pass)
	}
}

func TestFileBackendAccountMapping(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CBX_KEYRING_BACKEND", "file")
	t.Setenv("CBX_KEYRING_FILE_DIR", dir)
	setRingForTest(t, nil) // force a fresh open from the env

	if err := Set("claude", "sk-ant-test-123"); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// The account name maps 1:1 to the keyring Item.Key (one file per key in
	// the file backend) — the same identity the OS-keychain backend uses as
	// the "account" attribute.
	if _, err := os.Stat(filepath.Join(dir, "claude")); err != nil {
		t.Fatalf("expected item file named after the account: %v", err)
	}

	// An independently opened keyring with the same config resolves the same
	// item, proving Set/Get address items purely by (service, account).
	kr, err := keyring.Open(backendConfig(keyring.FileBackend, dir))
	if err != nil {
		t.Fatalf("open independent keyring: %v", err)
	}
	item, err := kr.Get("claude")
	if err != nil {
		t.Fatalf("independent Get failed: %v", err)
	}
	if string(item.Data) != "sk-ant-test-123" {
		t.Fatalf("expected sk-ant-test-123, got %q", string(item.Data))
	}

	val, err := Get("claude")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if val != "sk-ant-test-123" {
		t.Fatalf("expected sk-ant-test-123, got %q", val)
	}

	if err := Delete("claude"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, err := Get("claude"); !errors.Is(err, keyring.ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound after delete, got: %v", err)
	}
}

func TestGetDecodesLegacyZalandoEncodings(t *testing.T) {
	// zalando/go-keyring (used before the 99designs migration) wrapped every
	// secret it stored on macOS: "go-keyring-base64:<base64>" in current
	// versions, "go-keyring-encoded:<hex>" historically. Items it wrote must
	// read back as plaintext.
	seed := []keyring.Item{
		{
			Key:  "claude",
			Data: []byte(legacyBase64Prefix + base64.StdEncoding.EncodeToString([]byte("sk-ant-legacy-key"))),
		},
		{
			Key:  "codex",
			Data: []byte(legacyHexPrefix + hex.EncodeToString([]byte("sk-legacy-hex-key"))),
		},
		{
			Key:  "plain",
			Data: []byte("sk-post-migration-key"),
		},
	}
	setRingForTest(t, keyring.NewArrayKeyring(seed))

	for _, tc := range []struct {
		account, want string
	}{
		{"claude", "sk-ant-legacy-key"},
		{"codex", "sk-legacy-hex-key"},
		{"plain", "sk-post-migration-key"},
	} {
		got, err := Get(tc.account)
		if err != nil {
			t.Fatalf("Get(%q) failed: %v", tc.account, err)
		}
		if got != tc.want {
			t.Fatalf("Get(%q) = %q, want %q", tc.account, got, tc.want)
		}
	}
}

func TestDecodeLegacyMalformedPayload(t *testing.T) {
	if _, err := decodeLegacy(legacyBase64Prefix + "%%%not-base64%%%"); err == nil {
		t.Fatal("expected error for malformed base64 payload")
	}
	if _, err := decodeLegacy(legacyHexPrefix + "zz-not-hex"); err == nil {
		t.Fatal("expected error for malformed hex payload")
	}
}

func TestOpenBackendUnknown(t *testing.T) {
	if _, err := openBackend("nonexistent"); err == nil {
		t.Fatal("expected error for unknown backend")
	}
}
