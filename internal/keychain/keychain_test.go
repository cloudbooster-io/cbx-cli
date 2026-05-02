package keychain

import (
	"testing"

	"github.com/zalando/go-keyring"
)

func TestKeychainRoundTrip(t *testing.T) {
	UseMock()

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
	if err != keyring.ErrNotFound {
		t.Fatalf("expected ErrNotFound after delete, got: %v", err)
	}
}

func TestKeychainServiceName(t *testing.T) {
	// Ensure the service name is distinct from CloudBooster auth.
	if Service != "cloudbooster-llm" {
		t.Fatalf("expected service name cloudbooster-llm, got %q", Service)
	}
}
