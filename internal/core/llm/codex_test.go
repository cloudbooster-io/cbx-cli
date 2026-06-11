package llm

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCodexClientComplete(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("expected path /v1/chat/completions, got %s", r.URL.Path)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer test-key" {
			t.Errorf("expected Authorization=Bearer test-key, got %s", auth)
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		events := []string{
			`{"choices":[{"delta":{"content":"Hello"}}]}`,
			`{"choices":[{"delta":{"content":" world"}}]}`,
			`{"choices":[{"delta":{"content":"!"}}]}`,
		}
		for _, e := range events {
			fmt.Fprintf(w, "data: %s\n\n", e)
			flusher.Flush()
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		flusher.Flush()
	}))
	defer ts.Close()

	client := NewCodexClient(ClientConfig{
		BaseURL: ts.URL,
		APIKey:  "test-key",
		Model:   "codex-test",
	})

	stream, err := client.Complete(context.Background(), "say hello", CompleteOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got strings.Builder
	for {
		tok, err := stream.Next()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			t.Fatalf("unexpected stream error: %v", err)
		}
		got.WriteString(tok)
	}

	if want := "Hello world!"; got.String() != want {
		t.Fatalf("expected %q, got %q", want, got.String())
	}
}

func TestCodexClientAuthFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	client := NewCodexClient(ClientConfig{
		BaseURL: ts.URL,
		APIKey:  "bad-key",
	})

	_, err := client.Complete(context.Background(), "test", CompleteOptions{})
	if err == nil {
		t.Fatal("expected error for 401")
	}
	if !strings.Contains(err.Error(), "authentication expired") {
		t.Fatalf("expected auth expired error, got: %v", err)
	}
}

func TestCodexClientMissingKey(t *testing.T) {
	client := NewCodexClient(ClientConfig{})
	_, err := client.Complete(context.Background(), "test", CompleteOptions{})
	if err == nil {
		t.Fatal("expected error for missing key")
	}
	if !strings.Contains(err.Error(), "missing API key") {
		t.Fatalf("expected missing key error, got: %v", err)
	}
}

func TestReadCodexToken(t *testing.T) {
	tmpDir := t.TempDir()
	home := filepath.Join(tmpDir, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatalf("creating home: %v", err)
	}

	// No token found initially.
	oldHome := os.Getenv("HOME")
	os.Setenv("HOME", home)
	defer os.Setenv("HOME", oldHome)

	tok, err := ReadCodexToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "" {
		t.Fatalf("expected empty token, got %q", tok)
	}

	// Write token to ~/.codex/config.json
	codexDir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatalf("creating .codex dir: %v", err)
	}
	configPath := filepath.Join(codexDir, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"api_key":"codex-secret"}`), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	tok, err = ReadCodexToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "codex-secret" {
		t.Fatalf("expected codex-secret, got %q", tok)
	}
}
