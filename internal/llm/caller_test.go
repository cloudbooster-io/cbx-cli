package llm

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCallerStreamClaude(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if key := r.Header.Get("x-api-key"); key != "sk-test" {
			t.Errorf("unexpected api key: %s", key)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"Hello\"}}")
		fmt.Fprintln(w, "data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\" world\"}}")
		fmt.Fprintln(w, "data: [DONE]")
	}))
	defer srv.Close()

	caller := NewCaller(Provider{
		Name:    "claude",
		BaseURL: srv.URL,
		Model:   "claude-test",
	}, "sk-test")

	var tokens []string
	err := caller.Stream(context.Background(), "test prompt", func(token string) {
		tokens = append(tokens, token)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := strings.Join(tokens, "")
	if got != "Hello world" {
		t.Fatalf("expected 'Hello world', got %q", got)
	}
}

func TestCallerStreamOpenAI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}")
		fmt.Fprintln(w, "data: [DONE]")
	}))
	defer srv.Close()

	caller := NewCaller(Provider{
		Name:    "openai",
		BaseURL: srv.URL,
		Model:   "gpt-4o",
	}, "sk-openai")

	var tokens []string
	err := caller.Stream(context.Background(), "test", func(token string) {
		tokens = append(tokens, token)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tokens) != 1 || tokens[0] != "Hi" {
		t.Fatalf("expected ['Hi'], got %v", tokens)
	}
}

func TestCallerStreamOllama(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"response":"yo","done":false}`)
		fmt.Fprintln(w, `{"response":"!","done":true}`)
	}))
	defer srv.Close()

	caller := NewCaller(Provider{
		Name:    "ollama",
		BaseURL: srv.URL,
		Model:   "llama3",
	}, "")

	var tokens []string
	err := caller.Stream(context.Background(), "test", func(token string) {
		tokens = append(tokens, token)
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := strings.Join(tokens, "")
	if got != "yo!" {
		t.Fatalf("expected 'yo!', got %q", got)
	}
}

func TestCallerUnsupportedProvider(t *testing.T) {
	caller := NewCaller(Provider{Name: "unknown"}, "")
	err := caller.Stream(context.Background(), "test", func(string) {})
	if err == nil {
		t.Fatal("expected error for unsupported provider")
	}
	if !strings.Contains(err.Error(), "unsupported provider") {
		t.Fatalf("unexpected error: %v", err)
	}
}
