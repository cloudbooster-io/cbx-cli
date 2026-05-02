package llm

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClaudeClientComplete(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Errorf("expected path /v1/messages, got %s", r.URL.Path)
		}
		if auth := r.Header.Get("X-Api-Key"); auth != "test-key" {
			t.Errorf("expected X-Api-Key=test-key, got %s", auth)
		}
		if r.Header.Get("Accept") != "text/event-stream" {
			t.Errorf("expected Accept=text/event-stream, got %s", r.Header.Get("Accept"))
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("expected http.Flusher")
		}

		events := []string{
			`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":"Hello"}}`,
			`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" world"}}`,
			`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"!"}}`,
		}
		for _, e := range events {
			fmt.Fprintf(w, "data: %s\n\n", e)
			flusher.Flush()
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		flusher.Flush()
	}))
	defer ts.Close()

	client := NewClaudeClient(ClientConfig{
		BaseURL: ts.URL,
		APIKey:  "test-key",
		Model:   "claude-test",
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

func TestClaudeClientAuthFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	client := NewClaudeClient(ClientConfig{
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

func TestClaudeClientMissingKey(t *testing.T) {
	client := NewClaudeClient(ClientConfig{})
	_, err := client.Complete(context.Background(), "test", CompleteOptions{})
	if err == nil {
		t.Fatal("expected error for missing key")
	}
	if !strings.Contains(err.Error(), "missing API key") {
		t.Fatalf("expected missing key error, got: %v", err)
	}
}

func TestClaudeClientStreamError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		// Write a partial/malformed event and abort.
		fmt.Fprint(w, "data: not-json\n\n")
		flusher := w.(http.Flusher)
		flusher.Flush()
		// Stream ends without [DONE].
	}))
	defer ts.Close()

	client := NewClaudeClient(ClientConfig{
		BaseURL: ts.URL,
		APIKey:  "test-key",
	})

	stream, err := client.Complete(context.Background(), "test", CompleteOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should gracefully skip malformed events and then hit EOF.
	_, err = stream.Next()
	if err == nil {
		t.Fatal("expected EOF after stream ends")
	}
	if err.Error() != "EOF" {
		t.Fatalf("expected EOF, got: %v", err)
	}
}
