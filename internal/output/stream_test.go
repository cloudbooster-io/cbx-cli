package output

import (
	"strings"
	"testing"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/core/llm"
)

func TestWriteStream(t *testing.T) {
	ch := make(chan string, 3)
	ch <- "Hello"
	ch <- " "
	ch <- "world"
	close(ch)

	s := llm.NewTestStream(ch)
	var w strings.Builder
	got, err := WriteStream(&w, s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "Hello world"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
	if w.String() != want {
		t.Fatalf("writer expected %q, got %q", want, w.String())
	}
}

func TestWriteStreamNilWriter(t *testing.T) {
	ch := make(chan string, 1)
	ch <- "x"
	close(ch)

	s := llm.NewTestStream(ch)
	got, err := WriteStream(nil, s)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "x" {
		t.Fatalf("expected %q, got %q", "x", got)
	}
}
