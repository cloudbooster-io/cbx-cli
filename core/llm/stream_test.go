package llm

import (
	"io"
	"testing"
)

func TestStreamNext(t *testing.T) {
	ch := make(chan string, 3)
	ch <- "The"
	ch <- " quick"
	ch <- " fox"
	close(ch)

	s := NewStream(ch)

	var got string
	for {
		tok, err := s.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("unexpected error: %v", err)
		}
		got += tok
	}

	if want := "The quick fox"; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestStreamError(t *testing.T) {
	ch := make(chan string)
	close(ch)

	s := NewStream(ch)
	s.SetErr(io.ErrUnexpectedEOF)

	_, err := s.Next()
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("expected io.ErrUnexpectedEOF, got: %v", err)
	}
}

func TestStreamToChannel(t *testing.T) {
	ch := make(chan string, 2)
	ch <- "a"
	ch <- "b"
	close(ch)

	s := NewStream(ch)
	out := s.ToChannel()

	var got string
	for tok := range out {
		got += tok
	}
	if want := "ab"; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestStreamCollect(t *testing.T) {
	ch := make(chan string, 3)
	ch <- "Hello"
	ch <- " "
	ch <- "world"
	close(ch)

	s := NewStream(ch)
	got, err := s.Collect()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "Hello world"; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestStreamCollectError(t *testing.T) {
	ch := make(chan string, 1)
	ch <- "partial"
	close(ch)

	s := NewStream(ch)
	s.SetErr(io.ErrUnexpectedEOF)

	got, err := s.Collect()
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("expected io.ErrUnexpectedEOF, got: %v", err)
	}
	if want := "partial"; got != want {
		t.Fatalf("expected accumulated text %q before the error, got %q", want, got)
	}
}

func TestStreamCollectEmpty(t *testing.T) {
	ch := make(chan string)
	close(ch)

	s := NewStream(ch)
	got, err := s.Collect()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty text, got %q", got)
	}
}
