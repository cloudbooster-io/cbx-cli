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

	s := newStream(ch)

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

	s := newStream(ch)
	s.setErr(io.ErrUnexpectedEOF)

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

	s := newStream(ch)
	out := s.ToChannel()

	var got string
	for tok := range out {
		got += tok
	}
	if want := "ab"; got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
