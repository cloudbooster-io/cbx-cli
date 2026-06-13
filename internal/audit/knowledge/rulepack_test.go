package knowledge

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRulePack_FetchesRawArtifactWithETag(t *testing.T) {
	const artifact = `{"manifest":{"pack":"cb-aws-audit"}}`
	var gotPath, gotQuery, gotINM string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotINM = r.Header.Get("If-None-Match")
		w.Header().Set("ETag", `"v1-abc"`)
		_, _ = w.Write([]byte(artifact))
	}))
	defer srv.Close()

	raw, etag, err := New(srv.URL).RulePack(context.Background(), "stable", "", 0)
	if err != nil {
		t.Fatalf("RulePack: %v", err)
	}
	// Raw bytes, verbatim — NOT envelope-decoded. Sign-then-serve depends
	// on the client never re-serializing the artifact.
	if string(raw) != artifact {
		t.Errorf("raw artifact = %q, want verbatim %q", raw, artifact)
	}
	if etag != `"v1-abc"` {
		t.Errorf("etag = %q, want %q", etag, `"v1-abc"`)
	}
	if gotPath != "/v1/knowledge/aws/rulepack" {
		t.Errorf("path = %q", gotPath)
	}
	if !strings.Contains(gotQuery, "schema=1") || !strings.Contains(gotQuery, "channel=stable") {
		t.Errorf("query = %q, want schema=1 and channel=stable", gotQuery)
	}
	if strings.Contains(gotQuery, "version=") {
		t.Errorf("query = %q carries version= for pin 0", gotQuery)
	}
	if gotINM != "" {
		t.Errorf("If-None-Match sent on first fetch: %q", gotINM)
	}
}

func TestRulePack_VersionPinAndIfNoneMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("version") != "7" {
			t.Errorf("version = %q, want 7", r.URL.Query().Get("version"))
		}
		if r.Header.Get("If-None-Match") != `"v7-xyz"` {
			t.Errorf("If-None-Match = %q", r.Header.Get("If-None-Match"))
		}
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	raw, etag, err := New(srv.URL).RulePack(context.Background(), "stable", `"v7-xyz"`, 7)
	if !errors.Is(err, ErrNotModified) {
		t.Fatalf("err = %v, want ErrNotModified", err)
	}
	if raw != nil {
		t.Errorf("raw = %q on 304, want nil", raw)
	}
	if etag != `"v7-xyz"` {
		t.Errorf("etag = %q, want the validated cache ETag back", etag)
	}
}

func TestRulePack_404IsErrNotAuthored(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	_, _, err := New(srv.URL).RulePack(context.Background(), "stable", "", 0)
	if !errors.Is(err, ErrNotAuthored) {
		t.Fatalf("err = %v, want ErrNotAuthored (not-yet-deployed endpoint lands on the resolve ladder)", err)
	}
}

func TestRulePack_5xxRetriesThenFails(t *testing.T) {
	restore := retryBackoff
	retryBackoff = time.Millisecond
	defer func() { retryBackoff = restore }()

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer srv.Close()

	_, _, err := New(srv.URL).RulePack(context.Background(), "stable", "", 0)
	if err == nil || errors.Is(err, ErrNotAuthored) || errors.Is(err, ErrNotModified) {
		t.Fatalf("err = %v, want transport-class failure", err)
	}
	if got := hits.Load(); got != retryAttempts {
		t.Errorf("server hit %d times, want %d (5xx retries)", got, retryAttempts)
	}
}

func TestRulePack_5xxThenSuccessRecovers(t *testing.T) {
	restore := retryBackoff
	retryBackoff = time.Millisecond
	defer func() { retryBackoff = restore }()

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			http.Error(w, "boom", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	raw, _, err := New(srv.URL).RulePack(context.Background(), "stable", "", 0)
	if err != nil {
		t.Fatalf("RulePack after retry: %v", err)
	}
	if string(raw) != `{}` {
		t.Errorf("raw = %q", raw)
	}
}

func TestRulePack_OversizedBodyRejectedNotRetried(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write(make([]byte, maxResponseBytes+1))
	}))
	defer srv.Close()

	_, _, err := New(srv.URL).RulePack(context.Background(), "stable", "", 0)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want oversized-body rejection", err)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("server hit %d times, want 1 (deterministic failure, no retry)", got)
	}
}
