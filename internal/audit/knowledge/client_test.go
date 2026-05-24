package knowledge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// envelopeJSON helper assembles a {schema_version, data, meta} body
// matching platform-app's ResponseEnvelope.
func envelopeJSON(t *testing.T, data interface{}) string {
	t.Helper()
	dataBytes, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal data: %v", err)
	}
	wrap := map[string]interface{}{
		"schema_version": "1",
		"data":           json.RawMessage(dataBytes),
		"meta":           map[string]interface{}{"request_id": "req_test"},
	}
	out, err := json.Marshal(wrap)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return string(out)
}

func TestLookupPrimitive_200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/knowledge/aws/primitives/") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		body := envelopeJSON(t, map[string]interface{}{
			"kb_version": 7,
			"chunks": []map[string]interface{}{
				{
					"doc_path":    "resources/aws/primitives/s3_bucket/primitive.md",
					"chunk_text":  "S3 buckets should be private by default.",
					"chunk_index": 0,
					"token_count": 12,
					"category":    "primitive",
				},
			},
		})
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	c := New(srv.URL)
	got, err := c.LookupPrimitive(context.Background(), "aws:s3/bucket@v1")
	if err != nil {
		t.Fatalf("LookupPrimitive: %v", err)
	}
	if got.KBVersion != 7 {
		t.Errorf("kb_version: got %d want 7", got.KBVersion)
	}
	if len(got.Chunks) != 1 || !strings.Contains(got.Chunks[0].ChunkText, "private by default") {
		t.Errorf("chunks not parsed: %+v", got.Chunks)
	}
}

func TestLookupPrimitive_404IsNotAuthored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"not_found","message":"nope"}}`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.LookupPrimitive(context.Background(), "aws:missing/thing@v1")
	if !errors.Is(err, ErrNotAuthored) {
		t.Fatalf("want ErrNotAuthored, got %v", err)
	}
}

func TestBestPracticesFor_QueryParam(t *testing.T) {
	var sawWorkload string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawWorkload = r.URL.Query().Get("workload")
		_, _ = w.Write([]byte(envelopeJSON(t, map[string]interface{}{
			"kb_version": 1,
			"chunks":     []map[string]interface{}{},
		})))
	}))
	defer srv.Close()

	c := New(srv.URL)
	if _, err := c.BestPracticesFor(context.Background(), "static-site"); err != nil {
		t.Fatalf("BestPracticesFor: %v", err)
	}
	if sawWorkload != "static-site" {
		t.Errorf("workload query: got %q want static-site", sawWorkload)
	}
}

func TestCompositionFor_PostBody(t *testing.T) {
	var sawBody map[string][]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method: got %s want POST", r.Method)
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &sawBody); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		_, _ = w.Write([]byte(envelopeJSON(t, map[string]interface{}{
			"kb_version": 1,
			"chunks":     []map[string]interface{}{},
		})))
	}))
	defer srv.Close()

	c := New(srv.URL)
	if _, err := c.CompositionFor(context.Background(), []string{"aws:s3/bucket@v1", "aws:cdn/distribution@v1"}); err != nil {
		t.Fatalf("CompositionFor: %v", err)
	}
	if got := sawBody["type_ids"]; len(got) != 2 || got[0] != "aws:s3/bucket@v1" || got[1] != "aws:cdn/distribution@v1" {
		t.Errorf("type_ids body: got %v", got)
	}
}

func TestDo_429Surface(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"code":"rate_limited","message":"slow down"}}`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.LookupPrimitive(context.Background(), "aws:s3/bucket@v1")
	if err == nil {
		t.Fatalf("want error, got nil")
	}
	if errors.Is(err, ErrNotAuthored) {
		t.Fatalf("429 must not collapse to ErrNotAuthored")
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("error should mention status: %v", err)
	}
}
