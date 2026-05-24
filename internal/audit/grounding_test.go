package audit

import (
	"context"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit/knowledge"
)

// fakeKnowledgeServer stands up an httptest server that answers the
// three CB knowledge endpoints with predictable, content-stable bodies.
// Returns the live *Client so tests can call BuildGrounding directly.
func fakeKnowledgeServer(t *testing.T) (*knowledge.Client, func()) {
	t.Helper()
	envelope := func(data map[string]interface{}) string {
		body, _ := json.Marshal(map[string]interface{}{
			"schema_version": "1",
			"data":           data,
			"meta":           map[string]interface{}{"request_id": "req_t"},
		})
		return string(body)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/knowledge/aws/primitives/"):
			typeID := strings.TrimPrefix(r.URL.Path, "/v1/knowledge/aws/primitives/")
			_, _ = w.Write([]byte(envelope(map[string]interface{}{
				"kb_version": 1,
				"chunks": []map[string]interface{}{
					{
						"doc_path":    "aws/" + typeID + ".md",
						"chunk_text":  "Posture for " + typeID,
						"chunk_index": 0,
						"category":    "primitive",
					},
				},
			})))
		case r.URL.Path == "/v1/knowledge/aws/practices":
			workload := r.URL.Query().Get("workload")
			_, _ = w.Write([]byte(envelope(map[string]interface{}{
				"kb_version": 1,
				"chunks": []map[string]interface{}{
					{
						"doc_path":    "aws/practices/" + workload + ".md",
						"chunk_text":  "Best practices for " + workload,
						"chunk_index": 0,
						"category":    "practices",
					},
				},
			})))
		case r.URL.Path == "/v1/knowledge/aws/composition":
			_, _ = w.Write([]byte(envelope(map[string]interface{}{
				"kb_version": 1,
				"chunks": []map[string]interface{}{
					{
						"doc_path":    "aws/composition/rules.md",
						"chunk_text":  "Composition rules apply.",
						"chunk_index": 0,
						"category":    "composition",
					},
				},
			})))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return knowledge.New(srv.URL), srv.Close
}

// TestBuildGrounding_StableAcrossInputShuffle is the load-bearing
// determinism test: the same resources in shuffled order must produce
// byte-identical bundles. If this test fails, the prompt will drift
// between runs and we lose the whole point of the rewrite.
func TestBuildGrounding_StableAcrossInputShuffle(t *testing.T) {
	client, closeSrv := fakeKnowledgeServer(t)
	defer closeSrv()

	original := []DiscoveredResource{
		{Type: "aws_s3_bucket", URN: "aws_s3_bucket.a"},
		{Type: "aws_cloudfront_distribution", URN: "aws_cf.b"},
		{Type: "aws_lambda_function", URN: "aws_lambda.c"},
		{Type: "aws_s3_bucket", URN: "aws_s3_bucket.d"}, // duplicate primitive
	}
	shuffled := append([]DiscoveredResource(nil), original...)
	rng := rand.New(rand.NewSource(42))
	rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

	workloadsOriginal := []string{"static-site", "secure-s3-bucket"}
	workloadsShuffled := []string{"secure-s3-bucket", "static-site"}

	b1, _, err := BuildGrounding(context.Background(), client, original, workloadsOriginal, 4)
	if err != nil {
		t.Fatalf("first BuildGrounding: %v", err)
	}
	b2, _, err := BuildGrounding(context.Background(), client, shuffled, workloadsShuffled, 4)
	if err != nil {
		t.Fatalf("second BuildGrounding: %v", err)
	}

	// Compare the JSON serialisations — easy way to catch any ordering
	// or content drift in the nested structs.
	j1, _ := json.Marshal(b1)
	j2, _ := json.Marshal(b2)
	if string(j1) != string(j2) {
		t.Errorf("bundles differ across shuffled input:\n  a=%s\n  b=%s", j1, j2)
	}
}

// TestBuildGroundedPrompt_StableAcrossResourceShuffle pins the prompt
// builder's output: shuffling the resource slice cannot change a single
// byte of the rendered prompt. Together with the BuildGrounding test
// this covers the whole deterministic pipeline.
func TestBuildGroundedPrompt_StableAcrossResourceShuffle(t *testing.T) {
	bundle := &GroundingBundle{
		Primitives: []PrimitiveKnowledge{
			{TypeID: "aws:cdn/distribution@v1", Missing: true},
			{TypeID: "aws:compute/lambda@v1", Missing: true},
			{TypeID: "aws:s3/bucket@v1", Missing: true},
		},
		Practices: []WorkloadKnowledge{
			{Workload: "static-site", Missing: true},
		},
		Composition: &CompositionKnowledge{
			TypeIDs: []string{"aws:cdn/distribution@v1", "aws:compute/lambda@v1", "aws:s3/bucket@v1"},
			Missing: true,
		},
	}
	resources := []DiscoveredResource{
		{Type: "aws_s3_bucket", URN: "urn:a", Region: "us-east-1"},
		{Type: "aws_cloudfront_distribution", URN: "urn:b", Region: "us-east-1"},
		{Type: "aws_lambda_function", URN: "urn:c", Region: "us-west-2"},
	}
	shuffled := append([]DiscoveredResource(nil), resources...)
	rng := rand.New(rand.NewSource(7))
	rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

	p1 := buildGroundedPrompt(IaCTypeTerraform, nil, resources, bundle)
	p2 := buildGroundedPrompt(IaCTypeTerraform, nil, shuffled, bundle)
	if p1 != p2 {
		t.Errorf("prompt differs across shuffled resources:\n  a=%s\n  b=%s", p1, p2)
	}
}

// TestBuildGrounding_404IsPlaceholder verifies that a knowledge gap
// surfaces as a Missing entry — not as an error and not as a silently
// dropped slot. Required by advisor flag #3.
func TestBuildGrounding_404IsPlaceholder(t *testing.T) {
	envelope := func(data map[string]interface{}) []byte {
		body, _ := json.Marshal(map[string]interface{}{
			"schema_version": "1",
			"data":           data,
			"meta":           map[string]interface{}{"request_id": "req_t"},
		})
		return body
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "missing") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(envelope(map[string]interface{}{
			"kb_version": 1,
			"chunks":     []map[string]interface{}{{"doc_path": "ok.md", "chunk_text": "ok"}},
		}))
	}))
	defer srv.Close()

	client := knowledge.New(srv.URL)
	resources := []DiscoveredResource{
		{Type: "aws_s3_bucket", URN: "urn:a"}, // resolves to aws:s3/bucket@v1
	}
	// Inject a synthetic primitive that the fake server will 404 by
	// inserting a fake Inputs override the resolver picks up.
	resources[0].Inputs = map[string]any{"cb_describer_primitive_resolved": "aws:fake/missing@v1"}

	bundle, _, err := BuildGrounding(context.Background(), client, resources, nil, 1)
	if err != nil {
		t.Fatalf("BuildGrounding: %v", err)
	}
	if len(bundle.Primitives) != 1 {
		t.Fatalf("expected 1 primitive, got %d", len(bundle.Primitives))
	}
	if !bundle.Primitives[0].Missing {
		t.Errorf("expected Missing=true for 404'd primitive, got %+v", bundle.Primitives[0])
	}
}
