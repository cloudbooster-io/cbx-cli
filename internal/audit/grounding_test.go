package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/knowledge"
	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle/rulesbundletest"
)

// fakeKnowledgeHandler answers the three CB knowledge endpoints with
// predictable, content-stable bodies. Shared by the healthy fake server
// and the failure-injecting variant below.
func fakeKnowledgeHandler() http.HandlerFunc {
	envelope := func(data map[string]interface{}) string {
		body, _ := json.Marshal(map[string]interface{}{
			"schema_version": "1",
			"data":           data,
			"meta":           map[string]interface{}{"request_id": "req_t"},
		})
		return string(body)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/health":
			// The grounded streamer constructors (newGroundedClaudeStreamer
			// / newGroundedCodexStreamer) preflight the backend via /health
			// before discovery; answer 2xx so tests that go through those
			// constructors don't abort.
			w.WriteHeader(http.StatusOK)
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
	}
}

// newFakeKnowledgeServer stands up an httptest server over the healthy
// handler above.
func newFakeKnowledgeServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(fakeKnowledgeHandler())
}

// newFailingKnowledgeServer answers like newFakeKnowledgeServer except
// requests whose URL path contains failSubstr get `status` back instead.
// failSubstr == "" fails EVERY request (wipeout / auth-abort tests).
// Note the composition endpoint carries type_ids in the POST body, not
// the path — a primitive-id failSubstr leaves composition healthy.
func newFailingKnowledgeServer(t *testing.T, failSubstr string, status int) *httptest.Server {
	t.Helper()
	healthy := fakeKnowledgeHandler()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failSubstr == "" || strings.Contains(r.URL.Path, failSubstr) {
			w.WriteHeader(status)
			return
		}
		healthy(w, r)
	}))
}

// fakeKnowledgeServer returns a knowledge.Client bound to a fresh fake
// server plus its cleanup func, for tests that call BuildGrounding directly.
func fakeKnowledgeServer(t *testing.T) (*knowledge.Client, func()) {
	t.Helper()
	srv := newFakeKnowledgeServer(t)
	return knowledge.New(srv.URL), srv.Close
}

// useFakeKnowledgeBackend points CB_API_URL at a fresh fake knowledge
// server for the duration of the test, so analyzer paths that resolve the
// backend via resolvedCBAPIURL() stay hermetic (no real network).
func useFakeKnowledgeBackend(t *testing.T) {
	t.Helper()
	srv := newFakeKnowledgeServer(t)
	t.Cleanup(srv.Close)
	t.Setenv(cbAPIURLEnv, srv.URL)
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

	pack := rulesbundletest.Pack(t)
	p1 := buildGroundedPrompt(IaCTypeTerraform, nil, resources, bundle, nil, pack)
	p2 := buildGroundedPrompt(IaCTypeTerraform, nil, shuffled, bundle, nil, pack)
	if p1 != p2 {
		t.Errorf("prompt differs across shuffled resources:\n  a=%s\n  b=%s", p1, p2)
	}
}

// TestBuildGroundedPrompt_RendersAccountPosture asserts the account
// posture block lands in the prompt with the LLM-readable per-region
// EBS-encryption table, the IAM summary, and the probe-errors list.
// Without this the LLM has no signal for account-wide gaps like
// "default EBS encryption disabled in eu-central-1".
func TestBuildGroundedPrompt_RendersAccountPosture(t *testing.T) {
	hasPolicy := false
	posture := &AccountPosture{
		EBSEncryptionByDefault: map[string]bool{
			"eu-central-1": false,
			"us-east-1":    true,
		},
		IAMSummary: map[string]int32{
			"AccountMFAEnabled": 0,
			"Users":             3,
		},
		PasswordPolicyPresent: &hasPolicy,
		Errors:                []string{"iam:ListVirtualMFADevices: AccessDenied"},
	}
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, nil, nil, posture, rulesbundletest.Pack(t))
	for _, want := range []string{
		"ACCOUNT POSTURE",
		"eu-central-1: false",
		"us-east-1: true",
		"AccountMFAEnabled: 0",
		"IAM password policy configured: false",
		"AccessDenied",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
}

// TestBuildGroundedPrompt_RendersRulePackSections asserts the three rule-pack
// policy sections — baseline rules (intro, every bullet with its sub-items,
// outro), the no-merge-orthogonal block, and the severity rubric — render into
// the grounded prompt in that order, via the synthetic pack's anchors. This is
// the structural guard that replaced the deleted per-rule prose pins: the
// production prose is API-distributed (its content is exercised by the
// e2e_staging tier), so what a unit test can and must pin is that
// buildGroundedPrompt stitches every pack section in at all, with sub-items
// attached to their parent bullet, and that none of them is reordered or
// silently dropped.
func TestBuildGroundedPrompt_RendersRulePackSections(t *testing.T) {
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, nil, nil, nil, rulesbundletest.Pack(t))
	for _, want := range []string{
		// baseline section: intro, the (group, order)-sorted bullets with
		// the mega-block's sub-items, outro
		"SYNTHETIC baseline rules intro.",
		"- SYNTHETIC-ALPHA:",
		"- SYNTHETIC-BRAVO:",
		"  - bravo sub-item one",
		"  - bravo sub-item two",
		"- SYNTHETIC-CHARLIE:",
		"SYNTHETIC baseline rules outro.",
		// orthogonality block
		"SYNTHETIC: do not merge orthogonal issues.",
		// severity rubric
		"SYNTHETIC severity rubric: critical > high > warning > info.",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("grounded prompt missing rule-pack anchor %q", want)
		}
	}
	// Section order is part of the prompt contract: baseline + orthogonality
	// are reasoning-rules items 1 and 2, the rubric follows the JSON schema.
	baseline := strings.Index(prompt, "SYNTHETIC baseline rules intro.")
	orthogonal := strings.Index(prompt, "SYNTHETIC: do not merge orthogonal issues.")
	rubric := strings.Index(prompt, "SYNTHETIC severity rubric:")
	if baseline >= orthogonal || orthogonal >= rubric {
		t.Errorf("rule-pack sections out of order: baseline=%d orthogonality=%d rubric=%d", baseline, orthogonal, rubric)
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
	// 404 is the EXPECTED not-authored state, never a transient miss —
	// it must not feed the LLM-CB-KNOWLEDGE-PARTIAL finding.
	if len(bundle.Misses) != 0 {
		t.Errorf("a 404 must not be recorded as a miss, got %+v", bundle.Misses)
	}
}

// TestBuildGrounding_TransientMissDegradesNotAborts pins the review-L24
// degradation policy: a 5xx (after the client's bounded retry) on ONE
// primitive must not cancel the fan-out. The failed slot keeps a Missing
// placeholder (stable prompt structure), the failure lands in
// bundle.Misses, and every other lookup — including composition — still
// completes with real data.
func TestBuildGrounding_TransientMissDegradesNotAborts(t *testing.T) {
	srv := newFailingKnowledgeServer(t, "flaky", http.StatusServiceUnavailable)
	defer srv.Close()

	client := knowledge.New(srv.URL)
	resources := []DiscoveredResource{
		{Type: "aws_s3_bucket", URN: "urn:a"}, // resolves to aws:s3/bucket@v1 — healthy
		{
			Type: "aws_lambda_function", URN: "urn:b",
			Inputs: map[string]any{"cb_describer_primitive_resolved": "aws:fake/flaky@v1"},
		},
	}

	bundle, _, err := BuildGrounding(context.Background(), client, resources, []string{"static-site"}, 2)
	if err != nil {
		t.Fatalf("a single transient failure must degrade, not abort: %v", err)
	}

	if len(bundle.Misses) != 1 {
		t.Fatalf("expected exactly 1 miss, got %+v", bundle.Misses)
	}
	miss := bundle.Misses[0]
	if miss.Kind != "primitive" || miss.Key != "aws:fake/flaky@v1" {
		t.Errorf("miss = %+v, want primitive aws:fake/flaky@v1", miss)
	}
	if !strings.Contains(miss.Err, "503") {
		t.Errorf("miss should carry the underlying error, got %q", miss.Err)
	}

	for _, p := range bundle.Primitives {
		switch p.TypeID {
		case "aws:fake/flaky@v1":
			if !p.Missing || p.Data != nil {
				t.Errorf("failed primitive must hold a Missing placeholder, got %+v", p)
			}
		default:
			if p.Missing || p.Data == nil {
				t.Errorf("sibling primitive %s must still be fetched, got %+v", p.TypeID, p)
			}
		}
	}
	if len(bundle.Practices) != 1 || bundle.Practices[0].Data == nil {
		t.Errorf("practices lookup must still complete, got %+v", bundle.Practices)
	}
	if bundle.Composition == nil || bundle.Composition.Data == nil {
		t.Errorf("composition lookup must still complete, got %+v", bundle.Composition)
	}
}

// TestBuildGrounding_TotalWipeoutAborts pins the abort half of the L24
// policy: when the backend answers NOTHING (every lookup 5xx, not even a
// 404), there is no knowledge to be partial of — BuildGrounding must
// fail loudly like the old first-error policy did.
func TestBuildGrounding_TotalWipeoutAborts(t *testing.T) {
	srv := newFailingKnowledgeServer(t, "", http.StatusServiceUnavailable)
	defer srv.Close()

	client := knowledge.New(srv.URL)
	resources := []DiscoveredResource{{Type: "aws_s3_bucket", URN: "urn:a"}}

	bundle, _, err := BuildGrounding(context.Background(), client, resources, nil, 1)
	if err == nil {
		t.Fatalf("expected a total-wipeout abort, got bundle %+v", bundle)
	}
	if !strings.Contains(err.Error(), "unreachable") {
		t.Errorf("wipeout error should say the backend is unreachable, got %q", err)
	}
}

// TestBuildGrounding_AuthErrorAborts pins the other abort class: 401/403
// mean the backend is rejecting this client, so every remaining lookup
// would fail identically — keep the fail-fast behavior, never degrade.
func TestBuildGrounding_AuthErrorAborts(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		srv := newFailingKnowledgeServer(t, "", status)

		client := knowledge.New(srv.URL)
		resources := []DiscoveredResource{{Type: "aws_s3_bucket", URN: "urn:a"}}

		bundle, _, err := BuildGrounding(context.Background(), client, resources, nil, 1)
		srv.Close()
		if err == nil {
			t.Fatalf("status %d: expected an auth-class abort, got bundle %+v", status, bundle)
		}
		if !strings.Contains(err.Error(), fmt.Sprintf("returned %d", status)) {
			t.Errorf("status %d: error should carry the auth status, got %q", status, err)
		}
	}
}

// TestBuildGroundedPrompt_RendersObservabilityPosture asserts the
// GuardDuty and AWS Config posture blocks reach the prompt — including
// the derived aggregate lines the FP-safe rules key on (per-region facts
// alone aren't enough: the LLM must not flag a single-region absence /
// global-types gap when another region covers it).
func TestBuildGroundedPrompt_RendersObservabilityPosture(t *testing.T) {
	posture := &AccountPosture{
		GuardDutyByRegion: map[string]string{
			"us-east-1":    "disabled",
			"eu-central-1": "absent",
		},
		ConfigRecorderByRegion: map[string]ConfigRecorderState{
			"us-east-1":    {Present: true, RecordsGlobalTypes: false},
			"eu-central-1": {Present: false, RecordsGlobalTypes: false},
		},
	}
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, nil, nil, posture, rulesbundletest.Pack(t))
	for _, want := range []string{
		"GuardDuty detector",
		"us-east-1: disabled",
		"eu-central-1: absent",
		// us-east-1 holds a DISABLED detector, so a detector IS present
		// account-wide → present-anywhere is true even though no region is
		// "enabled". This is the gate that stops the absent-everywhere
		// WARNING from double-firing alongside the per-region disabled HIGH.
		"GuardDuty detector present in at least one audited region: true",
		"AWS Config recorder",
		"us-east-1: present=true records_global_types=false",
		"AWS Config recorder present in at least one audited region: true",
		"global resource types recorded in at least one audited region: false",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
}

// TestBuildGroundedPrompt_GuardDutyDisabledIsNotAbsent locks the
// disabled↔absent distinction that the absent-everywhere WARNING keys on.
// Live validation of the observability rules found that WARNING
// double-firing on a DISABLED detector: the old aggregate was true only
// for exactly "enabled", so a disabled-everywhere account derived
// enabled-anywhere=false and the LLM read "no GuardDuty in the account"
// — even though a detector demonstrably exists. The fix mirrors the AWS
// Config recorder gate: present-anywhere counts a disabled detector as
// present, so only a TRUE no-detector-anywhere account trips the warning.
//
// This asserts the deterministic render GATE (the present-anywhere line
// the rule tells the LLM to key on), not the LLM's finding emission —
// that's the layer a unit test can pin. A disabled-only account must
// render present=true (no absent-everywhere warning; the per-region HIGH
// still fires off its own "disabled" line); an all-absent account must
// render present=false (warning preserved).
func TestBuildGroundedPrompt_GuardDutyDisabledIsNotAbsent(t *testing.T) {
	disabledOnly := &AccountPosture{
		GuardDutyByRegion: map[string]string{
			"us-east-1":    "disabled",
			"eu-central-1": "absent",
		},
	}
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, nil, nil, disabledOnly, rulesbundletest.Pack(t))
	if !strings.Contains(prompt, "GuardDuty detector present in at least one audited region: true") {
		t.Errorf("a disabled detector must keep present-anywhere=true (a detector exists; only the per-region HIGH should fire, not the account-wide absent warning)")
	}
	if strings.Contains(prompt, "GuardDuty detector present in at least one audited region: false") {
		t.Errorf("present-anywhere must not be false while a disabled detector exists")
	}

	absentEverywhere := &AccountPosture{
		GuardDutyByRegion: map[string]string{
			"us-east-1":    "absent",
			"eu-central-1": "absent",
		},
	}
	prompt = buildGroundedPrompt(IaCTypeTerraform, nil, nil, nil, absentEverywhere, rulesbundletest.Pack(t))
	if !strings.Contains(prompt, "GuardDuty detector present in at least one audited region: false") {
		t.Errorf("a genuinely no-detector-anywhere account must render present-anywhere=false so the absent-everywhere WARNING still fires")
	}
}

// TestBuildGroundedPrompt_RendersVPCFlowLogsEnrichment guards the link
// the annotateVPCFlowLogs unit test can't see: that
// cb_describer_flow_logs_enabled actually reaches the DISCOVERED
// RESOURCES table the LLM reads (writeResourceTable → serialiseInputs
// dumps the whole Inputs map as JSON). If a refactor ever curated that
// to an allow-list, the VPC flow-logs rule would fire on a field the LLM
// never sees — a silent recall miss — and this test catches it. We
// assert the JSON form ("...": false) so a match can only come from the
// resource table, never from rule prose (the synthetic pack carries no
// describer-field text at all, but the discipline is load-bearing for
// any pack).
func TestBuildGroundedPrompt_RendersVPCFlowLogsEnrichment(t *testing.T) {
	resources := []DiscoveredResource{
		{
			Type:   "AWS::EC2::VPC",
			URN:    "aws://us-east-1/AWS::EC2::VPC/vpc-nolog",
			ID:     "vpc-nolog",
			Region: "us-east-1",
			Inputs: map[string]any{"cb_describer_flow_logs_enabled": false},
		},
	}
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, resources, nil, nil, rulesbundletest.Pack(t))
	table := prompt[strings.Index(prompt, "==== DISCOVERED RESOURCES ===="):]
	if !strings.Contains(table, `"cb_describer_flow_logs_enabled": false`) {
		t.Errorf("resource table missing rendered cb_describer_flow_logs_enabled=false")
	}
}

// TestBuildGroundedPrompt_ObservabilityPostureDeterministic guards the
// sorted-key rendering of the new maps. Map iteration order is random,
// so an unsorted render would diverge across builds — and the existing
// determinism test passes a nil posture, so it can't catch this.
func TestBuildGroundedPrompt_ObservabilityPostureDeterministic(t *testing.T) {
	posture := &AccountPosture{
		GuardDutyByRegion: map[string]string{
			"us-east-1": "enabled", "eu-central-1": "disabled",
			"ap-south-1": "absent", "us-west-2": "enabled",
		},
		ConfigRecorderByRegion: map[string]ConfigRecorderState{
			"us-east-1":    {Present: true, RecordsGlobalTypes: true},
			"eu-central-1": {Present: true, RecordsGlobalTypes: false},
			"ap-south-1":   {Present: false}, "us-west-2": {Present: true, RecordsGlobalTypes: true},
		},
	}
	pack := rulesbundletest.Pack(t)
	first := buildGroundedPrompt(IaCTypeTerraform, nil, nil, nil, posture, pack)
	for i := 0; i < 20; i++ {
		if got := buildGroundedPrompt(IaCTypeTerraform, nil, nil, nil, posture, pack); got != first {
			t.Fatalf("observability posture render not deterministic across builds")
		}
	}
}
