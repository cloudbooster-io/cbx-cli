package aws

import (
	"context"
	"testing"

	lambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/smithy-go"
)

// enrichLambda maps a synthesised raw through mapToDiscovered and runs the real
// lambdaFunctionDescriber over it — the describer makes NO SDK call (its Enrich
// discards ctx + awsCfg), so this is the same path runJob takes, exercised
// without a live client. The returned Inputs are exactly what the !36 baseline
// rules read.
func enrichLambda(t *testing.T, raw rawResource) map[string]any {
	t.Helper()
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	if err := (lambdaFunctionDescriber{}).Enrich(context.Background(), awsCfg{}, &dr); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	return dr.Inputs
}

// A function with no dead-letter target and no reserved concurrency is the
// variant-03 posture that was going dark: the synthesised raw must, after the
// describer runs, set BOTH cb_describer_dlq_configured=false and
// cb_describer_reserved_concurrency_set=false so the two WARNINGs fire — and
// carry Role so the Lambda→IAM-role cross-reference can run. This is the whole
// reason the fallback synthesises finding-bearing props rather than a name-only
// raw (the describer reads these from Inputs, it does not fetch them live).
func TestLambdaFunctionToRaw_InsecurePostureFiresFindings(t *testing.T) {
	fn := lambdatypes.FunctionConfiguration{
		FunctionName: strp("checkout-worker"),
		FunctionArn:  strp("arn:aws:lambda:eu-central-1:111122223333:function:checkout-worker"),
		Role:         strp("arn:aws:iam::111122223333:role/checkout-worker-role"),
		Runtime:      lambdatypes.RuntimePython312,
		// No DeadLetterConfig → missing-DLQ. No reserved concurrency probed.
	}

	raw, ok := lambdaFunctionToRaw(fn, nil, "eu-central-1")
	if !ok {
		t.Fatal("lambdaFunctionToRaw !ok for a valid function")
	}
	if raw.CFNType != "AWS::Lambda::Function" || raw.Identifier != "checkout-worker" {
		t.Fatalf("unexpected raw: type=%q id=%q", raw.CFNType, raw.Identifier)
	}

	in := enrichLambda(t, raw)
	if v, ok := in["cb_describer_dlq_configured"].(bool); !ok || v {
		t.Errorf("cb_describer_dlq_configured: got %v, want false (missing-DLQ WARNING fires)", in["cb_describer_dlq_configured"])
	}
	if v, ok := in["cb_describer_reserved_concurrency_set"].(bool); !ok || v {
		t.Errorf("cb_describer_reserved_concurrency_set: got %v, want false (no-reserved-concurrency WARNING fires)", in["cb_describer_reserved_concurrency_set"])
	}
	if in["cb_describer_role_arn"] != "arn:aws:iam::111122223333:role/checkout-worker-role" {
		t.Errorf("cb_describer_role_arn: got %v (Role must survive for the Lambda→role cross-reference)", in["cb_describer_role_arn"])
	}
}

// The inverse posture — a dead-letter target set AND reserved concurrency
// threaded in from the probe — must flip both signals true so NEITHER WARNING
// fires. Guards against the mapper hard-coding the "bad" shape, and proves the
// probe value round-trips. Also asserts the secondary describer signals
// (vpc-attached, plaintext-secret-env) read off the carried-through props.
func TestLambdaFunctionToRaw_SecurePostureInverse(t *testing.T) {
	reserved := int32(50)
	fn := lambdatypes.FunctionConfiguration{
		FunctionName:     strp("payments-api"),
		Role:             strp("arn:aws:iam::111122223333:role/payments-api-role"),
		DeadLetterConfig: &lambdatypes.DeadLetterConfig{TargetArn: strp("arn:aws:sqs:eu-central-1:111122223333:payments-dlq")},
		VpcConfig:        &lambdatypes.VpcConfigResponse{SubnetIds: []string{"subnet-0a1b2c3d"}},
		Environment:      &lambdatypes.EnvironmentResponse{Variables: map[string]string{"DB_PASSWORD": "hunter2"}},
	}

	raw, ok := lambdaFunctionToRaw(fn, &reserved, "eu-central-1")
	if !ok {
		t.Fatal("lambdaFunctionToRaw !ok")
	}

	in := enrichLambda(t, raw)
	if v, ok := in["cb_describer_dlq_configured"].(bool); !ok || !v {
		t.Errorf("cb_describer_dlq_configured: got %v, want true (DLQ set ⇒ no finding)", in["cb_describer_dlq_configured"])
	}
	if v, ok := in["cb_describer_reserved_concurrency_set"].(bool); !ok || !v {
		t.Errorf("cb_describer_reserved_concurrency_set: got %v, want true (reserved set ⇒ no finding)", in["cb_describer_reserved_concurrency_set"])
	}
	if got, _ := in["cb_describer_reserved_concurrency"].(float64); got != 50 {
		t.Errorf("cb_describer_reserved_concurrency: got %v, want 50 (probe value must round-trip)", in["cb_describer_reserved_concurrency"])
	}
	if v, ok := in["cb_describer_vpc_attached"].(bool); !ok || !v {
		t.Errorf("cb_describer_vpc_attached: got %v, want true (VpcConfig.SubnetIds carried through)", in["cb_describer_vpc_attached"])
	}
	if v, ok := in["cb_describer_env_has_plaintext_secrets"].(bool); !ok || !v {
		t.Errorf("cb_describer_env_has_plaintext_secrets: got %v, want true (Environment.Variables carried through)", in["cb_describer_env_has_plaintext_secrets"])
	}
}

func TestLambdaFunctionToRaw_EmptyName(t *testing.T) {
	if _, ok := lambdaFunctionToRaw(lambdatypes.FunctionConfiguration{FunctionName: nil}, nil, "eu-central-1"); ok {
		t.Error("lambdaFunctionToRaw returned ok for a nil function name")
	}
	if _, ok := lambdaFunctionToRaw(lambdatypes.FunctionConfiguration{FunctionName: strp("")}, nil, "eu-central-1"); ok {
		t.Error("lambdaFunctionToRaw returned ok for an empty function name")
	}
}

// fakeLambdaFallback implements lambdaFallbackAPI so pagination and the
// per-function GetFunctionConcurrency probe can be exercised without a live call.
// ListFunctions returns pages[callIdx] in order (callers drive it via NextMarker);
// GetFunctionConcurrency reports conc[name] unless failConc[name], in which case it
// returns an AccessDenied APIError — the SCP/permission-boundary deny the
// partial-recovery path exists for.
type fakeLambdaFallback struct {
	pages    []*lambda.ListFunctionsOutput
	listErr  error
	conc     map[string]*int32
	failConc map[string]bool
	callIdx  int
}

func (f *fakeLambdaFallback) ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := f.pages[f.callIdx]
	f.callIdx++
	return out, nil
}

func (f *fakeLambdaFallback) GetFunctionConcurrency(_ context.Context, in *lambda.GetFunctionConcurrencyInput, _ ...func(*lambda.Options)) (*lambda.GetFunctionConcurrencyOutput, error) {
	name := ""
	if in.FunctionName != nil {
		name = *in.FunctionName
	}
	if f.failConc[name] {
		return nil, &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied by SCP"}
	}
	return &lambda.GetFunctionConcurrencyOutput{ReservedConcurrentExecutions: f.conc[name]}, nil
}

func mappedByID(t *testing.T, raws []rawResource) map[string]map[string]any {
	t.Helper()
	m := make(map[string]map[string]any, len(raws))
	for _, r := range raws {
		dr, err := r.mapToDiscovered()
		if err != nil {
			t.Fatalf("mapToDiscovered(%s): %v", r.Identifier, err)
		}
		m[r.Identifier] = dr.Inputs
	}
	return m
}

// ListFunctions paginates by Marker ← NextMarker; collectLambdaFunctions must
// walk every page and probe each function's reserved concurrency. Two pages, a
// reservation set on one function, verifies both the pagination loop and that the
// probe value lands in the synthesised props.
func TestCollectLambdaFunctions_PaginatesAndProbes(t *testing.T) {
	reserved := int32(10)
	client := &fakeLambdaFallback{
		pages: []*lambda.ListFunctionsOutput{
			{
				Functions: []lambdatypes.FunctionConfiguration{
					{FunctionName: strp("alpha")},
					{FunctionName: strp("bravo")},
				},
				NextMarker: strp("page-2"),
			},
			{
				Functions: []lambdatypes.FunctionConfiguration{
					{FunctionName: strp("charlie")},
				},
			},
		},
		conc: map[string]*int32{"bravo": &reserved},
	}

	results, err := collectLambdaFunctions(context.Background(), client, "eu-central-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected all 3 functions across both pages, got %d", len(results))
	}
	by := mappedByID(t, results)
	for _, name := range []string{"alpha", "bravo", "charlie"} {
		if by[name] == nil {
			t.Errorf("function %q missing from the paginated result", name)
		}
	}
	if got, _ := by["bravo"]["ReservedConcurrentExecutions"].(float64); got != 10 {
		t.Errorf("bravo ReservedConcurrentExecutions: got %v, want 10 (probe value must be synthesised)", by["bravo"]["ReservedConcurrentExecutions"])
	}
	if _, present := by["alpha"]["ReservedConcurrentExecutions"]; present {
		t.Error("alpha (no reservation) must omit ReservedConcurrentExecutions so the WARNING fires")
	}
}

// A per-function GetFunctionConcurrency failure must NOT drop the function —
// ListFunctions already fully described it, so we keep it (reserved concurrency
// left absent, the WARNING still fires) and surface the first error so --diagnose
// sees the permission gap. Mirrors listDynamoDBTablesNative's pitrErr contract.
func TestCollectLambdaFunctions_ConcurrencyProbeErrorKeepsFunction(t *testing.T) {
	client := &fakeLambdaFallback{
		pages: []*lambda.ListFunctionsOutput{
			{
				Functions: []lambdatypes.FunctionConfiguration{
					{FunctionName: strp("alpha")},
					{FunctionName: strp("bravo")}, // its concurrency probe is denied
				},
			},
		},
		failConc: map[string]bool{"bravo": true},
	}

	results, err := collectLambdaFunctions(context.Background(), client, "eu-central-1")
	if len(results) != 2 {
		t.Fatalf("expected both functions kept despite the probe denial, got %d", len(results))
	}
	if err == nil {
		t.Fatal("expected the GetFunctionConcurrency error surfaced alongside the recovered functions")
	}
	if _, ok := asPermissionError(err); !ok {
		t.Errorf("expected the AccessDenied to classify as *PermissionError, got %T", err)
	}
	// The denied function still fires the WARNING: absent reserved concurrency
	// reads as reserved_concurrency_set=false (the describer's CC contract).
	by := mappedByID(t, results)
	if _, present := by["bravo"]["ReservedConcurrentExecutions"]; present {
		t.Error("bravo's reserved concurrency must be absent (probe failed) so the WARNING still fires")
	}
}

// A ListFunctions failure is fatal — there's nothing to recover — and must come
// back classified for --diagnose.
func TestCollectLambdaFunctions_ListFunctionsErrorFatal(t *testing.T) {
	client := &fakeLambdaFallback{listErr: &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied"}}

	results, err := collectLambdaFunctions(context.Background(), client, "eu-central-1")
	if results != nil {
		t.Fatalf("expected nil results on a ListFunctions failure, got %d", len(results))
	}
	if _, ok := asPermissionError(err); !ok {
		t.Fatalf("expected *PermissionError from a denied ListFunctions, got %T (%v)", err, err)
	}
}

// Empty primary (CloudControl's silent-empty for AWS::Lambda::Function — the
// variant-03 gap) must trigger the fallback, and because lambdaFunctionDescriber
// makes no live call, the REAL describer runs over the synthesised resource inside
// runJob — so the output already carries the firing WARNING signals. Unlike the S3
// fallback test, allDescribers is left intact to prove exactly that.
func TestRunJob_LambdaFunctionFallbackFires(t *testing.T) {
	fallbackRaw, ok := lambdaFunctionToRaw(
		lambdatypes.FunctionConfiguration{
			FunctionName: strp("checkout-worker"),
			Role:         strp("arn:aws:iam::111122223333:role/checkout-worker-role"),
		}, nil, "eu-central-1")
	if !ok {
		t.Fatal("lambdaFunctionToRaw !ok")
	}

	spec := cfnTypeSpec{
		Type:         "AWS::Lambda::Function",
		CustomLister: func(context.Context, awsCfg, string) ([]rawResource, error) { return nil, nil },
		FallbackLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			return []rawResource{fallbackRaw}, nil
		},
	}

	res := runJob(context.Background(), awsCfg{}, "eu-central-1", spec, nil)
	if len(res.resources) != 1 {
		t.Fatalf("expected 1 function from the fallback, got %d", len(res.resources))
	}
	got := res.resources[0]
	if got.Type != "AWS::Lambda::Function" || got.ID != "checkout-worker" {
		t.Fatalf("unexpected resource: type=%q id=%q", got.Type, got.ID)
	}
	if v, ok := got.Inputs["cb_describer_dlq_configured"].(bool); !ok || v {
		t.Errorf("cb_describer_dlq_configured: got %v, want false — the describer must have run over the fallback resource", got.Inputs["cb_describer_dlq_configured"])
	}
	if v, ok := got.Inputs["cb_describer_reserved_concurrency_set"].(bool); !ok || v {
		t.Errorf("cb_describer_reserved_concurrency_set: got %v, want false", got.Inputs["cb_describer_reserved_concurrency_set"])
	}
}

// When CloudControl lists the function, the fallback must NOT fire — CC's richer
// payload wins and there's no double-counting.
func TestRunJob_LambdaFunctionFallbackNotFiredWhenPrimaryReturns(t *testing.T) {
	primaryRaw, ok := lambdaFunctionToRaw(lambdatypes.FunctionConfiguration{FunctionName: strp("cc-listed-fn")}, nil, "eu-central-1")
	if !ok {
		t.Fatal("lambdaFunctionToRaw !ok")
	}

	fallbackCalled := false
	spec := cfnTypeSpec{
		Type:         "AWS::Lambda::Function",
		CustomLister: func(context.Context, awsCfg, string) ([]rawResource, error) { return []rawResource{primaryRaw}, nil },
		FallbackLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			fallbackCalled = true
			return []rawResource{{CFNType: "AWS::Lambda::Function", Identifier: "should-not-appear"}}, nil
		},
	}

	res := runJob(context.Background(), awsCfg{}, "eu-central-1", spec, nil)
	if fallbackCalled {
		t.Error("FallbackLister fired even though CloudControl returned a function")
	}
	if len(res.resources) != 1 || res.resources[0].ID != "cc-listed-fn" {
		t.Fatalf("expected only the CloudControl function, got %+v", res.resources)
	}
}

// A FallbackLister that recovers functions BUT hits a GetFunctionConcurrency
// failure must surface the error (so --diagnose sees the permission gap) while
// still delivering the functions — never trade the DLQ / role findings
// ListFunctions already carries for one secondary-call failure. Mirrors runJob's
// contract: a non-empty fallback with a non-nil error keeps the resources and
// collects the error.
func TestRunJob_LambdaFallbackSurfacesConcurrencyErrorButKeepsFunction(t *testing.T) {
	fallbackRaw, ok := lambdaFunctionToRaw(lambdatypes.FunctionConfiguration{FunctionName: strp("checkout-worker")}, nil, "eu-central-1")
	if !ok {
		t.Fatal("lambdaFunctionToRaw !ok")
	}

	spec := cfnTypeSpec{
		Type:         "AWS::Lambda::Function",
		CustomLister: func(context.Context, awsCfg, string) ([]rawResource, error) { return nil, nil },
		FallbackLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			return []rawResource{fallbackRaw}, &PermissionError{
				Service: "lambda", Action: "lambda:GetFunctionConcurrency", Region: "eu-central-1",
			}
		},
	}

	res := runJob(context.Background(), awsCfg{}, "eu-central-1", spec, nil)
	if len(res.resources) != 1 {
		t.Fatalf("expected the function to survive the concurrency error, got %d resources", len(res.resources))
	}
	if len(res.permErrs) != 1 {
		t.Fatalf("expected the concurrency permission error collected for --diagnose, got %d", len(res.permErrs))
	}
	if res.listErr != nil {
		t.Errorf("listErr should be cleared once the fallback recovered functions, got %v", res.listErr)
	}
}
