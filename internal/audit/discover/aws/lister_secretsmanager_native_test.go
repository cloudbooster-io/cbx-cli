package aws

import (
	"context"
	"testing"

	secretsmanager "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go"
)

// A secret with rotation disabled is the variant-00 posture that was going dark:
// the synthesised raw must carry RotationEnabled=false so the secret-no-rotation
// rule ("RotationEnabled: false or unset") fires. There is no SecretsManager
// describer, so the round-trip asserts the raw field lands in Inputs exactly as
// the grounded LLM reads it.
func TestSecretToRaw_NoRotationFiresFinding(t *testing.T) {
	s := smtypes.SecretListEntry{
		ARN:             strp("arn:aws:secretsmanager:eu-central-1:111122223333:secret:prod/db-credentials-AbCdEf"),
		Name:            strp("prod/db-credentials"),
		RotationEnabled: boolp(false),
	}

	raw, ok := secretToRaw(s, "eu-central-1")
	if !ok {
		t.Fatal("secretToRaw !ok for a valid secret")
	}
	if raw.CFNType != "AWS::SecretsManager::Secret" {
		t.Fatalf("unexpected CFN type: %q", raw.CFNType)
	}
	if raw.Identifier != *s.ARN {
		t.Fatalf("identifier: got %q, want the ARN %q (CloudControl's primary id)", raw.Identifier, *s.ARN)
	}

	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	if v, ok := dr.Inputs["RotationEnabled"].(bool); !ok || v {
		t.Errorf("RotationEnabled: got %v, want false (secret-no-rotation finding fires)", dr.Inputs["RotationEnabled"])
	}
	if dr.Inputs["Name"] != "prod/db-credentials" {
		t.Errorf("Name: got %v, want prod/db-credentials (carried for finding references)", dr.Inputs["Name"])
	}
}

// FP-SAFETY — the whole point of carrying RotationEnabled. A ROTATED secret
// restored by the fallback WITHOUT its ::RotationSchedule sibling (CloudControl
// dropped one or both; this fallback only restores the Secret) must still read
// rotation-present: RotationEnabled=true is neither "false" nor "unset", so the
// rule suppresses. This is the Api-vs-Route FP shape — a Secret-only restore that
// must not false-fire — and it proves the schedule resource needs no fallback of
// its own.
func TestSecretToRaw_RotatedSecretDoesNotFalseFire(t *testing.T) {
	s := smtypes.SecretListEntry{
		ARN:               strp("arn:aws:secretsmanager:eu-central-1:111122223333:secret:prod/api-key-XyZ123"),
		Name:              strp("prod/api-key"),
		RotationEnabled:   boolp(true),
		RotationLambdaARN: strp("arn:aws:lambda:eu-central-1:111122223333:function:rotate-api-key"),
	}

	raw, ok := secretToRaw(s, "eu-central-1")
	if !ok {
		t.Fatal("secretToRaw !ok")
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	// The rule keys on this field; true ⇒ rotation-present ⇒ NO finding, even
	// though no RotationSchedule resource accompanies the secret in the set.
	if v, ok := dr.Inputs["RotationEnabled"].(bool); !ok || !v {
		t.Errorf("RotationEnabled: got %v, want true (rotated secret must read rotation-present and NOT false-fire)", dr.Inputs["RotationEnabled"])
	}
}

// A secret with no ARN (CloudControl's primary id) cannot be synthesised into a
// secretToRaw must carry the secret's encryption CMK under the exact CFN
// property name crossReferenceKMS walks ("KmsKeyId"). ListSecrets returns it
// only for a customer CMK (the default aws/secretsmanager key leaves it nil), so
// the default-key case stays absent.
func TestSecretToRaw_CarriesKmsKeyId(t *testing.T) {
	cases := []struct {
		name    string
		kms     *string
		wantKey any // expected Inputs["KmsKeyId"], or nil for "absent"
	}{
		{
			name:    "customer cmk → stored under KmsKeyId",
			kms:     strp("arn:aws:kms:eu-central-1:123:key/secret-cmk"),
			wantKey: "arn:aws:kms:eu-central-1:123:key/secret-cmk",
		},
		{
			name:    "no key (aws/secretsmanager default) → absent",
			kms:     nil,
			wantKey: nil,
		},
		{
			name:    "empty key → absent (putStr discipline)",
			kms:     strp(""),
			wantKey: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, ok := secretToRaw(smtypes.SecretListEntry{
				ARN:      strp("arn:aws:secretsmanager:eu-central-1:111122223333:secret:prod/enc-AbCdEf"),
				KmsKeyId: tc.kms,
			}, "eu-central-1")
			if !ok {
				t.Fatal("secretToRaw !ok")
			}
			dr, err := raw.mapToDiscovered()
			if err != nil {
				t.Fatalf("mapToDiscovered: %v", err)
			}
			got, present := dr.Inputs["KmsKeyId"]
			if tc.wantKey == nil {
				if present {
					t.Errorf("KmsKeyId = %v, want absent", got)
				}
				return
			}
			if !present {
				t.Fatalf("KmsKeyId absent, want %v", tc.wantKey)
			}
			if got != tc.wantKey {
				t.Errorf("KmsKeyId = %v, want %v", got, tc.wantKey)
			}
		})
	}
}

// Gating assertion: a customer CMK used ONLY to encrypt a fallback-discovered
// secret resolves to is_unused=false. The full toRaw → mapToDiscovered (JSON
// round-trip) → crossReferenceKMS path catches a wrong-cased store.
func TestSecretToRaw_CrossRefCountsSecret(t *testing.T) {
	keyARN := "arn:aws:kms:eu-central-1:123:key/secret-only-key"
	raw, ok := secretToRaw(smtypes.SecretListEntry{
		ARN:      strp("arn:aws:secretsmanager:eu-central-1:111122223333:secret:prod/only-ref-XyZ"),
		KmsKeyId: strp(keyARN),
	}, "eu-central-1")
	if !ok {
		t.Fatal("secretToRaw !ok")
	}
	secret, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}

	resources := []DiscoveredResource{
		{
			Type: "AWS::KMS::Key",
			URN:  "aws://eu-central-1/AWS::KMS::Key/secret-only-key",
			Inputs: map[string]any{
				"Arn":   keyARN,
				"KeyId": "secret-only-key",
			},
		},
		secret,
	}

	crossReferenceKMS(resources)

	key := findResource(t, resources, "aws://eu-central-1/AWS::KMS::Key/secret-only-key")
	if key.Inputs["cb_describer_is_unused"] != false {
		t.Errorf("CMK used only as Secrets Manager secret key flagged is_unused=%v, want false (the FP this fix closes)", key.Inputs["cb_describer_is_unused"])
	}
}

// CFN-shape raw — secretToRaw must skip it rather than emit an id-less resource.
func TestSecretToRaw_EmptyARN(t *testing.T) {
	if _, ok := secretToRaw(smtypes.SecretListEntry{ARN: nil, Name: strp("orphan")}, "eu-central-1"); ok {
		t.Error("secretToRaw returned ok for a nil ARN")
	}
	if _, ok := secretToRaw(smtypes.SecretListEntry{ARN: strp("")}, "eu-central-1"); ok {
		t.Error("secretToRaw returned ok for an empty ARN")
	}
}

// fakeSecretsManagerFallback implements secretsManagerFallbackAPI so the
// NextToken pagination loop can be exercised without a live call. ListSecrets
// returns pages[callIdx] in order; callers drive it via NextToken.
type fakeSecretsManagerFallback struct {
	pages   []*secretsmanager.ListSecretsOutput
	listErr error
	callIdx int
}

func (f *fakeSecretsManagerFallback) ListSecrets(context.Context, *secretsmanager.ListSecretsInput, ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := f.pages[f.callIdx]
	f.callIdx++
	return out, nil
}

// ListSecrets paginates by NextToken; collectSecretsManagerSecrets must walk
// every page. Two pages, a rotated and an unrotated secret, verifies both the
// pagination loop and that each secret's RotationEnabled lands in the
// synthesised props with the right polarity.
func TestCollectSecretsManagerSecrets_PaginatesAndCarriesRotation(t *testing.T) {
	client := &fakeSecretsManagerFallback{
		pages: []*secretsmanager.ListSecretsOutput{
			{
				SecretList: []smtypes.SecretListEntry{
					{ARN: strp("arn:aws:secretsmanager:eu-central-1:111122223333:secret:unrotated-A"), Name: strp("unrotated"), RotationEnabled: boolp(false)},
				},
				NextToken: strp("page-2"),
			},
			{
				SecretList: []smtypes.SecretListEntry{
					{ARN: strp("arn:aws:secretsmanager:eu-central-1:111122223333:secret:rotated-B"), Name: strp("rotated"), RotationEnabled: boolp(true)},
				},
			},
		},
	}

	results, err := collectSecretsManagerSecrets(context.Background(), client, "eu-central-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected both secrets across both pages, got %d", len(results))
	}

	byName := map[string]map[string]any{}
	for _, r := range results {
		dr, err := r.mapToDiscovered()
		if err != nil {
			t.Fatalf("mapToDiscovered(%s): %v", r.Identifier, err)
		}
		name, _ := dr.Inputs["Name"].(string)
		byName[name] = dr.Inputs
	}
	if v, ok := byName["unrotated"]["RotationEnabled"].(bool); !ok || v {
		t.Errorf("unrotated.RotationEnabled: got %v, want false (finding fires)", byName["unrotated"]["RotationEnabled"])
	}
	if v, ok := byName["rotated"]["RotationEnabled"].(bool); !ok || !v {
		t.Errorf("rotated.RotationEnabled: got %v, want true (finding suppressed)", byName["rotated"]["RotationEnabled"])
	}
}

// A ListSecrets failure is fatal — there's nothing to recover — and must come
// back classified for --diagnose.
func TestCollectSecretsManagerSecrets_ListErrorFatal(t *testing.T) {
	client := &fakeSecretsManagerFallback{listErr: &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied"}}

	results, err := collectSecretsManagerSecrets(context.Background(), client, "eu-central-1")
	if results != nil {
		t.Fatalf("expected nil results on a ListSecrets failure, got %d", len(results))
	}
	if _, ok := asPermissionError(err); !ok {
		t.Fatalf("expected *PermissionError from a denied ListSecrets, got %T (%v)", err, err)
	}
}

// Empty primary (CloudControl's silent-empty for AWS::SecretsManager::Secret —
// the variant-00 gap) must trigger the fallback, and the synthesised secret must
// flow through the real runJob path into the resource set the LLM sees, carrying
// the firing RotationEnabled=false signal.
func TestRunJob_SecretsManagerFallbackFires(t *testing.T) {
	fallbackRaw, ok := secretToRaw(smtypes.SecretListEntry{
		ARN:             strp("arn:aws:secretsmanager:eu-central-1:111122223333:secret:prod/db-credentials-AbCdEf"),
		Name:            strp("prod/db-credentials"),
		RotationEnabled: boolp(false),
	}, "eu-central-1")
	if !ok {
		t.Fatal("secretToRaw !ok")
	}

	spec := cfnTypeSpec{
		Type: "AWS::SecretsManager::Secret",
		// Primary path returns empty, exactly like CloudControl's silent miss.
		CustomLister: func(context.Context, awsCfg, string) ([]rawResource, error) { return nil, nil },
		FallbackLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			return []rawResource{fallbackRaw}, nil
		},
	}

	res := runJob(context.Background(), awsCfg{}, "eu-central-1", spec, nil)
	if len(res.resources) != 1 {
		t.Fatalf("expected 1 secret from the fallback, got %d", len(res.resources))
	}
	got := res.resources[0]
	if got.Type != "AWS::SecretsManager::Secret" {
		t.Fatalf("unexpected resource type: %q", got.Type)
	}
	if v, ok := got.Inputs["RotationEnabled"].(bool); !ok || v {
		t.Errorf("RotationEnabled: got %v, want false (the no-rotation finding's input survives runJob)", got.Inputs["RotationEnabled"])
	}
}

// When CloudControl lists the secret, the fallback must NOT fire — CC's payload
// wins and there's no double-counting.
func TestRunJob_SecretsManagerFallbackNotFiredWhenPrimaryReturns(t *testing.T) {
	primaryRaw, ok := secretToRaw(smtypes.SecretListEntry{
		ARN:  strp("arn:aws:secretsmanager:eu-central-1:111122223333:secret:cc-listed-secret"),
		Name: strp("cc-listed"),
	}, "eu-central-1")
	if !ok {
		t.Fatal("secretToRaw !ok")
	}

	fallbackCalled := false
	spec := cfnTypeSpec{
		Type:         "AWS::SecretsManager::Secret",
		CustomLister: func(context.Context, awsCfg, string) ([]rawResource, error) { return []rawResource{primaryRaw}, nil },
		FallbackLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			fallbackCalled = true
			return []rawResource{{CFNType: "AWS::SecretsManager::Secret", Identifier: "should-not-appear"}}, nil
		},
	}

	res := runJob(context.Background(), awsCfg{}, "eu-central-1", spec, nil)
	if fallbackCalled {
		t.Error("FallbackLister fired even though CloudControl returned a secret")
	}
	if len(res.resources) != 1 || res.resources[0].ID != "arn:aws:secretsmanager:eu-central-1:111122223333:secret:cc-listed-secret" {
		t.Fatalf("expected only the CloudControl secret, got %+v", res.resources)
	}
}
