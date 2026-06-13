package aws

import (
	"context"

	secretsmanager "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

// listSecretsManagerSecretsNative is the FallbackLister for
// AWS::SecretsManager::Secret. Secret + its sibling
// AWS::SecretsManager::RotationSchedule are queried via CloudControl with no
// fallback, so the same non-deterministic silent-empty miss the EC2 / RDS /
// Lambda / DynamoDB fallbacks cover drops the secret with permission_errors=[]
// — and the secret-no-rotation rule (llm_analyzer.go: "Secrets without rotation
// (RotationEnabled: false or unset)") then has nothing to fire on (the
// variant-00 miss). secretsmanager:ListSecrets is the authoritative enumeration
// and fires only when CloudControl returned nothing for this type in this region.
//
// There is no SecretsManager describer; the synthesised CFN-shape Properties are
// read directly by the grounded LLM (like the DynamoDB fallback), so secretToRaw
// must carry the finding-bearing field — RotationEnabled.
//
// FP-SAFETY (the reason RotationSchedule needs no fallback of its own):
// CloudControl's AWS::SecretsManager::Secret read payload does NOT carry
// RotationEnabled (it isn't in that type's CFN read schema), so a CloudControl-
// listed secret relies on the LLM cross-referencing the separate
// ::RotationSchedule list to tell rotated from unrotated. ListSecrets, by
// contrast, returns RotationEnabled PER SECRET directly — so a fallback-restored
// secret is self-describing: a rotated secret carries RotationEnabled=true
// (≠ "false or unset" ⇒ the rule suppresses) even when its ::RotationSchedule
// sibling was NOT restored. Carrying RotationEnabled is therefore both necessary
// and sufficient; restoring the schedule resource would be redundant and could
// not change the rule's verdict. (Known, out-of-scope: if CloudControl lists the
// secret normally but drops only ::RotationSchedule, a rotated secret can still
// FP via the cross-reference path — this fallback can't help there because it
// doesn't fire when CloudControl returned the secret; that pre-existing mode is
// not the variant-00 miss closed here.)
//
// Unlike the Lambda / DynamoDB fallbacks, the one finding-bearing field
// (RotationEnabled) is returned by ListSecrets itself — there is no secondary
// per-secret probe — so this lister has no degrade-with-results tail: it returns
// (results, nil) on success and (nil, classified-error) on a fatal ListSecrets
// failure.
func listSecretsManagerSecretsNative(ctx context.Context, c awsCfg, region string) ([]rawResource, error) {
	return collectSecretsManagerSecrets(ctx, secretsmanager.NewFromConfig(c.withRegion(region).cfg), region)
}

// secretsManagerFallbackAPI is the narrow slice of the Secrets Manager client
// collectSecretsManagerSecrets needs — just ListSecrets. The concrete
// *secretsmanager.Client satisfies it; the seam lets pagination be unit-tested
// without a live call (mirrors lambdaFallbackAPI).
type secretsManagerFallbackAPI interface {
	ListSecrets(context.Context, *secretsmanager.ListSecretsInput, ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
}

// collectSecretsManagerSecrets enumerates secrets via ListSecrets (paginated by
// NextToken) and synthesises a CFN-shape raw per secret. A ListSecrets failure
// is fatal (nothing to recover) and comes back classified for --diagnose.
func collectSecretsManagerSecrets(ctx context.Context, client secretsManagerFallbackAPI, region string) ([]rawResource, error) {
	var results []rawResource
	var token *string
	for {
		out, err := client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{NextToken: token})
		if err != nil {
			return nil, classifyAWSError(err, "secretsmanager", "secretsmanager:ListSecrets", region)
		}
		for _, s := range out.SecretList {
			if raw, ok := secretToRaw(s, region); ok {
				results = append(results, raw)
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	return results, nil
}

// secretToRaw maps an SDK SecretListEntry into CloudControl's
// AWS::SecretsManager::Secret CFN shape so the synthesised resource flows
// through mapToDiscovered + the grounded LLM identically to a CC-listed secret.
// The ARN is the identifier (CloudControl's primary id for this type, surfaced
// as the read-only Id property). The load-bearing field:
//
//   - RotationEnabled → the secret-no-rotation rule. ListSecrets returns it
//     directly (CloudControl's Secret payload does not), so emit it whenever the
//     API gave a value: true ⇒ rotated (rule suppresses), false ⇒ unrotated
//     (rule fires). A nil (never observed for live secrets) falls through to
//     absent, which the rule reads as "unset" and still fires — the safe
//     direction. This is the single field that makes a fallback-restored secret
//     self-describing for rotation; see the FP-safety note above.
//
// Name is carried for human-readable finding references. Pure (no SDK client)
// for unit testing; mirrors dynamoTableToRaw / lambdaFunctionToRaw.
func secretToRaw(s smtypes.SecretListEntry, region string) (rawResource, bool) {
	if s.ARN == nil || *s.ARN == "" {
		return rawResource{}, false
	}
	id := *s.ARN

	props := map[string]any{"Id": id}
	putStr(props, "Name", s.Name)
	putBool(props, "RotationEnabled", s.RotationEnabled)
	// KmsKeyId is the CFN property crossReferenceKMS walks (isKMSFieldName).
	// ListSecrets returns it ONLY when a customer CMK encrypts the secret (the
	// default aws/secretsmanager key leaves it nil), so a CMK used only as this
	// secret's encryption key is counted as referenced instead of being
	// mis-flagged cb_describer_is_unused=true. putStr sets it only when present,
	// so the default-key case stays absent. FP-safe by direction: it can only
	// count a real reference, never invent an unused=true.
	putStr(props, "KmsKeyId", s.KmsKeyId)

	return marshalRaw("AWS::SecretsManager::Secret", id, region, props)
}
