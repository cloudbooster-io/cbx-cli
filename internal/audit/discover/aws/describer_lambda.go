package aws

import (
	"context"
	"regexp"
	"strings"
)

// lambdaFunctionDescriber post-processes CloudControl's
// AWS::Lambda::Function Properties into the cb_describer_* namespace
// the audit's downstream rules and grounded analyzer consume. CC's
// schema for this type is broad — Runtime, Role, Environment.Variables,
// VpcConfig, MemorySize, Timeout, EphemeralStorage, Architectures,
// Layers, KmsKeyArn, LoggingConfig are all in CC's response — so the
// describer makes no SDK call and reads only from r.Inputs.
//
// Two operational-resilience signals are surfaced as explicit booleans
// the grounded prompt's baseline rule keys off — cb_describer_dlq_configured
// (DeadLetterConfig.TargetArn present) and cb_describer_reserved_concurrency_set
// (ReservedConcurrentExecutions present). Both source properties are
// normal readable CFN properties — NOT writeOnly, verified against the
// AWS::Lambda::Function registry schema — so CloudControl returns them
// when set and omits them when unset; absence is a reliable "not
// configured" signal. Emitting the booleans rather than relying on the
// LLM to notice a *missing* key is the whole point: absence is invisible
// in the raw Properties JSON, a present `false` is not.
//
// One detection lives here that CC can't compute on its own:
// cb_describer_env_has_plaintext_secrets. It's a key-shape heuristic
// over Environment.Variables — env keys that look like secrets when
// stored in cleartext (DB_PASSWORD, API_KEY, BEARER_TOKEN, …) are a
// common Lambda footgun. The check is intentionally over the *keys*,
// never the values: a secret value could be a perfectly fine pointer
// like "arn:aws:secretsmanager:...". Naming the variable
// "DB_PASSWORD" still telegraphs a cleartext store; naming it
// "DB_PASSWORD_ARN" suggests indirection through Secrets Manager,
// which the heuristic intentionally skips.
//
// Because the full Inputs map is later inlined verbatim into the
// grounded `claude -p` prompt, Enrich also MASKS the VALUES of
// secret-shaped env keys in place (redactSecretEnvValues) — after the
// boolean above is computed, so the heuristic's signal is unchanged.
type lambdaFunctionDescriber struct{}

func (lambdaFunctionDescriber) CFNType() string { return "AWS::Lambda::Function" }

func (lambdaFunctionDescriber) Enrich(_ context.Context, _ awsCfg, r *DiscoveredResource) error {
	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}

	copyStr(r.Inputs, "Runtime", "cb_describer_runtime")
	copyStr(r.Inputs, "Role", "cb_describer_role_arn")
	copyNumeric(r.Inputs, "MemorySize", "cb_describer_memory_size_mb")
	copyNumeric(r.Inputs, "Timeout", "cb_describer_timeout_seconds")

	if subnets := lambdaSubnetIDs(r.Inputs); len(subnets) > 0 {
		r.Inputs["cb_describer_vpc_attached"] = true
	} else {
		r.Inputs["cb_describer_vpc_attached"] = false
	}

	envVars := lambdaEnvVars(r.Inputs)
	r.Inputs["cb_describer_env_var_count"] = float64(len(envVars))
	r.Inputs["cb_describer_env_has_plaintext_secrets"] = anyKeyLooksLikeSecret(envVars)
	// MUST run after the flag above — it mutates Environment.Variables in
	// place so secret-shaped values never reach the grounded prompt.
	redactSecretEnvValues(r.Inputs)

	r.Inputs["cb_describer_dlq_configured"] = lambdaHasDLQ(r.Inputs)
	if rc, ok := readNumericPtr(r.Inputs, "ReservedConcurrentExecutions"); ok {
		r.Inputs["cb_describer_reserved_concurrency_set"] = true
		r.Inputs["cb_describer_reserved_concurrency"] = rc
	} else {
		r.Inputs["cb_describer_reserved_concurrency_set"] = false
	}
	return nil
}

// lambdaHasDLQ reports whether the function declares a dead-letter
// target. CloudControl returns DeadLetterConfig only when one is
// configured; a real DLQ carries a non-empty TargetArn (an SNS topic or
// SQS queue ARN). A missing block or empty TargetArn means failed async
// invocations are silently dropped — the missing-DLQ footgun.
func lambdaHasDLQ(m map[string]any) bool {
	dlc, ok := m["DeadLetterConfig"].(map[string]any)
	if !ok {
		return false
	}
	return strings.TrimSpace(readStr(dlc, "TargetArn")) != ""
}

// lambdaSubnetIDs returns the subnet-id list under VpcConfig.SubnetIds
// when present. Empty/missing means "not VPC-attached" — Lambda's
// default network mode.
func lambdaSubnetIDs(m map[string]any) []string {
	vpc, ok := m["VpcConfig"].(map[string]any)
	if !ok {
		return nil
	}
	raw, ok := vpc["SubnetIds"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// lambdaEnvVars extracts Environment.Variables as a map. CC returns
// the CFN-shape Environment.Variables (a flat string→string map). When
// the function has no env vars at all, the key is absent — return nil
// so the count is 0 and the secret-detector trivially short-circuits.
func lambdaEnvVars(m map[string]any) map[string]string {
	env, ok := m["Environment"].(map[string]any)
	if !ok {
		return nil
	}
	raw, ok := env["Variables"].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		s, _ := v.(string)
		out[k] = s
	}
	return out
}

// secretKeyHeuristic catches the common cleartext-secret-in-Lambda-env
// naming patterns. We deliberately suffix-test "_arn" / "_id" / "_uri"
// /"_url" via a negative lookbehind-equivalent regex (Go has no lookaround,
// so we post-filter) so DB_PASSWORD trips the rule but DB_PASSWORD_ARN
// does not — the latter is the canonical indirection-via-Secrets-Manager
// shape.
var secretKeyHeuristic = regexp.MustCompile(`(?i)(secret|password|passwd|token|api[_-]?key|credential|private[_-]?key)`)

// secretKeySafeSuffix matches the trailing form that means "this is a
// reference, not a value." Order matters — list longest first to avoid
// partial-match surprises.
//
// Known false-positive class: keys ending in _PATH / _FILE / _CONFIG /
// _TYPE that legitimately point at non-secret artefacts but still match
// the heuristic root (e.g. OAUTH_TOKEN_PATH for a JWKS file path). The
// finding is info-severity so the noise cost is bounded; tighten this
// suffix list when real users surface specific false positives rather
// than guessing.
var secretKeySafeSuffix = regexp.MustCompile(`(?i)(_arn|_id|_uri|_url)$`)

// keyLooksLikeSecret is the per-key form of the heuristic: a secret-shaped
// root that does NOT carry the reference-shape suffix. Shared by the
// boolean flag below, the value redaction here, and the ECS task-definition
// lister's container-env redaction (lister_ecs_native.go).
func keyLooksLikeSecret(k string) bool {
	return secretKeyHeuristic.MatchString(k) && !secretKeySafeSuffix.MatchString(k)
}

func anyKeyLooksLikeSecret(env map[string]string) bool {
	for k := range env {
		if keyLooksLikeSecret(k) {
			return true
		}
	}
	return false
}

// redactedEnvValue is the marker that replaces a secret-shaped env var's
// VALUE before the Inputs map is serialised into the grounded prompt
// (llm_analyzer.go's writeResourceTable inlines the FULL Inputs map, so an
// unmasked value would ship verbatim to a third-party LLM).
const redactedEnvValue = "[REDACTED by cbx]"

// secretValueIsReference reports whether a value stored under a
// secret-shaped key is clearly an indirection — an ARN pointing at Secrets
// Manager / SSM — rather than secret material. ARNs are public identifiers
// (nothing to protect), and the grounded rules' suppress paths key off the
// `arn:` prefix to recognise the indirection shape, so masking one would
// trade a real suppress signal for zero security gain.
func secretValueIsReference(v string) bool {
	return strings.HasPrefix(strings.TrimSpace(v), "arn:")
}

// redactSecretEnvValues masks the VALUE of every secret-shaped key in
// Environment.Variables IN PLACE. It runs AFTER the
// cb_describer_env_has_plaintext_secrets flag is computed — the flag reads
// only key names, so its semantics are untouched. This describer is the
// single choke point for both origins: CloudControl-listed functions and
// the native fallback's synthesised props (lister_lambda_native.go) flow
// through Enrich identically (runJob enriches fallback raws too). A
// non-string value under a secret-shaped key can't be shape-checked, so it
// is masked as well (fail closed).
func redactSecretEnvValues(m map[string]any) {
	env, ok := m["Environment"].(map[string]any)
	if !ok {
		return
	}
	raw, ok := env["Variables"].(map[string]any)
	if !ok {
		return
	}
	for k, v := range raw {
		if !keyLooksLikeSecret(k) {
			continue
		}
		if s, isStr := v.(string); isStr && secretValueIsReference(s) {
			continue
		}
		raw[k] = redactedEnvValue
	}
}
