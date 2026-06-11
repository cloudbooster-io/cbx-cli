package aws

import (
	"context"
)

// ecsClusterDescriber normalizes the CloudWatch Container Insights posture
// of an AWS::ECS::Cluster into a single boolean the grounded prompt keys
// off. CloudControl already returns the cluster's ClusterSettings array
// (a list of {Name, Value} pairs) in the resource Properties, so no extra
// SDK call is needed — the describer reads it from r.Inputs, mirroring the
// RDS describer's "read CC Properties, re-publish under cb_describer_*"
// shape rather than the apigw describer's API-call shape.
//
// FP-safety follows the normalizer contract ("populate when known, skip
// when not"). cb_describer_container_insights_enabled is set ONLY when
// ClusterSettings carries an explicit containerInsights entry:
//
//	value "enabled" / "enhanced" -> true
//	value "disabled"             -> false
//
// When the entry is ABSENT the key is left UNSET — an absent cluster-level
// setting does not prove Container Insights is off, because an account-level
// default (`ecs put-account-setting --name containerInsights --value enabled`)
// can enable it without a cluster override. Firing the rule only on an
// EXPLICIT cluster-level "disabled" keeps it false-positive-free: an explicit
// cluster-level disable overrides any account default, so the effective state
// really is off — an unambiguous gap.
type ecsClusterDescriber struct{}

func (ecsClusterDescriber) CFNType() string { return "AWS::ECS::Cluster" }

func (ecsClusterDescriber) Enrich(_ context.Context, _ awsCfg, r *DiscoveredResource) error {
	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}
	applyContainerInsights(r.Inputs, readClusterSettings(r.Inputs))
	return nil
}

// clusterSetting is the SDK-free view of one ClusterSettings entry, so the
// decision logic stays a pure function the unit tests exercise without a
// CloudControl payload.
type clusterSetting struct {
	name  string
	value string
}

// readClusterSettings lifts the ClusterSettings array out of CloudControl's
// JSON-unmarshalled Properties into the SDK-free view. Tolerant of the shape
// the decoder hands us ([]any of map[string]any) and of missing / malformed
// entries — anything it can't read is simply skipped, never guessed.
func readClusterSettings(inputs map[string]any) []clusterSetting {
	raw, ok := inputs["ClusterSettings"].([]any)
	if !ok {
		return nil
	}
	out := make([]clusterSetting, 0, len(raw))
	for _, e := range raw {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["Name"].(string)
		value, _ := m["Value"].(string)
		out = append(out, clusterSetting{name: name, value: value})
	}
	return out
}

// applyContainerInsights folds the cluster settings into the single
// cb_describer_container_insights_enabled boolean. See the type comment for
// the FP-safety contract: the key is set ONLY for an explicit containerInsights
// entry with a recognised value, and left unset otherwise.
func applyContainerInsights(inputs map[string]any, settings []clusterSetting) {
	for _, s := range settings {
		if s.name != "containerInsights" {
			continue
		}
		switch s.value {
		case "enabled", "enhanced":
			inputs["cb_describer_container_insights_enabled"] = true
		case "disabled":
			inputs["cb_describer_container_insights_enabled"] = false
		}
		return
	}
}

// ecsTaskDefinitionDescriber closes the CloudControl-origin redaction gap
// for AWS::ECS::TaskDefinition. The native fallback lister masks
// secret-shaped container env-var VALUES at synthesis time
// (containerDefinitionsToCFN, lister_ecs_native.go), but when CloudControl
// itself lists a task definition its ContainerDefinitions arrive verbatim
// in Properties — and the full Inputs map is later inlined into the
// grounded `claude -p` prompt, so an unmasked value would ship to a
// third-party LLM. This describer is the choke point for that origin: a
// pure in-place Inputs transform, no SDK call. Both origins flow through
// Enrich (runJob enriches fallback raws too); re-masking an
// already-redacted value is a no-op, so the double pass is harmless.
//
// Redaction policy is identical to the Lambda describer and the native ECS
// path: mask the Value of an Environment entry whose Name matches
// keyLooksLikeSecret, unless the value is an arn:-prefixed reference — the
// Secrets-Manager/SSM indirection shape the grounded plaintext-env rule's
// suppress path keys off (see secretValueIsReference). Fail OPEN on
// structure — unexpected shapes are left untouched and never error — and
// CLOSED on secrets: a non-string Value under a secret-shaped Name can't
// be shape-checked, so it is masked.
type ecsTaskDefinitionDescriber struct{}

func (ecsTaskDefinitionDescriber) CFNType() string { return "AWS::ECS::TaskDefinition" }

func (ecsTaskDefinitionDescriber) Enrich(_ context.Context, _ awsCfg, r *DiscoveredResource) error {
	// A nil Inputs map reads safely — nothing to redact, and this
	// describer adds no keys of its own.
	redactTaskDefEnvValues(r.Inputs)
	return nil
}

// redactTaskDefEnvValues walks the CFN-shaped ContainerDefinitions array
// — a []any of container maps, each carrying Environment as a []any of
// {"Name", "Value"} maps — and masks secret-shaped values IN PLACE.
// Tolerant of the shapes the JSON decoder hands us: anything it can't
// read is skipped, never guessed (and a value it can't shape-check under
// a secret-shaped name is masked — see the type comment).
func redactTaskDefEnvValues(inputs map[string]any) {
	defs, ok := inputs["ContainerDefinitions"].([]any)
	if !ok {
		return
	}
	for _, d := range defs {
		cd, ok := d.(map[string]any)
		if !ok {
			continue
		}
		env, ok := cd["Environment"].([]any)
		if !ok {
			continue
		}
		for _, e := range env {
			kv, ok := e.(map[string]any)
			if !ok {
				continue
			}
			name, ok := kv["Name"].(string)
			if !ok || !keyLooksLikeSecret(name) {
				continue
			}
			v, present := kv["Value"]
			if !present {
				continue
			}
			if s, isStr := v.(string); isStr && secretValueIsReference(s) {
				continue
			}
			kv["Value"] = redactedEnvValue
		}
	}
}
