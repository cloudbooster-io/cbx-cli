package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/aws/smithy-go"
)

// listAndGet enumerates every resource of the given CFN type in the given
// region and returns one rawResource per item. Returns (nil, nil) when
// the type isn't in the CFN registry (UnsupportedActionException) so the
// caller can skip silently. Other errors propagate.
//
// The spec.KeepIdentifier hook, when set, filters identifiers between
// the list pagination and the GetResource fan-out — critical for types
// like AWS::IAM::ManagedPolicy where CloudControl returns ~1,400
// AWS-managed entries that we never want to audit.
func listAndGet(ctx context.Context, c awsCfg, region string, spec cfnTypeSpec) ([]rawResource, error) {
	cfnType := spec.Type
	regionalCfg := c.withRegion(region)
	client := cloudcontrol.NewFromConfig(regionalCfg.cfg)

	var identifiers []string
	var nextToken *string
	for {
		out, err := client.ListResources(ctx, &cloudcontrol.ListResourcesInput{
			TypeName:  &cfnType,
			NextToken: nextToken,
		})
		if err != nil {
			if isUnsupportedType(err) {
				// CFN registry doesn't know this type in this region.
				// Treat as "no resources of this type" so the per-type
				// loop continues with the next type.
				return nil, nil
			}
			return nil, classifyCloudControlError(err, cfnType, region, "cloudformation:ListResources")
		}
		for _, d := range out.ResourceDescriptions {
			if d.Identifier == nil {
				continue
			}
			if spec.KeepIdentifier != nil && !spec.KeepIdentifier(*d.Identifier) {
				continue
			}
			identifiers = append(identifiers, *d.Identifier)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}

	if len(identifiers) == 0 {
		return nil, nil
	}

	// Fetch each resource's full state. CloudControl has no batch read;
	// we serialise per-type. Concurrency across types is handled at the
	// caller level via the worker pool in discover.go.
	results := make([]rawResource, 0, len(identifiers))
	for _, id := range identifiers {
		out, err := client.GetResource(ctx, &cloudcontrol.GetResourceInput{
			TypeName:   &cfnType,
			Identifier: &id,
		})
		if err != nil {
			// One resource failing shouldn't kill the whole type. Wrap
			// in PermissionError if it looks like access denied; bubble
			// other errors up so the caller can collect them.
			return results, classifyCloudControlError(err, cfnType, region, "cloudformation:GetResource")
		}
		if out.ResourceDescription == nil {
			continue
		}
		props := ""
		if out.ResourceDescription.Properties != nil {
			props = *out.ResourceDescription.Properties
		}
		results = append(results, rawResource{
			CFNType:    cfnType,
			Identifier: id,
			Region:     region,
			Properties: props,
		})
	}
	return results, nil
}

// rawResource is the internal shape we collect before mapping onto the
// shared audit.DiscoveredResource. Keeps the SDK type out of the mapper
// layer for testability.
type rawResource struct {
	CFNType    string // e.g. "AWS::S3::Bucket"
	Identifier string // CloudControl primary identifier (often the resource name)
	Region     string // discovered-in region
	Properties string // JSON-encoded resource properties (CFN-shape)
}

// isUnsupportedType returns true when the error indicates the CFN type
// isn't in the registry for this region — treated as "skip silently"
// rather than as a real failure.
func isUnsupportedType(err error) bool {
	var ae smithy.APIError
	if !errors.As(err, &ae) {
		return false
	}
	switch ae.ErrorCode() {
	case "UnsupportedActionException", "TypeNotFoundException":
		return true
	}
	// Newer AWS regions return this for types not yet rolled out.
	return strings.Contains(strings.ToLower(ae.ErrorMessage()), "is not currently supported")
}

// classifyCloudControlError wraps AccessDenied / UnauthorizedOperation
// failures as *PermissionError so the --diagnose path can collect them
// uniformly. Other errors pass through as-is.
func classifyCloudControlError(err error, cfnType, region, action string) error {
	var ae smithy.APIError
	if !errors.As(err, &ae) {
		return fmt.Errorf("%s [%s in %s]: %w", action, cfnType, region, err)
	}
	switch ae.ErrorCode() {
	case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation":
		return &PermissionError{
			Service: "cloudformation",
			Action:  action,
			Region:  region,
			Cause:   fmt.Errorf("listing %s: %w", cfnType, err),
		}
	}
	return fmt.Errorf("%s [%s in %s]: %w", action, cfnType, region, err)
}

// mapToDiscovered converts a rawResource into the shared
// audit.DiscoveredResource shape. CFN type name lands in Type, the
// CloudControl identifier in ID, and the entire CFN-shape properties
// JSON into Inputs. Tags are extracted with extractTags() which
// handles both shapes CFN uses (list-of-pairs vs map).
func (r rawResource) mapToDiscovered() (DiscoveredResource, error) {
	var props map[string]any
	if r.Properties != "" {
		if err := json.Unmarshal([]byte(r.Properties), &props); err != nil {
			return DiscoveredResource{}, fmt.Errorf("decoding %s/%s properties: %w", r.CFNType, r.Identifier, err)
		}
	}
	return DiscoveredResource{
		Type:   r.CFNType,
		URN:    cfnURN(r.CFNType, r.Identifier, r.Region),
		ID:     r.Identifier,
		Region: r.Region,
		Tags:   extractTags(props),
		Inputs: props,
	}, nil
}

// cfnURN builds a synthetic URN of the form "aws://<region>/<cfn-type>/<id>"
// — it isn't a real ARN (CloudControl returns the primary identifier, not
// the ARN, for many types), but it's unique within a single audit run and
// human-readable. Future per-service describers can replace it with the
// real ARN when known.
func cfnURN(cfnType, id, region string) string {
	if region == "" {
		region = "global"
	}
	return fmt.Sprintf("aws://%s/%s/%s", region, cfnType, id)
}

// extractTags pulls tags out of a CFN properties map. CFN uses two
// shapes depending on the resource: a list of {Key, Value} objects
// (most services) or a flat map (S3-bucket-style). Both are supported.
// Returns nil when no Tags field is present.
func extractTags(props map[string]any) map[string]string {
	if props == nil {
		return nil
	}
	raw, ok := props["Tags"]
	if !ok {
		return nil
	}
	out := map[string]string{}
	switch v := raw.(type) {
	case []any:
		for _, item := range v {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			key, _ := m["Key"].(string)
			val, _ := m["Value"].(string)
			if key != "" {
				out[key] = val
			}
		}
	case map[string]any:
		for k, val := range v {
			if s, ok := val.(string); ok {
				out[k] = s
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// dedupeByURN collapses entries with the same synthetic URN — happens
// when global services (IAM/CloudFront/Route53) are listed from multiple
// regions during fan-out. First occurrence wins.
func dedupeByURN(in []DiscoveredResource) []DiscoveredResource {
	seen := make(map[string]struct{}, len(in))
	out := make([]DiscoveredResource, 0, len(in))
	for _, r := range in {
		if _, dup := seen[r.URN]; dup {
			continue
		}
		seen[r.URN] = struct{}{}
		out = append(out, r)
	}
	return out
}
