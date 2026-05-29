// Package aws implements live-AWS resource discovery for `cbx audit aws`.
// It owns the IAM preflight, region resolution, CloudControl-based
// discovery, and the curated per-service describers. Discovery returns
// a []DiscoveredResource shaped identically to the existing state and
// source parsers so all downstream FindingProviders work unchanged.
//
// This package is offline-by-default for everything but the actual AWS
// API calls — no CloudBooster backend calls happen here. CB-knowledge
// grounding is layered on top via the existing Phase F analyzer.
package aws

import (
	"fmt"
	"strings"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/parsers"
)

// DiscoveredResource is the cross-mode resource shape every audit
// FindingProvider consumes. Aliased from internal/audit/parsers so the
// discovery package can return it without dragging the higher-level
// audit package back in via an import cycle. The aliasing means a
// resource discovered by the live-AWS path is interchangeable with one
// parsed from Pulumi/Terraform state by downstream code.
type DiscoveredResource = parsers.DiscoveredResource

// Identity is the result of an STS GetCallerIdentity probe. Surfaced in
// the audit report header so the user can see which AWS account + ARN
// the run actually used. AccountAlias is the best-effort friendly name
// from iam:ListAccountAliases — empty when no alias is configured, when
// the role lacks the permission, or when the call otherwise fails (we
// don't want a missing alias to be a hard error since it's purely
// cosmetic).
type Identity struct {
	AccountID    string
	AccountAlias string
	ARN          string
	UserID       string
}

// String renders an Identity for the report header.
func (i Identity) String() string {
	if i.AccountAlias != "" {
		return fmt.Sprintf("account=%s (%s) arn=%s", i.AccountID, i.AccountAlias, i.ARN)
	}
	return fmt.Sprintf("account=%s arn=%s", i.AccountID, i.ARN)
}

// PermissionError wraps an AWS API call failure attributable to missing
// IAM permissions. The discovery layer wraps every AccessDenied / similar
// error in this type so the --diagnose renderer can produce a useful IAM
// policy patch instead of dumping raw error text.
type PermissionError struct {
	Service string // AWS service short name, e.g. "s3" / "iam"
	Action  string // IAM action that was denied, e.g. "s3:ListAllMyBuckets"
	Region  string // region the call was made in, "" for global services
	Cause   error  // underlying smithy / aws-sdk error
}

func (e *PermissionError) Error() string {
	if e.Region != "" {
		return fmt.Sprintf("%s denied in %s: %v", e.Action, e.Region, e.Cause)
	}
	return fmt.Sprintf("%s denied: %v", e.Action, e.Cause)
}

func (e *PermissionError) Unwrap() error { return e.Cause }

// IsPermissionError returns true if err (or any error in its chain) is a
// *PermissionError. Used by --diagnose to filter the error stream.
func IsPermissionError(err error) bool {
	var pe *PermissionError
	return errorsAs(err, &pe)
}

// errorsAs is a one-line wrapper around errors.As that avoids dragging
// the import into the public API surface of this package. The aws subpackage
// is small enough that callers shouldn't need to do their own type-assertion.
func errorsAs(err error, target any) bool {
	return aerrAs(err, target)
}

// regionsLiteralAll is the user-facing sentinel for "audit every enabled
// region in the account." Recognised by ResolveRegions.
const regionsLiteralAll = "all"

// IsAllRegionsLiteral reports whether the input list is the single-element
// "all" sentinel. Exposed so the CLI can render a friendlier confirmation
// before kicking off the enumeration.
func IsAllRegionsLiteral(regions []string) bool {
	return len(regions) == 1 && strings.EqualFold(regions[0], regionsLiteralAll)
}
