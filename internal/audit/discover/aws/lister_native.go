package aws

import (
	"errors"
	"fmt"

	"github.com/aws/smithy-go"
)

// The native-Describe fallback listers in this package (lister_*_native.go)
// exist because CloudControl's ListResources is eventually consistent: it
// returns an empty set — not an error — for freshly-created workload
// resources (EC2 instances, EBS volumes, RDS, ALB, ECS services, EKS
// clusters). An audit run right after `terraform apply` therefore silently
// drops the very resources it most wants to inspect, with permission_errors
// staying 0. Each fallback calls the service's strongly-consistent native
// Describe API and synthesises the same CFN-shape rawResource records, so
// the resource flows through mapToDiscovered + the existing describers
// unchanged. They are wired via cfnTypeSpec.FallbackLister and fire only
// when the primary (CloudControl) path returned nothing.

// classifyAWSError wraps AccessDenied / UnauthorizedOperation failures from
// the native Describe APIs as *PermissionError so the --diagnose summary
// collects them uniformly with the CloudControl path. Other errors pass
// through annotated with the service action and region.
func classifyAWSError(err error, service, action, region string) error {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation":
			return &PermissionError{
				Service: service,
				Action:  action,
				Region:  region,
				Cause:   err,
			}
		}
	}
	return fmt.Errorf("%s [%s]: %w", action, region, err)
}
