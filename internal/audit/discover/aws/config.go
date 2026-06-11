package aws

import sdkaws "github.com/aws/aws-sdk-go-v2/aws"

// awsCfg wraps an aws.Config so the rest of this package can pass it
// around without importing the SDK's aws-package symbol everywhere
// (which collides ergonomically with our own package name).
type awsCfg struct {
	cfg sdkaws.Config
}

// withRegion returns a clone of awsCfg pinned to the given region. Used
// to fan out per-region clients during discovery.
func (c awsCfg) withRegion(region string) awsCfg {
	cp := c.cfg.Copy()
	cp.Region = region
	return awsCfg{cfg: cp}
}

// region reports the currently configured region, or "" if none.
func (c awsCfg) region() string {
	return c.cfg.Region
}
