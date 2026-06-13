package aws

import (
	"context"
	"errors"
	"testing"
)

func TestDescriberFor(t *testing.T) {
	registered := []string{
		"AWS::S3::Bucket",
		"AWS::IAM::Role",
		"AWS::IAM::Group",
		"AWS::RDS::DBInstance",
		"AWS::RDS::DBCluster",
		"AWS::Lambda::Function",
		"AWS::EC2::Instance",
		"AWS::ECR::Repository",
		"AWS::Backup::BackupVault",
		"AWS::Backup::BackupPlan",
		"AWS::ElasticLoadBalancingV2::LoadBalancer",
		"AWS::EKS::Cluster",
	}
	for _, cfnType := range registered {
		if d := describerFor(cfnType); d == nil {
			t.Errorf("expected a describer for %q", cfnType)
		}
	}
	if d := describerFor("AWS::Foo::Bar"); d != nil {
		t.Error("expected no describer for an unregistered fake type")
	}
}

// fakeDescriber lets the registry plumbing be tested without booting the
// SDK. Used by TestEnrich_RegistrySwap which swaps allDescribers for the
// duration of a single test, then restores.
type fakeDescriber struct {
	cfnType string
	called  bool
	err     error
	mutate  func(r *DiscoveredResource)
}

func (f *fakeDescriber) CFNType() string { return f.cfnType }
func (f *fakeDescriber) Enrich(ctx context.Context, c awsCfg, r *DiscoveredResource) error {
	f.called = true
	if f.mutate != nil {
		f.mutate(r)
	}
	return f.err
}

func TestEnrich_RegistrySwap(t *testing.T) {
	saved := allDescribers
	defer func() { allDescribers = saved }()

	fake := &fakeDescriber{
		cfnType: "AWS::Test::Fake",
		mutate: func(r *DiscoveredResource) {
			if r.Inputs == nil {
				r.Inputs = map[string]any{}
			}
			r.Inputs["fake_enriched"] = true
		},
	}
	allDescribers = []Describer{fake}

	d := describerFor("AWS::Test::Fake")
	if d == nil {
		t.Fatal("registry swap failed")
	}
	r := DiscoveredResource{Type: "AWS::Test::Fake", ID: "thing"}
	if err := d.Enrich(context.Background(), awsCfg{}, &r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fake.called {
		t.Error("enrich not invoked")
	}
	if v, _ := r.Inputs["fake_enriched"].(bool); !v {
		t.Error("enrich did not mutate the resource")
	}
}

func TestEnrich_ErrorPropagates(t *testing.T) {
	saved := allDescribers
	defer func() { allDescribers = saved }()

	wantErr := errors.New("boom")
	fake := &fakeDescriber{cfnType: "AWS::Test::Fake", err: wantErr}
	allDescribers = []Describer{fake}

	d := describerFor("AWS::Test::Fake")
	r := DiscoveredResource{Type: "AWS::Test::Fake", ID: "thing"}
	gotErr := d.Enrich(context.Background(), awsCfg{}, &r)
	if !errors.Is(gotErr, wantErr) {
		t.Errorf("got %v, want %v in error chain", gotErr, wantErr)
	}
}
