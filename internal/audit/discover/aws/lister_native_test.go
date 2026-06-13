package aws

import (
	"context"
	"net/url"
	"testing"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
)

// --- fallback wiring (the headline P0 behaviour) -------------------------

// When the primary list path returns an empty set (CloudControl's silent
// eventual-consistency miss), the FallbackLister must fire AND its
// resources must flow through the normal describer enrichment — proving
// the resource reaches the component/grounding set the LLM sees.
func TestRunJob_FallbackFiresOnEmptyPrimary(t *testing.T) {
	inst := ec2types.Instance{
		InstanceId:      strp("i-0abc"),
		SubnetId:        strp("subnet-1"),
		PublicIpAddress: strp("203.0.113.5"),
		State:           &ec2types.InstanceState{Name: ec2types.InstanceStateName("running")},
		MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{HttpTokens: ec2types.HttpTokensState("optional")},
	}
	fallbackRaw, ok := instanceToRaw(inst, "eu-central-1")
	if !ok {
		t.Fatal("instanceToRaw returned !ok for a valid instance")
	}

	spec := cfnTypeSpec{
		Type: "AWS::EC2::Instance",
		// Primary path returns empty, exactly like CloudControl's
		// ListResources for a freshly-created instance.
		CustomLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			return nil, nil
		},
		FallbackLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			return []rawResource{fallbackRaw}, nil
		},
	}

	res := runJob(context.Background(), awsCfg{}, "eu-central-1", spec, nil)

	if len(res.resources) != 1 {
		t.Fatalf("expected 1 resource from the fallback, got %d", len(res.resources))
	}
	got := res.resources[0]
	if got.Type != "AWS::EC2::Instance" || got.ID != "i-0abc" {
		t.Fatalf("unexpected resource: type=%q id=%q", got.Type, got.ID)
	}
	// The real ec2InstanceDescriber must have run on the fallback resource:
	// IMDSv1 still allowed (HttpTokens=optional) and a public IP present.
	if v, _ := got.Inputs["cb_describer_imdsv2_required"].(bool); v {
		t.Errorf("cb_describer_imdsv2_required: got true, want false (HttpTokens=optional)")
	}
	if v, _ := got.Inputs["cb_describer_public_ip_present"].(bool); !v {
		t.Errorf("cb_describer_public_ip_present: got false, want true")
	}
}

// When the primary path returns something, the fallback must NOT fire —
// CloudControl's richer payload wins and there's no double-counting.
func TestRunJob_FallbackNotFiredWhenPrimaryReturns(t *testing.T) {
	primaryRaw := rawResource{
		CFNType:    "AWS::EC2::Instance",
		Identifier: "i-fromcc",
		Region:     "eu-central-1",
		Properties: `{"InstanceId":"i-fromcc","State":{"Name":"running"}}`,
	}

	fallbackCalled := false
	spec := cfnTypeSpec{
		Type: "AWS::EC2::Instance",
		CustomLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			return []rawResource{primaryRaw}, nil
		},
		FallbackLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			fallbackCalled = true
			return []rawResource{{CFNType: "AWS::EC2::Instance", Identifier: "i-shouldnotappear"}}, nil
		},
	}

	res := runJob(context.Background(), awsCfg{}, "eu-central-1", spec, nil)

	if fallbackCalled {
		t.Error("FallbackLister fired even though the primary returned a resource")
	}
	if len(res.resources) != 1 || res.resources[0].ID != "i-fromcc" {
		t.Fatalf("expected only the primary resource, got %+v", res.resources)
	}
}

// A fallback error is collected (so --diagnose surfaces it) but doesn't
// crash the job.
func TestRunJob_FallbackErrorIsCollected(t *testing.T) {
	spec := cfnTypeSpec{
		Type:         "AWS::EC2::Instance",
		CustomLister: func(context.Context, awsCfg, string) ([]rawResource, error) { return nil, nil },
		FallbackLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			return nil, &PermissionError{Service: "ec2", Action: "ec2:DescribeInstances", Region: "eu-central-1"}
		},
	}
	res := runJob(context.Background(), awsCfg{}, "eu-central-1", spec, nil)
	if len(res.permErrs) != 1 {
		t.Fatalf("expected 1 permission error collected, got %d", len(res.permErrs))
	}
	if len(res.resources) != 0 {
		t.Fatalf("expected no resources, got %d", len(res.resources))
	}
}

// --- CFN-shape round-trips through the real describers -------------------

// The State-shape trap: EC2 Instance State is nested ({"Name":...}). This
// test runs the full instanceToRaw → mapToDiscovered → ec2InstanceDescriber
// → crossReferenceNetwork chain and asserts the derived cb_describer_*
// values, which only come out right if the shape matches CloudControl's.
func TestInstanceToRaw_RoundTripThroughDescriber(t *testing.T) {
	inst := ec2types.Instance{
		InstanceId:         strp("i-0abc"),
		SubnetId:           strp("subnet-public"),
		PublicIpAddress:    strp("203.0.113.5"),
		State:              &ec2types.InstanceState{Name: ec2types.InstanceStateName("running")},
		MetadataOptions:    &ec2types.InstanceMetadataOptionsResponse{HttpTokens: ec2types.HttpTokensState("optional")},
		IamInstanceProfile: &ec2types.IamInstanceProfile{Arn: strp("arn:aws:iam::111122223333:instance-profile/web")},
	}
	raw, ok := instanceToRaw(inst, "eu-central-1")
	if !ok {
		t.Fatal("instanceToRaw !ok")
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	if err := (ec2InstanceDescriber{}).Enrich(context.Background(), awsCfg{}, &dr); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	if got := dr.Inputs["cb_describer_state"]; got != "running" {
		t.Errorf("cb_describer_state: got %v, want running (nested State.Name shape)", got)
	}
	if v, _ := dr.Inputs["cb_describer_imdsv2_required"].(bool); v {
		t.Errorf("cb_describer_imdsv2_required: got true, want false")
	}
	if v, _ := dr.Inputs["cb_describer_public_ip_present"].(bool); !v {
		t.Errorf("cb_describer_public_ip_present: got false, want true")
	}
	if got := dr.Inputs["cb_describer_instance_profile_arn"]; got != "arn:aws:iam::111122223333:instance-profile/web" {
		t.Errorf("cb_describer_instance_profile_arn: got %v", got)
	}

	// crossReferenceNetwork resolves SubnetId → a public subnet.
	subnet := DiscoveredResource{
		Type:   "AWS::EC2::Subnet",
		ID:     "subnet-public",
		Inputs: map[string]any{"SubnetId": "subnet-public", "MapPublicIpOnLaunch": true},
	}
	resources := []DiscoveredResource{dr, subnet}
	crossReferenceNetwork(resources)
	if v, _ := resources[0].Inputs["cb_describer_subnet_is_public"].(bool); !v {
		t.Errorf("cb_describer_subnet_is_public: got false, want true (SubnetId must be a flat string)")
	}
}

// EBS Volume State is a FLAT string (not nested) — the inverse of the
// instance trap. Assert the volume describer reads it correctly.
func TestVolumeToRaw_RoundTripThroughDescriber(t *testing.T) {
	vol := ec2types.Volume{
		VolumeId:  strp("vol-0abc"),
		Encrypted: boolp(false),
		State:     ec2types.VolumeState("available"),
		// No attachments → orphan volume.
	}
	raw, ok := volumeToRaw(vol, "eu-central-1")
	if !ok {
		t.Fatal("volumeToRaw !ok")
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	if err := (ebsVolumeDescriber{}).Enrich(context.Background(), awsCfg{}, &dr); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	if v, ok := dr.Inputs["cb_describer_encrypted"].(bool); !ok || v {
		t.Errorf("cb_describer_encrypted: got %v, want false", dr.Inputs["cb_describer_encrypted"])
	}
	if got := dr.Inputs["cb_describer_state"]; got != "available" {
		t.Errorf("cb_describer_state: got %v, want available (flat State string)", got)
	}
	if v, _ := dr.Inputs["cb_describer_is_attached"].(bool); v {
		t.Errorf("cb_describer_is_attached: got true, want false (orphan volume)")
	}
}

// RDS DBInstance: the public/unencrypted/backup-0 posture must survive the
// native shape, AND DBSubnetGroupName must drive cb_describer_effectively_public.
func TestRDSInstanceToRaw_RoundTripThroughDescriberAndCrossref(t *testing.T) {
	// The instance describer now runs a best-effort rds:DescribeDBInstances
	// role probe; inject a fake so this round-trip test stays network-free and
	// focused on CC-field reconstruction + crossref (probe behaviour is covered
	// in describer_rds_test.go).
	installFakeRDSClient(t, &fakeRDSReplicaClient{out: &rds.DescribeDBInstancesOutput{}})

	inst := rdstypes.DBInstance{
		DBInstanceIdentifier:  strp("cbx-db"),
		Engine:                strp("postgres"),
		PubliclyAccessible:    boolp(true),
		StorageEncrypted:      boolp(false),
		MultiAZ:               boolp(false),
		DeletionProtection:    boolp(false),
		BackupRetentionPeriod: int32p(0),
		DBSubnetGroup:         &rdstypes.DBSubnetGroup{DBSubnetGroupName: strp("db-grp")},
	}
	raw, ok := rdsInstanceToRaw(inst, "eu-central-1")
	if !ok {
		t.Fatal("rdsInstanceToRaw !ok")
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	if err := (rdsInstanceDescriber{}).Enrich(context.Background(), awsCfg{}, &dr); err != nil {
		t.Fatalf("Enrich: %v", err)
	}

	if v, _ := dr.Inputs["cb_describer_publicly_accessible"].(bool); !v {
		t.Errorf("cb_describer_publicly_accessible: want true")
	}
	if v, ok := dr.Inputs["cb_describer_storage_encrypted"].(bool); !ok || v {
		t.Errorf("cb_describer_storage_encrypted: want false")
	}
	if got, _ := dr.Inputs["cb_describer_backup_retention_days"].(float64); got != 0 {
		t.Errorf("cb_describer_backup_retention_days: got %v, want 0", dr.Inputs["cb_describer_backup_retention_days"])
	}
	if got := dr.Inputs["cb_describer_engine"]; got != "postgres" {
		t.Errorf("cb_describer_engine: got %v, want postgres", got)
	}

	// effectively_public requires the DB subnet group to resolve to a
	// routable subnet — proves DBSubnetGroupName was reconstructed.
	dbGroup := DiscoveredResource{
		Type:   "AWS::RDS::DBSubnetGroup",
		ID:     "db-grp",
		Inputs: map[string]any{"DBSubnetGroupName": "db-grp", "SubnetIds": []any{"subnet-pub"}},
	}
	subnet := DiscoveredResource{
		Type:   "AWS::EC2::Subnet",
		ID:     "subnet-pub",
		Inputs: map[string]any{"SubnetId": "subnet-pub", "MapPublicIpOnLaunch": true},
	}
	resources := []DiscoveredResource{dr, dbGroup, subnet}
	crossReferenceNetwork(resources)
	if v, _ := resources[0].Inputs["cb_describer_effectively_public"].(bool); !v {
		t.Errorf("cb_describer_effectively_public: want true")
	}
}

// --- ECS / EKS have no describer; assert the key posture fields land in
//     Inputs so the grounded LLM sees them. ----------------------------------

// The HTTP-only listener finding: an empty primary (CloudControl) list
// must trigger the Listener fallback, and a Protocol=HTTP listener must
// reach the job output via the real runJob path (no Listener describer, so
// the raw CFN field is what the LLM reads).
func TestRunJob_ListenerFallbackFiresWithHTTPProtocol(t *testing.T) {
	listener := elbv2types.Listener{
		ListenerArn:     strp("arn:aws:elasticloadbalancing:eu-central-1:111122223333:listener/app/web/abc/def"),
		LoadBalancerArn: strp("arn:aws:elasticloadbalancing:eu-central-1:111122223333:loadbalancer/app/web/abc"),
		Protocol:        elbv2types.ProtocolEnum("HTTP"),
		Port:            int32p(80),
		// No certificates → plaintext.
	}
	fallbackRaw, ok := listenerToRaw(listener, "eu-central-1")
	if !ok {
		t.Fatal("listenerToRaw !ok")
	}

	spec := cfnTypeSpec{
		Type: "AWS::ElasticLoadBalancingV2::Listener",
		CustomLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			return nil, nil // CloudControl returns nothing for the fresh ALB.
		},
		FallbackLister: func(context.Context, awsCfg, string) ([]rawResource, error) {
			return []rawResource{fallbackRaw}, nil
		},
	}

	res := runJob(context.Background(), awsCfg{}, "eu-central-1", spec, nil)
	if len(res.resources) != 1 {
		t.Fatalf("expected 1 listener from the fallback, got %d", len(res.resources))
	}
	got := res.resources[0]
	if got.Type != "AWS::ElasticLoadBalancingV2::Listener" {
		t.Fatalf("type: got %q", got.Type)
	}
	if proto := got.Inputs["Protocol"]; proto != "HTTP" {
		t.Errorf("Protocol: got %v, want HTTP", proto)
	}
	if v, _ := got.Inputs["cb_describer_has_tls_certificate"].(bool); v {
		t.Errorf("cb_describer_has_tls_certificate: got true, want false (plaintext HTTP)")
	}
}

func TestECSServiceToRaw_KeyFields(t *testing.T) {
	svc := ecstypes.Service{
		ServiceArn:  strp("arn:aws:ecs:eu-central-1:111122223333:service/cl/web"),
		ServiceName: strp("web"),
		ClusterArn:  strp("arn:aws:ecs:eu-central-1:111122223333:cluster/cl"),
		LaunchType:  ecstypes.LaunchType("FARGATE"),
		NetworkConfiguration: &ecstypes.NetworkConfiguration{
			AwsvpcConfiguration: &ecstypes.AwsVpcConfiguration{
				AssignPublicIp: ecstypes.AssignPublicIp("ENABLED"),
				Subnets:        []string{"subnet-1"},
			},
		},
	}
	raw, ok := ecsServiceToRaw(svc, "eu-central-1")
	if !ok {
		t.Fatal("ecsServiceToRaw !ok")
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	netCfg, _ := dr.Inputs["NetworkConfiguration"].(map[string]any)
	awsvpc, _ := netCfg["AwsvpcConfiguration"].(map[string]any)
	if got := awsvpc["AssignPublicIp"]; got != "ENABLED" {
		t.Errorf("AssignPublicIp: got %v, want ENABLED", got)
	}
}

func TestEKSClusterToRaw_KeyFields(t *testing.T) {
	cl := ekstypes.Cluster{
		Name:    strp("cbx-eks"),
		Arn:     strp("arn:aws:eks:eu-central-1:111122223333:cluster/cbx-eks"),
		Version: strp("1.29"),
		ResourcesVpcConfig: &ekstypes.VpcConfigResponse{
			EndpointPublicAccess:  true,
			EndpointPrivateAccess: false,
			PublicAccessCidrs:     []string{"0.0.0.0/0"},
		},
	}
	raw, ok := eksClusterToRaw(cl, "eu-central-1")
	if !ok {
		t.Fatal("eksClusterToRaw !ok")
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	vpc, _ := dr.Inputs["ResourcesVpcConfig"].(map[string]any)
	if v, _ := vpc["EndpointPublicAccess"].(bool); !v {
		t.Errorf("ResourcesVpcConfig.EndpointPublicAccess: want true")
	}
	if v, _ := dr.Inputs["EncryptionConfigPresent"].(bool); v {
		t.Errorf("EncryptionConfigPresent: want false (no encryption config set)")
	}
}

// IAM ManagedPolicy fallback: the ListPolicies(Scope=Local) + GetPolicyVersion
// path must produce a PolicyDocument in the CloudControl-compatible
// (URL-encoded) shape so iamManagedPolicyDescriber decodes it and flags the
// multi-service wildcard — the exact variant-02 planted miss.
func TestIAMPolicyToRaw_RoundTripThroughDescriber(t *testing.T) {
	// url.QueryEscape of {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	urlEncoded := url.QueryEscape(doc)

	p := iamtypes.Policy{
		Arn:              strp("arn:aws:iam::111122223333:policy/cbx-custom-overbroad"),
		PolicyName:       strp("cbx-custom-overbroad"),
		DefaultVersionId: strp("v1"),
	}
	raw, ok := iamPolicyToRaw(p, urlEncoded, "")
	if !ok {
		t.Fatal("iamPolicyToRaw !ok")
	}
	if raw.CFNType != "AWS::IAM::ManagedPolicy" || raw.Identifier != *p.Arn {
		t.Fatalf("unexpected raw: type=%q id=%q", raw.CFNType, raw.Identifier)
	}
	dr, err := raw.mapToDiscovered()
	if err != nil {
		t.Fatalf("mapToDiscovered: %v", err)
	}
	if err := (iamManagedPolicyDescriber{}).Enrich(context.Background(), awsCfg{}, &dr); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if v, _ := dr.Inputs["cb_describer_policy_has_wildcard_allow"].(bool); !v {
		t.Errorf("cb_describer_policy_has_wildcard_allow: want true (Action:* Resource:*)")
	}
}

// Guard the P0.4 diagnosis: keepCustomerIAMPolicy must KEEP a customer ARN
// (so the miss is CloudControl incompleteness, not over-filtering) and DROP
// the AWS-managed alias.
func TestKeepCustomerIAMPolicy_DiagnosisGuard(t *testing.T) {
	if !keepCustomerIAMPolicy("arn:aws:iam::111122223333:policy/cbx-custom-overbroad") {
		t.Error("customer-managed policy must be kept — filter is not the P0.4 bug")
	}
	if keepCustomerIAMPolicy("arn:aws:iam::aws:policy/AdministratorAccess") {
		t.Error("AWS-managed policy must be dropped")
	}
}

// --- tiny pointer helpers (test-local) ----------------------------------

func strp(s string) *string { return &s }
func boolp(b bool) *bool    { return &b }
func int32p(i int32) *int32 { return &i }
