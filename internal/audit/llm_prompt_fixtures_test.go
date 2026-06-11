package audit

import (
	"fmt"
	"strings"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/knowledge"
)

// groundedPromptFixture is one input combination for the grounded
// prompt builder. The matrix below exercises every section of the
// assembled prompt: the rulepack-rendered policy blocks are constant,
// while the compiled-in serializers (account posture, knowledge
// bundle, resource table incl. truncation, source files) vary.
//
// Shared between the P0 dual-builder byte-identity test (refactor
// commit) and the prompt golden test that replaces it — keep the
// fixtures deterministic: no time, no randomness, fixed ordering.
type groundedPromptFixture struct {
	name      string
	files     []SourceFile
	resources []DiscoveredResource
	bundle    *GroundingBundle
	posture   *AccountPosture
}

func groundedPromptFixtures() []groundedPromptFixture {
	return []groundedPromptFixture{
		{name: "all-nil"},
		{name: "empty-bundle", bundle: &GroundingBundle{}},
		{name: "populated-bundle", bundle: fixtureBundle()},
		{name: "posture-full", posture: fixturePostureFull()},
		{name: "posture-probe-errors", posture: fixturePostureProbeErrors()},
		{name: "resources-describer-fields", resources: fixtureDescriberResources(), bundle: &GroundingBundle{}},
		{name: "resources-count-truncation", resources: fixtureManyResources(defaultLLMMaxPromptResources + 10)},
		{name: "resources-byte-truncation", resources: fixtureOversizedResources()},
		{name: "source-files", files: fixtureSourceFiles(), resources: fixtureDescriberResources()[:1]},
		{
			name:      "kitchen-sink",
			files:     fixtureSourceFiles(),
			resources: fixtureDescriberResources(),
			bundle:    fixtureBundle(),
			posture:   fixturePostureFull(),
		},
	}
}

func fixtureBundle() *GroundingBundle {
	return &GroundingBundle{
		Primitives: []PrimitiveKnowledge{
			{
				TypeID: "aws:s3/bucket@v1",
				Data: &knowledge.Response{
					KBVersion: 7,
					Chunks: []knowledge.Chunk{
						// Deliberately out of order + whitespace-padded:
						// writeChunks re-sorts by (DocPath, ChunkIndex) and
						// TrimSpaces the body.
						{DocPath: "aws/s3/bucket.md", Heading: "Encryption", ChunkText: "  SSE-S3 is acceptable for standard workloads.\n", ChunkIndex: 2},
						{DocPath: "aws/s3/bucket.md", Heading: "Posture", ChunkText: "Block Public Access should stay enabled.", ChunkIndex: 1},
					},
				},
			},
			{TypeID: "aws:vpc/network@v1", Missing: true},
		},
		Practices: []WorkloadKnowledge{
			{
				Workload: "serverless-api",
				Data: &knowledge.Response{
					KBVersion: 7,
					Chunks: []knowledge.Chunk{
						{DocPath: "aws/patterns/serverless.md", ChunkText: "Prefer per-function least-privilege roles.", ChunkIndex: 0},
					},
				},
			},
			{Workload: "static-site", Missing: true},
		},
		Composition: &CompositionKnowledge{
			TypeIDs: []string{"aws:s3/bucket@v1", "aws:vpc/network@v1"},
			Data: &knowledge.Response{
				KBVersion: 7,
				Chunks: []knowledge.Chunk{
					{DocPath: "aws/global/composition.md", Heading: "S3 + VPC", ChunkText: "Use gateway endpoints for in-VPC S3 traffic.", ChunkIndex: 0},
				},
			},
		},
		Misses: []GroundingMiss{
			{Kind: "primitive", Key: "aws:kms/key@v1", Err: "GET /v1/knowledge/aws/primitives/aws:kms/key@v1: 503 after retries"},
		},
	}
}

func fixturePostureFull() *AccountPosture {
	no := false
	return &AccountPosture{
		EBSEncryptionByDefault: map[string]bool{"eu-central-1": true, "us-east-1": false},
		IAMSummary: map[string]int32{
			"AccountAccessKeysPresent": 1,
			"AccountMFAEnabled":        0,
			"Users":                    7,
		},
		PasswordPolicyPresent: &no,
		TrailCoverageByRegion: map[string]bool{"eu-central-1": true, "us-east-1": false},
		GuardDutyByRegion:     map[string]string{"eu-central-1": "enabled", "eu-west-1": "disabled", "us-east-1": "absent"},
		ConfigRecorderByRegion: map[string]ConfigRecorderState{
			"eu-central-1": {Present: true, RecordsGlobalTypes: false},
			"us-east-1":    {Present: false, RecordsGlobalTypes: false},
		},
		GlueCatalogPolicyByRegion: map[string]*GlueCatalogPolicy{
			"eu-central-1": {GrantsWildcardPrincipal: true, Document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"glue:*"}]}`},
		},
		CredentialReport: &CredentialReportPosture{
			ConsolePasswordUsersEvaluated: 5,
			ConsoleUsersWithoutMFA:        []string{"alice", "bob"},
		},
	}
}

func fixturePostureProbeErrors() *AccountPosture {
	return &AccountPosture{
		EBSEncryptionByDefault: map[string]bool{"eu-central-1": true},
		TrailCoverageByRegion:  map[string]bool{"eu-central-1": true},
		Errors: []string{
			"iam:GetAccountSummary: AccessDenied",
			"iam:GetCredentialReport: ReportNotPresent",
			"guardduty:ListDetectors (us-east-1): timeout",
		},
	}
}

// fixtureDescriberResources exercises cb_describer_* enrichment fields,
// raw CFN properties, nested maps/arrays, and an Inputs-less resource —
// the shapes serialiseInputs / writeResourceTable must keep stable.
func fixtureDescriberResources() []DiscoveredResource {
	return []DiscoveredResource{
		{
			Type:   "AWS::S3::Bucket",
			URN:    "aws://eu-central-1/AWS::S3::Bucket/cbx-data-archive",
			ID:     "cbx-data-archive",
			Region: "eu-central-1",
			Inputs: map[string]any{
				"BucketName": "cbx-data-archive",
				"cb_describer_public_access_block": map[string]any{
					"block_public_acls": false, "block_public_policy": true,
					"ignore_public_acls": false, "restrict_public_buckets": true,
				},
				"cb_describer_versioning_enabled":     false,
				"cb_describer_sse_is_kms":             false,
				"cb_describer_bucket_policy_present":  false,
				"cb_describer_lifecycle_present":      false,
				"cb_describer_access_logging_enabled": false,
				"Tags":                                []any{map[string]any{"Key": "intent", "Value": "archive"}},
			},
		},
		{
			Type:   "AWS::RDS::DBInstance",
			URN:    "aws://eu-central-1/AWS::RDS::DBInstance/prod-web-db",
			ID:     "prod-web-db",
			Region: "eu-central-1",
			Inputs: map[string]any{
				"DBInstanceIdentifier":               "prod-web-db",
				"AutoMinorVersionUpgrade":            false,
				"PubliclyAccessible":                 true,
				"cb_describer_backup_retention_days": 1,
				"cb_describer_deletion_protection":   false,
				"cb_describer_multi_az":              false,
				"cb_describer_is_read_replica":       false,
				"cb_describer_is_cluster_member":     false,
				"cb_describer_storage_encrypted":     false,
				"cb_describer_effectively_public":    false,
			},
		},
		{
			Type:   "AWS::EC2::Instance",
			URN:    "aws://eu-central-1/AWS::EC2::Instance/i-0123456789abcdef0",
			ID:     "i-0123456789abcdef0",
			Region: "eu-central-1",
			Inputs: map[string]any{
				"MetadataOptions":                   map[string]any{"HttpTokens": "optional", "HttpPutResponseHopLimit": 2},
				"cb_describer_instance_profile_arn": "",
				"cb_describer_state":                "running",
				"cb_describer_subnet_is_public":     true,
				"cb_describer_public_ip_present":    true,
			},
		},
		{
			Type:   "AWS::EKS::Cluster",
			URN:    "aws://eu-central-1/AWS::EKS::Cluster/cbx-workloads",
			ID:     "cbx-workloads",
			Region: "eu-central-1",
			Inputs: map[string]any{
				"Name":                    "cbx-workloads",
				"EncryptionConfigPresent": false,
				"cb_describer_eks_irsa_oidc_provider_present": false,
				"cb_describer_eks_pod_identity_present":       false,
			},
		},
		{
			Type:   "AWS::KMS::Key",
			URN:    "aws://eu-central-1/AWS::KMS::Key/1234abcd-12ab-34cd-56ef-1234567890ab",
			ID:     "1234abcd-12ab-34cd-56ef-1234567890ab",
			Region: "eu-central-1",
			Inputs: map[string]any{
				"KeyPolicy": map[string]any{
					"Version": "2012-10-17",
					"Statement": []any{
						map[string]any{"Effect": "Allow", "Principal": map[string]any{"AWS": "*"}, "Action": "kms:*", "Resource": "*"},
					},
				},
				"cb_describer_key_manager":          "CUSTOMER",
				"cb_describer_key_rotation_enabled": false,
				"cb_describer_key_spec":             "SYMMETRIC_DEFAULT",
				"cb_describer_key_usage":            "ENCRYPT_DECRYPT",
				"cb_describer_is_unused":            true,
			},
		},
		{
			Type:   "AWS::EC2::SecurityGroup",
			URN:    "aws://eu-central-1/AWS::EC2::SecurityGroup/sg-0aa11bb22cc33dd44",
			ID:     "sg-0aa11bb22cc33dd44",
			Region: "eu-central-1",
			Inputs: map[string]any{
				"GroupName": "web-admin",
				"cb_describer_ingress_exposed_admin_ports": []any{22, 3389},
			},
		},
		{
			// No Inputs at all — header-line-only rendering path.
			Type:   "AWS::SQS::Queue",
			URN:    "aws://eu-central-1/AWS::SQS::Queue/cbx-jobs",
			ID:     "cbx-jobs",
			Region: "eu-central-1",
		},
	}
}

// fixtureManyResources returns n tiny resources — enough to trip the
// defaultLLMMaxPromptResources count cap deterministically.
func fixtureManyResources(n int) []DiscoveredResource {
	out := make([]DiscoveredResource, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, DiscoveredResource{
			Type:   "AWS::SQS::Queue",
			URN:    fmt.Sprintf("aws://eu-central-1/AWS::SQS::Queue/q-%04d", i),
			ID:     fmt.Sprintf("q-%04d", i),
			Region: "eu-central-1",
			Inputs: map[string]any{"QueueName": fmt.Sprintf("q-%04d", i)},
		})
	}
	return out
}

// fixtureOversizedResources trips the byte cap: the second resource's
// serialised Inputs pushes the running total past
// defaultLLMMaxResourceTableBytes, so the sorted tail is dropped.
func fixtureOversizedResources() []DiscoveredResource {
	big := strings.Repeat("x", defaultLLMMaxResourceTableBytes/2)
	out := make([]DiscoveredResource, 0, 3)
	for i := 0; i < 3; i++ {
		out = append(out, DiscoveredResource{
			Type:   "AWS::SSM::Parameter",
			URN:    fmt.Sprintf("aws://eu-central-1/AWS::SSM::Parameter/p-%d", i),
			ID:     fmt.Sprintf("p-%d", i),
			Region: "eu-central-1",
			Inputs: map[string]any{"Value": big},
		})
	}
	return out
}

func fixtureSourceFiles() []SourceFile {
	return []SourceFile{
		{Path: "main.tf", Content: []byte("resource \"aws_s3_bucket\" \"data\" {\n  bucket = \"cbx-data-archive\"\n}\n")},
		{Path: "modules/db/rds.tf", Content: []byte("resource \"aws_db_instance\" \"web\" {}\n"), Truncated: true},
	}
}
