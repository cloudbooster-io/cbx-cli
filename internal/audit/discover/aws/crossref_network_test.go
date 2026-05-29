package aws

import "testing"

func TestCrossReferenceNetwork_MapPublicIpOnLaunchMarksRoutable(t *testing.T) {
	resources := []DiscoveredResource{
		{
			Type: "AWS::EC2::Subnet",
			URN:  "urn:public",
			ID:   "subnet-pub",
			Inputs: map[string]any{
				"SubnetId":            "subnet-pub",
				"VpcId":               "vpc-1",
				"MapPublicIpOnLaunch": true,
			},
		},
		{
			Type: "AWS::EC2::Subnet",
			URN:  "urn:private",
			ID:   "subnet-priv",
			Inputs: map[string]any{
				"SubnetId":            "subnet-priv",
				"VpcId":               "vpc-1",
				"MapPublicIpOnLaunch": false,
			},
		},
	}

	crossReferenceNetwork(resources)

	if v, _ := resources[0].Inputs["cb_describer_internet_routable"].(bool); !v {
		t.Errorf("public subnet: expected internet_routable=true")
	}
	if v, _ := resources[1].Inputs["cb_describer_internet_routable"].(bool); v {
		t.Errorf("private subnet: expected internet_routable=false")
	}
}

func TestCrossReferenceNetwork_RouteTableIGWFallback(t *testing.T) {
	resources := []DiscoveredResource{
		{
			Type: "AWS::EC2::Subnet",
			ID:   "subnet-x",
			Inputs: map[string]any{
				"SubnetId": "subnet-x",
				"VpcId":    "vpc-1",
				// MapPublicIpOnLaunch absent
			},
		},
		{
			Type: "AWS::EC2::RouteTable",
			ID:   "rtb-1",
			Inputs: map[string]any{
				"RouteTableId": "rtb-1",
				"VpcId":        "vpc-1",
				"Routes": []any{
					map[string]any{
						"DestinationCidrBlock": "0.0.0.0/0",
						"GatewayId":            "igw-abc",
					},
				},
			},
		},
		{
			Type: "AWS::EC2::SubnetRouteTableAssociation",
			Inputs: map[string]any{
				"SubnetId":     "subnet-x",
				"RouteTableId": "rtb-1",
			},
		},
	}

	crossReferenceNetwork(resources)

	if v, _ := resources[0].Inputs["cb_describer_internet_routable"].(bool); !v {
		t.Errorf("subnet with IGW route via explicit assoc: expected internet_routable=true")
	}
}

func TestCrossReferenceNetwork_RDSEffectivelyPublic(t *testing.T) {
	resources := []DiscoveredResource{
		{
			Type: "AWS::EC2::Subnet",
			ID:   "subnet-pub",
			Inputs: map[string]any{
				"SubnetId":            "subnet-pub",
				"MapPublicIpOnLaunch": true,
			},
		},
		{
			Type: "AWS::EC2::Subnet",
			ID:   "subnet-priv",
			Inputs: map[string]any{
				"SubnetId":            "subnet-priv",
				"MapPublicIpOnLaunch": false,
			},
		},
		{
			Type: "AWS::RDS::DBSubnetGroup",
			ID:   "private-only",
			Inputs: map[string]any{
				"DBSubnetGroupName": "private-only",
				"SubnetIds":         []any{"subnet-priv"},
			},
		},
		{
			Type: "AWS::RDS::DBSubnetGroup",
			ID:   "mixed",
			Inputs: map[string]any{
				"DBSubnetGroupName": "mixed",
				"SubnetIds":         []any{"subnet-priv", "subnet-pub"},
			},
		},
		{
			Type: "AWS::RDS::DBInstance",
			URN:  "urn:db-private",
			Inputs: map[string]any{
				"PubliclyAccessible": true,
				"DBSubnetGroupName":  "private-only",
			},
		},
		{
			Type: "AWS::RDS::DBInstance",
			URN:  "urn:db-mixed",
			Inputs: map[string]any{
				"PubliclyAccessible": true,
				"DBSubnetGroupName":  "mixed",
			},
		},
		{
			Type: "AWS::RDS::DBInstance",
			URN:  "urn:db-flag-false",
			Inputs: map[string]any{
				"PubliclyAccessible": false,
				"DBSubnetGroupName":  "mixed",
			},
		},
	}

	crossReferenceNetwork(resources)

	findDB := func(urn string) DiscoveredResource {
		for _, r := range resources {
			if r.URN == urn {
				return r
			}
		}
		t.Fatalf("no resource %q", urn)
		return DiscoveredResource{}
	}

	if v, _ := findDB("urn:db-private").Inputs["cb_describer_effectively_public"].(bool); v {
		t.Errorf("db-private: PubliclyAccessible=true but all subnets private → expected effectively_public=false")
	}
	if v, _ := findDB("urn:db-mixed").Inputs["cb_describer_effectively_public"].(bool); !v {
		t.Errorf("db-mixed: PubliclyAccessible=true + one public subnet → expected effectively_public=true")
	}
	if v, _ := findDB("urn:db-flag-false").Inputs["cb_describer_effectively_public"].(bool); v {
		t.Errorf("db-flag-false: PubliclyAccessible=false → expected effectively_public=false")
	}
}

func TestCrossReferenceLambdaRole_CopiesAdminFlag(t *testing.T) {
	resources := []DiscoveredResource{
		{
			Type: "AWS::IAM::Role",
			ID:   "admin-role",
			Inputs: map[string]any{
				"RoleName": "admin-role",
				"Arn":      "arn:aws:iam::123:role/admin-role",
				"cb_describer_admin_managed_policy_attached":    true,
				"cb_describer_inline_policy_has_wildcard_allow": false,
			},
		},
		{
			Type: "AWS::IAM::Role",
			ID:   "tame-role",
			Inputs: map[string]any{
				"RoleName": "tame-role",
				"Arn":      "arn:aws:iam::123:role/tame-role",
				"cb_describer_admin_managed_policy_attached": false,
			},
		},
		{
			Type: "AWS::Lambda::Function",
			URN:  "urn:lambda-admin",
			Inputs: map[string]any{
				"FunctionName": "admin-fn",
				"Role":         "arn:aws:iam::123:role/admin-role",
			},
		},
		{
			Type: "AWS::Lambda::Function",
			URN:  "urn:lambda-tame",
			Inputs: map[string]any{
				"FunctionName": "tame-fn",
				"Role":         "tame-role", // bare name form
			},
		},
		{
			Type: "AWS::Lambda::Function",
			URN:  "urn:lambda-orphan",
			Inputs: map[string]any{
				"FunctionName": "orphan-fn",
				"Role":         "arn:aws:iam::999:role/external-role",
			},
		},
	}

	crossReferenceLambdaRole(resources)

	findLambda := func(urn string) DiscoveredResource {
		for _, r := range resources {
			if r.URN == urn {
				return r
			}
		}
		t.Fatalf("no resource %q", urn)
		return DiscoveredResource{}
	}

	admin := findLambda("urn:lambda-admin")
	if v, _ := admin.Inputs["cb_describer_role_is_admin_equivalent"].(bool); !v {
		t.Errorf("admin lambda: expected role_is_admin_equivalent=true")
	}

	tame := findLambda("urn:lambda-tame")
	if v, _ := tame.Inputs["cb_describer_role_is_admin_equivalent"].(bool); v {
		t.Errorf("tame lambda: expected role_is_admin_equivalent=false")
	}

	orphan := findLambda("urn:lambda-orphan")
	if _, ok := orphan.Inputs["cb_describer_role_is_admin_equivalent"]; ok {
		t.Errorf("orphan lambda: role not in inventory → flag should be unset, not false")
	}
}
