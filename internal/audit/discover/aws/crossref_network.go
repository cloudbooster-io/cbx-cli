package aws

// crossReferenceNetwork pre-computes internet-reachability signals so
// the LLM doesn't have to walk subnet → route-table → IGW chains
// (which it does inconsistently). Two output annotations land on the
// resources:
//
//   - AWS::EC2::Subnet     cb_describer_internet_routable (bool)
//   - AWS::RDS::DBInstance cb_describer_effectively_public (bool)
//   - AWS::EC2::Instance   cb_describer_subnet_is_public  (bool)
//
// "Internet-routable" for a subnet means either:
//
//	(a) MapPublicIpOnLaunch=true (the AWS-canonical "public subnet"
//	    flag — true means the AWS console treats it as a public
//	    subnet, which is the strongest direct signal), OR
//	(b) the subnet's associated route table contains a 0.0.0.0/0
//	    route whose target is an InternetGateway. Falls back to the
//	    VPC's "main" route table when no explicit
//	    SubnetRouteTableAssociation links the subnet — same default
//	    AWS itself applies.
//
// "Effectively public" for an RDS instance: PubliclyAccessible=true
// AND at least one constituent subnet (from its DBSubnetGroup) is
// internet-routable. PubliclyAccessible=true with all subnets private
// is the "flag set but blast radius is one route-table change away"
// case the audit should rate HIGH, not CRITICAL.
//
// "Subnet is public" for an EC2 instance: the instance's SubnetId
// resolves to a subnet with internet_routable=true. The LLM combines
// this with cb_describer_public_ip_present (already lifted by the
// EC2 describer) to decide CRITICAL vs HIGH.
func crossReferenceNetwork(resources []DiscoveredResource) {
	// Index all the relevant resource shapes once so per-pass lookups
	// are constant-time. Indexing by both ARN (when known) and bare id
	// because CFN Properties sometimes carry one, sometimes the other.
	subnetIdx := map[string]int{}            // SubnetId → index
	routeTableIdx := map[string]int{}        // RouteTableId → index
	dbSubnetGroupIdx := map[string]int{}     // DBSubnetGroupName → index
	subnetRouteTable := map[string]string{}  // SubnetId → RouteTableId (explicit assoc)
	vpcMainRouteTable := map[string]string{} // VpcId → RouteTableId (main RT)

	for i, r := range resources {
		switch r.Type {
		case "AWS::EC2::Subnet":
			if id := stringInput(r.Inputs, "SubnetId"); id != "" {
				subnetIdx[id] = i
			}
			// Some CC responses return the resource id only under
			// the resource's own ID field, not in Properties.
			if r.ID != "" {
				subnetIdx[r.ID] = i
			}
		case "AWS::EC2::RouteTable":
			if id := stringInput(r.Inputs, "RouteTableId"); id != "" {
				routeTableIdx[id] = i
			}
			if r.ID != "" {
				routeTableIdx[r.ID] = i
			}
			// CFN's AWS::EC2::RouteTable Properties surface Associations
			// (a list of {SubnetId, RouteTableAssociationId, Main}) on
			// the route table itself in some CFN shapes. Capture both
			// the per-subnet associations and the main RT for the VPC.
			vpcID := stringInput(r.Inputs, "VpcId")
			if assocs, ok := r.Inputs["Associations"].([]any); ok {
				for _, a := range assocs {
					am, ok := a.(map[string]any)
					if !ok {
						continue
					}
					if main, _ := am["Main"].(bool); main && vpcID != "" {
						vpcMainRouteTable[vpcID] = r.ID
					}
					if sid, _ := am["SubnetId"].(string); sid != "" {
						subnetRouteTable[sid] = r.ID
					}
				}
			}
		case "AWS::EC2::SubnetRouteTableAssociation":
			sid := stringInput(r.Inputs, "SubnetId")
			rtid := stringInput(r.Inputs, "RouteTableId")
			if sid != "" && rtid != "" {
				subnetRouteTable[sid] = rtid
			}
		case "AWS::RDS::DBSubnetGroup":
			name := stringInput(r.Inputs, "DBSubnetGroupName")
			if name == "" {
				name = r.ID
			}
			if name != "" {
				dbSubnetGroupIdx[name] = i
			}
		}
	}

	// publicRouteTable[id] = true when the RT has a 0.0.0.0/0 route to
	// an IGW. Computed once because subnets often share a route table.
	publicRouteTable := map[string]bool{}
	for id, idx := range routeTableIdx {
		publicRouteTable[id] = routeTableIsPublic(resources[idx].Inputs)
	}

	// First pass: annotate subnets with internet_routable. Uses
	// MapPublicIpOnLaunch as the primary signal (strongest direct
	// indicator AWS itself uses) and falls back to the route-table walk.
	for i, r := range resources {
		if r.Type != "AWS::EC2::Subnet" {
			continue
		}
		if r.Inputs == nil {
			resources[i].Inputs = map[string]any{}
		}

		routable := false
		// Primary signal: MapPublicIpOnLaunch.
		if mp, ok := r.Inputs["MapPublicIpOnLaunch"].(bool); ok && mp {
			routable = true
		}
		// Secondary signal: any associated route table with 0.0.0.0/0 → IGW.
		if !routable {
			rt := subnetRouteTable[stringInput(r.Inputs, "SubnetId")]
			if rt == "" {
				// Fall back to VPC main RT.
				rt = vpcMainRouteTable[stringInput(r.Inputs, "VpcId")]
			}
			if rt != "" && publicRouteTable[rt] {
				routable = true
			}
		}
		resources[i].Inputs["cb_describer_internet_routable"] = routable
	}

	// Re-read subnetIdx values after the annotation so RDS/EC2
	// resolution sees the just-set flag.
	subnetIsRoutable := func(subnetID string) bool {
		idx, ok := subnetIdx[subnetID]
		if !ok {
			return false
		}
		v, _ := resources[idx].Inputs["cb_describer_internet_routable"].(bool)
		return v
	}

	for i, r := range resources {
		switch r.Type {
		case "AWS::RDS::DBInstance":
			if r.Inputs == nil {
				resources[i].Inputs = map[string]any{}
			}
			publicly, _ := r.Inputs["PubliclyAccessible"].(bool)
			if !publicly {
				resources[i].Inputs["cb_describer_effectively_public"] = false
				continue
			}
			subnetGroupName := stringInput(r.Inputs, "DBSubnetGroupName")
			if subnetGroupName == "" {
				// Default subnet group is "default"; we can't resolve
				// it without enumerating default subnets — treat as
				// "unknown reachability".
				resources[i].Inputs["cb_describer_effectively_public"] = false
				continue
			}
			idx, ok := dbSubnetGroupIdx[subnetGroupName]
			if !ok {
				resources[i].Inputs["cb_describer_effectively_public"] = false
				continue
			}
			effective := false
			if ids, ok := resources[idx].Inputs["SubnetIds"].([]any); ok {
				for _, item := range ids {
					if s, ok := item.(string); ok && subnetIsRoutable(s) {
						effective = true
						break
					}
				}
			}
			resources[i].Inputs["cb_describer_effectively_public"] = effective

		case "AWS::EC2::Instance":
			if r.Inputs == nil {
				resources[i].Inputs = map[string]any{}
			}
			sid := stringInput(r.Inputs, "SubnetId")
			resources[i].Inputs["cb_describer_subnet_is_public"] = subnetIsRoutable(sid)
		}
	}
}

// routeTableIsPublic returns true when the route table's Routes
// contain a 0.0.0.0/0 entry whose target is an InternetGateway.
// Routes are typically a list of {DestinationCidrBlock, GatewayId,
// ...} maps in CFN-shaped properties. We accept GatewayId starting
// with "igw-" as the IGW signal; that's how the EC2 API encodes
// internet gateways.
func routeTableIsPublic(in map[string]any) bool {
	routes, ok := in["Routes"].([]any)
	if !ok {
		return false
	}
	for _, item := range routes {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		dest, _ := m["DestinationCidrBlock"].(string)
		if dest != "0.0.0.0/0" {
			continue
		}
		gateway, _ := m["GatewayId"].(string)
		if gateway != "" && len(gateway) > 4 && gateway[:4] == "igw-" {
			return true
		}
	}
	return false
}
