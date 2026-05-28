package aws

import (
	"context"
)

// securityGroupDescriber normalizes AWS::EC2::SecurityGroup ingress
// rules into top-level cb_describer_* fields. CloudControl returns
// SecurityGroupIngress as a nested array of CFN-shape rules; the
// grounded analyzer doesn't reliably spot "open SSH/RDP from
// 0.0.0.0/0" buried in that shape (the audit verification flagged this
// as a CRITICAL miss). Lifting the dangerous patterns into named
// booleans gives the LLM a crisp signal to ground.
//
// No AWS API calls — pure normalization over CloudControl's response.
type securityGroupDescriber struct{}

func (securityGroupDescriber) CFNType() string { return "AWS::EC2::SecurityGroup" }

// Internet-exposed ports the audit flags explicitly. The list is
// intentionally short: admin/database ports where a wide-open ingress
// rule is almost never intentional. Wider port surveys belong in the
// LLM's general assessment, not here.
var dangerousAdminPorts = map[int]string{
	22:    "SSH",
	3389:  "RDP",
	5432:  "PostgreSQL",
	3306:  "MySQL",
	1433:  "MSSQL",
	27017: "MongoDB",
	6379:  "Redis",
	9200:  "Elasticsearch",
}

func (securityGroupDescriber) Enrich(_ context.Context, _ awsCfg, r *DiscoveredResource) error {
	if r.Inputs == nil {
		r.Inputs = map[string]any{}
	}

	rules, _ := r.Inputs["SecurityGroupIngress"].([]any)

	openToInternet := []map[string]any{}
	exposedAdminPorts := []string{}
	hasAllPortsAllProtoOpen := false

	for _, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		// CIDR can be IPv4 (CidrIp) or IPv6 (CidrIpv6); both 0.0.0.0/0
		// and ::/0 are "public internet" for our purposes.
		cidr4, _ := rule["CidrIp"].(string)
		cidr6, _ := rule["CidrIpv6"].(string)
		isInternet := cidr4 == "0.0.0.0/0" || cidr6 == "::/0"
		if !isInternet {
			continue
		}

		proto, _ := rule["IpProtocol"].(string)
		from := readPort(rule, "FromPort")
		to := readPort(rule, "ToPort")

		entry := map[string]any{
			"protocol":  proto,
			"from_port": from,
			"to_port":   to,
		}
		if cidr4 != "" {
			entry["cidr_ip"] = cidr4
		}
		if cidr6 != "" {
			entry["cidr_ipv6"] = cidr6
		}
		openToInternet = append(openToInternet, entry)

		// Protocol "-1" + missing/zero ports = all protocols all ports.
		// That's the worst-case SG misconfiguration.
		if proto == "-1" {
			hasAllPortsAllProtoOpen = true
			continue
		}

		// Mark any dangerous admin port that falls inside the rule's
		// FromPort..ToPort range. A single-port rule (from==to) is the
		// common case; ranges are rare but get a sweep.
		for port, name := range dangerousAdminPorts {
			if from <= port && port <= to {
				exposedAdminPorts = append(exposedAdminPorts, name)
			}
		}
	}

	r.Inputs["cb_describer_ingress_open_to_internet"] = openToInternet
	r.Inputs["cb_describer_ingress_exposed_admin_ports"] = exposedAdminPorts
	r.Inputs["cb_describer_ingress_allows_all_traffic_from_internet"] = hasAllPortsAllProtoOpen
	return nil
}

// readPort pulls an int port out of CloudControl's response. CC encodes
// ports as JSON numbers, which Go unmarshals to float64; an absent field
// stays missing.
func readPort(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}
