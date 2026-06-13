package parsers

import "fmt"

// ParseTerraformState extracts DiscoveredResources from a Terraform state map.
// It expects the top-level JSON object that has already been unmarshaled.
func ParseTerraformState(state map[string]interface{}) ([]DiscoveredResource, error) {
	var resources []DiscoveredResource

	if rawResources, ok := state["resources"].([]interface{}); ok {
		for _, r := range rawResources {
			if m, ok := r.(map[string]interface{}); ok {
				if err := checkProvisionerDenylist(m); err != nil {
					return nil, err
				}
				resources = append(resources, terraformMapToDiscoveredResource(m))
			}
		}
	}

	// Terraform state v4 wraps resources under "resources" array directly.
	// `terraform show -json` output nests resources under values/root_module,
	// with module-managed resources in child_modules (arbitrarily nested).
	if values, ok := state["values"].(map[string]interface{}); ok {
		if rootModule, ok := values["root_module"].(map[string]interface{}); ok {
			moduleResources, err := collectTerraformModuleResources(rootModule)
			if err != nil {
				return nil, err
			}
			resources = append(resources, moduleResources...)
		}
	}

	if len(resources) == 0 {
		return nil, ThreeLineError(
			"failed to parse Terraform state",
			"no resources found in state file",
			"verify the file is a valid Terraform state export",
		)
	}

	return resources, nil
}

// collectTerraformModuleResources gathers the resources of a `terraform show
// -json` module object, recursing into its child_modules at every depth.
func collectTerraformModuleResources(module map[string]interface{}) ([]DiscoveredResource, error) {
	var resources []DiscoveredResource

	if res, ok := module["resources"].([]interface{}); ok {
		for _, r := range res {
			if m, ok := r.(map[string]interface{}); ok {
				if err := checkProvisionerDenylist(m); err != nil {
					return nil, err
				}
				resources = append(resources, terraformMapToDiscoveredResource(m))
			}
		}
	}

	if children, ok := module["child_modules"].([]interface{}); ok {
		for _, c := range children {
			if child, ok := c.(map[string]interface{}); ok {
				childResources, err := collectTerraformModuleResources(child)
				if err != nil {
					return nil, err
				}
				resources = append(resources, childResources...)
			}
		}
	}

	return resources, nil
}

func terraformMapToDiscoveredResource(m map[string]interface{}) DiscoveredResource {
	res := DiscoveredResource{
		Type: str(m, "type"),
		URN:  str(m, "name"),
	}
	if res.URN == "" {
		res.URN = str(m, "id")
	}
	if res.URN == "" {
		res.URN = "unknown"
	}
	res.ID = str(m, "id")

	var attrs map[string]interface{}
	if raw, ok := m["values"].(map[string]interface{}); ok {
		attrs = raw
		res.Inputs = raw
	} else if raw, ok := m["attributes"].(map[string]interface{}); ok {
		attrs = raw
		res.Inputs = raw
	} else if instances, ok := m["instances"].([]interface{}); ok && len(instances) > 0 {
		if inst, ok := instances[0].(map[string]interface{}); ok {
			if raw, ok := inst["attributes"].(map[string]interface{}); ok {
				attrs = raw
				res.Inputs = raw
			} else if raw, ok := inst["values"].(map[string]interface{}); ok {
				attrs = raw
				res.Inputs = raw
			}
		}
	}

	if attrs != nil {
		res.Region = str(attrs, "region")
		if res.Region == "" {
			res.Region = regionFromARN(str(attrs, "arn"))
		}
		res.Tags = stringMap(attrs, "tags")
	}

	return res
}

func checkProvisionerDenylist(m map[string]interface{}) error {
	name := str(m, "name")
	if name == "" {
		name = str(m, "id")
	}

	check := func(list []interface{}) error {
		for _, p := range list {
			if prov, ok := p.(map[string]interface{}); ok {
				if str(prov, "type") == "remote-exec" {
					return ThreeLineError(
						"terraform state contains blocked provisioner",
						fmt.Sprintf("remote-exec provisioner detected in resource %q", name),
						"remove remote-exec provisioners and try again",
					)
				}
			}
		}
		return nil
	}

	if provs, ok := m["provisioner"].([]interface{}); ok {
		if err := check(provs); err != nil {
			return err
		}
	}

	if instances, ok := m["instances"].([]interface{}); ok {
		for _, inst := range instances {
			if instMap, ok := inst.(map[string]interface{}); ok {
				if provs, ok := instMap["provisioner"].([]interface{}); ok {
					if err := check(provs); err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}
