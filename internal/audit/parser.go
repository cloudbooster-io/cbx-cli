package audit

import (
	"encoding/json"
	"fmt"
	"os"
)

// ParseState reads a state file and extracts normalized resources.
// It auto-detects the format based on the top-level JSON keys.
func ParseState(stateFile string) ([]Resource, error) {
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return nil, fmt.Errorf("reading state file: %w", err)
	}

	var state map[string]interface{}
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parsing state file: %w", err)
	}

	// Pulumi state has a "deployment" or "version" key at the top level.
	// Terraform state has a "terraform_version" or "serial" key.
	if _, ok := state["deployment"]; ok {
		return parsePulumiState(state), nil
	}
	if _, ok := state["terraform_version"]; ok {
		return parseTerraformState(state), nil
	}
	if _, ok := state["version"]; ok {
		// Pulumi v3 states have a "version" key; fallback to Pulumi parsing.
		return parsePulumiState(state), nil
	}

	return nil, fmt.Errorf("unrecognized state file format")
}

func parsePulumiState(state map[string]interface{}) []Resource {
	var resources []Resource

	if deployment, ok := state["deployment"].(map[string]interface{}); ok {
		if res, ok := deployment["resources"].([]interface{}); ok {
			for _, r := range res {
				if m, ok := r.(map[string]interface{}); ok {
					resources = append(resources, mapToResource(m))
				}
			}
		}
	}

	// Fallback for states where resources are at the top level.
	if res, ok := state["resources"].([]interface{}); ok {
		for _, r := range res {
			if m, ok := r.(map[string]interface{}); ok {
				resources = append(resources, mapToResource(m))
			}
		}
	}

	return resources
}

func parseTerraformState(state map[string]interface{}) []Resource {
	var resources []Resource

	if modules, ok := state["resources"].([]interface{}); ok {
		for _, r := range modules {
			if m, ok := r.(map[string]interface{}); ok {
				resources = append(resources, terraformResourceToResource(m))
			}
		}
	}

	// Terraform state v4 wraps resources under "resources" array directly.
	// Some older versions may have modules/resources nesting.
	if rootModule, ok := state["values"].(map[string]interface{}); ok {
		if rootResources, ok := rootModule["root_module"].(map[string]interface{}); ok {
			if res, ok := rootResources["resources"].([]interface{}); ok {
				for _, r := range res {
					if m, ok := r.(map[string]interface{}); ok {
						resources = append(resources, terraformResourceToResource(m))
					}
				}
			}
		}
	}

	return resources
}

func mapToResource(m map[string]interface{}) Resource {
	res := Resource{
		Type: str(m, "type"),
		URN:  str(m, "urn"),
	}
	if res.URN == "" {
		res.URN = str(m, "id")
	}
	if res.URN == "" {
		res.URN = "unknown"
	}
	res.ID = str(m, "id")
	if inputs, ok := m["inputs"].(map[string]interface{}); ok {
		res.Inputs = inputs
	} else if attrs, ok := m["attributes"].(map[string]interface{}); ok {
		res.Inputs = attrs
	}
	return res
}

func terraformResourceToResource(m map[string]interface{}) Resource {
	res := Resource{
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
	if attrs, ok := m["values"].(map[string]interface{}); ok {
		res.Inputs = attrs
	} else if attrs, ok := m["attributes"].(map[string]interface{}); ok {
		res.Inputs = attrs
	} else if instances, ok := m["instances"].([]interface{}); ok && len(instances) > 0 {
		if inst, ok := instances[0].(map[string]interface{}); ok {
			if attrs, ok := inst["attributes"].(map[string]interface{}); ok {
				res.Inputs = attrs
			} else if attrs, ok := inst["values"].(map[string]interface{}); ok {
				res.Inputs = attrs
			}
		}
	}
	return res
}

func str(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
