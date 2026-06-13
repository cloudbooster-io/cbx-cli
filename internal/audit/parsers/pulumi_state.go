package parsers

// ParsePulumiState extracts DiscoveredResources from a Pulumi state map.
// It expects the top-level JSON object that has already been unmarshaled.
func ParsePulumiState(state map[string]interface{}) ([]DiscoveredResource, error) {
	var resources []DiscoveredResource

	if deployment, ok := state["deployment"].(map[string]interface{}); ok {
		if res, ok := deployment["resources"].([]interface{}); ok {
			for _, r := range res {
				if m, ok := r.(map[string]interface{}); ok {
					resources = append(resources, mapToDiscoveredResource(m))
				}
			}
		}
	}

	// Fallback for states where resources are at the top level. Only taken
	// when the deployment loop found nothing, so a state carrying both
	// arrays does not double-count every resource.
	if res, ok := state["resources"].([]interface{}); ok && len(resources) == 0 {
		for _, r := range res {
			if m, ok := r.(map[string]interface{}); ok {
				resources = append(resources, mapToDiscoveredResource(m))
			}
		}
	}

	if len(resources) == 0 {
		return nil, ThreeLineError(
			"failed to parse Pulumi state",
			"no resources found in state file",
			"verify the file is a valid Pulumi state export",
		)
	}

	return resources, nil
}

func mapToDiscoveredResource(m map[string]interface{}) DiscoveredResource {
	res := DiscoveredResource{
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

	var inputs map[string]interface{}
	if raw, ok := m["inputs"].(map[string]interface{}); ok {
		inputs = raw
		res.Inputs = raw
	} else if raw, ok := m["attributes"].(map[string]interface{}); ok {
		inputs = raw
		res.Inputs = raw
	}

	if inputs != nil {
		res.Region = str(inputs, "region")
		res.Tags = stringMap(inputs, "tags")
	}

	return res
}
