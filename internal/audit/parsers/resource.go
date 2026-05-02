package parsers

// DiscoveredResource is a normalized representation of an infrastructure
// resource extracted from either a Pulumi or Terraform state file.
// JSON tags are chosen to match the server-side Pydantic model.
type DiscoveredResource struct {
	Type   string                 `json:"type"`
	URN    string                 `json:"urn"`
	ID     string                 `json:"id"`
	Region string                 `json:"region,omitempty"`
	Tags   map[string]string      `json:"tags,omitempty"`
	Inputs map[string]interface{} `json:"inputs,omitempty"`
}
