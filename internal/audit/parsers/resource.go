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

// CBDescriberPrimitiveResolved is the Inputs key under which a
// per-service describer publishes the engine-resolved CB primitive id
// (the only place that does this today is the RDS describer, which
// translates AWS::RDS::DBInstance + Engine attribute into one of the
// engine-split primitives like aws:db/postgres@v1).
//
// Lives here rather than in the audit or discover package because both
// the grouping pass (internal/audit/group) and the grounded prompt
// builder (internal/audit) read it; the parsers package is the one
// place every consumer already imports for DiscoveredResource, so the
// shared key constant rides along without forcing a new import edge.
const CBDescriberPrimitiveResolved = "cb_describer_primitive_resolved"
