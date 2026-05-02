package audit

// Severity levels for audit findings.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Finding represents a single audit finding.
type Finding struct {
	RuleID      string `json:"rule_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Resource    string `json:"resource"`
	Service     string `json:"service"`
	Remediation string `json:"remediation"`
}

// Resource is a normalized representation of an infrastructure resource
// extracted from either a Pulumi or Terraform state file.
type Resource struct {
	Type   string
	URN    string
	ID     string
	Inputs map[string]interface{}
}

// Options configures an audit run.
type Options struct {
	StateFile    string
	OutputFormat string
	ReportFile   string
	Interactive  bool
	NoTUI        bool
	Quiet        bool
	MockScanners bool // when true, use mock scanner implementations (zero network)
}
