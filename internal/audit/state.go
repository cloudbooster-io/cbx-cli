package audit

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/group"
)

// AuditState captures everything the diagram + report renderer needs
// to produce a report without re-running discovery, scanners, or the
// LLM call. RunFromResources writes a sidecar .state.json next to
// every AWS audit's .html / .md so dev iterators (tools/diagram-replay)
// can re-render the visual side in <1s instead of re-running a 60s
// live AWS audit.
//
// Schema is versioned via the Version field so a renderer-side change
// to the SVG layout doesn't require re-running audits in flight: a
// future renderer can refuse to load an unknown version and the
// state can be regenerated from a fresh audit run.
type AuditState struct {
	Version        int                  `json:"version"`
	Context        AWSAuditContext      `json:"context"`
	Resources      []DiscoveredResource `json:"resources"`
	Components     []group.Component    `json:"components"`
	Findings       []Finding            `json:"findings,omitempty"`
	LLMConnections []LLMConnection      `json:"llm_connections,omitempty"`
}

const auditStateVersion = 1

// SaveAuditState marshals the audit state to JSON at the given path.
// Pretty-prints with two-space indent so the file is git-diffable.
func SaveAuditState(path string, s AuditState) error {
	if s.Version == 0 {
		s.Version = auditStateVersion
	}
	body, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal audit state: %w", err)
	}
	// 0o600: audit state carries the account ID, the full resource inventory
	// and findings — restrict to the owner rather than the world-readable
	// default on shared hosts.
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return fmt.Errorf("write audit state: %w", err)
	}
	return nil
}

// LoadAuditState reads + unmarshals an AuditState from a JSON file.
// Returns an error if the version doesn't match what the renderer
// supports — the caller should refresh the state from a fresh audit
// rather than ship a stale render.
func LoadAuditState(path string) (*AuditState, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read audit state: %w", err)
	}
	var s AuditState
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("parse audit state: %w", err)
	}
	if s.Version != auditStateVersion {
		return nil, fmt.Errorf("audit state version mismatch: file=%d, want=%d", s.Version, auditStateVersion)
	}
	return &s, nil
}
