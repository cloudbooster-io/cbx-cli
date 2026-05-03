package plan

import (
	coreplan "gitlab.com/cloudbooster.io/platform/cbx-cli/core/plan"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
)

// Type aliases so existing internal/plan/ code can continue using short names.
type Component = coreplan.Component
type Plan = coreplan.Plan
type Turn = coreplan.Turn
type Session = coreplan.Session
type Client = coreplan.Client
type MockClient = coreplan.MockClient
type LLMPlanClient = coreplan.LLMPlanClient
type ComposeClient = coreplan.ComposeClient
type LLMCaller = coreplan.LLMCaller

// Wrapper functions for types that moved to core/plan/.
func NewSession(outputDir string) *Session {
	return coreplan.NewSession(outputDir)
}

func RenderADR(p *Plan) string {
	return coreplan.RenderADR(p)
}

func RenderD2(p *Plan) string {
	return coreplan.RenderD2(p)
}

func RenderMermaid(p *Plan) string {
	return coreplan.RenderMermaid(p)
}

func RenderHTML(p *Plan) string {
	return coreplan.RenderHTML(p)
}

func ExportJSON(p *Plan) (string, error) {
	return coreplan.ExportJSON(p)
}

func GetProvider(session *Session, cfg *config.Config) string {
	return coreplan.GetProvider(session, cfg)
}
