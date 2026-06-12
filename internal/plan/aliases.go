package plan

import (
	coreplan "github.com/cloudbooster-io/cbx-cli/core/plan"
	"github.com/cloudbooster-io/cbx-cli/internal/config"
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
	return coreplan.GetProvider(session, RunnerConfigFromConfig(cfg))
}

// RunnerConfigFromConfig adapts the CLI's *config.Config to the core/plan
// RunnerConfig consumed by coreplan.NewRunner and coreplan.GetProvider. The
// conversion lives here, at the composition-root side of the boundary, so
// core/plan stays free of internal/config.
func RunnerConfigFromConfig(cfg *config.Config) coreplan.RunnerConfig {
	providers := make(map[string]coreplan.LLMProvider, len(cfg.LLM.Providers))
	for name, p := range cfg.LLM.Providers {
		model := p.Model
		if coreplan.IsCLIExecutor(name) && !p.ModelPinned {
			// The "codex" config slot is shared between the api provider and
			// the CLI executor; an api login seeds Model with the HTTP
			// default, which must not leak into the local CLI's argv. Only a
			// deliberate `cbx llm model` pin rides through to --model.
			model = ""
		}
		providers[name] = coreplan.LLMProvider{Name: p.Name, BaseURL: p.BaseURL, Model: model}
	}
	return coreplan.RunnerConfig{
		APIURL:          cfg.APIURL,
		DefaultProvider: cfg.LLM.Default,
		Providers:       providers,
	}
}
