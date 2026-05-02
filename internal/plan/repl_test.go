package plan

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/tui/chat"

	tea "github.com/charmbracelet/bubbletea"
)

func TestReplStreamingTUIFullFlow(t *testing.T) {
	// Mock compose API
	composeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/compose/aws/propose":
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "data: {\"name\":\"S3\",\"description\":\"Static asset hosting\",\"service\":\"S3\"}")
			fmt.Fprintln(w, "data: {\"name\":\"Lambda\",\"description\":\"Serverless compute\",\"service\":\"Lambda\"}")
			fmt.Fprintln(w, "data: [DONE]")
		case "/v1/compose/aws/resolve":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"intent":"static site","components":[{"name":"S3","description":"Static asset hosting","service":"S3"}],"version":1}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer composeSrv.Close()

	// Mock LLM (Anthropic-style SSE)
	llmSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"Looks\"}}")
		fmt.Fprintln(w, "data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\" good\"}}")
		fmt.Fprintln(w, "data: [DONE]")
	}))
	defer llmSrv.Close()

	cfg := &config.Config{
		APIURL: composeSrv.URL,
		LLM: config.LLMConfig{
			Default: "claude",
			Providers: map[string]config.LLMProvider{
				"claude": {Name: "claude", BaseURL: llmSrv.URL, Model: "claude-test"},
			},
		},
	}

	m := chat.NewModel()
	m.SetStreamRenderer(chat.NewStreamRenderer())

	session := NewSession(".")
	pipeline := NewPipeline(nil, cfg, session)

	var p *tea.Program
	m.OnSubmit = func(input string) (string, error) {
		pipeline.Start(input)
		return "", nil
	}

	wrapper := newReplModel(m, session, pipeline)
	p = tea.NewProgram(wrapper, tea.WithInput(strings.NewReader("")), tea.WithOutput(io.Discard))
	pipeline.sender = p

	done := make(chan struct{})
	go func() {
		time.Sleep(50 * time.Millisecond)
		p.Send(tea.WindowSizeMsg{Width: 80, Height: 100})
		p.Send(chat.InputMsg("static site"))
		time.Sleep(800 * time.Millisecond)
		p.Send(tea.QuitMsg{})
		close(done)
	}()

	finalModel, err := p.Run()
	if err != nil {
		t.Fatalf("program run failed: %v", err)
	}
	<-done

	rm := finalModel.(replModel)
	view := rm.View()

	if !strings.Contains(view, "> static site") {
		t.Errorf("expected user intent in viewport, got:\n%s", view)
	}
	if !strings.Contains(view, "S3") {
		t.Errorf("expected S3 candidate in viewport, got:\n%s", view)
	}
	if !strings.Contains(view, "Lambda") {
		t.Errorf("expected Lambda candidate in viewport, got:\n%s", view)
	}
	if !strings.Contains(view, "Looks good") {
		t.Errorf("expected LLM tokens in viewport, got:\n%s", view)
	}
	if !strings.Contains(view, "Plan v1") {
		t.Errorf("expected plan version in viewport, got:\n%s", view)
	}
	if !strings.Contains(view, "ADR:") {
		t.Errorf("expected ADR content in viewport, got:\n%s", view)
	}
}
