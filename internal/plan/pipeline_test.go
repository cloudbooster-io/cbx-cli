package plan

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/tui/chat"

	tea "github.com/charmbracelet/bubbletea"
)

type testSender struct {
	msgs []tea.Msg
}

func (s *testSender) Send(msg tea.Msg) {
	s.msgs = append(s.msgs, msg)
}

func TestPipelineFullFlow(t *testing.T) {
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

	// Mock LLM (Anthropic-style)
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
				"claude": {
					Name:    "claude",
					BaseURL: llmSrv.URL,
					Model:   "claude-test",
				},
			},
		},
	}

	sender := &testSender{}
	session := NewSession(".")
	pipeline := NewPipeline(sender, cfg, session)
	pipeline.Start("static site")

	// Wait for pipeline to finish.
	time.Sleep(500 * time.Millisecond)

	// Verify message sequence.
	if len(sender.msgs) == 0 {
		t.Fatal("expected messages from pipeline")
	}

	var sawProposing, sawThinking, sawResolving, sawReady bool
	var tokenCount, candidateCount int
	var resolveMsg *chat.ResolveCompleteMsg

	for _, msg := range sender.msgs {
		switch m := msg.(type) {
		case chat.StatusMsg:
			if strings.Contains(m.Left, "proposing") {
				sawProposing = true
			}
			if strings.Contains(m.Left, "thinking") {
				sawThinking = true
			}
			if strings.Contains(m.Left, "resolving") {
				sawResolving = true
			}
			if m.Right == "ready" || m.Right == "BYO LLM — cost not tracked" {
				sawReady = true
			}
		case chat.StreamTokenMsg:
			tokenCount++
		case chat.ProposalCandidateMsg:
			candidateCount++
		case chat.ResolveCompleteMsg:
			resolveMsg = &m
		}
	}

	if !sawProposing {
		t.Error("expected 'proposing' status message")
	}
	if !sawThinking {
		t.Error("expected 'thinking' status message")
	}
	if !sawResolving {
		t.Error("expected 'resolving' status message")
	}
	if !sawReady {
		t.Error("expected 'ready' status message")
	}
	if tokenCount == 0 {
		t.Error("expected stream tokens")
	}
	if candidateCount != 2 {
		t.Fatalf("expected 2 candidates, got %d", candidateCount)
	}
	if resolveMsg == nil {
		t.Fatal("expected ResolveCompleteMsg")
	}
	if resolveMsg.Intent != "static site" {
		t.Fatalf("expected intent 'static site', got %q", resolveMsg.Intent)
	}
	if resolveMsg.Version != 1 {
		t.Fatalf("expected version 1, got %d", resolveMsg.Version)
	}
}

func TestPipelineCancel(t *testing.T) {
	// Slow mock server so cancellation has time to take effect.
	composeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/compose/aws/propose" {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			for i := 0; i < 10; i++ {
				fmt.Fprintln(w, fmt.Sprintf("data: {\"name\":\"C%d\",\"description\":\"d\",\"service\":\"S\"}", i))
				w.(http.Flusher).Flush()
				time.Sleep(50 * time.Millisecond)
			}
		}
	}))
	defer composeSrv.Close()

	cfg := &config.Config{
		APIURL: composeSrv.URL,
		LLM: config.LLMConfig{
			Default: "claude",
			Providers: map[string]config.LLMProvider{
				"claude": {Name: "claude", BaseURL: "http://localhost:9999", Model: "m"},
			},
		},
	}

	sender := &testSender{}
	session := NewSession(".")
	pipeline := NewPipeline(sender, cfg, session)
	pipeline.Start("test intent")

	// Cancel almost immediately.
	time.Sleep(20 * time.Millisecond)
	pipeline.Cancel()

	// Give a moment for cancellation to propagate.
	time.Sleep(100 * time.Millisecond)

	// We should have received at least the proposing status and a cancelled status.
	var sawCancelled bool
	for _, msg := range sender.msgs {
		if m, ok := msg.(chat.StatusMsg); ok && m.Right == "cancelled" {
			sawCancelled = true
		}
	}
	if !sawCancelled {
		t.Error("expected cancelled status message after Cancel()")
	}
}

func TestPipelineFallbackWhenAPIUnreachable(t *testing.T) {
	// No mock server — everything falls back to mock behaviour.
	cfg := &config.Config{
		APIURL: "http://localhost:1", // unreachable
		LLM: config.LLMConfig{
			Default: "claude",
			Providers: map[string]config.LLMProvider{
				"claude": {Name: "claude", BaseURL: "http://localhost:1", Model: "m"},
			},
		},
	}

	sender := &testSender{}
	session := NewSession(".")
	pipeline := NewPipeline(sender, cfg, session)
	pipeline.Start("static site with auth")

	time.Sleep(200 * time.Millisecond)

	var resolveMsg *chat.ResolveCompleteMsg
	for _, msg := range sender.msgs {
		if m, ok := msg.(chat.ResolveCompleteMsg); ok {
			resolveMsg = &m
		}
	}
	if resolveMsg == nil {
		t.Fatal("expected ResolveCompleteMsg from mock fallback")
	}
	if !strings.Contains(resolveMsg.Intent, "static site with auth") {
		t.Fatalf("expected intent containing 'static site with auth', got %q", resolveMsg.Intent)
	}
}
