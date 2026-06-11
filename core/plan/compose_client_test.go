package plan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestComposeClientProposeSSE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/compose/aws/propose" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer test-token" {
			t.Errorf("unexpected auth header: %s", auth)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "data: {\"name\":\"S3\",\"description\":\"Static asset hosting\",\"service\":\"S3\"}")
		fmt.Fprintln(w, "data: {\"name\":\"Lambda\",\"description\":\"Serverless compute\",\"service\":\"Lambda\"}")
		fmt.Fprintln(w, "data: [DONE]")
	}))
	defer srv.Close()

	client := NewComposeClient(srv.URL, "test-token")
	components, err := client.Propose(context.Background(), "static site")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(components))
	}
	if components[0].Name != "S3" {
		t.Errorf("expected S3, got %s", components[0].Name)
	}
}

func TestComposeClientProposeJSONFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `[{"name":"DynamoDB","description":"NoSQL data store","service":"DynamoDB"}]`)
	}))
	defer srv.Close()

	client := NewComposeClient(srv.URL, "")
	components, err := client.Propose(context.Background(), "data store")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(components) != 1 || components[0].Name != "DynamoDB" {
		t.Fatalf("expected DynamoDB, got %v", components)
	}
}

func TestComposeClientProposeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	client := NewComposeClient(srv.URL, "")
	_, err := client.Propose(context.Background(), "x")
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
	if !strings.Contains(err.Error(), "propose returned status 400") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestComposeClientResolve(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/compose/aws/resolve" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"intent":"resolved","components":[{"name":"S3","description":"d","service":"S3"}],"version":2}`)
	}))
	defer srv.Close()

	client := NewComposeClient(srv.URL, "test-token")
	plan, err := client.Resolve(context.Background(), []Component{{Name: "S3", Description: "d", Service: "S3"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.Intent != "resolved" {
		t.Errorf("expected intent 'resolved', got %q", plan.Intent)
	}
	if plan.Version != 2 {
		t.Errorf("expected version 2, got %d", plan.Version)
	}
	if plan.ADRContent == "" {
		t.Error("expected ADR to be rendered")
	}
	if plan.MermaidContent == "" {
		t.Error("expected Mermaid to be rendered")
	}
}
