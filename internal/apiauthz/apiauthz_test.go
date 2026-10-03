package apiauthz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/authz"
	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
	"github.com/gl1tch0x1/YourWAFSucks/internal/openapi"
)

const specJSON = `{
  "openapi": "3.0.0",
  "info": {"title": "T", "version": "1"},
  "security": [{"bearerAuth": []}],
  "paths": {
    "/admin": {"get": {"operationId": "admin"}},
    "/private": {"get": {"operationId": "private"}},
    "/health": {"get": {"operationId": "health", "security": []}}
  }
}`

func TestTestFindsUnauthAndEscalation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authed := r.Header.Get("Authorization") == "Bearer good"
		switch r.URL.Path {
		case "/admin":
			_, _ = w.Write([]byte("admin-panel"))
		case "/private":
			if authed {
				w.WriteHeader(200)
				_, _ = w.Write([]byte("secret"))
				return
			}
			w.WriteHeader(403)
			_, _ = w.Write([]byte("denied"))
		default:
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()

	spec, err := openapi.Parse([]byte(specJSON))
	if err != nil {
		t.Fatalf("Parse spec: %v", err)
	}
	sm := authz.NewSessionManager()
	if err := sm.AddSession(&authz.SessionContext{Name: "admin", Credentials: authz.Credentials{Type: "bearer", Token: "good"}}); err != nil {
		t.Fatalf("AddSession: %v", err)
	}
	client := httpclient.New(httpclient.Config{Timeout: 5 * time.Second, UserAgent: "test", MaxRetries: 0})

	findings, matrix, err := Test(context.Background(), client, sm, spec, Options{Target: srv.URL})
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if matrix == nil || len(matrix.Cells) != 6 {
		t.Fatalf("expected 6 matrix cells (3 endpoints x 2 sessions), got %+v", matrix)
	}

	var unauth, escalation bool
	for _, f := range findings {
		switch {
		case f.Session == "anonymous" && f.Endpoint == "GET /admin" && f.Severity == "high":
			unauth = true
		case f.Session == "admin" && f.Endpoint == "GET /private" && f.Severity == "high":
			escalation = true
		}
	}
	if !unauth {
		t.Fatalf("expected unauthenticated-access finding, got %+v", findings)
	}
	if !escalation {
		t.Fatalf("expected privilege-escalation finding, got %+v", findings)
	}

	results := ToResults(findings)
	if len(results) != len(findings) {
		t.Fatalf("ToResults length = %d, findings = %d", len(results), len(findings))
	}
	for _, r := range results {
		if r.Payload.Technique != "apiauthz" {
			t.Fatalf("unexpected technique %q", r.Payload.Technique)
		}
	}
}

func TestTestRequiresSpecAndSessions(t *testing.T) {
	client := httpclient.New(httpclient.Config{Timeout: time.Second, UserAgent: "t"})
	if _, _, err := Test(context.Background(), client, authz.NewSessionManager(), nil, Options{}); err == nil {
		t.Fatalf("expected error for nil spec")
	}
	spec, _ := openapi.Parse([]byte(specJSON))
	if _, _, err := Test(context.Background(), client, nil, spec, Options{}); err == nil {
		t.Fatalf("expected error for nil session manager")
	}
}
