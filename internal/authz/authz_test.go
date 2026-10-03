package authz

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
)

func TestParseSessionCookieWithQuotedValue(t *testing.T) {
	s, err := ParseSession(`admin;type=cookie;cookie="sid=abc; role=admin"`)
	if err != nil {
		t.Fatalf("ParseSession: %v", err)
	}
	if s.Name != "admin" {
		t.Fatalf("name = %q", s.Name)
	}
	if s.Credentials.Type != "cookie" {
		t.Fatalf("type = %q", s.Credentials.Type)
	}
	if s.Credentials.Cookie != "sid=abc; role=admin" {
		t.Fatalf("cookie = %q", s.Credentials.Cookie)
	}
}

func TestParseSessionInfersType(t *testing.T) {
	s, err := ParseSession(`api;token=secret`)
	if err != nil {
		t.Fatalf("ParseSession: %v", err)
	}
	if s.Credentials.Type != "bearer" {
		t.Fatalf("type = %q, want bearer", s.Credentials.Type)
	}
}

func TestParseSessionHeaderColonForm(t *testing.T) {
	s, err := ParseSession(`svc;header="X-Service-Token: s3cr3t"`)
	if err != nil {
		t.Fatalf("ParseSession: %v", err)
	}
	if s.Credentials.Type != "header" || s.Credentials.HeaderName != "X-Service-Token" || s.Credentials.HeaderValue != "s3cr3t" {
		t.Fatalf("unexpected header credentials: %+v", s.Credentials)
	}
}

func TestParseSessionBasicShorthand(t *testing.T) {
	s, err := ParseSession(`legacy;basic:alice=wonderland`)
	if err != nil {
		t.Fatalf("ParseSession: %v", err)
	}
	if s.Credentials.Type != "basic" || s.Credentials.Username != "alice" || s.Credentials.Password != "wonderland" {
		t.Fatalf("unexpected basic credentials: %+v", s.Credentials)
	}
}

func TestParseSessionErrors(t *testing.T) {
	if _, err := ParseSession("type=bearer;token=x"); err == nil {
		t.Fatalf("expected missing-name error")
	}
	if _, err := ParseSession(`name=a;bogus=1`); err == nil {
		t.Fatalf("expected unknown-field error")
	}
	if _, err := ParseSession(`name=a;cookie="unterminated`); err == nil {
		t.Fatalf("expected unterminated-quote error")
	}
}

func TestApplyCredentialsBasicEncodesBase64(t *testing.T) {
	req := &httpclient.Request{}
	ApplyCredentials(&SessionContext{Credentials: Credentials{Type: "basic", Username: "u", Password: "p"}}, req)
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("u:p"))
	if req.Headers["Authorization"] != want {
		t.Fatalf("Authorization = %q, want %q", req.Headers["Authorization"], want)
	}
}

func TestDifferentialsClassification(t *testing.T) {
	m := &Matrix{
		Sessions: []string{"anonymous", "admin", "denied"},
		Endpoints: []Endpoint{
			{Method: "GET", URL: "https://x/admin", Label: "GET /admin"},
			{Method: "GET", URL: "https://x/public", Label: "GET /public"},
		},
		Cells: []Cell{
			{Session: "anonymous", Endpoint: "GET /admin", Status: 403, BodyHash: "a"},
			{Session: "admin", Endpoint: "GET /admin", Status: 200, BodyHash: "b"},
			{Session: "denied", Endpoint: "GET /admin", Status: 403, BodyHash: "a"},
			{Session: "anonymous", Endpoint: "GET /public", Status: 200, BodyHash: "c"},
			{Session: "admin", Endpoint: "GET /public", Status: 200, BodyHash: "c"},
			{Session: "denied", Endpoint: "GET /public", Status: 403, BodyHash: "d"},
		},
	}
	diffs := m.Differentials("anonymous")
	if len(diffs) != 2 {
		t.Fatalf("expected 2 differentials, got %d: %+v", len(diffs), diffs)
	}
	var grant, deny *Differential
	for i := range diffs {
		switch diffs[i].Session {
		case "admin":
			grant = &diffs[i]
		case "denied":
			deny = &diffs[i]
		}
	}
	if grant == nil || grant.Severity != "high" || !grant.AccessGranted {
		t.Fatalf("admin differential = %+v", grant)
	}
	if deny == nil || deny.Severity != "low" {
		t.Fatalf("denied differential = %+v", deny)
	}
}

func TestRunMatrixAgainstServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer good" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("admin dashboard"))
			return
		}
		w.WriteHeader(403)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	client := httpclient.New(httpclient.Config{Timeout: 5 * time.Second, UserAgent: "test", MaxRetries: 0})
	admin := &SessionContext{Name: "admin", Credentials: Credentials{Type: "bearer", Token: "good"}}
	anon := &SessionContext{Name: "anonymous", Credentials: Credentials{Type: "none"}}

	m, err := RunMatrix(context.Background(), client, []*SessionContext{anon, admin},
		[]Endpoint{{Method: "GET", URL: srv.URL + "/admin", Label: "GET /admin"}}, MatrixOptions{})
	if err != nil {
		t.Fatalf("RunMatrix: %v", err)
	}
	if len(m.Cells) != 2 {
		t.Fatalf("expected 2 cells, got %d", len(m.Cells))
	}
	diffs := m.Differentials("anonymous")
	if len(diffs) != 1 || diffs[0].Severity != "high" {
		t.Fatalf("expected one high differential, got %+v", diffs)
	}
}
