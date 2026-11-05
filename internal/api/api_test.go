package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
	"github.com/gl1tch0x1/YourWAFSucks/internal/techniques"
)

func sampleFindings() []techniques.Result {
	r := techniques.Result{
		Payload: techniques.Payload{
			Technique:   "headers",
			Method:      "GET",
			URL:         "https://user:pass@example.test/admin?access_token=secret&view=full",
			Description: "spoof",
			Headers:     map[string]string{"Authorization": "Bearer secret-token"},
		},
		Response:    &httpclient.Response{Status: 200},
		ReplayCount: 1,
	}
	r.Score.Score = 80
	r.Score.Reason = "status differs"
	return []techniques.Result{r}
}

func newTestServer(opts Options) *httptest.Server {
	return httptest.NewServer(NewServer(opts).Handler())
}

func TestHealthzAndVersion(t *testing.T) {
	srv := httptest.NewServer(NewServer(Options{Target: "https://example.test", Version: "1.2.3"}).Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d", resp.StatusCode)
	}
	var health map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if health["status"] != "ok" {
		t.Errorf("health = %v", health)
	}

	vresp, err := http.Get(srv.URL + "/version")
	if err != nil {
		t.Fatalf("GET /version: %v", err)
	}
	defer vresp.Body.Close()
	var version map[string]string
	if err := json.NewDecoder(vresp.Body).Decode(&version); err != nil {
		t.Fatalf("decode version: %v", err)
	}
	if version["version"] != "1.2.3" || version["name"] != "YourWAFSucks" {
		t.Errorf("version = %v", version)
	}
}

func TestFindingsRedacted(t *testing.T) {
	srv := newTestServer(Options{Target: "https://example.test", Version: "1", Findings: sampleFindings})
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/findings")
	if err != nil {
		t.Fatalf("GET /findings: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got []findingDTO
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode findings: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(got))
	}
	if got[0].URL != "https://example.test/admin?access_token=%5BREDACTED%5D&view=full" {
		t.Errorf("URL = %q, not redacted", got[0].URL)
	}
	if got[0].Headers["Authorization"] != "[REDACTED]" {
		t.Errorf("Authorization = %q, not redacted", got[0].Headers["Authorization"])
	}
	if got[0].Severity != "high" {
		t.Errorf("Severity = %q, want high", got[0].Severity)
	}
}

func TestFindingsNilReturnsEmptyArray(t *testing.T) {
	srv := newTestServer(Options{})
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/findings")
	if err != nil {
		t.Fatalf("GET /findings: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.TrimSpace(string(body)) != "[]" {
		t.Errorf("body = %q, want []", body)
	}
}

func TestScanValidation(t *testing.T) {
	srv := newTestServer(Options{})
	defer srv.Close()

	// Malformed JSON -> 400.
	resp, err := http.Post(srv.URL+"/scan", "application/json", strings.NewReader("{"))
	if err != nil {
		t.Fatalf("POST /scan: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed body status = %d, want 400", resp.StatusCode)
	}

	// Missing URL -> 400.
	resp, err = http.Post(srv.URL+"/scan", "application/json", strings.NewReader(`{"techniques":["headers"]}`))
	if err != nil {
		t.Fatalf("POST /scan: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("missing url status = %d, want 400", resp.StatusCode)
	}
}

func TestScanNotImplemented(t *testing.T) {
	srv := newTestServer(Options{})
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/scan", "application/json", strings.NewReader(`{"url":"https://example.test"}`))
	if err != nil {
		t.Fatalf("POST /scan: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", resp.StatusCode)
	}
}

func TestScanSuccessAndError(t *testing.T) {
	opts := Options{
		Scan: func(_ context.Context, req ScanRequest) ([]techniques.Result, error) {
			if req.URL != "https://example.test" {
				return nil, errors.New("bad url")
			}
			return sampleFindings(), nil
		},
	}
	srv := newTestServer(opts)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/scan", "application/json", strings.NewReader(`{"url":"https://example.test"}`))
	if err != nil {
		t.Fatalf("POST /scan: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got []findingDTO
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("len = %d, want 1", len(got))
	}
}

func TestSARIFEndpoint(t *testing.T) {
	srv := newTestServer(Options{Target: "https://example.test", Version: "2.0.0", Findings: sampleFindings})
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/findings.sarif")
	if err != nil {
		t.Fatalf("GET /findings.sarif: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"2.1.0"`) {
		t.Errorf("missing SARIF version: %s", body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "sarif") {
		t.Errorf("Content-Type = %q", ct)
	}
}

func TestAuth(t *testing.T) {
	srv := newTestServer(Options{Token: "s3cret", Findings: sampleFindings})
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/findings")
	if err != nil {
		t.Fatalf("GET /findings: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token status = %d, want 401", resp.StatusCode)
	}

	// /healthz is exempt.
	resp, err = http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz status = %d, want 200", resp.StatusCode)
	}

	// Wrong token.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/findings", nil)
	req.Header.Set("Authorization", "Bearer nope")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /findings: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong token status = %d, want 401", resp.StatusCode)
	}

	// Correct token.
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/findings", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /findings: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("correct token status = %d, want 200", resp.StatusCode)
	}
}
