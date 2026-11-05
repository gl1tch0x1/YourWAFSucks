package protocol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
)

func resp(status int, body string) *httpclient.Response {
	return &httpclient.Response{Status: status, Body: []byte(body)}
}

func TestCompareRequestEquivalent(t *testing.T) {
	if _, found := CompareRequest("GET /x", resp(200, "same"), resp(200, "same")); found {
		t.Fatalf("expected no discrepancy for identical responses")
	}
}

func TestCompareRequestStatusMismatch(t *testing.T) {
	d, found := CompareRequest("GET /x", resp(200, "ok"), resp(403, "denied"))
	if !found || d.Kind != "status" || d.StatusA != 200 || d.StatusB != 403 {
		t.Fatalf("unexpected discrepancy: %+v found=%v", d, found)
	}
}

func TestCompareRequestBodyKinds(t *testing.T) {
	d, found := CompareRequest("GET /x", resp(200, "abc"), resp(200, "abcdef"))
	if !found || d.Kind != "length" {
		t.Fatalf("expected length discrepancy, got %+v found=%v", d, found)
	}
	d, found = CompareRequest("GET /x", resp(200, "abc"), resp(200, "abd"))
	if !found || d.Kind != "body" {
		t.Fatalf("expected body discrepancy, got %+v found=%v", d, found)
	}
}

func TestCompareRequestNil(t *testing.T) {
	d, found := CompareRequest("GET /x", nil, resp(200, "x"))
	if !found || d.Kind != "error" {
		t.Fatalf("expected error discrepancy, got %+v", d)
	}
}

func TestDetectAgainstServers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Client") == "A" {
			_, _ = w.Write([]byte("alpha"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("beta"))
	}))
	defer srv.Close()

	ca := httpclient.New(httpclient.Config{Timeout: 5 * time.Second, UserAgent: "t", MaxRetries: 0, Headers: map[string]string{"X-Client": "A"}})
	cb := httpclient.New(httpclient.Config{Timeout: 5 * time.Second, UserAgent: "t", MaxRetries: 0, Headers: map[string]string{"X-Client": "B"}})

	report, err := Detect(context.Background(), ca, cb, []httpclient.Request{{Method: "GET", URL: srv.URL + "/x"}})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if report.Requests != 1 || report.Consistent || len(report.Discrepancies) != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.Discrepancies[0].Kind != "status" {
		t.Fatalf("expected status discrepancy, got %+v", report.Discrepancies[0])
	}
}

func TestDetectNilClient(t *testing.T) {
	if _, err := Detect(context.Background(), nil, nil, nil); err == nil {
		t.Fatalf("expected error for nil clients")
	}
}
