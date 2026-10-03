package proxyorigin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
)

func TestCompareResponsesIdentical(t *testing.T) {
	origin := &httpclient.Response{Status: 200, Body: []byte("hello world")}
	proxy := &httpclient.Response{Status: 200, Body: []byte("hello world")}

	diff := CompareResponses("root", origin, proxy)
	if !diff.SameStatus {
		t.Fatal("CompareResponses() SameStatus = false, want true")
	}
	if !diff.SameBody {
		t.Fatal("CompareResponses() SameBody = false, want true")
	}
	if diff.BodyDelta != 0 {
		t.Fatalf("CompareResponses() BodyDelta = %v, want 0", diff.BodyDelta)
	}
	if diff.OriginStatus != 200 || diff.ProxyStatus != 200 {
		t.Fatalf("CompareResponses() statuses = (%d, %d), want (200, 200)", diff.OriginStatus, diff.ProxyStatus)
	}
}

func TestCompareResponsesStatusMismatch(t *testing.T) {
	origin := &httpclient.Response{Status: 200, Body: []byte("ok")}
	proxy := &httpclient.Response{Status: 403, Body: []byte("ok")}

	diff := CompareResponses("protected", origin, proxy)
	if diff.SameStatus {
		t.Fatal("CompareResponses() SameStatus = true, want false")
	}
	if !diff.SameBody {
		t.Fatal("CompareResponses() SameBody = false, want true for equal bodies")
	}
	if diff.Notes == "" {
		t.Fatal("CompareResponses() Notes is empty for a status mismatch")
	}
}

func TestCompareResponsesBodyMismatch(t *testing.T) {
	origin := &httpclient.Response{Status: 200, Body: []byte("aaaaaaaaaa")}
	proxy := &httpclient.Response{Status: 200, Body: []byte("bbbbbbbbbb")}

	diff := CompareResponses("body", origin, proxy)
	if !diff.SameStatus {
		t.Fatal("CompareResponses() SameStatus = false, want true")
	}
	if diff.SameBody {
		t.Fatal("CompareResponses() SameBody = true, want false")
	}
	if diff.BodyDelta <= 0 || diff.BodyDelta > 1 {
		t.Fatalf("CompareResponses() BodyDelta = %v, want in (0,1]", diff.BodyDelta)
	}
}

func TestCompareResponsesNilResponse(t *testing.T) {
	diff := CompareResponses("missing", nil, &httpclient.Response{Status: 500})
	if diff.SameStatus || diff.SameBody {
		t.Fatalf("CompareResponses() with a nil origin = %+v, want not-same", diff)
	}
	if diff.ProxyStatus != 500 {
		t.Fatalf("CompareResponses() ProxyStatus = %d, want 500", diff.ProxyStatus)
	}
}

func TestBodyDeltaEmptyBodies(t *testing.T) {
	if got := bodyDelta(nil, nil); got != 0 {
		t.Fatalf("bodyDelta(nil, nil) = %v, want 0", got)
	}
	if got := bodyDelta(nil, []byte("x")); got != 1 {
		t.Fatalf("bodyDelta(nil, x) = %v, want 1", got)
	}
}

func TestCompareUsesBothClients(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Route") == "proxy" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("blocked"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("origin"))
	}))
	defer server.Close()

	originClient := httpclient.New(httpclient.Config{Timeout: time.Second, MaxRetries: 0})
	proxyClient := httpclient.New(httpclient.Config{
		Timeout:    time.Second,
		MaxRetries: 0,
		Headers:    map[string]string{"X-Route": "proxy"},
	})

	report, err := Compare(context.Background(), originClient, proxyClient, []Endpoint{
		{URL: server.URL, Label: "root"},
	})
	if err != nil {
		t.Fatalf("Compare() error = %v", err)
	}
	if len(report.Diffs) != 1 {
		t.Fatalf("Compare() produced %d diffs, want 1", len(report.Diffs))
	}
	if report.Consistent {
		t.Fatal("Compare() reported Consistent = true, want false")
	}
	if report.Diffs[0].OriginStatus != http.StatusOK || report.Diffs[0].ProxyStatus != http.StatusForbidden {
		t.Fatalf("Compare() statuses = (%d, %d), want (200, 403)", report.Diffs[0].OriginStatus, report.Diffs[0].ProxyStatus)
	}
}

func TestCompareRejectsNilClients(t *testing.T) {
	if _, err := Compare(context.Background(), nil, nil, nil); err == nil {
		t.Fatal("Compare() accepted a nil client")
	}
}
