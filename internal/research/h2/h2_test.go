package h2

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
)

func TestProbesNonEmpty(t *testing.T) {
	probes := Probes()
	if len(probes) == 0 {
		t.Fatal("Probes() returned no probes")
	}
	for i, p := range probes {
		if strings.TrimSpace(p.Name) == "" {
			t.Fatalf("Probes()[%d].Name is empty", i)
		}
		if strings.TrimSpace(p.Description) == "" {
			t.Fatalf("Probes()[%d].Description is empty", i)
		}
	}
}

func TestSummarizeDeterministic(t *testing.T) {
	obs := []Observation{
		{Probe: "default-get", HTTPVersion: "HTTP/2", Status: 200, NegotiatedH2: true},
		{Probe: "head", HTTPVersion: "HTTP/1.x", Status: 204},
		{Probe: "options", Error: "dial tcp: timeout"},
	}

	first := Summarize(obs)
	second := Summarize(obs)
	if first != second {
		t.Fatalf("Summarize() is not deterministic:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
	if !strings.Contains(first, "default-get") || !strings.Contains(first, "HTTP/2") {
		t.Fatalf("Summarize() missing expected content:\n%s", first)
	}
	if !strings.Contains(first, "1/3") {
		t.Fatalf("Summarize() did not count HTTP/2 observations:\n%s", first)
	}

	if got := Summarize(nil); !strings.Contains(got, "no observations") {
		t.Fatalf("Summarize(nil) = %q, want an empty-state message", got)
	}
}

func TestSupportedDetectsHints(t *testing.T) {
	hinted := &httpclient.Response{Headers: http.Header{"X-Firefox-Spdy": {"h2"}}}
	if !Supported(hinted) {
		t.Fatal("Supported() = false, want true for X-Firefox-Spdy hint")
	}
	if Supported(nil) {
		t.Fatal("Supported(nil) = true, want false")
	}
	plain := &httpclient.Response{Headers: http.Header{"Server": {"nginx"}}}
	if Supported(plain) {
		t.Fatal("Supported() = true for a response with no HTTP/2 hints")
	}
}

func TestObserveRunsSafeProbes(t *testing.T) {
	var methods []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := httpclient.New(httpclient.Config{Timeout: time.Second, MaxRetries: 0})
	observations, err := Observe(context.Background(), client, server.URL)
	if err != nil {
		t.Fatalf("Observe() error = %v", err)
	}
	if len(observations) != len(Probes()) {
		t.Fatalf("Observe() returned %d observations, want %d", len(observations), len(Probes()))
	}
	for _, o := range observations {
		if o.Error != "" {
			t.Fatalf("Observe() probe %q error = %q", o.Probe, o.Error)
		}
		if o.Status != http.StatusOK {
			t.Fatalf("Observe() probe %q status = %d, want %d", o.Probe, o.Status, http.StatusOK)
		}
	}
	for _, want := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		found := false
		for _, got := range methods {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Observe() did not issue a %s request; saw %v", want, methods)
		}
	}
}

func TestObserveRejectsInvalidArguments(t *testing.T) {
	client := httpclient.New(httpclient.Config{Timeout: time.Second})
	if _, err := Observe(context.Background(), nil, "example.test"); err == nil {
		t.Fatal("Observe() accepted a nil client")
	}
	if _, err := Observe(context.Background(), client, "   "); err == nil {
		t.Fatal("Observe() accepted an empty target")
	}
}
