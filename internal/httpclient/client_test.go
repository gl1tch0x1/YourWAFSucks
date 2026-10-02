package httpclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRequestEnforcesMaximumRequestBudget(t *testing.T) {
	var received atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(Config{
		Timeout:     time.Second,
		MaxRetries:  0,
		MaxRequests: 2,
	})

	for range 2 {
		if _, err := client.Request(context.Background(), Request{Method: http.MethodGet, URL: server.URL}); err != nil {
			t.Fatalf("Request() error before budget was exhausted: %v", err)
		}
	}

	if _, err := client.Request(context.Background(), Request{Method: http.MethodGet, URL: server.URL}); !errors.Is(err, ErrRequestLimit) {
		t.Fatalf("Request() error = %v, want %v", err, ErrRequestLimit)
	}
	if got := received.Load(); got != 2 {
		t.Fatalf("server received %d requests, want 2", got)
	}
	if got := client.RequestsMade(); got != 2 {
		t.Fatalf("RequestsMade() = %d, want 2", got)
	}
}

func TestRequestRejectsHostOutsideAllowlist(t *testing.T) {
	var received atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(Config{
		Timeout:      time.Second,
		MaxRetries:   0,
		AllowedHosts: []string{"allowed.example"},
	})
	if _, err := client.Request(context.Background(), Request{Method: http.MethodGet, URL: server.URL}); !errors.Is(err, ErrHostNotAllowed) {
		t.Fatalf("Request() error = %v, want %v", err, ErrHostNotAllowed)
	}
	if got := received.Load(); got != 0 {
		t.Fatalf("server received %d requests, want 0", got)
	}
}

func TestRequestRejectsUntrustedTLSCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(Config{Timeout: time.Second, MaxRetries: 0})
	if _, err := client.Request(context.Background(), Request{Method: http.MethodGet, URL: server.URL}); err == nil {
		t.Fatal("Request() accepted an untrusted TLS certificate")
	}
}

func TestInvalidProxyFailsClosed(t *testing.T) {
	client := New(Config{Proxy: "socks5://proxy.example:1080", Timeout: time.Second})
	_, err := client.Request(context.Background(), Request{Method: http.MethodGet, URL: "http://example.test/"})
	if err == nil {
		t.Fatal("Request() silently ignored an unsupported proxy scheme")
	}
}

func TestNegativeRetryCountReturnsError(t *testing.T) {
	client := New(Config{MaxRetries: -1})
	response, err := client.Request(context.Background(), Request{Method: http.MethodGet, URL: "http://example.test/"})
	if err == nil || response != nil {
		t.Fatalf("Request() = (%v, %v), want (nil, error)", response, err)
	}
}
