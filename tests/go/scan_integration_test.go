package score_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/calibrate"
	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
	"github.com/gl1tch0x1/YourWAFSucks/internal/rate"
	"github.com/gl1tch0x1/YourWAFSucks/internal/replay"
	"github.com/gl1tch0x1/YourWAFSucks/internal/score"
	"github.com/gl1tch0x1/YourWAFSucks/internal/techniques"
)

func TestScanWorkflowAgainstLocalServer(t *testing.T) {
	var received atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		if r.URL.Path != "/admin" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-Forwarded-For") == "127.0.0.1" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("admin dashboard"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer server.Close()
	server.Config.SetKeepAlivesEnabled(false)

	parsedTarget, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	target := server.URL + "/admin"
	client := httpclient.New(httpclient.Config{
		Timeout:      time.Second,
		MaxRetries:   0,
		MaxRequests:  20,
		AllowedHosts: []string{parsedTarget.Hostname()},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	baseline, err := calibrate.Run(ctx, client, target)
	if err != nil {
		t.Fatalf("calibrate.Run() error: %v", err)
	}
	if baseline.BaselineStatus != http.StatusForbidden {
		t.Fatalf("baseline status = %d, want %d", baseline.BaselineStatus, http.StatusForbidden)
	}

	var payload techniques.Payload
	for _, candidate := range (techniques.Headers{}).Generate(techniques.Context{Target: target, BypassIP: "127.0.0.1"}) {
		if candidate.Headers["X-Forwarded-For"] == "127.0.0.1" {
			payload = candidate
			break
		}
	}
	if payload.URL == "" {
		t.Fatal("header technique did not generate the expected payload")
	}

	response, err := client.Request(ctx, httpclient.Request{
		Method:  payload.Method,
		URL:     payload.URL,
		Headers: payload.Headers,
	})
	if err != nil {
		t.Fatalf("mutated request error: %v", err)
	}
	findingScore := score.Compute(response, baseline)
	if !findingScore.Interesting {
		t.Fatalf("expected a finding, got %+v", findingScore)
	}

	findings := replay.Verify(ctx, client, []techniques.Result{{
		Payload:  payload,
		Response: response,
		Score:    findingScore,
	}})
	if len(findings) != 1 || findings[0].ReplayCount != 2 {
		t.Fatalf("replay results = %+v, want one finding replayed twice", findings)
	}
	if got := client.RequestsMade(); got != 8 {
		t.Errorf("HTTP attempts = %d, want 8", got)
	}
	if got := received.Load(); got != 8 {
		t.Errorf("server requests = %d, want 8", got)
	}
}

func TestRateLimiterHonorsContextWhileWaiting(t *testing.T) {
	limiter := rate.New(1, 1, false)
	if err := limiter.Wait(context.Background()); err != nil {
		t.Fatalf("initial limiter wait error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := limiter.Wait(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("limiter wait error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("cancelled limiter wait took %s, want under 500ms", elapsed)
	}
}
