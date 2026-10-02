package rate

import (
	"context"
	"testing"
	"time"
)

func TestNewNormalizesNonPositiveRateAndBurst(t *testing.T) {
	limiter := New(0, 0, false)
	stats := limiter.GetStats()
	if stats.Rate != 1 || stats.Tokens != 1 {
		t.Fatalf("New(0, 0) stats = %+v, want rate and initial token count 1", stats)
	}
	if err := limiter.Wait(context.Background()); err != nil {
		t.Fatalf("Wait() error: %v", err)
	}
}

func TestBackoffWaitCanBeCancelled(t *testing.T) {
	limiter := New(10, 1, true)
	for range 10 {
		limiter.RecordError()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := limiter.Wait(ctx); err != context.DeadlineExceeded {
		t.Fatalf("Wait() error = %v, want deadline exceeded", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancelled backoff wait exceeded one second")
	}
}
