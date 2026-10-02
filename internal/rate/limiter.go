package rate

import (
	"context"
	"sync"
	"time"
)

// Limiter implements an adaptive rate limiter with backoff
type Limiter struct {
	mu          sync.Mutex
	rate        int           // requests per second
	burst       int           // maximum burst size
	tokens      float64       // current token count
	lastUpdate  time.Time     // last token refill time
	errorCount  int           // consecutive errors
	maxErrors   int           // max errors before backoff
	backoffTime time.Duration // current backoff duration
	adaptive    bool          // enable adaptive rate limiting
}

// New creates a new rate limiter
func New(rate, burst int, adaptive bool) *Limiter {
	if rate <= 0 {
		rate = 1
	}
	if burst <= 0 {
		burst = 1
	}
	return &Limiter{
		rate:        rate,
		burst:       burst,
		tokens:      float64(burst),
		lastUpdate:  time.Now(),
		maxErrors:   10,
		backoffTime: 0,
		adaptive:    adaptive,
	}
}

// Wait blocks until a token is available or context is cancelled
func (l *Limiter) Wait(ctx context.Context) error {
	for {
		l.mu.Lock()
		backoff := l.backoffTime
		l.mu.Unlock()

		if backoff > 0 {
			timer := time.NewTimer(backoff)
			select {
			case <-timer.C:
				l.mu.Lock()
				if l.backoffTime == backoff {
					l.backoffTime = 0
				}
				l.mu.Unlock()
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			}
			continue
		}

		if err := l.wait(ctx); err != nil {
			return err
		}

		l.mu.Lock()
		backoff = l.backoffTime
		l.mu.Unlock()
		if backoff > 0 {
			continue
		}
		return nil
	}
}

func (l *Limiter) wait(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.lastUpdate).Seconds()

	// Refill tokens based on elapsed time
	l.tokens += elapsed * float64(l.rate)
	if l.tokens > float64(l.burst) {
		l.tokens = float64(l.burst)
	}
	l.lastUpdate = now

	// If we have tokens, consume one
	if l.tokens >= 1 {
		l.tokens -= 1
		return nil
	}

	// Calculate wait time for next token
	waitTime := time.Duration((1 - l.tokens) / float64(l.rate) * float64(time.Second))
	timer := time.NewTimer(waitTime)
	defer timer.Stop()
	select {
	case <-timer.C:
		l.tokens -= 1
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// RecordError records an error and triggers backoff if needed
func (l *Limiter) RecordError() {
	if !l.adaptive {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.errorCount++

	// Exponential backoff
	if l.errorCount >= l.maxErrors {
		l.backoffTime = time.Duration(1<<uint(l.errorCount-l.maxErrors+1)) * time.Second
		if l.backoffTime > 30*time.Second {
			l.backoffTime = 30 * time.Second
		}
	}
}

// RecordSuccess resets error count
func (l *Limiter) RecordSuccess() {
	if !l.adaptive {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.errorCount = 0
	l.backoffTime = 0
}

// SetRate dynamically adjusts the rate limit
func (l *Limiter) SetRate(rate int) {
	if rate <= 0 {
		rate = 1
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	l.rate = rate
	if l.burst < rate {
		l.burst = rate
	}
}

// GetStats returns current limiter statistics
func (l *Limiter) GetStats() Stats {
	l.mu.Lock()
	defer l.mu.Unlock()

	return Stats{
		Rate:        l.rate,
		Burst:       l.burst,
		Tokens:      l.tokens,
		ErrorCount:  l.errorCount,
		BackoffTime: l.backoffTime,
	}
}

// Stats represents limiter statistics
type Stats struct {
	Rate        int
	Burst       int
	Tokens      float64
	ErrorCount  int
	BackoffTime time.Duration
}
