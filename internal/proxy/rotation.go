package proxy

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"sync"
	"time"
)

// RotationStrategy defines how proxies are rotated
type RotationStrategy string

const (
	RoundRobin RotationStrategy = "round_robin"
	Random     RotationStrategy = "random"
	LeastUsed  RotationStrategy = "least_used"
)

// Proxy represents a proxy server
type Proxy struct {
	URL        string
	Healthy    bool
	LastUsed   time.Time
	UseCount   int
	ErrorCount int
}

// Manager handles proxy rotation
type Manager struct {
	proxies          []*Proxy
	currentIndex     int
	strategy         RotationStrategy
	healthCheck      bool
	failover         bool
	mu               sync.RWMutex
	healthCheckInterval time.Duration
}

// New creates a new proxy manager
func New(strategy RotationStrategy, healthCheck, failover bool) *Manager {
	return &Manager{
		strategy:            strategy,
		healthCheck:         healthCheck,
		failover:            failover,
		healthCheckInterval: 5 * time.Minute,
	}
}

// LoadFromFile loads proxies from a file
func (m *Manager) LoadFromFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open proxy file: %w", err)
	}
	defer file.Close()

	var proxies []*Proxy
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' {
			continue
		}

		// Validate proxy URL
		if _, err := url.Parse(line); err != nil {
			continue
		}

		proxies = append(proxies, &Proxy{
			URL:     line,
			Healthy: true,
		})
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading proxy file: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.proxies = proxies

	return nil
}

// Add adds a proxy to the manager
func (m *Manager) Add(proxyURL string) error {
	if _, err := url.Parse(proxyURL); err != nil {
		return fmt.Errorf("invalid proxy URL: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.proxies = append(m.proxies, &Proxy{
		URL:     proxyURL,
		Healthy: true,
	})

	return nil
}

// GetNext returns the next proxy to use
func (m *Manager) GetNext() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.proxies) == 0 {
		return "", fmt.Errorf("no proxies available")
	}

	// Filter healthy proxies
	var healthy []*Proxy
	for _, p := range m.proxies {
		if p.Healthy {
			healthy = append(healthy, p)
		}
	}

	if len(healthy) == 0 {
		if m.failover {
			// Fallback to unhealthy proxies
			healthy = m.proxies
		} else {
			return "", fmt.Errorf("no healthy proxies available")
		}
	}

	var selected *Proxy

	switch m.strategy {
	case RoundRobin:
		selected = m.roundRobin(healthy)
	case Random:
		selected = m.random(healthy)
	case LeastUsed:
		selected = m.leastUsed(healthy)
	default:
		selected = m.roundRobin(healthy)
	}

	selected.LastUsed = time.Now()
	selected.UseCount++

	return selected.URL, nil
}

func (m *Manager) roundRobin(proxies []*Proxy) *Proxy {
	proxy := proxies[m.currentIndex%len(proxies)]
	m.currentIndex++
	return proxy
}

func (m *Manager) random(proxies []*Proxy) *Proxy {
	return proxies[rand.Intn(len(proxies))]
}

func (m *Manager) leastUsed(proxies []*Proxy) *Proxy {
	selected := proxies[0]
	for _, p := range proxies {
		if p.UseCount < selected.UseCount {
			selected = p
		}
	}
	return selected
}

// MarkSuccess marks a proxy as successfully used
func (m *Manager) MarkSuccess(proxyURL string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, p := range m.proxies {
		if p.URL == proxyURL {
			p.Healthy = true
			p.ErrorCount = 0
			break
		}
	}
}

// MarkError marks a proxy as having an error
func (m *Manager) MarkError(proxyURL string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, p := range m.proxies {
		if p.URL == proxyURL {
			p.ErrorCount++
			if p.ErrorCount >= 5 {
				p.Healthy = false
			}
			break
		}
	}
}

// GetStats returns proxy statistics
func (m *Manager) GetStats() []ProxyStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make([]ProxyStats, len(m.proxies))
	for i, p := range m.proxies {
		stats[i] = ProxyStats{
			URL:        p.URL,
			Healthy:    p.Healthy,
			UseCount:   p.UseCount,
			ErrorCount: p.ErrorCount,
			LastUsed:   p.LastUsed,
		}
	}
	return stats
}

// ProxyStats represents proxy statistics
type ProxyStats struct {
	URL        string
	Healthy    bool
	UseCount   int
	ErrorCount int
	LastUsed   time.Time
}

// StartHealthCheck starts periodic health checks
func (m *Manager) StartHealthCheck(ctx context.Context, checkFunc func(string) bool) {
	if !m.healthCheck {
		return
	}

	ticker := time.NewTicker(m.healthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkAllHealth(checkFunc)
		}
	}
}

func (m *Manager) checkAllHealth(checkFunc func(string) bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, p := range m.proxies {
		healthy := checkFunc(p.URL)
		p.Healthy = healthy
		if healthy {
			p.ErrorCount = 0
		}
	}
}
