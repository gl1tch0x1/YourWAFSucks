package differential

import (
	"fmt"
	"math"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/calibrate"
	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
)

// Engine implements differential response analysis
type Engine struct {
	config Config
}

// Config holds differential engine configuration
type Config struct {
	BodySimilarityThreshold float64
	TimingThreshold         float64
	SizeThreshold           float64
	EnableSemanticAnalysis  bool
}

// Signals represents the differential signals detected
type Signals struct {
	StatusDelta      bool    `json:"status_delta"`
	BodyDelta        float64 `json:"body_delta"`
	HeaderDelta      float64 `json:"header_delta"`
	TimingDelta      float64 `json:"timing_delta"`
	SizeDelta        float64 `json:"size_delta"`
	RedirectDelta    bool    `json:"redirect_delta"`
	ContentTypeDelta bool    `json:"content_type_delta"`
	CookieDelta      float64 `json:"cookie_delta"`
}

// Result represents a differential analysis result
type Result struct {
	FindingConfidence float64  `json:"finding_confidence"`
	Signals           Signals  `json:"signals"`
	Stability         float64  `json:"stability"`
	ReplayCount       int      `json:"replay_count"`
	Reason            string   `json:"reason"`
	Evidence          Evidence `json:"evidence"`
}

// Evidence captures the differential evidence
type Evidence struct {
	BaselineStatus     int     `json:"baseline_status"`
	MutationStatus     int     `json:"mutation_status"`
	BaselineSize       int     `json:"baseline_size"`
	MutationSize       int     `json:"mutation_size"`
	BaselineTime       float64 `json:"baseline_time"`
	MutationTime       float64 `json:"mutation_time"`
	BaselineHash       string  `json:"baseline_hash"`
	MutationHash       string  `json:"mutation_hash"`
	ContentTypeChanged bool    `json:"content_type_changed"`
	RedirectChanged    bool    `json:"redirect_changed"`
}

// New creates a new differential engine
func New(cfg Config) *Engine {
	if cfg.BodySimilarityThreshold == 0 {
		cfg.BodySimilarityThreshold = 0.85
	}
	if cfg.TimingThreshold == 0 {
		cfg.TimingThreshold = 3.0
	}
	if cfg.SizeThreshold == 0 {
		cfg.SizeThreshold = 2.0
	}
	return &Engine{config: cfg}
}

// Analyze performs differential analysis between baseline and mutation
func (e *Engine) Analyze(baseline *httpclient.Response, mutation *httpclient.Response, cal *calibrate.Result) Result {
	signals := Signals{
		StatusDelta:   baseline.Status != mutation.Status,
		BodyDelta:     e.calculateBodyDelta(baseline.Body, mutation.Body),
		HeaderDelta:   e.calculateHeaderDelta(baseline.Headers, mutation.Headers),
		TimingDelta:   e.calculateTimingDelta(baseline.Time, mutation.Time, cal),
		SizeDelta:     e.calculateSizeDelta(len(baseline.Body), len(mutation.Body)),
		RedirectDelta: e.calculateRedirectDelta(baseline.Redirect, mutation.Redirect),
	}

	// Content type delta
	baselineCT := baseline.ContentType
	mutationCT := mutation.ContentType
	signals.ContentTypeDelta = baselineCT != mutationCT

	// Cookie delta
	signals.CookieDelta = e.calculateCookieDelta(baseline.Headers, mutation.Headers)

	// Calculate overall confidence
	confidence := e.calculateConfidence(signals, baseline.Status, mutation.Status)

	// Generate reason
	reason := e.generateReason(signals, baseline.Status, mutation.Status)

	// Build evidence
	evidence := Evidence{
		BaselineStatus:     baseline.Status,
		MutationStatus:     mutation.Status,
		BaselineSize:       len(baseline.Body),
		MutationSize:       len(mutation.Body),
		BaselineTime:       baseline.Time.Seconds(),
		MutationTime:       mutation.Time.Seconds(),
		BaselineHash:       hash(baseline.Body),
		MutationHash:       hash(mutation.Body),
		ContentTypeChanged: signals.ContentTypeDelta,
		RedirectChanged:    signals.RedirectDelta,
	}

	return Result{
		FindingConfidence: confidence,
		Signals:           signals,
		Stability:         0.0, // Will be set by replay verification
		ReplayCount:       0,
		Reason:            reason,
		Evidence:          evidence,
	}
}

// calculateBodyDelta computes body similarity (0-1, where 1 = identical)
func (e *Engine) calculateBodyDelta(baseline, mutation []byte) float64 {
	if len(baseline) == 0 && len(mutation) == 0 {
		return 1.0
	}
	if len(baseline) == 0 || len(mutation) == 0 {
		return 0.0
	}

	// Fast path: identical hash
	if hash(baseline) == hash(mutation) {
		return 1.0
	}

	// Size-based similarity
	maxLen := float64(max(len(baseline), len(mutation)))
	minLen := float64(min(len(baseline), len(mutation)))
	sizeRatio := minLen / maxLen

	// Byte-level similarity (simplified for now)
	// TODO: Enhance with DOM/JSON/text semantic analysis
	byteSimilarity := calculateByteSimilarity(baseline, mutation)

	// Combine size and byte similarity
	return (sizeRatio + byteSimilarity) / 2.0
}

// calculateHeaderDelta computes header similarity
func (e *Engine) calculateHeaderDelta(baseline, mutation map[string][]string) float64 {
	if len(baseline) == 0 && len(mutation) == 0 {
		return 1.0
	}

	// Count matching headers
	matches := 0
	total := 0

	for k, v1 := range baseline {
		total++
		if v2, ok := mutation[k]; ok {
			if compareSlices(v1, v2) {
				matches++
			}
		}
	}

	for k := range mutation {
		if _, ok := baseline[k]; !ok {
			total++
		}
	}

	if total == 0 {
		return 1.0
	}

	return float64(matches) / float64(total)
}

// calculateTimingDelta computes timing difference
func (e *Engine) calculateTimingDelta(baselineTime, mutationTime time.Duration, cal *calibrate.Result) float64 {
	if cal.BaselineTime == 0 || baselineTime == 0 || mutationTime == 0 {
		// No reliable timing reference; treat as identical so an unmeasured
		// baseline does not fabricate a timing-anomaly signal.
		return 1.0
	}

	_ = baselineTime // Use mutationTime relative to calibration baseline
	ratio := mutationTime.Seconds() / cal.BaselineTime.Seconds()

	// Normalize to 0-1 range where 1 = identical timing
	if ratio >= 0.9 && ratio <= 1.1 {
		return 1.0
	}

	// Calculate delta from ideal (1.0)
	delta := math.Abs(1.0 - ratio)

	// Clamp to 0-1
	if delta > 1.0 {
		return 0.0
	}

	return 1.0 - delta
}

// calculateSizeDelta computes size difference
func (e *Engine) calculateSizeDelta(baselineSize, mutationSize int) float64 {
	if baselineSize == 0 && mutationSize == 0 {
		return 1.0
	}
	if baselineSize == 0 || mutationSize == 0 {
		return 0.0
	}

	maxSize := float64(max(baselineSize, mutationSize))
	minSize := float64(min(baselineSize, mutationSize))

	return minSize / maxSize
}

// calculateRedirectDelta checks if redirect changed
func (e *Engine) calculateRedirectDelta(baselineRedirect, mutationRedirect string) bool {
	return baselineRedirect != mutationRedirect
}

// calculateCookieDelta computes cookie similarity
func (e *Engine) calculateCookieDelta(baseline, mutation map[string][]string) float64 {
	baselineCookies := getCookies(baseline)
	mutationCookies := getCookies(mutation)

	if len(baselineCookies) == 0 && len(mutationCookies) == 0 {
		return 1.0
	}

	matches := 0
	total := 0

	for k, v1 := range baselineCookies {
		total++
		if v2, ok := mutationCookies[k]; ok && v1 == v2 {
			matches++
		}
	}

	for k := range mutationCookies {
		if _, ok := baselineCookies[k]; !ok {
			total++
		}
	}

	if total == 0 {
		return 1.0
	}

	return float64(matches) / float64(total)
}

// calculateConfidence computes overall finding confidence
func (e *Engine) calculateConfidence(signals Signals, baselineStatus, mutationStatus int) float64 {
	confidence := 0.0
	weight := 0.0

	// Status delta is the strongest signal
	if signals.StatusDelta {
		_ = baselineStatus // Use baselineStatus for future comparison logic
		// 2xx is very significant
		if mutationStatus >= 200 && mutationStatus < 300 {
			confidence += 0.4
			weight += 0.4
		} else if mutationStatus >= 300 && mutationStatus < 400 {
			confidence += 0.2
			weight += 0.2
		} else {
			confidence += 0.1
			weight += 0.1
		}
	}

	// Body delta
	if signals.BodyDelta < e.config.BodySimilarityThreshold {
		diff := 1.0 - signals.BodyDelta
		confidence += diff * 0.3
		weight += 0.3
	}

	// Timing delta
	if signals.TimingDelta < (1.0 / e.config.TimingThreshold) {
		confidence += 0.1
		weight += 0.1
	}

	// Size delta
	if signals.SizeDelta < (1.0 / e.config.SizeThreshold) {
		confidence += 0.1
		weight += 0.1
	}

	// Redirect delta
	if signals.RedirectDelta {
		confidence += 0.05
		weight += 0.05
	}

	// Content type delta
	if signals.ContentTypeDelta {
		confidence += 0.05
		weight += 0.05
	}

	if weight > 0 {
		return confidence / weight
	}
	return 0.0
}

// generateReason creates a human-readable reason
func (e *Engine) generateReason(signals Signals, baselineStatus, mutationStatus int) string {
	reasons := []string{}

	if signals.StatusDelta {
		reasons = append(reasons, statusTransition(baselineStatus, mutationStatus))
	}

	if signals.BodyDelta < e.config.BodySimilarityThreshold {
		reasons = append(reasons, "content differs from baseline")
	}

	if signals.TimingDelta < (1.0 / e.config.TimingThreshold) {
		reasons = append(reasons, "timing anomaly detected")
	}

	if signals.SizeDelta < (1.0 / e.config.SizeThreshold) {
		reasons = append(reasons, "size anomaly detected")
	}

	if signals.RedirectDelta {
		reasons = append(reasons, "redirect behavior changed")
	}

	if len(reasons) == 0 {
		return "minor differential detected"
	}

	return joinReasons(reasons)
}

// UpdateStability updates the stability based on replay results
func (r *Result) UpdateStability(successfulReplays int, totalReplays int) {
	r.ReplayCount = totalReplays
	if totalReplays > 0 {
		r.Stability = float64(successfulReplays) / float64(totalReplays)
	}
}

// IsInteresting returns true if the finding is worth investigating
func (r *Result) IsInteresting(threshold float64) bool {
	return r.FindingConfidence >= threshold
}

// Helper functions

func hash(data []byte) string {
	// Simple hash for now - can be upgraded to SHA-256
	if len(data) == 0 {
		return ""
	}
	// Use first 8 bytes as simple hash
	h := uint32(0)
	for i, b := range data {
		h = h*31 + uint32(b)
		if i >= 100 { // Limit to first 100 bytes
			break
		}
	}
	return string(rune(h))
}

func calculateByteSimilarity(a, b []byte) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}

	minLen := min(len(a), len(b))
	if minLen == 0 {
		return 0.0
	}

	matches := 0
	for i := 0; i < minLen; i++ {
		if a[i] == b[i] {
			matches++
		}
	}

	return float64(matches) / float64(minLen)
}

func compareSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func getCookies(headers map[string][]string) map[string]string {
	cookies := make(map[string]string)
	for k, v := range headers {
		if k == "Cookie" || k == "Set-Cookie" {
			for _, cookie := range v {
				// Parse simple cookie format
				parts := splitCookie(cookie)
				if len(parts) > 0 {
					cookies[parts[0]] = cookie
				}
			}
		}
	}
	return cookies
}

func splitCookie(cookie string) []string {
	// Simple cookie parser - can be enhanced
	semicolon := 0
	for i, c := range cookie {
		if c == ';' {
			semicolon = i
			break
		}
	}
	if semicolon > 0 {
		return []string{cookie[:semicolon], cookie[semicolon+1:]}
	}
	return []string{cookie}
}

func statusTransition(from, to int) string {
	if from == 403 && to == 200 {
		return "authorization bypass (403 → 200)"
	}
	if from == 401 && to == 200 {
		return "authentication bypass (401 → 200)"
	}
	if from == 403 && to == 302 {
		return "redirect bypass (403 → 302)"
	}
	return fmt.Sprintf("status transition: %d → %d", from, to)
}

func joinReasons(reasons []string) string {
	if len(reasons) == 0 {
		return ""
	}
	if len(reasons) == 1 {
		return reasons[0]
	}
	result := reasons[0]
	for i := 1; i < len(reasons); i++ {
		result += "; " + reasons[i]
	}
	return result
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
