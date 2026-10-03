package score

import (
	"bytes"
	"crypto/sha1"
	"math"

	"github.com/gl1tch0x1/YourWAFSucks/internal/calibrate"
	"github.com/gl1tch0x1/YourWAFSucks/internal/differential"
	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
	"github.com/gl1tch0x1/YourWAFSucks/internal/similarity"
)

type Result struct {
	Score       int
	Interesting bool
	Reason      string
	Replay      bool
	ReplayCount int
	// New differential fields
	Differential *differential.Result `json:"differential,omitempty"`
	Similarity   *similarity.Result   `json:"similarity,omitempty"`
}

func Compute(resp *httpclient.Response, cal *calibrate.Result) Result {
	r := Result{}

	// Initialize differential engine
	diffEngine := differential.New(differential.Config{
		BodySimilarityThreshold: 0.85,
		TimingThreshold:         3.0,
		SizeThreshold:           2.0,
		EnableSemanticAnalysis:  true,
	})

	// Initialize similarity analyzer
	simAnalyzer := similarity.New(similarity.Config{
		EnableDOMAnalysis:   true,
		EnableJSONAnalysis:  true,
		EnableTextAnalysis:  true,
		TokenNormalization:  true,
		DynamicValueRemoval: true,
		HTMLStructureWeight: 0.4,
		TextContentWeight:   0.6,
		JSONStructureWeight: 0.7,
	})

	// Perform differential analysis. Prefer the full baseline response captured
	// during calibration, but fall back to the summarized calibration fields when
	// only those are available (e.g. synthetic baselines in tests).
	base := cal.BaselineResponse
	if base.Status == 0 && cal.BaselineStatus != 0 {
		base = httpclient.Response{
			Status: cal.BaselineStatus,
			Body:   cal.BaselineBody,
			Time:   cal.BaselineTime,
		}
	}
	diffResult := diffEngine.Analyze(&base, resp, cal)
	r.Differential = &diffResult

	// Perform similarity analysis
	simResult := simAnalyzer.Analyze(cal.BaselineBody, resp.Body)
	r.Similarity = &simResult

	// --- Soft-404 filter ---
	if cal.Soft404 && resp.Status == cal.Soft404Status {
		if sim(resp.Body, cal.Soft404Body) > 0.9 {
			r.Reason = "matches soft-404"
			return r
		}
	}

	// --- Status differs from baseline ---
	if resp.Status != cal.BaselineStatus {
		r.Interesting = true
		r.Score = 50
		r.Reason = "status differs from baseline"

		if resp.Status >= 200 && resp.Status < 300 {
			r.Score += 30
		} else if resp.Status >= 300 && resp.Status < 400 {
			r.Score += 15
		}
	} else if resp.Status == 403 || resp.Status == 401 {
		// --- Same status as baseline: check body/timing/size ---
		// Use similarity analysis instead of raw sim()
		if simResult.CombinedSimilarity < 0.85 {
			r.Interesting = true
			r.Score = 40
			r.Reason = "body differs from baseline"
		}

		if cal.BaselineTime > 0 {
			ratio := float64(resp.Time) / float64(cal.BaselineTime)
			if ratio >= 3.0 {
				r.Interesting = true
				r.Score += 20
				if r.Reason == "" {
					r.Reason = "timing anomaly"
				}
			}
		}

		if cal.BaselineSize > 0 {
			ratio := float64(len(resp.Body)) / float64(cal.BaselineSize)
			if ratio > 2.0 || ratio < 0.5 {
				r.Interesting = true
				r.Score += 15
				if r.Reason == "" {
					r.Reason = "size anomaly"
				}
			}
		}
	}

	// Enhance scoring with differential confidence
	if diffResult.FindingConfidence > 0.7 {
		r.Interesting = true
		// Boost score based on differential confidence
		r.Score = int(diffResult.FindingConfidence * 100)
		if r.Reason == "" {
			r.Reason = diffResult.Reason
		}
	}

	if !r.Interesting {
		return r
	}

	// Clamp
	if r.Score > 100 {
		r.Score = 100
	}
	if r.Score < 0 {
		r.Score = 0
	}
	return r
}

// similarity returns 0-1 (1 = identical)
func sim(a, b []byte) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}
	// Fast path: identical hash
	if sha1.Sum(a) == sha1.Sum(b) {
		return 1.0
	}
	// Size-based heuristic
	maxLen := float64(max(len(a), len(b)))
	minLen := float64(min(len(a), len(b)))
	sizeRatio := minLen / maxLen

	// Sample common substrings
	sampleLen := 256
	if len(a) < sampleLen || len(b) < sampleLen {
		return sizeRatio
	}
	// Compare first/last 256 bytes
	firstMatch := bytes.Equal(a[:sampleLen], b[:sampleLen])
	lastMatch := bytes.Equal(a[len(a)-sampleLen:], b[len(b)-sampleLen:])
	prefixScore := 0.0
	if firstMatch {
		prefixScore += 0.5
	}
	if lastMatch {
		prefixScore += 0.5
	}
	return (sizeRatio + prefixScore) / 2.0
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

var _ = math.Abs
