package score

import (
	"bytes"
	"crypto/sha1"
	"math"

	"github.com/gl1tch0x1/YourWAFSucks/internal/calibrate"
	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
)

type Result struct {
	Score       int
	Interesting bool
	Reason      string
	Replay      bool
	ReplayCount int
}

func Compute(resp *httpclient.Response, cal *calibrate.Result) Result {
	r := Result{}

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
		bodySim := sim(resp.Body, cal.BaselineBody)
		if bodySim < 0.85 {
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
