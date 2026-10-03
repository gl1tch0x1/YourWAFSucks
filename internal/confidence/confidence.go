package confidence

import (
	"fmt"
	"math"
)

// Input holds the signals combined into a calibrated confidence value.
type Input struct {
	BaseScore    int
	Differential float64
	Stability    float64
	Anomaly      float64
	Behavior     float64
	ReplayCount  int
	TotalReplay  int
}

// Result is a calibrated confidence with a qualitative severity label.
type Result struct {
	Confidence float64
	Severity   string
	Reason     string
}

// Compute combines the input signals into a confidence in [0,1]. When replay
// data is available (TotalReplay > 0) the stability term is derived from the
// replay match ratio, overriding the supplied Stability field.
func Compute(in Input) Result {
	base := clamp01(float64(in.BaseScore) / 100.0)
	diff := clamp01(in.Differential)
	anomaly := clamp01(in.Anomaly)
	behavior := clamp01(in.Behavior)

	stability := clamp01(in.Stability)
	if in.TotalReplay > 0 {
		stability = clamp01(float64(in.ReplayCount) / float64(in.TotalReplay))
	}

	conf := 0.30*base + 0.25*diff + 0.20*stability + 0.10*anomaly + 0.15*behavior
	conf = clamp01(conf)

	reason := fmt.Sprintf(
		"base=%.2f differential=%.2f stability=%.2f anomaly=%.2f behavior=%.2f",
		base, diff, stability, anomaly, behavior,
	)

	return Result{Confidence: conf, Severity: Severity(conf), Reason: reason}
}

// Severity maps a confidence in [0,1] to a qualitative label.
func Severity(confidence float64) string {
	switch {
	case confidence >= 0.9:
		return "critical"
	case confidence >= 0.7:
		return "high"
	case confidence >= 0.4:
		return "medium"
	case confidence > 0:
		return "low"
	default:
		return "info"
	}
}

func clamp01(v float64) float64 {
	if math.IsNaN(v) {
		return 0
	}
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
