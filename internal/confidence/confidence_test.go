package confidence

import "testing"

func TestComputeZeroInput(t *testing.T) {
	r := Compute(Input{})
	if r.Confidence != 0 {
		t.Fatalf("Confidence = %v, want 0", r.Confidence)
	}
	if r.Severity != "info" {
		t.Fatalf("Severity = %q, want info", r.Severity)
	}
	if r.Reason == "" {
		t.Fatal("Reason is empty")
	}
}

func TestComputeMaxInputClampedToOne(t *testing.T) {
	r := Compute(Input{
		BaseScore:    100,
		Differential: 1,
		Stability:    1,
		Anomaly:      1,
		Behavior:     1,
	})
	if r.Confidence != 1 {
		t.Fatalf("Confidence = %v, want 1", r.Confidence)
	}
	if r.Severity != "critical" {
		t.Fatalf("Severity = %q, want critical", r.Severity)
	}
}

func TestComputeClampsOutOfRangeInputs(t *testing.T) {
	over := Compute(Input{BaseScore: 500, Differential: 5, Stability: 9, Anomaly: 9, Behavior: 9})
	if over.Confidence != 1 {
		t.Fatalf("Confidence = %v, want 1 after clamping", over.Confidence)
	}

	under := Compute(Input{BaseScore: -50, Differential: -1, Stability: -1, Anomaly: -1, Behavior: -1})
	if under.Confidence != 0 {
		t.Fatalf("Confidence = %v, want 0 after clamping", under.Confidence)
	}
}

func TestReplayOverridesStability(t *testing.T) {
	withReplay := Compute(Input{Stability: 1.0, ReplayCount: 0, TotalReplay: 4})
	if withReplay.Confidence >= 0.2 {
		t.Fatalf("Confidence = %v, want low when all replays failed", withReplay.Confidence)
	}
	if withReplay.Confidence != 0 {
		t.Fatalf("Confidence = %v, want 0 for a single 0/4 replay signal", withReplay.Confidence)
	}

	stable := Compute(Input{ReplayCount: 4, TotalReplay: 4})
	if stable.Confidence <= withReplay.Confidence {
		t.Fatalf("stable Confidence = %v, want > unstable %v", stable.Confidence, withReplay.Confidence)
	}
}

func TestComputeDeterministic(t *testing.T) {
	in := Input{BaseScore: 70, Differential: 0.6, Stability: 0.5, Anomaly: 0.2, Behavior: 0.4, ReplayCount: 1, TotalReplay: 2}
	first := Compute(in)
	for i := 0; i < 10; i++ {
		if got := Compute(in); got != first {
			t.Fatalf("Compute() not deterministic: %+v vs %+v", got, first)
		}
	}
}

func TestSeverityBoundaries(t *testing.T) {
	cases := []struct {
		conf float64
		want string
	}{
		{0, "info"},
		{0.0001, "low"},
		{0.3999, "low"},
		{0.4, "medium"},
		{0.6999, "medium"},
		{0.7, "high"},
		{0.8999, "high"},
		{0.9, "critical"},
		{1, "critical"},
	}
	for _, c := range cases {
		if got := Severity(c.conf); got != c.want {
			t.Errorf("Severity(%v) = %q, want %q", c.conf, got, c.want)
		}
	}
}
