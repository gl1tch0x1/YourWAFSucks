package corpus

import (
	"context"
	"testing"
)

func TestBuiltinNonEmpty(t *testing.T) {
	cases := Builtin()
	if len(cases) == 0 {
		t.Fatalf("expected built-in corpus cases")
	}
	for _, c := range cases {
		if c.ID == "" || c.Name == "" || len(c.Experiments) == 0 || len(c.Expect) == 0 {
			t.Fatalf("incomplete case: %+v", c)
		}
	}
}

func TestRunAllBuiltinScoresPerfectly(t *testing.T) {
	score, err := RunAll(context.Background(), Builtin())
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	if score.Cases == 0 || score.Failed != 0 || score.Accuracy != 1.0 {
		t.Fatalf("expected perfect corpus score, got %+v", score)
	}
	if score.Passed != score.Cases {
		t.Fatalf("passed = %d, cases = %d", score.Passed, score.Cases)
	}
}

func TestScoreTrialReportsFailures(t *testing.T) {
	c := Builtin()[0]
	// Empty trial: no outcomes recorded, so every expectation fails.
	passed, failures := ScoreTrial(c, Trial{})
	if passed {
		t.Fatalf("expected failure for empty trial")
	}
	if len(failures) != len(c.Expect) {
		t.Fatalf("expected %d failures, got %d: %v", len(c.Expect), len(failures), failures)
	}
}
