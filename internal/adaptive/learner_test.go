package adaptive

import (
	"path/filepath"
	"testing"

	"github.com/gl1tch0x1/YourWAFSucks/internal/techniques"
)

func TestScoreUsesNeutralPriorForUnseenTechniques(t *testing.T) {
	l := NewLearner()
	if got := l.Score("never-seen"); got != defaultPrior {
		t.Fatalf("Score() = %v, want prior %v", got, defaultPrior)
	}
}

func TestScoreMonotonicWithFindingsAndScore(t *testing.T) {
	l := NewLearner()

	l.Record("weak", false, 10, 1)
	weak := l.Score("weak")

	l.Record("weak", false, 10, 1)
	weakAfter := l.Score("weak")
	if weakAfter > weak {
		t.Fatalf("Score() increased without a finding: %v -> %v", weak, weakAfter)
	}

	l.Record("strong", true, 90, 1)
	strong := l.Score("strong")
	if strong <= weakAfter {
		t.Fatalf("Score(strong) = %v, want > Score(weak) = %v", strong, weakAfter)
	}

	// More findings at a higher score must not lower the score.
	l.Record("strong", true, 95, 1)
	if got := l.Score("strong"); got < strong {
		t.Fatalf("Score() decreased after a stronger finding: %v -> %v", strong, got)
	}
}

func TestPrioritizeIsStable(t *testing.T) {
	l := NewLearner()
	l.Record("slow", false, 5, 1)
	l.Record("fast", true, 95, 1)

	payloads := []techniques.Payload{
		{Technique: "slow", URL: "a"},
		{Technique: "unknown-b", URL: "b"},
		{Technique: "fast", URL: "c"},
		{Technique: "unknown-a", URL: "d"},
	}

	got := l.Prioritize(payloads)

	wantOrder := []string{"fast", "unknown-b", "unknown-a", "slow"}
	for i, want := range wantOrder {
		if got[i].Technique != want {
			t.Fatalf("Prioritize()[%d] = %q, want %q (full order: %v)", i, got[i].Technique, want, techniquesOf(got))
		}
	}

	// The input slice must not be mutated.
	if payloads[0].Technique != "slow" {
		t.Fatalf("Prioritize() mutated its input: %v", techniquesOf(payloads))
	}
}

func TestPrioritizePreservesOrderWhenAllEqual(t *testing.T) {
	l := NewLearner()
	payloads := []techniques.Payload{
		{Technique: "a"}, {Technique: "b"}, {Technique: "c"}, {Technique: "d"},
	}
	got := l.Prioritize(payloads)
	for i := range payloads {
		if got[i].Technique != payloads[i].Technique {
			t.Fatalf("Prioritize() reordered equal scores: got %v", techniquesOf(got))
		}
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	l := NewLearner()
	l.Record("smt", true, 80, 2)
	l.Record("smt", false, 20, 2)
	l.Record("raw", true, 100, 1)

	path := filepath.Join(t.TempDir(), "learner.json")
	if err := l.Save(path); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := LoadLearner(path)
	if err != nil {
		t.Fatalf("LoadLearner() error = %v", err)
	}

	want := l.Stats()
	got := loaded.Stats()
	if len(got) != len(want) {
		t.Fatalf("loaded %d stats, want %d", len(got), len(want))
	}
	for name, w := range want {
		g, ok := got[name]
		if !ok {
			t.Fatalf("missing stat %q after round-trip", name)
		}
		if g != w {
			t.Fatalf("stat %q = %+v, want %+v", name, g, w)
		}
	}
	if loaded.Score("smt") != l.Score("smt") {
		t.Fatalf("Score() after round-trip = %v, want %v", loaded.Score("smt"), l.Score("smt"))
	}
}

func techniquesOf(payloads []techniques.Payload) []string {
	out := make([]string, len(payloads))
	for i, p := range payloads {
		out[i] = p.Technique
	}
	return out
}
