package lab

import (
	"context"
	"net/http"
	"testing"
)

func TestHeaderSignatureBlocksAndAllows(t *testing.T) {
	spec := Spec{
		Name:          "header-signature",
		DefaultStatus: http.StatusOK,
		Rules: []Rule{
			{
				ID:       "sig-header",
				Field:    "header:X-Signature",
				Operator: "contains",
				Pattern:  "evil",
				Action:   "block",
				Status:   http.StatusForbidden,
			},
		},
	}
	experiments := []Experiment{
		{Name: "blocked", Method: http.MethodGet, Path: "/", Headers: map[string]string{"X-Signature": "evil-payload"}},
		{Name: "allowed", Method: http.MethodGet, Path: "/", Headers: map[string]string{"X-Signature": "benign"}},
	}

	trial, err := Run(context.Background(), spec, experiments)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(trial.Outcomes) != 2 {
		t.Fatalf("Run() produced %d outcomes, want 2", len(trial.Outcomes))
	}

	blocked := outcomeByName(t, trial, "blocked")
	if blocked.Status != http.StatusForbidden || !blocked.Blocked {
		t.Fatalf("blocked outcome = %+v, want status 403 blocked", blocked)
	}
	if blocked.MatchedRule != "sig-header" {
		t.Fatalf("blocked MatchedRule = %q, want sig-header", blocked.MatchedRule)
	}

	allowed := outcomeByName(t, trial, "allowed")
	if allowed.Status != http.StatusOK || allowed.Blocked {
		t.Fatalf("allowed outcome = %+v, want status 200 not blocked", allowed)
	}
	if allowed.MatchedRule != "" {
		t.Fatalf("allowed MatchedRule = %q, want empty", allowed.MatchedRule)
	}

	replayed, err := Replay(trial)
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if !replayed.Reproducible {
		t.Fatal("Replay() reported Reproducible = false, want true")
	}
	if !outcomesEqual(trial.Outcomes, replayed.Outcomes) {
		t.Fatalf("Replay() outcomes differ:\noriginal: %+v\nreplay:   %+v", trial.Outcomes, replayed.Outcomes)
	}
}

func TestBodySignatureBlocks(t *testing.T) {
	spec := Spec{
		Name:          "body-signature",
		DefaultStatus: http.StatusOK,
		Rules: []Rule{
			{ID: "sig-body", Field: "body", Operator: "contains", Pattern: "<script", Action: "block", Status: http.StatusForbidden},
		},
	}
	experiments := []Experiment{
		{Name: "xss", Method: http.MethodPost, Path: "/comment", Body: []byte("<script>alert(1)</script>")},
		{Name: "clean", Method: http.MethodPost, Path: "/comment", Body: []byte("a normal comment")},
	}

	trial, err := Run(context.Background(), spec, experiments)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	xss := outcomeByName(t, trial, "xss")
	if !xss.Blocked || xss.Status != http.StatusForbidden || xss.MatchedRule != "sig-body" {
		t.Fatalf("xss outcome = %+v, want blocked by sig-body", xss)
	}
	clean := outcomeByName(t, trial, "clean")
	if clean.Blocked || clean.Status != http.StatusOK || clean.MatchedRule != "" {
		t.Fatalf("clean outcome = %+v, want allowed", clean)
	}
}

func TestOperatorsAndAllowAction(t *testing.T) {
	spec := Spec{
		Name:          "operators",
		DefaultStatus: http.StatusOK,
		Rules: []Rule{
			{ID: "debug-allow", Field: "header:X-Debug-Skip", Operator: "equals", Pattern: "1", Action: "allow", Status: http.StatusOK},
			{ID: "admin-regex", Field: "path", Operator: "regex", Pattern: "(?i)^/admin", Action: "block", Status: http.StatusForbidden},
		},
	}
	experiments := []Experiment{
		{Name: "allow-wins", Method: http.MethodGet, Path: "/admin/panel", Headers: map[string]string{"X-Debug-Skip": "1"}},
		{Name: "regex-blocks", Method: http.MethodGet, Path: "/ADMIN/panel"},
		{Name: "public", Method: http.MethodGet, Path: "/public"},
	}

	trial, err := Run(context.Background(), spec, experiments)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got := outcomeByName(t, trial, "allow-wins"); got.Blocked || got.MatchedRule != "debug-allow" || got.Status != http.StatusOK {
		t.Fatalf("allow-wins outcome = %+v, want allowed by debug-allow", got)
	}
	if got := outcomeByName(t, trial, "regex-blocks"); !got.Blocked || got.MatchedRule != "admin-regex" {
		t.Fatalf("regex-blocks outcome = %+v, want blocked by admin-regex", got)
	}
	if got := outcomeByName(t, trial, "public"); got.Blocked || got.MatchedRule != "" {
		t.Fatalf("public outcome = %+v, want allowed", got)
	}
}

func TestDefaultStatusIsUsedWhenNoRuleMatches(t *testing.T) {
	spec := Spec{Name: "empty", DefaultStatus: http.StatusTeapot}
	trial, err := Run(context.Background(), spec, []Experiment{{Name: "only", Method: http.MethodGet, Path: "/"}})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := outcomeByName(t, trial, "only"); got.Status != http.StatusTeapot || got.Blocked {
		t.Fatalf("outcome = %+v, want default 418 not blocked", got)
	}
}

func TestInvalidRegexNeverMatches(t *testing.T) {
	spec := Spec{
		Name:          "bad-regex",
		DefaultStatus: http.StatusOK,
		Rules:         []Rule{{ID: "broken", Field: "path", Operator: "regex", Pattern: "([", Action: "block", Status: http.StatusForbidden}},
	}
	trial, err := Run(context.Background(), spec, []Experiment{{Name: "req", Method: http.MethodGet, Path: "/anything"}})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := outcomeByName(t, trial, "req"); got.Blocked {
		t.Fatalf("outcome = %+v, want not blocked for an invalid regex", got)
	}
}

func TestSpecAccessorReturnsCopy(t *testing.T) {
	spec := Spec{Name: "copy", DefaultStatus: http.StatusOK, Rules: []Rule{{ID: "r1"}}}
	waf := NewReferenceWAF(spec)
	got := waf.Spec()
	if got.Name != spec.Name || len(got.Rules) != 1 {
		t.Fatalf("Spec() = %+v, want %+v", got, spec)
	}
}

func outcomeByName(t *testing.T, trial Trial, name string) Outcome {
	t.Helper()
	for _, outcome := range trial.Outcomes {
		if outcome.Experiment == name {
			return outcome
		}
	}
	t.Fatalf("trial has no outcome named %q: %+v", name, trial.Outcomes)
	return Outcome{}
}
