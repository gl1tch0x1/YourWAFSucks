// Package corpus provides a deterministic benchmark corpus for the reference
// WAF in internal/lab.
//
// Each Case bundles a specification, a set of experiments and the expected
// outcomes. RunAll executes every case and scores the observed behavior against
// the expectations.
package corpus

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gl1tch0x1/YourWAFSucks/internal/lab"
)

// Type aliases keep the corpus API self-contained while reusing the reference
// WAF types from internal/lab.
type (
	// Rule is an alias for lab.Rule.
	Rule = lab.Rule
	// Spec is an alias for lab.Spec.
	Spec = lab.Spec
	// Experiment is an alias for lab.Experiment.
	Experiment = lab.Experiment
	// Outcome is an alias for lab.Outcome.
	Outcome = lab.Outcome
	// Trial is an alias for lab.Trial.
	Trial = lab.Trial
)

// Expectation is the expected result for a single experiment in a Case.
type Expectation struct {
	Experiment  string `json:"experiment"`
	Blocked     bool   `json:"blocked"`
	MatchedRule string `json:"matched_rule,omitempty"`
}

// Case is one benchmark scenario.
type Case struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Spec        Spec          `json:"spec"`
	Experiments []Experiment  `json:"experiments"`
	Expect      []Expectation `json:"expect"`
}

// Score summarizes a corpus run.
type Score struct {
	Cases    int      `json:"cases"`
	Passed   int      `json:"passed"`
	Failed   int      `json:"failed"`
	Accuracy float64  `json:"accuracy"`
	Failures []string `json:"failures,omitempty"`
}

// Builtin returns a deterministic set of benchmark cases that the reference WAF
// is expected to score at 100% accuracy.
func Builtin() []Case {
	return []Case{
		{
			ID:   "sql-injection-query",
			Name: "SQL injection signature in the query string",
			Spec: Spec{
				Name:          "sqli-query",
				DefaultStatus: http.StatusOK,
				Rules: []Rule{
					{ID: "sqli-union", Field: "query", Operator: "contains", Pattern: "union+select", Action: "block", Status: http.StatusForbidden},
				},
			},
			Experiments: []Experiment{
				{Name: "sqli", Method: http.MethodGet, Path: "/search?q=1+union+select+password"},
				{Name: "benign", Method: http.MethodGet, Path: "/search?q=hello"},
			},
			Expect: []Expectation{
				{Experiment: "sqli", Blocked: true, MatchedRule: "sqli-union"},
				{Experiment: "benign", Blocked: false},
			},
		},
		{
			ID:   "xss-body",
			Name: "XSS signature in the request body",
			Spec: Spec{
				Name:          "xss-body",
				DefaultStatus: http.StatusOK,
				Rules: []Rule{
					{ID: "xss-script", Field: "body", Operator: "contains", Pattern: "<script", Action: "block", Status: http.StatusForbidden},
				},
			},
			Experiments: []Experiment{
				{Name: "xss", Method: http.MethodPost, Path: "/comment", Body: []byte("<script>alert(1)</script>")},
				{Name: "clean", Method: http.MethodPost, Path: "/comment", Body: []byte("a normal comment")},
			},
			Expect: []Expectation{
				{Experiment: "xss", Blocked: true, MatchedRule: "xss-script"},
				{Experiment: "clean", Blocked: false},
			},
		},
		{
			ID:   "scanner-header",
			Name: "Scanner User-Agent is blocked",
			Spec: Spec{
				Name:          "scanner-header",
				DefaultStatus: http.StatusOK,
				Rules: []Rule{
					{ID: "scanner-ua", Field: "header:User-Agent", Operator: "contains", Pattern: "sqlmap", Action: "block", Status: http.StatusForbidden},
				},
			},
			Experiments: []Experiment{
				{Name: "scanner", Method: http.MethodGet, Path: "/", Headers: map[string]string{"User-Agent": "sqlmap/1.7"}},
				{Name: "browser", Method: http.MethodGet, Path: "/", Headers: map[string]string{"User-Agent": "Mozilla/5.0"}},
			},
			Expect: []Expectation{
				{Experiment: "scanner", Blocked: true, MatchedRule: "scanner-ua"},
				{Experiment: "browser", Blocked: false},
			},
		},
		{
			ID:   "admin-path-regex",
			Name: "Case-insensitive admin path rule",
			Spec: Spec{
				Name:          "admin-path-regex",
				DefaultStatus: http.StatusOK,
				Rules: []Rule{
					{ID: "admin-path", Field: "path", Operator: "regex", Pattern: "(?i)^/admin", Action: "block", Status: http.StatusForbidden},
				},
			},
			Experiments: []Experiment{
				{Name: "admin-upper", Method: http.MethodGet, Path: "/ADMIN/panel"},
				{Name: "public", Method: http.MethodGet, Path: "/public"},
			},
			Expect: []Expectation{
				{Experiment: "admin-upper", Blocked: true, MatchedRule: "admin-path"},
				{Experiment: "public", Blocked: false},
			},
		},
		{
			ID:   "explicit-allow-overrides",
			Name: "An explicit allow rule short-circuits a later block rule",
			Spec: Spec{
				Name:          "allow-override",
				DefaultStatus: http.StatusOK,
				Rules: []Rule{
					{ID: "debug-allow", Field: "header:X-Debug-Skip", Operator: "equals", Pattern: "1", Action: "allow", Status: http.StatusOK},
					{ID: "private-block", Field: "path", Operator: "contains", Pattern: "/private", Action: "block", Status: http.StatusForbidden},
				},
			},
			Experiments: []Experiment{
				{Name: "debug", Method: http.MethodGet, Path: "/private/secret", Headers: map[string]string{"X-Debug-Skip": "1"}},
				{Name: "no-debug", Method: http.MethodGet, Path: "/private/secret"},
				{Name: "public", Method: http.MethodGet, Path: "/public"},
			},
			Expect: []Expectation{
				{Experiment: "debug", Blocked: false, MatchedRule: "debug-allow"},
				{Experiment: "no-debug", Blocked: true, MatchedRule: "private-block"},
				{Experiment: "public", Blocked: false},
			},
		},
	}
}

// ScoreTrial compares the outcomes of a Trial against a Case's expectations.
// It returns whether every expectation was met and a list of human-readable
// failure descriptions.
func ScoreTrial(c Case, t Trial) (bool, []string) {
	outcomes := make(map[string]Outcome, len(t.Outcomes))
	for _, outcome := range t.Outcomes {
		outcomes[outcome.Experiment] = outcome
	}

	var failures []string
	for _, expect := range c.Expect {
		outcome, ok := outcomes[expect.Experiment]
		if !ok {
			failures = append(failures, fmt.Sprintf("%s/%s: no outcome recorded", c.ID, expect.Experiment))
			continue
		}
		if outcome.Blocked != expect.Blocked {
			failures = append(failures, fmt.Sprintf("%s/%s: blocked=%t want %t (status %d)", c.ID, expect.Experiment, outcome.Blocked, expect.Blocked, outcome.Status))
			continue
		}
		if expect.MatchedRule != "" && outcome.MatchedRule != expect.MatchedRule {
			failures = append(failures, fmt.Sprintf("%s/%s: matched_rule=%q want %q", c.ID, expect.Experiment, outcome.MatchedRule, expect.MatchedRule))
		}
	}
	return len(failures) == 0, failures
}

// RunAll executes every case against the reference WAF and returns an aggregate
// Score. It returns an error only when a case cannot be executed.
func RunAll(ctx context.Context, cases []Case) (Score, error) {
	score := Score{Cases: len(cases)}
	for _, c := range cases {
		trial, err := lab.Run(ctx, c.Spec, c.Experiments)
		if err != nil {
			return Score{}, fmt.Errorf("corpus: run case %q: %w", c.ID, err)
		}
		passed, failures := ScoreTrial(c, trial)
		if passed {
			score.Passed++
			continue
		}
		score.Failed++
		score.Failures = append(score.Failures, failures...)
	}
	if score.Cases > 0 {
		score.Accuracy = float64(score.Passed) / float64(score.Cases)
	}
	return score, nil
}
