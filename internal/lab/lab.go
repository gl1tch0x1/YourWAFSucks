// Package lab implements an offline, deterministic WAF test laboratory.
//
// It provides a small reference WAF that evaluates requests against an ordered
// ruleset and a runner that executes experiments against it through httptest.
// Because everything runs in-process, results are reproducible without touching
// a real target.
package lab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
)

// Response header names used to surface rule evaluation outcomes to the runner.
const (
	HeaderMatchedRule = "X-Reference-WAF-Rule"
	HeaderBlocked     = "X-Reference-WAF-Blocked"
)

// Rule is a single WAF rule. Operator is one of "contains", "regex" or
// "equals". Action is one of "block" or "allow".
type Rule struct {
	ID       string
	Field    string
	Operator string
	Pattern  string
	Action   string
	Status   int
}

// Spec is a complete, self-contained WAF specification.
type Spec struct {
	Name          string
	Rules         []Rule
	DefaultStatus int
}

// compiledRule pairs a Rule with its pre-compiled regular expression (when the
// operator is "regex").
type compiledRule struct {
	rule Rule
	re   *regexp.Regexp
}

// ReferenceWAF evaluates requests against a Spec. It is safe for concurrent use
// because its compiled rule set is immutable after construction.
type ReferenceWAF struct {
	spec  Spec
	rules []compiledRule
}

// NewReferenceWAF builds a ReferenceWAF from spec. Invalid regex patterns are
// retained but never match, so construction cannot fail.
func NewReferenceWAF(spec Spec) *ReferenceWAF {
	waf := &ReferenceWAF{spec: spec}
	waf.rules = make([]compiledRule, 0, len(spec.Rules))
	for _, rule := range spec.Rules {
		compiled := compiledRule{rule: rule}
		if strings.EqualFold(strings.TrimSpace(rule.Operator), "regex") {
			compiled.re, _ = regexp.Compile(rule.Pattern)
		}
		waf.rules = append(waf.rules, compiled)
	}
	return waf
}

// Spec returns a copy of the specification backing the WAF.
func (w *ReferenceWAF) Spec() Spec {
	return w.spec
}

// Handler returns the HTTP handler that evaluates requests against the rules.
// The first matching rule wins; a "block" action returns the rule status and an
// "allow" action returns the spec default status.
func (w *ReferenceWAF) Handler() http.Handler {
	return http.HandlerFunc(w.serveHTTP)
}

func (w *ReferenceWAF) serveHTTP(rw http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)

	status := w.spec.DefaultStatus
	matched := ""
	blocked := false

	for _, compiled := range w.rules {
		if !compiled.matches(req, body) {
			continue
		}
		matched = compiled.rule.ID
		if strings.EqualFold(strings.TrimSpace(compiled.rule.Action), "allow") {
			status = w.spec.DefaultStatus
			blocked = false
		} else {
			status = compiled.rule.Status
			if status == 0 {
				status = http.StatusForbidden
			}
			blocked = true
		}
		break
	}

	if status == 0 {
		status = http.StatusOK
	}

	rw.Header().Set(HeaderMatchedRule, matched)
	if blocked {
		rw.Header().Set(HeaderBlocked, "true")
	} else {
		rw.Header().Set(HeaderBlocked, "false")
	}
	rw.WriteHeader(status)
}

func (c compiledRule) matches(req *http.Request, body []byte) bool {
	value, ok := fieldValue(c.rule.Field, req, body)
	if !ok {
		return false
	}

	switch strings.ToLower(strings.TrimSpace(c.rule.Operator)) {
	case "contains":
		return strings.Contains(value, c.rule.Pattern)
	case "equals":
		return value == c.rule.Pattern
	case "regex":
		return c.re != nil && c.re.MatchString(value)
	default:
		return false
	}
}

func fieldValue(field string, req *http.Request, body []byte) (string, bool) {
	trimmed := strings.TrimSpace(field)
	lower := strings.ToLower(trimmed)

	switch lower {
	case "body":
		return string(body), true
	case "path":
		if req.URL == nil {
			return "", false
		}
		return req.URL.Path, true
	case "query", "rawquery":
		if req.URL == nil {
			return "", false
		}
		return req.URL.RawQuery, true
	case "method":
		return req.Method, true
	case "host":
		return req.Host, true
	case "user-agent", "useragent":
		return req.Header.Get("User-Agent"), true
	}

	if name, ok := strings.CutPrefix(trimmed, "header:"); ok {
		return req.Header.Get(strings.TrimSpace(name)), true
	}
	if strings.HasPrefix(lower, "header.") {
		return req.Header.Get(trimmed[len("header."):]), true
	}

	if value := req.Header.Get(trimmed); value != "" {
		return value, true
	}
	return "", false
}

// Experiment is a single request to run against a Spec.
type Experiment struct {
	Name    string
	Method  string
	Path    string
	Headers map[string]string
	Body    []byte
}

// Outcome is the observed result of running an Experiment.
type Outcome struct {
	Experiment  string
	Status      int
	Blocked     bool
	MatchedRule string
	BodyHash    string
}

// Trial records a full run of a Spec against a set of Experiments.
type Trial struct {
	Spec         Spec
	Experiments  []Experiment
	Outcomes     []Outcome
	Reproducible bool
}

// Run executes every experiment against a fresh httptest server backed by
// NewReferenceWAF(spec). It returns an error only when the server cannot be
// constructed or an experiment request cannot be issued.
func Run(ctx context.Context, spec Spec, experiments []Experiment) (Trial, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	server := httptest.NewServer(NewReferenceWAF(spec).Handler())
	defer server.Close()

	client := &http.Client{}
	outcomes := make([]Outcome, 0, len(experiments))

	for _, experiment := range experiments {
		method := experiment.Method
		if method == "" {
			method = http.MethodGet
		}

		req, err := http.NewRequestWithContext(ctx, method, server.URL+experiment.Path, bytes.NewReader(experiment.Body))
		if err != nil {
			return Trial{}, fmt.Errorf("lab: build experiment %q: %w", experiment.Name, err)
		}
		for key, value := range experiment.Headers {
			req.Header.Set(key, value)
		}

		resp, err := client.Do(req)
		if err != nil {
			return Trial{}, fmt.Errorf("lab: run experiment %q: %w", experiment.Name, err)
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return Trial{}, fmt.Errorf("lab: read experiment %q: %w", experiment.Name, readErr)
		}

		outcomes = append(outcomes, Outcome{
			Experiment:  experiment.Name,
			Status:      resp.StatusCode,
			Blocked:     strings.EqualFold(resp.Header.Get(HeaderBlocked), "true"),
			MatchedRule: resp.Header.Get(HeaderMatchedRule),
			BodyHash:    hashBody(body),
		})
	}

	return Trial{
		Spec:         spec,
		Experiments:  experiments,
		Outcomes:     outcomes,
		Reproducible: true,
	}, nil
}

// Replay runs the same spec and experiments again and reports whether the new
// outcomes match the original. The returned Trial carries the replayed
// outcomes and Reproducible reflects the comparison.
func Replay(trial Trial) (Trial, error) {
	replayed, err := Run(context.Background(), trial.Spec, trial.Experiments)
	if err != nil {
		return Trial{}, err
	}
	replayed.Reproducible = outcomesEqual(trial.Outcomes, replayed.Outcomes)
	return replayed, nil
}

func outcomesEqual(a, b []Outcome) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Experiment != b[i].Experiment ||
			a[i].Status != b[i].Status ||
			a[i].Blocked != b[i].Blocked ||
			a[i].MatchedRule != b[i].MatchedRule {
			return false
		}
	}
	return true
}

func hashBody(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
