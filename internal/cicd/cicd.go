// Package cicd provides helpers for driving YourWAFSucks from a CI/CD
// pipeline: pass/fail policy evaluation, JUnit XML output and GitHub Actions
// annotations.
package cicd

import (
	"encoding/xml"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/gl1tch0x1/YourWAFSucks/internal/techniques"
)

// Exit code conventions shared with the rest of the tool.
const (
	ExitPass    = 0
	ExitFinding = 10
)

// Policy describes when a pipeline run should be considered a failure.
type Policy struct {
	// FailOnFindings fails the build whenever any finding is present.
	FailOnFindings bool
	// MinScore fails the build when a finding reaches or exceeds this score.
	MinScore int
	// FailOnSeverity fails the build at or above this severity. Valid values
	// are "", "low", "medium", "high" and "critical"; "" disables the check.
	FailOnSeverity string
}

// Report summarizes the outcome of a policy evaluation.
type Report struct {
	Findings     int
	HighestScore int
	Severity     string
	ShouldFail   bool
	ExitCode     int
	Summary      string
}

// SeverityFor maps a numeric score onto a coarse severity label.
func SeverityFor(score int) string {
	switch {
	case score >= 90:
		return "critical"
	case score >= 70:
		return "high"
	case score >= 40:
		return "medium"
	case score > 0:
		return "low"
	default:
		return ""
	}
}

func severityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 0
	}
}

// Evaluate applies a policy to findings and reports whether the pipeline
// should fail.
func Evaluate(findings []techniques.Result, p Policy) Report {
	rep := Report{Findings: len(findings)}

	for _, f := range findings {
		if f.Score.Score > rep.HighestScore {
			rep.HighestScore = f.Score.Score
		}
	}
	rep.Severity = SeverityFor(rep.HighestScore)

	var reasons []string
	if p.FailOnFindings && rep.Findings > 0 {
		rep.ShouldFail = true
		reasons = append(reasons, fmt.Sprintf("%d finding(s) present", rep.Findings))
	}
	if p.MinScore > 0 && rep.HighestScore >= p.MinScore {
		rep.ShouldFail = true
		reasons = append(reasons, fmt.Sprintf("highest score %d >= threshold %d", rep.HighestScore, p.MinScore))
	}
	if threshold := severityRank(p.FailOnSeverity); threshold > 0 {
		if severityRank(rep.Severity) >= threshold {
			rep.ShouldFail = true
			reasons = append(reasons, fmt.Sprintf("severity %q >= threshold %q", rep.Severity, strings.ToLower(p.FailOnSeverity)))
		}
	}

	if rep.ShouldFail {
		rep.ExitCode = ExitFinding
		rep.Summary = fmt.Sprintf("FAIL: %s", strings.Join(reasons, "; "))
	} else {
		rep.ExitCode = ExitPass
		rep.Summary = fmt.Sprintf("PASS: %d finding(s), highest score %d", rep.Findings, rep.HighestScore)
	}
	return rep
}

type junitTestSuites struct {
	XMLName  xml.Name         `xml:"testsuites"`
	Tests    int              `xml:"tests,attr"`
	Failures int              `xml:"failures,attr"`
	Suites   []junitTestSuite `xml:"testsuite"`
}

type junitTestSuite struct {
	Name     string          `xml:"name,attr"`
	Tests    int             `xml:"tests,attr"`
	Failures int             `xml:"failures,attr"`
	Cases    []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	Classname string        `xml:"classname,attr"`
	Name      string        `xml:"name,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

// WriteJUnit writes findings as a JUnit XML report so CI systems can display
// them alongside test results. Every positive finding is reported as a failing
// test case.
func WriteJUnit(path string, findings []techniques.Result) error {
	suite := junitTestSuite{Name: "YourWAFSucks"}
	failures := 0
	for _, f := range findings {
		technique := f.Payload.Technique
		if technique == "" {
			technique = "unknown"
		}
		tc := junitTestCase{
			Classname: "YourWAFSucks." + technique,
			Name:      fmt.Sprintf("%s %s", f.Payload.Method, RedactURL(f.Payload.URL)),
		}
		if f.Score.Score > 0 {
			failures++
			message := f.Score.Reason
			if message == "" {
				message = f.Payload.Description
			}
			tc.Failure = &junitFailure{
				Message: message,
				Type:    SeverityFor(f.Score.Score),
				Text:    fmt.Sprintf("score=%d technique=%s", f.Score.Score, technique),
			}
		}
		suite.Cases = append(suite.Cases, tc)
	}
	suite.Tests = len(suite.Cases)
	suite.Failures = failures

	doc := junitTestSuites{
		Tests:    suite.Tests,
		Failures: suite.Failures,
		Suites:   []junitTestSuite{suite},
	}

	data, err := xml.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	data = append([]byte(xml.Header), data...)
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

// Annotations returns GitHub Actions workflow command lines (::error, ::warning
// and ::notice) describing each finding.
func Annotations(findings []techniques.Result) []string {
	if len(findings) == 0 {
		return nil
	}
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		message := f.Score.Reason
		if message == "" {
			message = f.Payload.Description
		}
		line := fmt.Sprintf("%s %s %s (score %d): %s",
			techniqueOf(f), f.Payload.Method, RedactURL(f.Payload.URL), f.Score.Score, message)
		out = append(out, fmt.Sprintf("::%s::%s", annotationLevel(f.Score.Score), escapeCommand(line)))
	}
	return out
}

func techniqueOf(f techniques.Result) string {
	if f.Payload.Technique == "" {
		return "unknown"
	}
	return f.Payload.Technique
}

func annotationLevel(score int) string {
	switch {
	case score >= 90:
		return "error"
	case score >= 70:
		return "warning"
	default:
		return "notice"
	}
}

// escapeCommand escapes GitHub Actions workflow command data.
func escapeCommand(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

// RedactURL removes userinfo and redacts sensitive query parameters, matching
// internal/output and internal/sarif.
func RedactURL(raw string) string {
	return redactURL(raw)
}

// SortedTechniques returns the distinct techniques present in findings, sorted.
func SortedTechniques(findings []techniques.Result) []string {
	seen := make(map[string]struct{})
	for _, f := range findings {
		seen[techniqueOf(f)] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
