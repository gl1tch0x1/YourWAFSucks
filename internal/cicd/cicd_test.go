package cicd

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
	"github.com/gl1tch0x1/YourWAFSucks/internal/techniques"
)

func finding(technique string, score int, status int) techniques.Result {
	r := techniques.Result{
		Payload: techniques.Payload{
			Technique:   technique,
			Method:      "GET",
			URL:         "https://user:pass@example.test/admin?access_token=secret",
			Description: "desc",
		},
		Response: &httpclient.Response{Status: status},
	}
	r.Score.Score = score
	return r
}

func TestSeverityFor(t *testing.T) {
	cases := map[int]string{0: "", 1: "low", 39: "low", 40: "medium", 69: "medium", 70: "high", 89: "high", 90: "critical", 100: "critical"}
	for score, want := range cases {
		if got := SeverityFor(score); got != want {
			t.Errorf("SeverityFor(%d) = %q, want %q", score, got, want)
		}
	}
}

func TestEvaluatePass(t *testing.T) {
	findings := []techniques.Result{finding("headers", 30, 200)}
	findings[0].Score.Score = 30

	rep := Evaluate(findings, Policy{MinScore: 70})
	if rep.ShouldFail {
		t.Errorf("ShouldFail = true, want false (%s)", rep.Summary)
	}
	if rep.ExitCode != ExitPass {
		t.Errorf("ExitCode = %d, want %d", rep.ExitCode, ExitPass)
	}
	if rep.Findings != 1 || rep.HighestScore != 30 || rep.Severity != "low" {
		t.Errorf("unexpected report: %+v", rep)
	}
}

func TestEvaluateFailOnFindings(t *testing.T) {
	rep := Evaluate([]techniques.Result{finding("headers", 10, 200)}, Policy{FailOnFindings: true})
	if !rep.ShouldFail || rep.ExitCode != ExitFinding {
		t.Errorf("expected failure, got %+v", rep)
	}
}

func TestEvaluateMinScore(t *testing.T) {
	findings := []techniques.Result{finding("headers", 75, 200), finding("encoding", 20, 200)}
	rep := Evaluate(findings, Policy{MinScore: 70})
	if !rep.ShouldFail || rep.ExitCode != ExitFinding {
		t.Errorf("expected failure, got %+v", rep)
	}
	if rep.HighestScore != 75 || rep.Severity != "high" {
		t.Errorf("unexpected report: %+v", rep)
	}
}

func TestEvaluateFailOnSeverity(t *testing.T) {
	findings := []techniques.Result{finding("headers", 95, 200)}
	rep := Evaluate(findings, Policy{FailOnSeverity: "critical"})
	if !rep.ShouldFail {
		t.Errorf("expected failure at critical threshold, got %+v", rep)
	}
	rep = Evaluate(findings, Policy{FailOnSeverity: "bogus"})
	if rep.ShouldFail {
		t.Errorf("invalid severity should not fail, got %+v", rep)
	}
	rep = Evaluate([]techniques.Result{finding("headers", 50, 200)}, Policy{FailOnSeverity: "high"})
	if rep.ShouldFail {
		t.Errorf("medium should not satisfy high threshold, got %+v", rep)
	}
}

func TestWriteJUnit(t *testing.T) {
	findings := []techniques.Result{finding("headers", 95, 200), finding("encoding", 0, 200)}
	path := filepath.Join(t.TempDir(), "report.xml")
	if err := WriteJUnit(path, findings); err != nil {
		t.Fatalf("WriteJUnit() error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}
	var doc junitTestSuites
	if err := xml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}
	if doc.Tests != 2 || doc.Failures != 1 {
		t.Errorf("tests=%d failures=%d, want 2/1", doc.Tests, doc.Failures)
	}
	if len(doc.Suites) != 1 || doc.Suites[0].Cases[0].Failure == nil {
		t.Errorf("expected first case to be a failure")
	}
	if !strings.Contains(doc.Suites[0].Cases[0].Name, "access_token=%5BREDACTED%5D") {
		t.Errorf("JUnit name not redacted: %q", doc.Suites[0].Cases[0].Name)
	}
	if strings.Contains(string(data), "secret") {
		t.Errorf("JUnit output leaked secret: %s", data)
	}
}

func TestAnnotations(t *testing.T) {
	findings := []techniques.Result{
		finding("headers", 95, 200),
		finding("encoding", 75, 200),
		finding("verbs", 20, 200),
	}
	lines := Annotations(findings)
	if len(lines) != 3 {
		t.Fatalf("len(Annotations) = %d, want 3", len(lines))
	}
	if !strings.HasPrefix(lines[0], "::error::") {
		t.Errorf("line 0 = %q, want error", lines[0])
	}
	if !strings.HasPrefix(lines[1], "::warning::") {
		t.Errorf("line 1 = %q, want warning", lines[1])
	}
	if !strings.HasPrefix(lines[2], "::notice::") {
		t.Errorf("line 2 = %q, want notice", lines[2])
	}
}

func TestSortedTechniques(t *testing.T) {
	got := SortedTechniques([]techniques.Result{
		finding("headers", 1, 200), finding("encoding", 1, 200), finding("headers", 1, 200),
	})
	want := []string{"encoding", "headers"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("SortedTechniques = %v, want %v", got, want)
	}
}
