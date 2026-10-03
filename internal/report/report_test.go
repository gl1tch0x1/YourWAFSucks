package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
	"github.com/gl1tch0x1/YourWAFSucks/internal/techniques"
)

func sample() []techniques.Result {
	r := techniques.Result{
		Payload: techniques.Payload{
			Technique:   "headers",
			Method:      "GET",
			URL:         "https://user:pass@example.test/<script>alert(1)</script>?access_token=secret",
			Description: "<script>alert(2)</script>",
			Headers: map[string]string{
				"Authorization": "Bearer secret-token",
				"X-Real-IP":     "127.0.0.1",
			},
		},
		Response:    &httpclient.Response{Status: 200},
		ReplayCount: 3,
	}
	r.Score.Score = 92
	r.Score.Reason = "<script>alert(3)</script> bypass"
	return []techniques.Result{r}
}

func TestRenderIsSelfContainedAndEscaped(t *testing.T) {
	out := Render(sample(), "https://example.test/admin", "1.2.3")
	if out == "" {
		t.Fatal("Render() returned empty output")
	}
	if !strings.Contains(out, "https://example.test/admin") {
		t.Errorf("output does not contain target")
	}
	if !strings.Contains(out, "1.2.3") {
		t.Errorf("output does not contain version")
	}
	if strings.Contains(out, "<script>alert") {
		t.Errorf("output contains unescaped script payload")
	}
	if strings.Contains(out, "Bearer secret-token") {
		t.Errorf("output leaked Authorization header")
	}
	if strings.Contains(out, "user:pass@") {
		t.Errorf("output leaked URL userinfo")
	}
	if strings.Contains(out, "access_token=secret") {
		t.Errorf("output leaked query secret")
	}
	// The embedded JSON must remain valid after escaping.
	if !strings.Contains(out, "&lt;script&gt;alert") {
		t.Errorf("expected escaped payload in output")
	}
	for _, cdn := range []string{"http://cdn", "https://cdn", "//unpkg.com", "//cdnjs"} {
		if strings.Contains(out, cdn) {
			t.Errorf("output references external resource %q", cdn)
		}
	}
}

func TestRenderEmptyFindings(t *testing.T) {
	out := Render(nil, "https://example.test", "dev")
	if !strings.Contains(out, "Total findings") {
		t.Errorf("expected summary cards in output")
	}
}

func TestWriteHTML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTML(path, sample(), "https://example.test", "1.0.0"); err != nil {
		t.Fatalf("WriteHTML() error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}
	if !strings.Contains(string(data), "<!DOCTYPE html>") {
		t.Errorf("expected HTML document")
	}
}

func TestSeverityForAndRedact(t *testing.T) {
	cases := map[int]string{0: "info", 1: "low", 50: "medium", 70: "high", 95: "critical"}
	for score, want := range cases {
		if got := severityFor(score); got != want {
			t.Errorf("severityFor(%d) = %q, want %q", score, got, want)
		}
	}
	if got := redactURL("https://example.test/a?session=x&p=1"); got != "https://example.test/a?p=1&session=%5BREDACTED%5D" {
		t.Errorf("redactURL = %q", got)
	}
}
