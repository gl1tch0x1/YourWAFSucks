package sarif

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
	"github.com/gl1tch0x1/YourWAFSucks/internal/techniques"
)

func sampleFindings() []techniques.Result {
	return []techniques.Result{
		{
			Payload: techniques.Payload{
				Technique:   "headers",
				Method:      "GET",
				URL:         "https://user:pass@example.test/admin?access_token=secret&view=full",
				Description: "X-Forwarded-For spoof",
			},
			Response:    &httpclient.Response{Status: 200, Time: time.Millisecond},
			ReplayCount: 2,
		},
	}
}

func TestBuildProducesValidSARIF(t *testing.T) {
	findings := []techniques.Result{
		{
			Payload: techniques.Payload{
				Technique:   "headers",
				Method:      "GET",
				URL:         "https://user:pass@example.test/admin?access_token=secret&view=full",
				Description: "X-Forwarded-For spoof",
			},
			Response:    &httpclient.Response{Status: 200, Time: time.Millisecond},
			ReplayCount: 2,
		},
		{
			Payload: techniques.Payload{
				Technique:   "encoding",
				Method:      "GET",
				URL:         "https://example.test/%2e%2e/admin",
				Description: "double encoding",
			},
			Response: &httpclient.Response{Status: 301},
		},
	}
	findings[0].Score.Score = 95
	findings[0].Score.Reason = "status differs from baseline"
	findings[1].Score.Score = 45
	findings[1].Score.Reason = "body differs"

	log, err := Build(findings, "https://example.test", "1.2.3")
	if err != nil {
		t.Fatalf("Build() error: %v", err)
	}
	if log.Version != "2.1.0" {
		t.Errorf("Version = %q, want 2.1.0", log.Version)
	}
	if log.Schema != SchemaURL {
		t.Errorf("Schema = %q, want %q", log.Schema, SchemaURL)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("len(Runs) = %d, want 1", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "YourWAFSucks" {
		t.Errorf("driver name = %q", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "1.2.3" {
		t.Errorf("driver version = %q", run.Tool.Driver.Version)
	}
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("len(Rules) = %d, want 2", len(run.Tool.Driver.Rules))
	}
	if run.Tool.Driver.Rules[0].ID != "encoding" || run.Tool.Driver.Rules[0].DefaultConfiguration.Level != "note" {
		t.Errorf("first rule = %+v, want encoding/note (sorted)", run.Tool.Driver.Rules[0])
	}
	if run.Tool.Driver.Rules[1].ID != "headers" || run.Tool.Driver.Rules[1].DefaultConfiguration.Level != "error" {
		t.Errorf("second rule = %+v, want headers/error", run.Tool.Driver.Rules[1])
	}
	if len(run.Results) != 2 {
		t.Fatalf("len(Results) = %d, want 2", len(run.Results))
	}
	if run.Results[0].Level != "error" {
		t.Errorf("result level = %q, want error", run.Results[0].Level)
	}
	uri := run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	if uri != "https://example.test/admin?access_token=%5BREDACTED%5D&view=full" {
		t.Errorf("redacted uri = %q", uri)
	}
	if run.Results[0].Properties["score"] != 95 {
		t.Errorf("properties score = %v, want 95", run.Results[0].Properties["score"])
	}
	if run.Results[0].Properties["replay_count"] != 2 {
		t.Errorf("properties replay_count = %v, want 2", run.Results[0].Properties["replay_count"])
	}

	// Unmarshal back to confirm the camelCase surface is stable.
	data, err := json.Marshal(log)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}
	var back map[string]interface{}
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}
	if back["version"] != "2.1.0" {
		t.Errorf("marshalled version = %v", back["version"])
	}
}

func TestWriteCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.sarif")
	if err := Write(path, sampleFindings(), "https://example.test", "9.9.9"); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}
	var log Log
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Errorf("unexpected log: %+v", log)
	}
}

func TestLevelFor(t *testing.T) {
	cases := map[int]string{0: "note", 69: "note", 70: "warning", 89: "warning", 90: "error", 100: "error"}
	for score, want := range cases {
		if got := LevelFor(score); got != want {
			t.Errorf("LevelFor(%d) = %q, want %q", score, got, want)
		}
	}
}
