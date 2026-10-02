package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/techniques"
)

func TestWriteJSONLIncludesScanMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.jsonl")
	findings := []techniques.Result{{
		Payload: techniques.Payload{
			Technique:   "headers",
			Method:      "GET",
			URL:         "https://user:pass@example.test/admin?access_token=payload-secret&view=full",
			Description: "header mutation",
		},
	}}

	if err := WriteJSONL(path, findings, "https://user:pass@example.test/admin?session=session-secret", "1.2.3"); err != nil {
		t.Fatalf("WriteJSONL() error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}
	var record Record
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}
	if record.Target != "https://example.test/admin?session=%5BREDACTED%5D" {
		t.Errorf("Target = %q, want sanitized target URL", record.Target)
	}
	if record.URL != "https://example.test/admin?access_token=%5BREDACTED%5D&view=full" {
		t.Errorf("URL = %q, want sanitized finding URL", record.URL)
	}
	if record.ToolVersion != "1.2.3" {
		t.Errorf("ToolVersion = %q, want 1.2.3", record.ToolVersion)
	}
	if record.ScannedAt.IsZero() || record.ScannedAt.Location() != time.UTC {
		t.Errorf("ScannedAt = %v, want a UTC timestamp", record.ScannedAt)
	}
}
