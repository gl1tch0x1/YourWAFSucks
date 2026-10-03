package evidence

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
)

// Package represents an evidence package for a finding
type Package struct {
	ID            string
	Timestamp     time.Time
	Target        string
	FindingID     string
	Technique     string
	Baseline      Evidence
	Mutation      Evidence
	ReplayResults []ReplayResult
	Metadata      Metadata
}

// Evidence represents request/response evidence
type Evidence struct {
	Request     Request
	Response    Response
	Headers     map[string]string
	BodyHash    string
	BodySize    int
	StatusCode  int
	ContentType string
	Timing      float64
}

// Request represents HTTP request evidence
type Request struct {
	Method    string
	URL       string
	Headers   map[string]string
	Body      []byte
	BodySize  int
	Timestamp time.Time
}

// Response represents HTTP response evidence
type Response struct {
	StatusCode  int
	Headers     map[string]string
	Body        []byte
	BodySize    int
	ContentType string
	Timing      float64
	Timestamp   time.Time
}

// ReplayResult represents a single replay attempt
type ReplayResult struct {
	AttemptNumber int
	Success       bool
	StatusCode    int
	BodyHash      string
	Timing        float64
	Error         string
}

// Metadata represents finding metadata
type Metadata struct {
	Confidence  float64
	Stability   float64
	ReplayCount int
	Reason      string
	Signals     interface{} // Differential signals
}

// Collector captures evidence for findings
type Collector struct {
	baseDir string
	config  Config
}

// Config holds evidence collector configuration
type Config struct {
	OutputDir        string
	SaveRequestBody  bool
	SaveResponseBody bool
	IncludeHeaders   bool
	IncludeTiming    bool
}

// New creates a new evidence collector
func New(cfg Config) *Collector {
	if cfg.OutputDir == "" {
		cfg.OutputDir = "evidence"
	}
	return &Collector{
		baseDir: cfg.OutputDir,
		config:  cfg,
	}
}

// Capture creates an evidence package for a finding
func (c *Collector) Capture(target string, findingID string, technique string,
	baselineResp, mutationResp *httpclient.Response,
	replayResults []ReplayResult, confidence, stability float64,
	reason string, signals interface{}) (*Package, error) {

	pkg := &Package{
		ID:            generatePackageID(),
		Timestamp:     time.Now(),
		Target:        target,
		FindingID:     findingID,
		Technique:     technique,
		Baseline:      c.createEvidence(baselineResp, "baseline"),
		Mutation:      c.createEvidence(mutationResp, "mutation"),
		ReplayResults: replayResults,
		Metadata: Metadata{
			Confidence:  confidence,
			Stability:   stability,
			ReplayCount: len(replayResults),
			Reason:      reason,
			Signals:     signals,
		},
	}

	return pkg, nil
}

// createEvidence creates evidence from a response
func (c *Collector) createEvidence(resp *httpclient.Response, evidenceType string) Evidence {
	_ = evidenceType // Keep for future use in evidence naming
	headers := make(map[string]string)
	for k, v := range resp.Headers {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return Evidence{
		Response: Response{
			StatusCode:  resp.Status,
			Headers:     headers,
			Body:        resp.Body,
			BodySize:    len(resp.Body),
			ContentType: resp.ContentType,
			Timing:      resp.Time.Seconds(),
			Timestamp:   time.Now(),
		},
		Headers:     headers,
		BodyHash:    hash(resp.Body),
		BodySize:    len(resp.Body),
		StatusCode:  resp.Status,
		ContentType: resp.ContentType,
		Timing:      resp.Time.Seconds(),
	}
}

// Save saves the evidence package to disk
func (c *Collector) Save(pkg *Package) error {
	// Create finding directory
	findingDir := filepath.Join(c.baseDir, pkg.FindingID)
	if err := os.MkdirAll(findingDir, 0755); err != nil {
		return fmt.Errorf("failed to create finding directory: %w", err)
	}

	// Save metadata
	metadataFile := filepath.Join(findingDir, "metadata.json")
	metadataData, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}
	if err := os.WriteFile(metadataFile, metadataData, 0644); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	// Save baseline evidence
	if err := c.saveEvidence(findingDir, "baseline", pkg.Baseline); err != nil {
		return err
	}

	// Save mutation evidence
	if err := c.saveEvidence(findingDir, "mutation", pkg.Mutation); err != nil {
		return err
	}

	// Save replay results
	if len(pkg.ReplayResults) > 0 {
		replayFile := filepath.Join(findingDir, "replay.json")
		replayData, err := json.MarshalIndent(pkg.ReplayResults, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal replay results: %w", err)
		}
		if err := os.WriteFile(replayFile, replayData, 0644); err != nil {
			return fmt.Errorf("failed to write replay results: %w", err)
		}
	}

	return nil
}

// saveEvidence saves individual evidence to disk
func (c *Collector) saveEvidence(dir, evidenceType string, evidence Evidence) error {
	// Save response body
	if c.config.SaveResponseBody && len(evidence.Response.Body) > 0 {
		bodyFile := filepath.Join(dir, fmt.Sprintf("%s_response_body.txt", evidenceType))
		if err := os.WriteFile(bodyFile, evidence.Response.Body, 0644); err != nil {
			return fmt.Errorf("failed to write body: %w", err)
		}
	}

	// Save headers
	if c.config.IncludeHeaders {
		headersFile := filepath.Join(dir, fmt.Sprintf("%s_headers.json", evidenceType))
		headersData, err := json.MarshalIndent(evidence.Headers, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal headers: %w", err)
		}
		if err := os.WriteFile(headersFile, headersData, 0644); err != nil {
			return fmt.Errorf("failed to write headers: %w", err)
		}
	}

	// Save timing
	if c.config.IncludeTiming {
		timingFile := filepath.Join(dir, fmt.Sprintf("%s_timing.txt", evidenceType))
		timingStr := fmt.Sprintf("%.6f seconds", evidence.Timing)
		if err := os.WriteFile(timingFile, []byte(timingStr), 0644); err != nil {
			return fmt.Errorf("failed to write timing: %w", err)
		}
	}

	return nil
}

// Export creates a zip archive of the evidence package
func (c *Collector) Export(pkg *Package) (string, error) {
	// First save the package
	if err := c.Save(pkg); err != nil {
		return "", err
	}

	// Create zip archive
	// TODO: Implement zip creation
	// For now, return the directory path
	return filepath.Join(c.baseDir, pkg.FindingID), nil
}

// generatePackageID generates a unique package ID
func generatePackageID() string {
	timestamp := time.Now().Format("20060102-150405")
	hash := sha1.Sum([]byte(timestamp))
	return fmt.Sprintf("EVIDENCE-%s-%s", timestamp, hex.EncodeToString(hash[:4]))
}

// hash computes SHA-1 hash of data
func hash(data []byte) string {
	h := sha1.Sum(data)
	return hex.EncodeToString(h[:])
}

// CreateDiffHTML creates an HTML diff view
func (c *Collector) CreateDiffHTML(pkg *Package) (string, error) {
	html := `<!DOCTYPE html>
<html>
<head>
	<title>` + pkg.FindingID + ` - Differential Evidence</title>
	<style>
		body { font-family: monospace; padding: 20px; }
		.baseline { background: #ffeef0; padding: 10px; margin: 10px 0; }
		.mutation { background: #e6ffed; padding: 10px; margin: 10px 0; }
		.diff { background: #fff4e6; padding: 10px; margin: 10px 0; }
		h2 { margin-top: 0; }
	</style>
</head>
<body>
	<h1>Differential Evidence: ` + pkg.FindingID + `</h1>
	<p><strong>Target:</strong> ` + pkg.Target + `</p>
	<p><strong>Technique:</strong> ` + pkg.Technique + `</p>
	<p><strong>Confidence:</strong> ` + fmt.Sprintf("%.2f", pkg.Metadata.Confidence*100) + `%</p>
	<p><strong>Stability:</strong> ` + fmt.Sprintf("%.2f", pkg.Metadata.Stability*100) + `%</p>
	<p><strong>Reason:</strong> ` + pkg.Metadata.Reason + `</p>
	
	<h2>Baseline</h2>
	<div class="baseline">
		<p><strong>Status:</strong> ` + fmt.Sprintf("%d", pkg.Baseline.StatusCode) + `</p>
		<p><strong>Body Size:</strong> ` + fmt.Sprintf("%d", pkg.Baseline.BodySize) + `</p>
		<p><strong>Timing:</strong> ` + fmt.Sprintf("%.6f", pkg.Baseline.Timing) + `s</p>
		<p><strong>Content-Type:</strong> ` + pkg.Baseline.ContentType + `</p>
	</div>
	
	<h2>Mutation</h2>
	<div class="mutation">
		<p><strong>Status:</strong> ` + fmt.Sprintf("%d", pkg.Mutation.StatusCode) + `</p>
		<p><strong>Body Size:</strong> ` + fmt.Sprintf("%d", pkg.Mutation.BodySize) + `</p>
		<p><strong>Timing:</strong> ` + fmt.Sprintf("%.6f", pkg.Mutation.Timing) + `s</p>
		<p><strong>Content-Type:</strong> ` + pkg.Mutation.ContentType + `</p>
	</div>
	
	<h2>Differential</h2>
	<div class="diff">
		<p><strong>Status Change:</strong> ` + fmt.Sprintf("%d → %d", pkg.Baseline.StatusCode, pkg.Mutation.StatusCode) + `</p>
		<p><strong>Size Change:</strong> ` + fmt.Sprintf("%d → %d", pkg.Baseline.BodySize, pkg.Mutation.BodySize) + `</p>
		<p><strong>Timing Change:</strong> ` + fmt.Sprintf("%.6f → %.6f", pkg.Baseline.Timing, pkg.Mutation.Timing) + `s</p>
	</div>
	
	<h2>Replay Verification</h2>
	<p><strong>Attempts:</strong> ` + fmt.Sprintf("%d", pkg.Metadata.ReplayCount) + `</p>
</body>
</html>`

	return html, nil
}
