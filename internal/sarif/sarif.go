// Package sarif renders scan findings as a SARIF 2.1.0 log.
//
// SARIF (Static Analysis Results Interchange Format) is understood by code
// scanning dashboards and CI systems, which makes it a convenient way to feed
// YourWAFSucks results into existing security workflows.
package sarif

import (
	"encoding/json"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/gl1tch0x1/YourWAFSucks/internal/techniques"
)

// SchemaURL points at the official SARIF 2.1.0 JSON schema.
const SchemaURL = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"

// Log is the top level SARIF document.
type Log struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

// Run is a single tool invocation and its results.
type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

// Tool describes the analysis tool that produced a run.
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver carries the identifying metadata and rule catalog for a tool.
type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri"`
	Rules          []Rule `json:"rules"`
}

// Rule describes one detectable result class.
type Rule struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name"`
	ShortDescription     Message           `json:"shortDescription"`
	DefaultConfiguration RuleConfiguration `json:"defaultConfiguration"`
}

// RuleConfiguration holds the default reporting level for a rule.
type RuleConfiguration struct {
	Level string `json:"level"`
}

// Message is a human readable SARIF message.
type Message struct {
	Text string `json:"text"`
}

// Result is a single finding.
type Result struct {
	RuleID     string                 `json:"ruleId"`
	Level      string                 `json:"level"`
	Message    Message                `json:"message"`
	Locations  []Location             `json:"locations"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// Location is a result location, here always a URL artifact.
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation identifies the artifact a result points at.
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
}

// ArtifactLocation holds the (redacted) artifact URI.
type ArtifactLocation struct {
	URI string `json:"uri"`
}

// LevelFor maps a numeric score to a SARIF level.
func LevelFor(score int) string {
	switch {
	case score >= 90:
		return "error"
	case score >= 70:
		return "warning"
	default:
		return "note"
	}
}

type ruleKey struct {
	id   string
	name string
}

// Build assembles a SARIF log from findings. Rules are emitted once per
// distinct technique, sorted by id, and results preserve the input order.
func Build(findings []techniques.Result, target, version string) (Log, error) {
	log := Log{
		Version: "2.1.0",
		Schema:  SchemaURL,
	}

	ruleScores := make(map[ruleKey]int)
	for _, f := range findings {
		id := f.Payload.Technique
		if id == "" {
			id = "unknown"
		}
		k := ruleKey{id: id, name: id}
		if score := f.Score.Score; score > ruleScores[k] {
			ruleScores[k] = score
		}
	}

	keys := make([]ruleKey, 0, len(ruleScores))
	for k := range ruleScores {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].id < keys[j].id })

	rules := make([]Rule, 0, len(keys))
	for _, k := range keys {
		rules = append(rules, Rule{
			ID:                   k.id,
			Name:                 k.name,
			ShortDescription:     Message{Text: k.name},
			DefaultConfiguration: RuleConfiguration{Level: LevelFor(ruleScores[k])},
		})
	}

	results := make([]Result, 0, len(findings))
	for _, f := range findings {
		id := f.Payload.Technique
		if id == "" {
			id = "unknown"
		}

		message := f.Score.Reason
		if message == "" {
			message = f.Payload.Description
		}
		if message == "" {
			message = id
		}

		status := 0
		if f.Response != nil {
			status = f.Response.Status
		}

		results = append(results, Result{
			RuleID:  id,
			Level:   LevelFor(f.Score.Score),
			Message: Message{Text: message},
			Locations: []Location{{
				PhysicalLocation: PhysicalLocation{
					ArtifactLocation: ArtifactLocation{URI: RedactURL(f.Payload.URL)},
				},
			}},
			Properties: map[string]interface{}{
				"score":        f.Score.Score,
				"status":       status,
				"replay_count": f.ReplayCount,
			},
		})
	}

	log.Runs = []Run{{
		Tool: Tool{Driver: Driver{
			Name:           "YourWAFSucks",
			Version:        version,
			InformationURI: "https://github.com/gl1tch0x1/YourWAFSucks",
			Rules:          rules,
		}},
		Results: results,
	}}
	return log, nil
}

// Write builds the SARIF log and writes it to path.
func Write(path string, findings []techniques.Result, target, version string) error {
	log, err := Build(findings, target, version)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

// RedactURL removes userinfo and redacts sensitive query parameters. It mirrors
// the rules used by internal/output so reports never leak credentials.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.User = nil
	query := u.Query()
	for key := range query {
		normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
		switch normalized {
		case "token", "access_token", "refresh_token", "api_key", "apikey", "secret",
			"password", "passwd", "authorization", "session", "cookie":
			query[key] = []string{"[REDACTED]"}
		}
	}
	u.RawQuery = query.Encode()
	return u.String()
}
