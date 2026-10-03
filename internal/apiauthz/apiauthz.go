// Package apiauthz drives OpenAPI-discovered endpoints through the session
// authorization matrix and reports access-control weaknesses such as
// unauthenticated access to protected operations and cross-session privilege
// escalation.
package apiauthz

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/authz"
	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
	"github.com/gl1tch0x1/YourWAFSucks/internal/openapi"
	"github.com/gl1tch0x1/YourWAFSucks/internal/score"
	"github.com/gl1tch0x1/YourWAFSucks/internal/techniques"
)

// Options configures an API authorization run.
type Options struct {
	// Target is the base target URL used to resolve relative server entries.
	Target string
	// BaselineSession is the reference session. Defaults to "anonymous".
	BaselineSession string
	// PathOverrides supplies concrete values for {path} parameters.
	PathOverrides map[string]string
	// MaxRequests caps the total number of requests.
	MaxRequests int
	// Delay is inserted between requests.
	Delay time.Duration
	// IncludePublic additionally reports response differences on endpoints that
	// do not declare a security requirement.
	IncludePublic bool
}

// Finding is a single API authorization observation.
type Finding struct {
	ID             string
	Session        string
	Endpoint       string
	Method         string
	URL            string
	Status         int
	BaselineStatus int
	Severity       string
	Reason         string
	RequiresAuth   bool
	Security       []string
	OperationID    string
	Response       *httpclient.Response
	Score          int
}

// Test discovers every operation in the spec, probes it with each configured
// session, and classifies authorization differences.
func Test(ctx context.Context, client *httpclient.Client, sm *authz.SessionManager, spec *openapi.Spec, opts Options) ([]Finding, *authz.Matrix, error) {
	if spec == nil {
		return nil, nil, fmt.Errorf("apiauthz: nil spec")
	}
	if sm == nil {
		return nil, nil, fmt.Errorf("apiauthz: nil session manager")
	}

	base := spec.BaseURL(opts.Target)
	ops := spec.Endpoints()
	endpoints := make([]authz.Endpoint, 0, len(ops))
	meta := make(map[string]openapi.Endpoint, len(ops))
	for _, op := range ops {
		label := op.Method + " " + op.Path
		endpoints = append(endpoints, authz.Endpoint{
			Method: op.Method,
			URL:    op.ResolvePath(base, opts.PathOverrides),
			Label:  label,
		})
		meta[label] = op
	}
	if len(endpoints) == 0 {
		return nil, nil, fmt.Errorf("apiauthz: spec contains no operations")
	}

	baseline := opts.BaselineSession
	if baseline == "" {
		baseline = "anonymous"
	}

	matrix, err := authz.RunMatrix(ctx, client, sm.All(), endpoints, authz.MatrixOptions{
		BaselineSession: baseline,
		MaxRequests:     opts.MaxRequests,
		Delay:           opts.Delay,
	})
	if err != nil {
		return nil, matrix, err
	}

	var findings []Finding

	// 1) Unauthenticated access to operations that declare security.
	for _, op := range ops {
		if !op.RequiresAuth {
			continue
		}
		label := op.Method + " " + op.Path
		cell, ok := matrix.Cell(baseline, label)
		if !ok || cell.Error != "" || !success(cell.Status) {
			continue
		}
		findings = append(findings, Finding{
			ID:           findingID("unauth", label, baseline),
			Session:      baseline,
			Endpoint:     label,
			Method:       op.Method,
			URL:          endpointURL(endpoints, label),
			Status:       cell.Status,
			Severity:     "high",
			Reason:       fmt.Sprintf("protected operation %s returned %d without credentials", label, cell.Status),
			RequiresAuth: true,
			Security:     op.Security,
			OperationID:  op.OperationID,
			Score:        90,
		})
	}

	// 2) Session-vs-baseline differentials.
	for _, d := range matrix.Differentials(baseline) {
		op, known := meta[d.Endpoint]
		if known && !op.RequiresAuth && !opts.IncludePublic {
			continue
		}
		if d.Severity == "info" && !opts.IncludePublic {
			continue
		}
		f := Finding{
			ID:             findingID(d.Severity, d.Endpoint, d.Session),
			Session:        d.Session,
			Endpoint:       d.Endpoint,
			Method:         d.Method,
			URL:            d.URL,
			Status:         d.Status,
			BaselineStatus: d.BaselineStatus,
			Severity:       d.Severity,
			Reason:         d.Reason,
			OperationID:    op.OperationID,
			RequiresAuth:   known && op.RequiresAuth,
			Security:       op.Security,
			Score:          scoreForSeverity(d.Severity),
		}
		f.Response = responseCell(matrix, d.Session, d.Endpoint)
		findings = append(findings, f)
	}

	// 3) Peer body divergence on parameterized operations (BOLA candidates).
	findings = append(findings, peerDivergence(ops, matrix, baseline, opts)...)

	// Attach responses to the spec-derived findings where possible.
	for i := range findings {
		if findings[i].Response == nil {
			findings[i].Response = responseCell(matrix, findings[i].Session, findings[i].Endpoint)
		}
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
		}
		return findings[i].Endpoint < findings[j].Endpoint
	})
	return findings, matrix, nil
}

// peerDivergence flags parameterized operations where two authenticated
// sessions both succeed but receive different bodies, a common object-level
// authorization (BOLA/IDOR) indicator.
func peerDivergence(ops []openapi.Endpoint, m *authz.Matrix, baseline string, opts Options) []Finding {
	var out []Finding
	for _, op := range ops {
		if !hasObjectParam(op) {
			continue
		}
		label := op.Method + " " + op.Path
		type peer struct {
			session string
			cell    authz.Cell
		}
		var peers []peer
		for _, session := range m.Sessions {
			if session == baseline {
				continue
			}
			cell, ok := m.Cell(session, label)
			if !ok || cell.Error != "" || !success(cell.Status) {
				continue
			}
			peers = append(peers, peer{session: session, cell: cell})
		}
		if len(peers) < 2 {
			continue
		}
		base := peers[0]
		for _, p := range peers[1:] {
			if p.cell.BodyHash == base.cell.BodyHash {
				continue
			}
			out = append(out, Finding{
				ID:           findingID("bola", label, p.session+":"+base.session),
				Session:      p.session,
				Endpoint:     label,
				Method:       op.Method,
				URL:          endpointURLFromMatrix(m, label),
				Status:       p.cell.Status,
				Severity:     "medium",
				Reason:       fmt.Sprintf("sessions %q and %q receive different bodies for %s (object-level access candidate)", p.session, base.session, label),
				OperationID:  op.OperationID,
				RequiresAuth: op.RequiresAuth,
				Security:     op.Security,
				Score:        65,
			})
			break
		}
	}
	return out
}

// ToResults converts API authorization findings into scanner results so they
// flow through the existing scoring, replay, reporting, and exit-code paths.
func ToResults(findings []Finding) []techniques.Result {
	out := make([]techniques.Result, 0, len(findings))
	for _, f := range findings {
		desc := f.Reason
		if desc == "" {
			desc = f.Severity + " API authorization finding"
		}
		out = append(out, techniques.Result{
			Payload: techniques.Payload{
				Method:      f.Method,
				URL:         f.URL,
				Description: desc,
				Technique:   "apiauthz",
			},
			Response: f.Response,
			Score: score.Result{
				Score:       f.Score,
				Interesting: true,
				Reason:      f.Reason,
			},
		})
	}
	return out
}

func hasObjectParam(op openapi.Endpoint) bool {
	for _, p := range op.Parameters {
		if p.In != "path" {
			continue
		}
		n := strings.ToLower(p.Name)
		for _, hint := range []string{"id", "uuid", "user", "account", "order", "resource", "object", "tenant", "team"} {
			if strings.Contains(n, hint) {
				return true
			}
		}
	}
	return false
}

func success(status int) bool {
	return (status >= 200 && status < 300) || (status >= 300 && status < 400)
}

func endpointURL(endpoints []authz.Endpoint, label string) string {
	for _, e := range endpoints {
		if e.Label == label {
			return e.URL
		}
	}
	return ""
}

func endpointURLFromMatrix(m *authz.Matrix, label string) string {
	for _, e := range m.Endpoints {
		if e.Label == label {
			return e.URL
		}
	}
	return ""
}

func responseCell(m *authz.Matrix, session, endpoint string) *httpclient.Response {
	// The matrix stores summaries, not full responses, so synthesize a minimal
	// response to preserve status/size for downstream reporting.
	cell, ok := m.Cell(session, endpoint)
	if !ok {
		return nil
	}
	return &httpclient.Response{
		Status: cell.Status,
		Body:   make([]byte, cell.Size),
		Time:   time.Duration(cell.Time * float64(time.Second)),
		URL:    cell.URL,
	}
}

func scoreForSeverity(sev string) int {
	switch sev {
	case "critical":
		return 95
	case "high":
		return 90
	case "medium":
		return 70
	case "low":
		return 45
	default:
		return 30
	}
}

func severityRank(sev string) int {
	switch sev {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

func findingID(kind, endpoint, session string) string {
	sum := sha1.Sum([]byte(kind + "|" + endpoint + "|" + session))
	return "API-" + strings.ToUpper(hex.EncodeToString(sum[:4]))
}
