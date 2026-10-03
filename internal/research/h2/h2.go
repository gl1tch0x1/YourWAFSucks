// Package h2 provides read-only HTTP/2 behavior research helpers.
//
// The package intentionally sends only safe, idempotent probes (GET, HEAD and
// OPTIONS) so it can be used against production targets without mutating state.
// Protocol detection is best-effort because httpclient.Response does not expose
// the raw protocol version; the helpers fall back to well-known HTTP/2 hint
// headers when present.
package h2

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
)

// Probe describes a single read-only research probe.
type Probe struct {
	Name        string
	Description string
}

// Observation records the outcome of running a single Probe.
type Observation struct {
	Probe        string
	HTTPVersion  string
	Status       int
	NegotiatedH2 bool
	Notes        string
	Error        string
}

// Probes returns the deterministic set of safe probes Observe executes.
//
// The returned slice is freshly allocated on each call so callers may mutate it
// without affecting later invocations.
func Probes() []Probe {
	return []Probe{
		{
			Name:        "default-get",
			Description: "Baseline GET using the client's configured User-Agent to observe status and negotiated protocol.",
		},
		{
			Name:        "head",
			Description: "HEAD request to observe response metadata without transferring a body.",
		},
		{
			Name:        "options",
			Description: "OPTIONS request to observe advertised server capabilities.",
		},
	}
}

// Observe runs the safe probe set against target using the supplied client.
//
// Individual probe failures are recorded in Observation.Error rather than
// aborting the run; the returned error is reserved for invalid arguments or a
// cancelled context. target is accepted with or without a scheme and defaults
// to https:// when no scheme is present.
func Observe(ctx context.Context, client *httpclient.Client, target string) ([]Observation, error) {
	if client == nil {
		return nil, errors.New("h2: nil client")
	}
	if strings.TrimSpace(target) == "" {
		return nil, errors.New("h2: empty target")
	}
	target = normalizeTarget(target)

	probes := Probes()
	observations := make([]Observation, 0, len(probes))
	for _, probe := range probes {
		observation := Observation{
			Probe: probe.Name,
			Notes: probe.Description,
		}

		resp, err := client.Request(ctx, httpclient.Request{
			Method: methodFor(probe.Name),
			URL:    target,
		})
		if err != nil {
			observation.Error = err.Error()
			observations = append(observations, observation)
			continue
		}

		observation.Status = resp.Status
		observation.NegotiatedH2 = Supported(resp)
		observation.HTTPVersion = httpVersionLabel(resp)
		observations = append(observations, observation)
	}

	if err := ctx.Err(); err != nil {
		return observations, err
	}
	return observations, nil
}

// Supported reports whether resp carries signals consistent with an HTTP/2
// response. Detection is heuristic: httpclient.Response does not expose the
// negotiated protocol, so known protocol hint headers are inspected instead.
func Supported(resp *httpclient.Response) bool {
	if resp == nil || resp.Headers == nil {
		return false
	}
	if resp.Headers.Get("X-Firefox-Spdy") != "" {
		return true
	}
	if resp.Headers.Get("HTTP2-Settings") != "" {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(resp.Headers.Get("Upgrade")), "h2c") {
		return true
	}
	if altSvc := resp.Headers.Get("Alt-Svc"); strings.Contains(strings.ToLower(altSvc), "h2") {
		return true
	}
	return false
}

// Summarize renders a deterministic, human-readable summary of observations.
func Summarize(obs []Observation) string {
	if len(obs) == 0 {
		return "h2: no observations recorded"
	}

	var b strings.Builder
	h2Count := 0
	for _, o := range obs {
		fmt.Fprintf(&b, "%s: ", o.Probe)
		if o.Error != "" {
			fmt.Fprintf(&b, "error=%s\n", o.Error)
			continue
		}
		fmt.Fprintf(&b, "%s status=%d h2=%t\n", o.HTTPVersion, o.Status, o.NegotiatedH2)
		if o.NegotiatedH2 {
			h2Count++
		}
	}
	fmt.Fprintf(&b, "h2: %d/%d probes observed HTTP/2", h2Count, len(obs))
	return b.String()
}

func methodFor(probeName string) string {
	switch probeName {
	case "head":
		return http.MethodHead
	case "options":
		return http.MethodOptions
	default:
		return http.MethodGet
	}
}

func httpVersionLabel(resp *httpclient.Response) string {
	if Supported(resp) {
		return "HTTP/2"
	}
	return "HTTP/1.x"
}

func normalizeTarget(target string) string {
	target = strings.TrimSpace(target)
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	return target
}
