// Package proxyorigin compares how a target behaves when reached directly
// (origin) versus through a proxy. It issues only safe, idempotent GET
// requests and reports per-endpoint response differences.
package proxyorigin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
)

// Endpoint identifies a URL to compare under both clients.
type Endpoint struct {
	URL   string
	Label string
}

// Diff describes how a single endpoint responded through the origin and proxy
// paths.
type Diff struct {
	Label        string
	OriginStatus int
	ProxyStatus  int
	SameStatus   bool
	SameBody     bool
	BodyDelta    float64
	Notes        string
}

// Report aggregates every Diff for a target.
type Report struct {
	Target     string
	Diffs      []Diff
	Consistent bool
}

// Compare requests every endpoint through originClient and proxyClient and
// builds a Report. Per-endpoint request failures are recorded in Diff.Notes and
// mark the report inconsistent; Compare returns an error only for invalid
// arguments.
func Compare(ctx context.Context, originClient, proxyClient *httpclient.Client, endpoints []Endpoint) (Report, error) {
	if originClient == nil || proxyClient == nil {
		return Report{}, errors.New("proxyorigin: nil client")
	}

	report := Report{Consistent: true}
	if len(endpoints) > 0 {
		report.Target = endpoints[0].URL
	}

	for _, endpoint := range endpoints {
		origin, originErr := originClient.Request(ctx, httpclient.Request{Method: http.MethodGet, URL: endpoint.URL})
		proxy, proxyErr := proxyClient.Request(ctx, httpclient.Request{Method: http.MethodGet, URL: endpoint.URL})

		if originErr != nil || proxyErr != nil {
			diff := Diff{Label: endpoint.Label}
			if origin != nil {
				diff.OriginStatus = origin.Status
			}
			if proxy != nil {
				diff.ProxyStatus = proxy.Status
			}
			diff.Notes = errorNotes(originErr, proxyErr)
			report.Diffs = append(report.Diffs, diff)
			report.Consistent = false
			continue
		}

		diff := CompareResponses(endpoint.Label, origin, proxy)
		if !diff.SameStatus || !diff.SameBody {
			report.Consistent = false
		}
		report.Diffs = append(report.Diffs, diff)
	}

	return report, nil
}

// CompareResponses computes the Diff between an origin and proxy response. It is
// pure and tolerates nil responses so it can be unit tested with synthetic
// values.
func CompareResponses(label string, origin, proxy *httpclient.Response) Diff {
	diff := Diff{Label: label}
	if origin != nil {
		diff.OriginStatus = origin.Status
	}
	if proxy != nil {
		diff.ProxyStatus = proxy.Status
	}
	if origin == nil || proxy == nil {
		diff.Notes = "origin or proxy response is missing"
		return diff
	}

	diff.SameStatus = origin.Status == proxy.Status
	diff.SameBody = bytes.Equal(origin.Body, proxy.Body)
	diff.BodyDelta = bodyDelta(origin.Body, proxy.Body)

	switch {
	case diff.SameStatus && diff.SameBody:
		diff.Notes = "origin and proxy responses are identical"
	case !diff.SameStatus:
		diff.Notes = fmt.Sprintf("status mismatch: origin=%d proxy=%d", origin.Status, proxy.Status)
	default:
		diff.Notes = fmt.Sprintf("body mismatch: delta=%.4f", diff.BodyDelta)
	}
	return diff
}

// bodyDelta returns a normalized [0,1] difference between two bodies, where 0
// means identical and 1 means maximally different.
func bodyDelta(a, b []byte) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 1.0
	}
	if bytes.Equal(a, b) {
		return 0.0
	}

	longer := len(a)
	if len(b) > longer {
		longer = len(b)
	}
	shorter := len(a)
	if len(b) < shorter {
		shorter = len(b)
	}

	sizeRatio := float64(shorter) / float64(longer)
	matches := 0
	for i := 0; i < shorter; i++ {
		if a[i] == b[i] {
			matches++
		}
	}
	byteSimilarity := float64(matches) / float64(shorter)
	similarity := (sizeRatio + byteSimilarity) / 2.0

	delta := 1.0 - similarity
	if delta < 0 {
		return 0
	}
	if delta > 1 {
		return 1
	}
	return delta
}

func errorNotes(originErr, proxyErr error) string {
	switch {
	case originErr != nil && proxyErr != nil:
		return fmt.Sprintf("origin error: %v; proxy error: %v", originErr, proxyErr)
	case originErr != nil:
		return fmt.Sprintf("origin error: %v", originErr)
	default:
		return fmt.Sprintf("proxy error: %v", proxyErr)
	}
}
