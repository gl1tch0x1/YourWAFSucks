// Package protocol detects behavioral discrepancies between two transports or
// protocol configurations (for example HTTP/1.1 versus HTTP/2, or a direct
// connection versus a proxy). It compares matching requests and reports where
// the two paths diverge.
package protocol

import (
	"bytes"
	"context"
	"fmt"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
)

// Discrepancy describes where two responses to the same request differ.
type Discrepancy struct {
	Request   string  `json:"request"`
	Method    string  `json:"method"`
	URL       string  `json:"url"`
	StatusA   int     `json:"status_a"`
	StatusB   int     `json:"status_b"`
	BodyDelta float64 `json:"body_delta"`
	Kind      string  `json:"kind"`
	Notes     string  `json:"notes"`
}

// Report aggregates every discrepancy observed across a set of requests.
type Report struct {
	Requests      int           `json:"requests"`
	Discrepancies []Discrepancy `json:"discrepancies"`
	Consistent    bool          `json:"consistent"`
}

// Detect issues each request through both clients and records any differences.
// Per-request transport errors are reported as discrepancies rather than
// aborting the run; Detect returns an error only for invalid arguments.
func Detect(ctx context.Context, clientA, clientB *httpclient.Client, requests []httpclient.Request) (Report, error) {
	if clientA == nil || clientB == nil {
		return Report{}, fmt.Errorf("protocol: nil client")
	}

	report := Report{Requests: len(requests), Consistent: true}
	for _, req := range requests {
		name := req.Method + " " + req.URL
		respA, errA := clientA.Request(ctx, req)
		respB, errB := clientB.Request(ctx, req)

		if errA != nil || errB != nil {
			report.Consistent = false
			report.Discrepancies = append(report.Discrepancies, Discrepancy{
				Request: name,
				Method:  req.Method,
				URL:     req.URL,
				StatusA: statusOf(respA),
				StatusB: statusOf(respB),
				Kind:    "error",
				Notes:   errorNotes(errA, errB),
			})
			continue
		}

		if d, found := CompareRequest(name, respA, respB); found {
			d.Method = req.Method
			d.URL = req.URL
			report.Consistent = false
			report.Discrepancies = append(report.Discrepancies, d)
		}
	}
	return report, nil
}

// CompareRequest compares two responses to the same request. It returns
// found == false when the responses are equivalent.
func CompareRequest(name string, a, b *httpclient.Response) (Discrepancy, bool) {
	d := Discrepancy{Request: name, StatusA: statusOf(a), StatusB: statusOf(b)}

	switch {
	case a == nil || b == nil:
		d.Kind = "error"
		d.Notes = "one or both responses are missing"
		return d, true
	case a.Status != b.Status:
		d.Kind = "status"
		d.BodyDelta = bodyDelta(a.Body, b.Body)
		d.Notes = fmt.Sprintf("status mismatch: A=%d B=%d", a.Status, b.Status)
		return d, true
	case !bytes.Equal(a.Body, b.Body):
		d.BodyDelta = bodyDelta(a.Body, b.Body)
		if len(a.Body) != len(b.Body) {
			d.Kind = "length"
			d.Notes = fmt.Sprintf("body length mismatch: A=%d B=%d", len(a.Body), len(b.Body))
		} else {
			d.Kind = "body"
			d.Notes = fmt.Sprintf("body content mismatch (delta=%.4f)", d.BodyDelta)
		}
		return d, true
	}
	return d, false
}

func statusOf(resp *httpclient.Response) int {
	if resp == nil {
		return 0
	}
	return resp.Status
}

// bodyDelta returns a normalized [0,1] difference where 0 is identical.
func bodyDelta(a, b []byte) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	if len(a) == 0 || len(b) == 0 {
		return 1
	}
	if bytes.Equal(a, b) {
		return 0
	}
	longer, shorter := len(a), len(b)
	if longer < shorter {
		longer, shorter = shorter, longer
	}
	matches := 0
	for i := 0; i < shorter; i++ {
		if a[i] == b[i] {
			matches++
		}
	}
	sizeRatio := float64(shorter) / float64(longer)
	byteSimilarity := float64(matches) / float64(shorter)
	delta := 1.0 - (sizeRatio+byteSimilarity)/2.0
	if delta < 0 {
		return 0
	}
	if delta > 1 {
		return 1
	}
	return delta
}

func errorNotes(a, b error) string {
	switch {
	case a != nil && b != nil:
		return fmt.Sprintf("A error: %v; B error: %v", a, b)
	case a != nil:
		return fmt.Sprintf("A error: %v", a)
	default:
		return fmt.Sprintf("B error: %v", b)
	}
}
