// Package normalize provides read-only normalization differential research.
//
// It generates deterministic path-normalization variants and observes how a
// target treats each one relative to a baseline. Only idempotent GET requests
// are issued; no attack payloads are sent.
package normalize

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
)

// Variant is a named path-normalization candidate.
type Variant struct {
	Name string
	Path string
}

// Result captures the observed response for a single Variant.
type Result struct {
	Variant  string
	Status   int
	BodyHash string
	BodyLen  int
	Error    string
}

// Differential holds the baseline, every observed result and the names of the
// variants that behaved identically to the baseline (Normalized).
type Differential struct {
	Baseline   Variant
	Results    []Result
	Normalized []string
}

// Variants returns a deterministic list of path-normalization candidates built
// from basePath. It exercises case folding, %2e / %2f encoding, double slashes,
// dot segments, double encoding and trailing dot/slash suffixes.
func Variants(basePath string) []Variant {
	base := basePath
	if base == "" {
		base = "/"
	}
	if !strings.HasPrefix(base, "/") {
		base = "/" + base
	}
	stripped := strings.TrimRight(base, "/")

	return []Variant{
		{Name: "baseline", Path: base},
		{Name: "case-upper", Path: strings.ToUpper(base)},
		{Name: "case-lower", Path: strings.ToLower(base)},
		{Name: "trailing-slash", Path: stripped + "/"},
		{Name: "trailing-dot", Path: stripped + "."},
		{Name: "double-slash", Path: strings.ReplaceAll(base, "/", "//")},
		{Name: "dot-segment", Path: stripped + "/./"},
		{Name: "dotdot-segment", Path: stripped + "/../"},
		{Name: "encoded-dot", Path: stripped + "/%2e"},
		{Name: "encoded-slash", Path: stripped + "%2f"},
		{Name: "double-encoded-dot", Path: stripped + "/%252e"},
		{Name: "double-encoded-slash", Path: stripped + "%252f"},
	}
}

// Run requests every normalization variant against baseURL and classifies each
// one relative to the baseline. Per-variant request failures are recorded in
// Result.Error. Run returns an error only for invalid arguments or when the
// baseline request itself fails.
func Run(ctx context.Context, client *httpclient.Client, baseURL string) (Differential, error) {
	if client == nil {
		return Differential{}, errors.New("normalize: nil client")
	}

	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return Differential{}, fmt.Errorf("normalize: parse base URL: %w", err)
	}
	if parsed.Host == "" {
		return Differential{}, errors.New("normalize: base URL is missing a host")
	}

	variants := Variants(parsed.Path)
	origin := (&url.URL{Scheme: parsed.Scheme, Host: parsed.Host}).String()

	results := make([]Result, 0, len(variants))
	normalized := make([]string, 0, len(variants))
	var baseline Result

	for i, variant := range variants {
		result := Result{Variant: variant.Name}
		resp, reqErr := client.Request(ctx, httpclient.Request{
			Method: http.MethodGet,
			URL:    origin + variant.Path,
		})
		if reqErr != nil {
			result.Error = reqErr.Error()
		} else {
			result.Status = resp.Status
			result.BodyHash = hashBody(resp.Body)
			result.BodyLen = len(resp.Body)
		}
		results = append(results, result)

		if i == 0 {
			baseline = result
			if result.Error != "" {
				return Differential{}, fmt.Errorf("normalize: baseline request failed: %s", result.Error)
			}
			continue
		}
		if result.Error == "" && result.Status == baseline.Status && result.BodyHash == baseline.BodyHash {
			normalized = append(normalized, variant.Name)
		}
	}

	return Differential{
		Baseline:   variants[0],
		Results:    results,
		Normalized: normalized,
	}, nil
}

// Differing returns the results whose behavior differs from the baseline. The
// baseline entry itself is never included.
func (d Differential) Differing() []Result {
	var baseline *Result
	for i := range d.Results {
		if d.Results[i].Variant == d.Baseline.Name {
			baseline = &d.Results[i]
			break
		}
	}
	if baseline == nil {
		return nil
	}

	differing := make([]Result, 0, len(d.Results))
	for _, r := range d.Results {
		if r.Variant == d.Baseline.Name {
			continue
		}
		if r.Error != "" || r.Status != baseline.Status || r.BodyHash != baseline.BodyHash {
			differing = append(differing, r)
		}
	}
	return differing
}

func hashBody(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
