package replay

import (
	"context"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
	"github.com/gl1tch0x1/YourWAFSucks/internal/techniques"
)

// Verify replays findings and discards unstable ones with enhanced stability tracking
func Verify(ctx context.Context, client *httpclient.Client, findings []techniques.Result) []techniques.Result {
	var verified []techniques.Result

	for _, f := range findings {
		matches := 0
		attempts := 2

		for i := 0; i < attempts; i++ {
			resp, err := client.Request(ctx, httpclient.Request{
				Method:  f.Payload.Method,
				URL:     f.Payload.URL,
				Headers: f.Payload.Headers,
				Body:    f.Payload.Body,
			})

			if err != nil {
				continue
			}

			if resp.Status == f.Response.Status {
				matches++
			}
		}

		// Update stability
		if f.Differential != nil {
			f.Differential.UpdateStability(matches, attempts)
		}
		f.ReplayCount = matches

		// Only keep findings with high stability
		stabilityThreshold := 0.5 // 50% stability required
		if f.Differential != nil && f.Differential.Stability >= stabilityThreshold {
			verified = append(verified, f)
		} else if f.Differential == nil && matches == attempts {
			// Fallback for old-style results without differential
			verified = append(verified, f)
		}
	}

	return verified
}
