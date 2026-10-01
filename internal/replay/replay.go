package replay

import (
	"context"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
	"github.com/gl1tch0x1/YourWAFSucks/internal/techniques"
)

// Verify replays findings and discards unstable ones.
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

		f.ReplayCount = matches
		f.Score.Replay = matches == attempts
		if matches == attempts {
			f.Score.Score += 10
		} else if matches == 0 {
			f.Score.Score -= 20
		}

		verified = append(verified, f)
	}

	return verified
}
