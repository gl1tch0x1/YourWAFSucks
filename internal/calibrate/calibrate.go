package calibrate

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
)

type Result struct {
	BaselineStatus int
	BaselineSize   int
	BaselineTime   time.Duration
	BaselineHash   string
	BaselineBody   []byte

	Soft404       bool
	Soft404Status int
	Soft404Body   []byte

	ParentStatus int
	ParentBody   []byte
}

func Run(ctx context.Context, client *httpclient.Client, target string) (*Result, error) {
	r := &Result{}

	// --- Multi-sample baseline (3 samples, take median) ---
	var sizes []int
	var times []time.Duration
	var bodies [][]byte
	var statuses []int

	for i := 0; i < 3; i++ {
		resp, err := client.Request(ctx, httpclient.Request{
			Method: "GET",
			URL:    target,
		})
		if err != nil {
			return nil, fmt.Errorf("baseline request %d failed: %w", i, err)
		}
		if i == 0 || resp.Status == statuses[0] {
			statuses = append(statuses, resp.Status)
			sizes = append(sizes, len(resp.Body))
			times = append(times, resp.Time)
			bodies = append(bodies, resp.Body)
		}
	}

	if len(sizes) == 0 {
		return nil, fmt.Errorf("no valid baseline samples")
	}

	r.BaselineStatus = statuses[0]
	r.BaselineSize = medianInt(sizes)
	r.BaselineTime = medianDuration(times)

	// Pick the sample closest to median size
	bestIdx := 0
	bestDiff := math.MaxInt
	for i, s := range sizes {
		d := abs(s - r.BaselineSize)
		if d < bestDiff {
			bestDiff = d
			bestIdx = i
		}
	}
	if bestIdx < len(bodies) {
		r.BaselineBody = bodies[bestIdx]
		h := sha1.Sum(r.BaselineBody)
		r.BaselineHash = hex.EncodeToString(h[:])
	}

	// --- Soft-404 probe (2 random paths) ---
	var s404Statuses []int
	var s404Bodies [][]byte
	for i := 0; i < 2; i++ {
		rnd := randomString(12)
		resp, err := client.Request(ctx, httpclient.Request{
			Method: "GET",
			URL:    fmt.Sprintf("%s/%s%d", baseOf(target), rnd, i),
		})
		if err != nil {
			continue
		}
		s404Statuses = append(s404Statuses, resp.Status)
		s404Bodies = append(s404Bodies, resp.Body)
	}
	if len(s404Statuses) == 2 &&
		s404Statuses[0] == s404Statuses[1] &&
		s404Statuses[0] != 404 && s404Statuses[0] != 410 {
		r.Soft404 = true
		r.Soft404Status = s404Statuses[0]
		r.Soft404Body = s404Bodies[0]
	}

	return r, nil
}

// --- helpers ---

func baseOf(u string) string {
	// Strip path component
	for i := len(u) - 1; i >= 0; i-- {
		if u[i] == '/' {
			return u[:i]
		}
	}
	return u
}

func randomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func medianInt(xs []int) int {
	if len(xs) == 0 {
		return 0
	}
	s := append([]int(nil), xs...)
	sort.Ints(s)
	return s[len(s)/2]
}

func medianDuration(xs []time.Duration) time.Duration {
	if len(xs) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), xs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
