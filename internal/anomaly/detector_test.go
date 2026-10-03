package anomaly

import (
	"testing"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
)

func newResp(status, size int, ms int64) *httpclient.Response {
	return &httpclient.Response{
		Status: status,
		Body:   make([]byte, size),
		Time:   time.Duration(ms) * time.Millisecond,
	}
}

func TestScoreRequiresMinimumSamples(t *testing.T) {
	d := NewDetector()
	for i := 0; i < 4; i++ {
		d.Observe(newResp(200, 100, 50))
	}
	if got := d.Score(newResp(200, 100, 50)); got != 0 {
		t.Fatalf("Score() with 4 samples = %v, want 0", got)
	}
}

func TestBaselineScoresNearZero(t *testing.T) {
	d := NewDetector()
	for i := 0; i < 6; i++ {
		d.Observe(newResp(200, 100, 50))
	}
	if got := d.Score(newResp(200, 100, 50)); got > 0.05 {
		t.Fatalf("Score() on identical baseline = %v, want ~0", got)
	}
}

func TestOutlierScoresHigh(t *testing.T) {
	d := NewDetector()
	d.Observe(newResp(200, 100, 50))
	d.Observe(newResp(200, 101, 51))
	d.Observe(newResp(200, 99, 49))
	d.Observe(newResp(200, 100, 50))
	d.Observe(newResp(200, 102, 52))

	outlier := newResp(500, 100000, 50)
	if got := d.Score(outlier); got <= 0.5 {
		t.Fatalf("Score() on outlier = %v, want > 0.5", got)
	}
}

func TestScoreNeverNaN(t *testing.T) {
	d := NewDetector()
	for i := 0; i < 5; i++ {
		d.Observe(newResp(200, 0, 0))
	}
	got := d.Score(newResp(200, 0, 0))
	if got != got {
		t.Fatal("Score() returned NaN")
	}
}

func TestClusterGroupsByStatusAndSize(t *testing.T) {
	d := NewDetector()
	responses := []*httpclient.Response{
		newResp(200, 100, 10),  // idx 0
		newResp(200, 105, 12),  // idx 1 (same status + size bucket)
		newResp(403, 100, 10),  // idx 2
		newResp(200, 5000, 10), // idx 3 (different size bucket)
	}

	clusters := d.Cluster(responses)
	if len(clusters) != 3 {
		t.Fatalf("Cluster() returned %d clusters, want 3", len(clusters))
	}

	// Deterministic ordering by ID.
	wantIDs := []string{"200:13", "200:7", "403:7"}
	for i, want := range wantIDs {
		if clusters[i].ID != want {
			t.Fatalf("clusters[%d].ID = %q, want %q", i, clusters[i].ID, want)
		}
	}

	byID := make(map[string]*Cluster, len(clusters))
	for _, c := range clusters {
		byID[c.ID] = c
	}
	g := byID["200:7"]
	if g == nil || g.Size != 2 || len(g.Members) != 2 || g.Members[0] != 0 || g.Members[1] != 1 {
		t.Fatalf("cluster 200:7 = %+v, want members [0 1]", g)
	}
	if g.MeanSize <= 0 || g.Statuses["200"] != 2 {
		t.Fatalf("cluster 200:7 stats = %+v, want mean size > 0 and status count 2", g)
	}
}

func TestObserveNilIsIgnored(t *testing.T) {
	d := NewDetector()
	d.Observe(nil)
	if d.Count() != 0 {
		t.Fatalf("Count() = %d, want 0", d.Count())
	}
}
