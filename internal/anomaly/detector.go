package anomaly

import (
	"fmt"
	"math"
	"sort"
	"sync"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
)

// Detector accumulates response statistics and scores new responses against
// them using robust, median-based anomaly detection. Observe is thread-safe.
type Detector struct {
	mu       sync.Mutex
	sizes    []float64
	times    []float64
	statuses map[int]int
}

// Cluster groups responses that share a status and size bucket.
type Cluster struct {
	ID       string
	Members  []int
	Size     int
	MeanSize float64
	MeanTime float64
	Statuses map[string]int
}

// NewDetector returns an empty detector.
func NewDetector() *Detector {
	return &Detector{statuses: make(map[int]int)}
}

// Observe records a response into the baseline.
func (d *Detector) Observe(resp *httpclient.Response) {
	if resp == nil {
		return
	}
	d.mu.Lock()
	d.sizes = append(d.sizes, float64(len(resp.Body)))
	d.times = append(d.times, resp.Time.Seconds())
	d.statuses[resp.Status]++
	d.mu.Unlock()
}

// Count returns the number of observed responses.
func (d *Detector) Count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.sizes)
}

// Score returns a robust anomaly score in [0,1] for a response. It returns 0
// until at least five responses have been observed.
func (d *Detector) Score(resp *httpclient.Response) float64 {
	if resp == nil {
		return 0
	}

	d.mu.Lock()
	sizes := append([]float64(nil), d.sizes...)
	times := append([]float64(nil), d.times...)
	statuses := make(map[int]int, len(d.statuses))
	for k, v := range d.statuses {
		statuses[k] = v
	}
	d.mu.Unlock()

	n := len(sizes)
	if n < 5 {
		return 0
	}

	zSize := robustZ(float64(len(resp.Body)), sizes)
	zTime := robustZ(resp.Time.Seconds(), times)

	rarity := 1.0
	if count, ok := statuses[resp.Status]; ok {
		rarity = 1.0 - float64(count)/float64(n)
	}

	score := 0.4*normZ(zSize) + 0.3*normZ(zTime) + 0.3*clamp01(rarity)
	return clamp01(score)
}

// Cluster groups responses by (status, size bucket) with deterministic IDs and
// ordering. Members hold indices into the supplied slice.
func (d *Detector) Cluster(responses []*httpclient.Response) []*Cluster {
	index := make(map[string]*Cluster)
	order := make([]string, 0)

	for i, resp := range responses {
		if resp == nil {
			continue
		}
		key := fmt.Sprintf("%d:%d", resp.Status, sizeBucket(len(resp.Body)))
		c, ok := index[key]
		if !ok {
			c = &Cluster{ID: key, Statuses: make(map[string]int)}
			index[key] = c
			order = append(order, key)
		}
		c.Members = append(c.Members, i)
		c.MeanSize += float64(len(resp.Body))
		c.MeanTime += resp.Time.Seconds()
		c.Statuses[fmt.Sprintf("%d", resp.Status)]++
	}

	sort.Strings(order)
	out := make([]*Cluster, 0, len(order))
	for _, key := range order {
		c := index[key]
		c.Size = len(c.Members)
		if c.Size > 0 {
			c.MeanSize /= float64(c.Size)
			c.MeanTime /= float64(c.Size)
		}
		out = append(out, c)
	}
	return out
}

func robustZ(x float64, data []float64) float64 {
	if len(data) == 0 {
		return 0
	}
	med := median(data)
	scale := 1.4826 * medianAbsDev(data, med)
	if scale <= 0 {
		scale = meanAbsDev(data, med)
	}
	if scale <= 0 {
		if x == med {
			return 0
		}
		return 6
	}
	return math.Abs(x-med) / scale
}

func normZ(z float64) float64 {
	if z <= 0 {
		return 0
	}
	return z / (z + 3.0)
}

func median(data []float64) float64 {
	if len(data) == 0 {
		return 0
	}
	s := append([]float64(nil), data...)
	sort.Float64s(s)
	return medianSorted(s)
}

func medianSorted(s []float64) float64 {
	n := len(s)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

func medianAbsDev(data []float64, med float64) float64 {
	dev := make([]float64, len(data))
	for i, v := range data {
		dev[i] = math.Abs(v - med)
	}
	sort.Float64s(dev)
	return medianSorted(dev)
}

func meanAbsDev(data []float64, med float64) float64 {
	if len(data) == 0 {
		return 0
	}
	var sum float64
	for _, v := range data {
		sum += math.Abs(v - med)
	}
	return sum / float64(len(data))
}

// sizeBucket maps a byte count to a log2-ish bucket.
func sizeBucket(n int) int {
	if n <= 0 {
		return 0
	}
	return int(math.Floor(math.Log2(float64(n)))) + 1
}

func clamp01(v float64) float64 {
	if math.IsNaN(v) || v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
