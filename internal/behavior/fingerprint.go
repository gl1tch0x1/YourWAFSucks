package behavior

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
)

// Fingerprint is a compact, comparable signature of an HTTP response.
type Fingerprint struct {
	Status          int
	SizeBucket      int
	TimingBucket    int
	ContentType     string
	TitleHash       string
	HeaderSignature string
	BodyHash        string
}

// Change describes how two fingerprints differ.
type Change struct {
	StatusChanged      bool
	SizeChanged        bool
	TimingChanged      bool
	ContentTypeChanged bool
	TitleChanged       bool
	HeaderChanged      bool
	Distance           float64
	Significant        bool
}

var titleRegex = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

var signatureHeaders = []string{"server", "content-type", "x-powered-by", "location"}

// Capture builds a fingerprint from a response. A nil response yields the zero
// fingerprint.
func Capture(resp *httpclient.Response) Fingerprint {
	if resp == nil {
		return Fingerprint{}
	}

	ct := resp.ContentType
	if ct == "" && resp.Headers != nil {
		ct = resp.Headers.Get("Content-Type")
	}

	return Fingerprint{
		Status:          resp.Status,
		SizeBucket:      sizeBucket(len(resp.Body)),
		TimingBucket:    timingBucket(resp.Time),
		ContentType:     normalizeContentType(ct),
		TitleHash:       titleHash(resp.Body),
		HeaderSignature: headerSignature(resp.Headers),
		BodyHash:        bodyHash(resp.Body),
	}
}

// Distance returns a normalized distance in [0,1] between two fingerprints;
// zero means identical.
func (f Fingerprint) Distance(o Fingerprint) float64 {
	d := 0.0
	if f.Status != o.Status {
		d += 0.25
	}
	d += 0.15 * bucketDistance(f.SizeBucket, o.SizeBucket)
	d += 0.15 * bucketDistance(f.TimingBucket, o.TimingBucket)
	if f.ContentType != o.ContentType {
		d += 0.15
	}
	if f.TitleHash != o.TitleHash {
		d += 0.15
	}
	if f.HeaderSignature != o.HeaderSignature {
		d += 0.075
	}
	if f.BodyHash != o.BodyHash {
		d += 0.075
	}
	return clamp01(d)
}

// SameClass reports whether two fingerprints fall within the given distance
// threshold.
func (f Fingerprint) SameClass(o Fingerprint, threshold float64) bool {
	return f.Distance(o) <= threshold
}

// Compare produces a detailed Change between two fingerprints. The change is
// Significant when the distance exceeds threshold.
func Compare(a, b Fingerprint, threshold float64) Change {
	dist := a.Distance(b)
	return Change{
		StatusChanged:      a.Status != b.Status,
		SizeChanged:        a.SizeBucket != b.SizeBucket,
		TimingChanged:      a.TimingBucket != b.TimingBucket,
		ContentTypeChanged: a.ContentType != b.ContentType,
		TitleChanged:       a.TitleHash != b.TitleHash,
		HeaderChanged:      a.HeaderSignature != b.HeaderSignature,
		Distance:           dist,
		Significant:        dist > threshold,
	}
}

// sizeBucket maps a byte count to a log2-ish bucket (0, 1, 2, 2, 3, ...).
func sizeBucket(n int) int {
	if n <= 0 {
		return 0
	}
	return int(math.Floor(math.Log2(float64(n)))) + 1
}

// timingBucket maps a duration to a log2-ish bucket based on milliseconds.
func timingBucket(d time.Duration) int {
	ms := d.Milliseconds()
	if ms <= 0 {
		return 0
	}
	return int(math.Floor(math.Log2(float64(ms)))) + 1
}

// bucketDistance returns a normalized distance between two buckets.
func bucketDistance(a, b int) float64 {
	if a == b {
		return 0
	}
	lo, hi := a, b
	if b < a {
		lo, hi = b, a
	}
	if hi <= 0 {
		return 0
	}
	return float64(hi-lo) / float64(hi)
}

func normalizeContentType(ct string) string {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if idx := strings.IndexByte(ct, ';'); idx >= 0 {
		ct = strings.TrimSpace(ct[:idx])
	}
	return ct
}

// titleHash extracts <title>...</title> case-insensitively and returns the first
// 16 hex characters of its sha256 digest, or "" when no title is present.
func titleHash(body []byte) string {
	m := titleRegex.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	title := strings.TrimSpace(string(m[1]))
	if title == "" {
		return ""
	}
	return shortHash([]byte(title))
}

// headerSignature hashes a sorted subset of security-relevant headers.
func headerSignature(h http.Header) string {
	if h == nil {
		return ""
	}

	parts := make([]string, 0, len(signatureHeaders)+1)
	for _, k := range signatureHeaders {
		if v := h.Get(k); v != "" {
			parts = append(parts, k+"="+strings.ToLower(strings.TrimSpace(v)))
		}
	}
	if len(h.Values("Set-Cookie")) > 0 {
		parts = append(parts, "set-cookie=1")
	} else {
		parts = append(parts, "set-cookie=0")
	}
	sort.Strings(parts)
	return shortHash([]byte(strings.Join(parts, "\n")))
}

// bodyHash returns the first 16 hex characters of the sha256 digest of body.
func bodyHash(body []byte) string {
	return shortHash(body)
}

func shortHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])[:16]
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
