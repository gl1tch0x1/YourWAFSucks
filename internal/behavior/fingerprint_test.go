package behavior

import (
	"net/http"
	"testing"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
)

func resp(status int, body string, headers http.Header) *httpclient.Response {
	return &httpclient.Response{
		Status:  status,
		Body:    []byte(body),
		Headers: headers,
		Time:    50 * time.Millisecond,
	}
}

func TestCaptureIdenticalDistanceZero(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "nginx")
	h.Set("Content-Type", "text/html; charset=utf-8")

	a := Capture(resp(200, "<html><title>Home</title></html>", h))
	b := Capture(resp(200, "<html><title>Home</title></html>", h))

	if d := a.Distance(b); d != 0 {
		t.Fatalf("Distance() = %v, want 0", d)
	}
	if !a.SameClass(b, 0.1) {
		t.Fatal("SameClass() = false for identical fingerprints")
	}

	c := Compare(a, b, 0.1)
	if c.Significant || c.Distance != 0 {
		t.Fatalf("Compare() = %+v, want insignificant zero-distance", c)
	}
}

func TestTitleHashIsCaseInsensitive(t *testing.T) {
	upper := Capture(resp(200, "<HTML><TITLE>Admin Panel</TITLE></HTML>", nil))
	lower := Capture(resp(200, "<html><title>Admin Panel</title></html>", nil))
	if upper.TitleHash == "" {
		t.Fatal("TitleHash is empty for a body containing <title>")
	}
	if upper.TitleHash != lower.TitleHash {
		t.Fatalf("TitleHash differs by tag case: %q vs %q", upper.TitleHash, lower.TitleHash)
	}
}

func TestTitleHashEmptyWhenMissing(t *testing.T) {
	f := Capture(resp(200, "<html><body>no title</body></html>", nil))
	if f.TitleHash != "" {
		t.Fatalf("TitleHash = %q, want empty", f.TitleHash)
	}
}

func TestSizeAndTimingBuckets(t *testing.T) {
	small := Capture(&httpclient.Response{Status: 200, Body: make([]byte, 10), Time: 5 * time.Millisecond})
	large := Capture(&httpclient.Response{Status: 200, Body: make([]byte, 100000), Time: 5 * time.Second})

	if large.SizeBucket <= small.SizeBucket {
		t.Fatalf("SizeBucket large = %d, want > small = %d", large.SizeBucket, small.SizeBucket)
	}
	if large.TimingBucket <= small.TimingBucket {
		t.Fatalf("TimingBucket large = %d, want > small = %d", large.TimingBucket, small.TimingBucket)
	}
}

func TestHeaderSignatureTracksSecurityHeaders(t *testing.T) {
	base := http.Header{}
	base.Set("Server", "nginx")
	base.Set("X-Powered-By", "PHP/8.1")

	withCookie := base.Clone()
	withCookie.Add("Set-Cookie", "sid=abc; Path=/")

	a := headerSignature(base)
	b := headerSignature(withCookie)
	if a == b {
		t.Fatal("headerSignature() ignored Set-Cookie presence")
	}
	if headerSignature(base) != a {
		t.Fatal("headerSignature() is not deterministic")
	}
}

func TestDistanceAndCompare(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "nginx")
	h.Set("Content-Type", "text/html")

	baseline := Capture(resp(200, "<html><title>Home</title></html>", h))
	forbidden := Capture(resp(403, "<html><title>Denied</title></html>", nil))

	if d := baseline.Distance(forbidden); d <= 0 || d > 1 {
		t.Fatalf("Distance() = %v, want in (0,1]", d)
	}

	c := Compare(baseline, forbidden, 0.2)
	if !c.StatusChanged || !c.TitleChanged || !c.HeaderChanged || !c.ContentTypeChanged {
		t.Fatalf("Compare() missed changed components: %+v", c)
	}
	if !c.Significant {
		t.Fatalf("Compare() = %+v, want Significant", c)
	}
	if baseline.SameClass(forbidden, 0.2) {
		t.Fatal("SameClass() = true for clearly different responses")
	}
}
