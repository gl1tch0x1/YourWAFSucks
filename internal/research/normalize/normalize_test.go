package normalize

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
)

func TestVariantsDeterministic(t *testing.T) {
	first := Variants("/Admin/Config")
	second := Variants("/Admin/Config")
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("Variants() is not deterministic:\nfirst:  %+v\nsecond: %+v", first, second)
	}
	if len(first) < 10 {
		t.Fatalf("Variants() returned %d variants, want at least 10", len(first))
	}
	if first[0].Name != "baseline" || first[0].Path != "/Admin/Config" {
		t.Fatalf("Variants()[0] = %+v, want baseline /Admin/Config", first[0])
	}

	seen := map[string]bool{}
	for _, v := range first {
		if v.Name == "" {
			t.Fatalf("Variants() produced a variant with an empty name: %+v", v)
		}
		if seen[v.Name] {
			t.Fatalf("Variants() produced duplicate name %q", v.Name)
		}
		seen[v.Name] = true
	}
}

func TestVariantsHandleRootAndRelativePaths(t *testing.T) {
	root := Variants("/")
	if root[0].Path != "/" {
		t.Fatalf("Variants(\"/\")[0].Path = %q, want \"/\"", root[0].Path)
	}
	relative := Variants("admin")
	if relative[0].Path != "/admin" {
		t.Fatalf("Variants(\"admin\")[0].Path = %q, want \"/admin\"", relative[0].Path)
	}
}

func TestDifferentialClassification(t *testing.T) {
	d := Differential{
		Baseline: Variant{Name: "baseline", Path: "/admin"},
		Results: []Result{
			{Variant: "baseline", Status: 200, BodyHash: "aaa"},
			{Variant: "same", Status: 200, BodyHash: "aaa"},
			{Variant: "status-diff", Status: 403, BodyHash: "aaa"},
			{Variant: "body-diff", Status: 200, BodyHash: "bbb"},
			{Variant: "errored", Error: "connection reset"},
		},
		Normalized: []string{"same"},
	}

	differing := d.Differing()
	if len(differing) != 3 {
		t.Fatalf("Differing() returned %d results, want 3: %+v", len(differing), differing)
	}
	got := map[string]bool{}
	for _, r := range differing {
		got[r.Variant] = true
	}
	for _, want := range []string{"status-diff", "body-diff", "errored"} {
		if !got[want] {
			t.Fatalf("Differing() did not include %q: %+v", want, differing)
		}
	}
	if got["baseline"] || got["same"] {
		t.Fatalf("Differing() included a normalized or baseline result: %+v", differing)
	}

	if len(d.Normalized) != 1 || d.Normalized[0] != "same" {
		t.Fatalf("Normalized = %v, want [same]", d.Normalized)
	}
}

func TestDifferentialDifferingWithoutBaseline(t *testing.T) {
	d := Differential{
		Baseline: Variant{Name: "baseline"},
		Results:  []Result{{Variant: "other", Status: 200}},
	}
	if got := d.Differing(); got != nil {
		t.Fatalf("Differing() = %+v, want nil when baseline is absent", got)
	}
}

func TestRunClassifiesAgainstServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only the exact baseline path is treated as the canonical response;
		// all other paths return a distinct body so they register as differing.
		if r.URL.Path == "/app" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("canonical"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer server.Close()

	client := httpclient.New(httpclient.Config{Timeout: time.Second, MaxRetries: 0})
	d, err := Run(context.Background(), client, server.URL+"/app")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if d.Baseline.Name != "baseline" {
		t.Fatalf("Run() baseline = %+v, want baseline", d.Baseline)
	}
	if len(d.Results) != len(Variants("/app")) {
		t.Fatalf("Run() recorded %d results, want %d", len(d.Results), len(Variants("/app")))
	}
	if d.Results[0].Error != "" {
		t.Fatalf("Run() baseline error = %q", d.Results[0].Error)
	}
	if len(d.Differing()) == 0 {
		t.Fatal("Run() found no differing normalization variants")
	}
}

func TestRunRejectsInvalidArguments(t *testing.T) {
	client := httpclient.New(httpclient.Config{Timeout: time.Second})
	if _, err := Run(context.Background(), nil, "http://example.test/"); err == nil {
		t.Fatal("Run() accepted a nil client")
	}
	if _, err := Run(context.Background(), client, "http:///missing-host"); err == nil {
		t.Fatal("Run() accepted a URL without a host")
	}
}
