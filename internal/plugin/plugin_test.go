package plugin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/gl1tch0x1/YourWAFSucks/internal/techniques"
)

func TestManifestJSONRoundTrip(t *testing.T) {
	in := Manifest{
		Name:        "custom",
		Version:     "1.0.0",
		Description: "demo",
		Headers:     []HeaderSpec{{Name: "X-Test", Value: "1", Description: "h"}},
		Paths:       []PathSpec{{Pattern: "{path}/admin", Description: "p"}},
		Methods:     []string{"GET", "POST"},
		Raw:         []RawSpec{{Method: "PUT", URL: "{target}/secret", Description: "r"}},
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}
	var out Manifest
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round trip mismatch:\n in=%+v\nout=%+v", in, out)
	}
}

func TestManifestPluginGenerateSubstitutesPlaceholders(t *testing.T) {
	p := ManifestPlugin{Manifest: Manifest{
		Name:    "custom",
		Methods: []string{"GET", "POST"},
		Headers: []HeaderSpec{{Name: "X-Test", Value: "1"}},
		Paths:   []PathSpec{{Pattern: "{path}/admin"}, {Pattern: "{target}/direct"}},
		Raw:     []RawSpec{{Method: "PUT", URL: "{target}/secret"}},
	}}
	payloads := p.Generate(techniques.Context{Target: "https://example.test/base"})

	// 1 header + (2 paths * 2 methods) + 2 methods + 1 raw = 8.
	if len(payloads) != 8 {
		t.Fatalf("len(payloads) = %d, want 8", len(payloads))
	}

	if payloads[0].URL != "https://example.test/base" || payloads[0].Headers["X-Test"] != "1" {
		t.Errorf("header payload = %+v", payloads[0])
	}
	if payloads[0].Technique != "custom" {
		t.Errorf("technique = %q, want custom", payloads[0].Technique)
	}

	if payloads[1].URL != "https://example.test/base/admin" {
		t.Errorf("path payload URL = %q, want /base/admin", payloads[1].URL)
	}
	if payloads[3].URL != "https://example.test/base/direct" {
		t.Errorf("target path payload URL = %q, want /base/direct", payloads[3].URL)
	}
	// raw is last
	last := payloads[len(payloads)-1]
	if last.Method != "PUT" || last.URL != "https://example.test/base/secret" {
		t.Errorf("raw payload = %+v", last)
	}
}

func TestLoadManifestAndDir(t *testing.T) {
	dir := t.TempDir()
	a := Manifest{Name: "alpha", Version: "1", Methods: []string{"GET"}}
	b := Manifest{Name: "beta", Version: "2", Raw: []RawSpec{{Method: "GET", URL: "{target}/x"}}}
	for name, m := range map[string]Manifest{"a.json": a, "b.json": b} {
		data, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("Marshal() error: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatalf("WriteFile() error: %v", err)
		}
	}

	loaded, err := LoadManifest(filepath.Join(dir, "a.json"))
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if loaded.Name != "alpha" {
		t.Errorf("LoadManifest name = %q", loaded.Name)
	}

	plugins, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir() error: %v", err)
	}
	if len(plugins) != 2 {
		t.Fatalf("len(plugins) = %d, want 2", len(plugins))
	}
	// Glob is sorted, so alpha comes first.
	if plugins[0].Name() != "alpha" || plugins[1].Name() != "beta" {
		t.Errorf("plugin order = %q, %q", plugins[0].Name(), plugins[1].Name())
	}
}

func TestLoadDirRejectsUnnamedManifest(t *testing.T) {
	dir := t.TempDir()
	data, _ := json.Marshal(Manifest{Version: "1"})
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), data, 0o600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("LoadDir() accepted a manifest without a name")
	}
}

func TestRegistryAggregates(t *testing.T) {
	r := NewRegistry()
	r.Register(ManifestPlugin{Manifest: Manifest{Name: "alpha", Methods: []string{"GET"}}})
	r.Register(ManifestPlugin{Manifest: Manifest{Name: "beta", Methods: []string{"GET", "POST"}}})
	r.Register(nil) // must be ignored

	names := r.Names()
	if len(names) != 2 || names[0] != "alpha" || names[1] != "beta" {
		t.Fatalf("Names() = %v", names)
	}
	payloads := r.Generate(techniques.Context{Target: "https://example.test"})
	if len(payloads) != 3 {
		t.Fatalf("len(payloads) = %d, want 3", len(payloads))
	}
}
