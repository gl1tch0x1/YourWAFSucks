package main

import (
	"testing"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/config"
)

func TestNormalizeTarget(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"bare host", "www.example.com/admin", "https://www.example.com/admin"},
		{"protocol-relative", "//www.example.com/admin", "https://www.example.com/admin"},
		{"explicit HTTP", "http://www.example.com/admin", "http://www.example.com/admin"},
		{"explicit HTTPS", "https://www.example.com/admin", "https://www.example.com/admin"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeTarget(tt.input)
			if err != nil {
				t.Fatalf("normalizeTarget(%q) error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("normalizeTarget(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeTargetRejectsInvalidURL(t *testing.T) {
	for _, input := range []string{"", "https:///admin", "ftp://www.example.com/"} {
		if got, err := normalizeTarget(input); err == nil {
			t.Errorf("normalizeTarget(%q) = %q, want an error", input, got)
		}
	}
}

func TestHostnameAllowedRequiresExactMatch(t *testing.T) {
	if !hostnameAllowed("https://app.example.test/path", []string{"app.example.test"}) {
		t.Fatal("expected exact hostname to be allowed")
	}
	if hostnameAllowed("https://sub.app.example.test/path", []string{"app.example.test"}) {
		t.Fatal("unexpectedly allowed a subdomain")
	}
}

func TestDefaultYAMLLoadsSafetyLimits(t *testing.T) {
	cfg, err := config.Load("../../config/default.yaml")
	if err != nil {
		t.Fatalf("config.Load() error: %v", err)
	}
	if cfg.Security.MaxRequestsPerTarget != 10000 {
		t.Errorf("MaxRequestsPerTarget = %d, want 10000", cfg.Security.MaxRequestsPerTarget)
	}
	if cfg.Security.MaxDuration != time.Hour {
		t.Errorf("MaxDuration = %s, want 1h", cfg.Security.MaxDuration)
	}
	for _, technique := range cfg.Techniques.Enabled {
		if technique == "raw" || technique == "protocol" {
			t.Errorf("unsupported technique %q should not be enabled by default", technique)
		}
	}
	for _, technique := range cfg.Techniques.Enabled {
		if technique == "raw" || technique == "protocol" {
			t.Errorf("unsupported technique %q should not be enabled by default", technique)
		}
	}
}

func TestParseTechniquesRejectsUnknownAndDeduplicates(t *testing.T) {
	available := []string{"headers", "verbs"}
	selected, err := parseTechniques("headers, headers,verbs", available)
	if err != nil {
		t.Fatalf("parseTechniques() error: %v", err)
	}
	if len(selected) != 2 || selected[0] != "headers" || selected[1] != "verbs" {
		t.Fatalf("selected techniques = %v, want [headers verbs]", selected)
	}
	if _, err := parseTechniques("headers,unknown", available); err == nil {
		t.Fatal("parseTechniques() accepted an unknown technique")
	}
}

func TestConfigValidateRejectsUnsafeRuntimeLimits(t *testing.T) {
	tests := []struct {
		name   string
		change func(*config.Config)
	}{
		{"workers", func(cfg *config.Config) { cfg.General.Workers = -1 }},
		{"retries", func(cfg *config.Config) { cfg.General.MaxRetries = -1 }},
		{"timeout", func(cfg *config.Config) { cfg.General.Timeout = 0 }},
		{"request budget", func(cfg *config.Config) { cfg.Security.MaxRequestsPerTarget = -1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			test.change(cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate() accepted an invalid runtime limit")
			}
		})
	}
}

func TestParseStatusCodes(t *testing.T) {
	codes, err := parseStatusCodes("200, 403,404")
	if err != nil {
		t.Fatalf("parseStatusCodes() error: %v", err)
	}
	for _, code := range []int{200, 403, 404} {
		if _, ok := codes[code]; !ok {
			t.Errorf("status %d missing from parsed filter", code)
		}
	}
	if _, err := parseStatusCodes("200,700"); err == nil {
		t.Fatal("expected invalid status code to fail")
	}
}
