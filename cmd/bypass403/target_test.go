package main

import "testing"

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
