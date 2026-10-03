package behavior

import (
	"fmt"
	"strings"
	"time"
)

// BehaviorProfile represents the behavioral fingerprint of a target
type BehaviorProfile struct {
	EdgeProfile     EdgeProfile
	HTTPProfile     HTTPProfile
	Normalization   NormalizationProfile
	RedirectProfile RedirectProfile
	HeaderProfile   HeaderProfile
	CookieProfile   CookieProfile
	Timestamp       time.Time
}

// EdgeProfile represents edge/proxy behavior
type EdgeProfile struct {
	PathNormalization   string `json:"path_normalization"`
	HeaderNormalization string `json:"header_normalization"`
	RedirectBehavior    string `json:"redirect_behavior"`
	BodyFiltering       bool   `json:"body_filtering"`
	Compression         bool   `json:"compression"`
	CacheBehavior       string `json:"cache_behavior"`
	WAFBehavior         string `json:"waf_behavior"`
}

// HTTPProfile represents HTTP behavior
type HTTPProfile struct {
	Versions           []string `json:"http_versions"`
	HeaderHandling     string   `json:"header_handling"`
	CaseHandling       string   `json:"case_handling"`
	DuplicateHandling  string   `json:"duplicate_handling"`
	QueryNormalization string   `json:"query_normalization"`
}

// NormalizationProfile represents normalization behavior
type NormalizationProfile struct {
	PathNormalization     string
	CaseNormalization     string
	EncodingNormalization string
	TrailingSlashHandling string
	DotSegmentHandling    string
}

// RedirectProfile represents redirect behavior
type RedirectProfile struct {
	FollowsRedirects         bool
	RedirectLocationHandling string
	RedirectStatusCodes      []int
	HeaderPreservation       bool
	CookiePreservation       bool
}

// HeaderProfile represents header behavior
type HeaderProfile struct {
	CasePreservation      bool
	DuplicateHandling     string
	UnknownHeaderHandling string
	HeaderRewriting       map[string]string
}

// CookieProfile represents cookie behavior
type CookieProfile struct {
	ParsingBehavior       string
	EncodingBehavior      string
	SeparatorBehavior     string
	AttributePreservation bool
}

// Fingerprinter fingerprints HTTP behavior
type Fingerprinter struct {
	testResults []BehaviorTest
}

// BehaviorTest represents a behavior test result
type BehaviorTest struct {
	Name       string
	TestType   string
	Expected   string
	Actual     string
	Passed     bool
	Confidence float64
}

// NewFingerprinter creates a new behavior fingerprinter
func NewFingerprinter() *Fingerprinter {
	return &Fingerprinter{
		testResults: make([]BehaviorTest, 0),
	}
}

// Fingerprint fingerprints the target's behavior
func (f *Fingerprinter) Fingerprint() *BehaviorProfile {
	profile := &BehaviorProfile{
		Timestamp: time.Now(),
	}

	// This would typically be populated by running actual tests
	// For now, we provide a structure that can be filled

	return profile
}

// AnalyzePathNormalization analyzes path normalization behavior
func (f *Fingerprinter) AnalyzePathNormalization(original, normalized string) string {
	if original == normalized {
		return "strict"
	}

	// Check for case normalization
	if strings.EqualFold(original, normalized) {
		return "case_insensitive"
	}

	// Check for dot segment normalization
	if strings.Contains(original, "/.") && !strings.Contains(normalized, "/.") {
		return "dot_segment_normalized"
	}

	// Check for encoding normalization
	if strings.Contains(original, "%") && !strings.Contains(normalized, "%") {
		return "encoding_normalized"
	}

	return "unknown"
}

// AnalyzeHeaderCase analyzes header case handling
func (f *Fingerprinter) AnalyzeHeaderCase(original, response string) string {
	if original == response {
		return "preserved"
	}

	if strings.EqualFold(original, response) {
		return "normalized_to_lowercase"
	}

	return "unknown"
}

// AnalyzeDuplicateHeaders analyzes duplicate header handling
func (f *Fingerprinter) AnalyzeDuplicateHeaders(headerValues []string) string {
	if len(headerValues) == 1 {
		return "merged"
	}

	if len(headerValues) > 1 {
		return "preserved"
	}

	return "unknown"
}

// AnalyzeRedirectBehavior analyzes redirect behavior
func (f *Fingerprinter) AnalyzeRedirectBehavior(statusCode int, location string) RedirectProfile {
	profile := RedirectProfile{
		FollowsRedirects: statusCode >= 300 && statusCode < 400,
	}

	if location != "" {
		profile.RedirectLocationHandling = "absolute"
	} else {
		profile.RedirectLocationHandling = "none"
	}

	profile.RedirectStatusCodes = []int{statusCode}

	return profile
}

// AnalyzeWAFBehavior analyzes WAF behavior
func (f *Fingerprinter) AnalyzeWAFBehavior(statusCode int, body string) string {
	// Check for common WAF responses
	if statusCode == 403 {
		if strings.Contains(strings.ToLower(body), "cloudflare") {
			return "cloudflare"
		}
		if strings.Contains(strings.ToLower(body), "aws") {
			return "aws_waf"
		}
		if strings.Contains(strings.ToLower(body), "akamai") {
			return "akamai"
		}
		if strings.Contains(strings.ToLower(body), "forbidden") {
			return "generic_403"
		}
	}

	if statusCode == 429 {
		return "rate_limited"
	}

	if statusCode == 406 {
		return "content_rejection"
	}

	return "unknown"
}

// AnalyzeCacheBehavior analyzes cache behavior
func (f *Fingerprinter) AnalyzeCacheBehavior(cacheHeaders map[string]string) string {
	if _, ok := cacheHeaders["X-Cache"]; ok {
		return "cache_header_present"
	}

	if _, ok := cacheHeaders["Age"]; ok {
		return "age_header_present"
	}

	if _, ok := cacheHeaders["Cache-Control"]; ok {
		return "cache_control_present"
	}

	return "unknown"
}

// DetectHeaderRewriting detects header rewriting
func (f *Fingerprinter) DetectHeaderRewriting(requestHeaders, responseHeaders map[string]string) map[string]string {
	rewritten := make(map[string]string)

	// Check for common rewritten headers
	if reqHost, ok := requestHeaders["Host"]; ok {
		if respHost, ok := responseHeaders["X-Forwarded-Host"]; ok {
			if reqHost != respHost {
				rewritten["Host"] = respHost
			}
		}
	}

	if reqFor, ok := requestHeaders["X-Forwarded-For"]; ok {
		if respFor, ok := responseHeaders["X-Real-IP"]; ok {
			if reqFor != respFor {
				rewritten["X-Forwarded-For"] = respFor
			}
		}
	}

	return rewritten
}

// DetectCompression detects compression behavior
func (f *Fingerprinter) DetectCompression(contentEncoding string) bool {
	return contentEncoding == "gzip" || contentEncoding == "deflate" || contentEncoding == "br"
}

// DetectBodyFiltering detects body filtering
func (f *Fingerprinter) DetectBodyFiltering(originalSize, responseSize int) bool {
	// If response is significantly smaller, likely filtered
	if responseSize < originalSize/2 {
		return true
	}
	return false
}

// AddTestResult adds a behavior test result
func (f *Fingerprinter) AddTestResult(test BehaviorTest) {
	f.testResults = append(f.testResults, test)
}

// GetTestResults returns all test results
func (f *Fingerprinter) GetTestResults() []BehaviorTest {
	return f.testResults
}

// GetProfileSummary returns a summary of the behavior profile
func (f *Fingerprinter) GetProfileSummary(profile *BehaviorProfile) string {
	summary := fmt.Sprintf("Behavior Profile (timestamp: %s)\n", profile.Timestamp.Format(time.RFC3339))
	summary += fmt.Sprintf("  Path Normalization: %s\n", profile.EdgeProfile.PathNormalization)
	summary += fmt.Sprintf("  Header Normalization: %s\n", profile.EdgeProfile.HeaderNormalization)
	summary += fmt.Sprintf("  Redirect Behavior: %s\n", profile.EdgeProfile.RedirectBehavior)
	summary += fmt.Sprintf("  HTTP Versions: %v\n", profile.HTTPProfile.Versions)
	summary += fmt.Sprintf("  Case Handling: %s\n", profile.HTTPProfile.CaseHandling)
	summary += fmt.Sprintf("  Duplicate Handling: %s\n", profile.HTTPProfile.DuplicateHandling)
	return summary
}

// CompareProfiles compares two behavior profiles
func (f *Fingerprinter) CompareProfiles(profile1, profile2 *BehaviorProfile) float64 {
	similarity := 0.0
	weight := 0.0

	// Compare path normalization
	if profile1.EdgeProfile.PathNormalization == profile2.EdgeProfile.PathNormalization {
		similarity += 0.2
	}
	weight += 0.2

	// Compare header normalization
	if profile1.EdgeProfile.HeaderNormalization == profile2.EdgeProfile.HeaderNormalization {
		similarity += 0.2
	}
	weight += 0.2

	// Compare redirect behavior
	if profile1.EdgeProfile.RedirectBehavior == profile2.EdgeProfile.RedirectBehavior {
		similarity += 0.2
	}
	weight += 0.2

	// Compare HTTP versions
	if compareStringSlices(profile1.HTTPProfile.Versions, profile2.HTTPProfile.Versions) {
		similarity += 0.2
	}
	weight += 0.2

	// Compare case handling
	if profile1.HTTPProfile.CaseHandling == profile2.HTTPProfile.CaseHandling {
		similarity += 0.2
	}
	weight += 0.2

	if weight > 0 {
		return similarity / weight
	}
	return 0.0
}

// compareStringSlices compares string slices
func compareStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
