package similarity

import (
	"encoding/json"
	"regexp"
	"strings"
	"unicode"
)

// Analyzer performs semantic similarity analysis
type Analyzer struct {
	config Config
}

// Config holds similarity analyzer configuration
type Config struct {
	EnableDOMAnalysis   bool
	EnableJSONAnalysis  bool
	EnableTextAnalysis  bool
	TokenNormalization  bool
	DynamicValueRemoval bool
	HTMLStructureWeight float64
	TextContentWeight   float64
	JSONStructureWeight float64
}

// Result represents similarity analysis result
type Result struct {
	RawSimilarity      float64 `json:"raw_similarity"`
	DOMSimilarity      float64 `json:"dom_similarity,omitempty"`
	TextSimilarity     float64 `json:"text_similarity,omitempty"`
	JSONSimilarity     float64 `json:"json_similarity,omitempty"`
	CombinedSimilarity float64 `json:"combined_similarity"`
	IsHTML             bool    `json:"is_html"`
	IsJSON             bool    `json:"is_json"`
}

// New creates a new similarity analyzer
func New(cfg Config) *Analyzer {
	if cfg.HTMLStructureWeight == 0 {
		cfg.HTMLStructureWeight = 0.4
	}
	if cfg.TextContentWeight == 0 {
		cfg.TextContentWeight = 0.6
	}
	if cfg.JSONStructureWeight == 0 {
		cfg.JSONStructureWeight = 0.7
	}
	return &Analyzer{config: cfg}
}

// Analyze performs comprehensive similarity analysis
func (a *Analyzer) Analyze(body1, body2 []byte) Result {
	result := Result{
		RawSimilarity: calculateRawSimilarity(body1, body2),
		IsHTML:        isHTML(body1) || isHTML(body2),
		IsJSON:        isJSON(body1) || isJSON(body2),
	}

	// If both are HTML, perform DOM analysis
	if result.IsHTML && a.config.EnableDOMAnalysis {
		result.DOMSimilarity = a.analyzeDOMStructure(body1, body2)
		result.TextSimilarity = a.analyzeTextContent(body1, body2)
		result.CombinedSimilarity = (result.DOMSimilarity * a.config.HTMLStructureWeight) +
			(result.TextSimilarity * a.config.TextContentWeight)
	} else if result.IsJSON && a.config.EnableJSONAnalysis {
		// If both are JSON, perform structure analysis
		result.JSONSimilarity = a.analyzeJSONStructure(body1, body2)
		result.CombinedSimilarity = result.JSONSimilarity
	} else if a.config.EnableTextAnalysis {
		// Text analysis for non-HTML/JSON
		result.TextSimilarity = a.analyzeTextContent(body1, body2)
		result.CombinedSimilarity = result.TextSimilarity
	} else {
		// Fall back to raw similarity
		result.CombinedSimilarity = result.RawSimilarity
	}

	return result
}

// calculateRawSimilarity computes byte-level similarity
func calculateRawSimilarity(body1, body2 []byte) float64 {
	if len(body1) == 0 && len(body2) == 0 {
		return 1.0
	}
	if len(body1) == 0 || len(body2) == 0 {
		return 0.0
	}

	// Size-based similarity
	maxLen := float64(max(len(body1), len(body2)))
	minLen := float64(min(len(body1), len(body2)))
	sizeRatio := minLen / maxLen

	// Byte-level similarity
	minLenInt := min(len(body1), len(body2))
	matches := 0
	for i := 0; i < minLenInt; i++ {
		if body1[i] == body2[i] {
			matches++
		}
	}
	byteSimilarity := float64(matches) / float64(minLenInt)

	// Combine size and byte similarity
	return (sizeRatio + byteSimilarity) / 2.0
}

// analyzeDOMStructure analyzes HTML DOM structure similarity
func (a *Analyzer) analyzeDOMStructure(body1, body2 []byte) float64 {
	// Extract tag structure (simplified DOM analysis)
	struct1 := extractHTMLStructure(body1)
	struct2 := extractHTMLStructure(body2)

	// Compare tag sequences
	return compareTagSequences(struct1, struct2)
}

// extractHTMLStructure extracts tag structure from HTML
func extractHTMLStructure(body []byte) []string {
	// Simple tag extraction - can be enhanced with proper HTML parser
	tags := []string{}
	currentTag := ""
	inTag := false

	for _, b := range body {
		if b == '<' {
			inTag = true
			continue
		}
		if b == '>' {
			inTag = false
			if len(currentTag) > 0 {
				// Normalize tag
				tag := normalizeTag(currentTag)
				if tag != "" {
					tags = append(tags, tag)
				}
				currentTag = ""
			}
			continue
		}
		if inTag {
			currentTag += string(b)
		}
	}

	return tags
}

// normalizeTag normalizes HTML tag
func normalizeTag(tag string) string {
	tag = strings.TrimSpace(tag)
	tag = strings.ToLower(tag)

	// Remove attributes (simplified)
	if space := strings.Index(tag, " "); space > 0 {
		tag = tag[:space]
	}

	// Skip comments and special tags
	if strings.HasPrefix(tag, "!--") || strings.HasPrefix(tag, "!") {
		return ""
	}

	return tag
}

// compareTagSequences compares tag sequences
func compareTagSequences(tags1, tags2 []string) float64 {
	if len(tags1) == 0 && len(tags2) == 0 {
		return 1.0
	}
	if len(tags1) == 0 || len(tags2) == 0 {
		return 0.0
	}

	// Use sequence alignment (simplified)
	maxLen := max(len(tags1), len(tags2))
	matches := 0

	for i := 0; i < maxLen; i++ {
		if i < len(tags1) && i < len(tags2) {
			if tags1[i] == tags2[i] {
				matches++
			}
		}
	}

	return float64(matches) / float64(maxLen)
}

// analyzeTextContent analyzes visible text content similarity
func (a *Analyzer) analyzeTextContent(body1, body2 []byte) float64 {
	// Extract visible text
	text1 := extractVisibleText(body1)
	text2 := extractVisibleText(body2)

	// Normalize if enabled
	if a.config.TokenNormalization {
		text1 = normalizeText(text1)
		text2 = normalizeText(text2)
	}

	// Remove dynamic values if enabled
	if a.config.DynamicValueRemoval {
		text1 = removeDynamicValues(text1)
		text2 = removeDynamicValues(text2)
	}

	// Calculate similarity
	return calculateTextSimilarity(text1, text2)
}

// extractVisibleText extracts visible text from body
func extractVisibleText(body []byte) string {
	// Remove HTML tags (simplified)
	html := string(body)

	// Remove script and style content
	html = removeScriptStyle(html)

	// Remove HTML tags
	html = htmlTagRegex.ReplaceAllString(html, " ")

	// Normalize whitespace
	html = whitespaceRegex.ReplaceAllString(html, " ")

	return strings.TrimSpace(html)
}

// removeScriptStyle removes script and style tags and their content
func removeScriptStyle(html string) string {
	// Remove <script>...</script>
	html = scriptRegex.ReplaceAllString(html, "")
	// Remove <style>...</style>
	html = styleRegex.ReplaceAllString(html, "")
	return html
}

// normalizeText normalizes text for comparison
func normalizeText(text string) string {
	// Convert to lowercase
	text = strings.ToLower(text)

	// Remove diacritics for better comparison
	text = removeDiacritics(text)

	// Remove extra whitespace
	text = whitespaceRegex.ReplaceAllString(text, " ")

	return strings.TrimSpace(text)
}

// removeDiacritics removes diacritical marks from text
func removeDiacritics(text string) string {
	var result []rune
	for _, r := range text {
		// Simple diacritic removal - can be enhanced with proper Unicode normalization
		if unicode.IsMark(r) {
			continue
		}
		result = append(result, r)
	}
	return string(result)
}

// removeDynamicValues removes dynamic values (timestamps, nonces, etc.)
func removeDynamicValues(text string) string {
	// Remove common dynamic patterns
	// Timestamps
	text = timestampRegex.ReplaceAllString(text, "[TIMESTAMP]")
	// UUIDs
	text = uuidRegex.ReplaceAllString(text, "[UUID]")
	// Nonces
	text = nonceRegex.ReplaceAllString(text, "[NONCE]")
	// Random hex strings
	text = hexRegex.ReplaceAllString(text, "[HEX]")

	return text
}

// calculateTextSimilarity computes text similarity using word-level comparison
func calculateTextSimilarity(text1, text2 string) float64 {
	if text1 == "" && text2 == "" {
		return 1.0
	}
	if text1 == "" || text2 == "" {
		return 0.0
	}

	words1 := strings.Fields(text1)
	words2 := strings.Fields(text2)

	if len(words1) == 0 && len(words2) == 0 {
		return 1.0
	}
	if len(words1) == 0 || len(words2) == 0 {
		return 0.0
	}

	// Use Jaccard similarity
	set1 := make(map[string]bool)
	set2 := make(map[string]bool)

	for _, w := range words1 {
		set1[w] = true
	}
	for _, w := range words2 {
		set2[w] = true
	}

	intersection := 0
	for w := range set1 {
		if set2[w] {
			intersection++
		}
	}

	union := len(set1) + len(set2) - intersection

	if union == 0 {
		return 1.0
	}

	return float64(intersection) / float64(union)
}

// analyzeJSONStructure analyzes JSON structure similarity
func (a *Analyzer) analyzeJSONStructure(body1, body2 []byte) float64 {
	var map1, map2 map[string]interface{}

	err1 := json.Unmarshal(body1, &map1)
	err2 := json.Unmarshal(body2, &map2)

	if err1 != nil || err2 != nil {
		// If not valid JSON, fall back to raw similarity
		return calculateRawSimilarity(body1, body2)
	}

	// Compare structure keys
	keys1 := getKeys(map1)
	keys2 := getKeys(map2)

	// Jaccard similarity on keys
	set1 := make(map[string]bool)
	set2 := make(map[string]bool)

	for _, k := range keys1 {
		set1[k] = true
	}
	for _, k := range keys2 {
		set2[k] = true
	}

	intersection := 0
	for k := range set1 {
		if set2[k] {
			intersection++
		}
	}

	union := len(set1) + len(set2) - intersection

	if union == 0 {
		return 1.0
	}

	return float64(intersection) / float64(union)
}

// getKeys extracts all keys from a nested map
func getKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
		// Recursively extract nested keys
		if nested, ok := m[k].(map[string]interface{}); ok {
			nestedKeys := getKeys(nested)
			for _, nk := range nestedKeys {
				keys = append(keys, k+"."+nk)
			}
		}
	}
	return keys
}

// isHTML checks if body appears to be HTML
func isHTML(body []byte) bool {
	str := string(body)
	lower := strings.ToLower(str)
	return strings.Contains(lower, "<html") ||
		strings.Contains(lower, "<!doctype") ||
		strings.Contains(lower, "<head") ||
		strings.Contains(lower, "<body")
}

// isJSON checks if body appears to be JSON
func isJSON(body []byte) bool {
	str := strings.TrimSpace(string(body))
	return (strings.HasPrefix(str, "{") && strings.HasSuffix(str, "}")) ||
		(strings.HasPrefix(str, "[") && strings.HasSuffix(str, "]"))
}

// Regex patterns
var (
	htmlTagRegex    = regexp.MustCompile(`<[^>]+>`)
	scriptRegex     = regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
	styleRegex      = regexp.MustCompile(`(?i)<style[^>]*>.*?</style>`)
	whitespaceRegex = regexp.MustCompile(`\s+`)
	timestampRegex  = regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}`)
	uuidRegex       = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	nonceRegex      = regexp.MustCompile(`nonce=["'][a-zA-Z0-9+/=]+["']`)
	hexRegex        = regexp.MustCompile(`[a-f0-9]{32,}`)
)

// Helper functions
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
