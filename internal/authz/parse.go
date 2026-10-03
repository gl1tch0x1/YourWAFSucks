package authz

import (
	"fmt"
	"strings"
)

// ParseSession parses a compact session specification into a SessionContext.
//
// The format is a list of key=value pairs separated by ';' or ','. Values may
// be double- or single-quoted when they contain separators (for example a
// Cookie header that itself contains ';'). The "name" and "type" keys are
// optional when the type can be inferred from the supplied fields.
//
//	admin;type=cookie;cookie="sid=abc; role=admin"
//	api;type=bearer;token=eyJ...
//	svc;header="X-Service-Token: s3cr3t"
//	legacy;basic:alice=wonderland
func ParseSession(spec string) (*SessionContext, error) {
	pairs, err := splitPairs(spec)
	if err != nil {
		return nil, err
	}
	if len(pairs) == 0 {
		return nil, fmt.Errorf("empty session specification")
	}

	cfg := Credentials{}
	name := ""

	for _, pair := range pairs {
		if strings.HasPrefix(strings.ToLower(pair), "basic:") {
			v := pair[len("basic:"):]
			u, p, _ := strings.Cut(v, "=")
			cfg.Username = strings.TrimSpace(u)
			cfg.Password = strings.TrimSpace(p)
			if cfg.Type == "" {
				cfg.Type = "basic"
			}
			continue
		}
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			// A bare token is treated as the session name.
			if name == "" && !strings.Contains(pair, ":") {
				name = strings.TrimSpace(pair)
				continue
			}
			return nil, fmt.Errorf("invalid session component %q (expected key=value)", pair)
		}

		key = strings.ToLower(strings.TrimSpace(key))
		value = trimQuotes(strings.TrimSpace(value))

		switch key {
		case "name":
			name = value
		case "type":
			cfg.Type = strings.ToLower(value)
		case "cookie":
			cfg.Cookie = value
		case "header", "header_name", "headername":
			if n, v, found := strings.Cut(value, ":"); found {
				cfg.HeaderName = strings.TrimSpace(n)
				cfg.HeaderValue = strings.TrimSpace(v)
			} else {
				cfg.HeaderName = value
			}
		case "header_value", "headerval", "value":
			cfg.HeaderValue = value
		case "username", "user":
			cfg.Username = value
		case "password", "pass":
			cfg.Password = value
		case "token":
			cfg.Token = value
		case "api_key", "apikey", "key":
			cfg.APIKey = value
		default:
			return nil, fmt.Errorf("unknown session field %q", key)
		}
	}

	if name == "" {
		return nil, fmt.Errorf("session name is required")
	}
	if cfg.Type == "" {
		cfg.Type = inferType(cfg)
	}
	return &SessionContext{Name: name, Credentials: cfg}, nil
}

func inferType(c Credentials) string {
	switch {
	case c.Cookie != "":
		return "cookie"
	case c.Token != "":
		return "bearer"
	case c.APIKey != "":
		return "apikey"
	case c.Username != "" || c.Password != "":
		return "basic"
	case c.HeaderName != "":
		return "header"
	default:
		return "none"
	}
}

func trimQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// splitPairs splits on ';' and ',' while respecting single and double quotes.
func splitPairs(spec string) ([]string, error) {
	var pairs []string
	var current strings.Builder
	var quote rune
	for _, r := range spec {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
			current.WriteRune(r)
		case r == '"' || r == '\'':
			quote = r
			current.WriteRune(r)
		case r == ';' || r == ',':
			if p := strings.TrimSpace(current.String()); p != "" {
				pairs = append(pairs, p)
			}
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote in session specification")
	}
	if p := strings.TrimSpace(current.String()); p != "" {
		pairs = append(pairs, p)
	}
	return pairs, nil
}
