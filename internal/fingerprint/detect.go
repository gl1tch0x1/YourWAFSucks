package fingerprint

import (
	"context"
	"strings"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
)

type Result struct {
	Type       string
	Confidence int
}

func Detect(ctx context.Context, client *httpclient.Client, target string) (Result, error) {
	resp, err := client.Request(ctx, httpclient.Request{
		Method: "GET",
		URL:    target,
	})
	if err != nil {
		return Result{}, err
	}

	h := resp.Headers
	server := strings.ToLower(h.Get("Server"))

	// Cloudflare
	if h.Get("CF-Ray") != "" || server == "cloudflare" {
		return Result{"cloudflare", 95}, nil
	}

	// AWS ALB / ELB
	if h.Get("X-Amzn-Trace-Id") != "" || strings.HasPrefix(h.Get("Via"), "1.1 ") {
		return Result{"aws-alb", 85}, nil
	}

	// CloudFront
	if h.Get("X-Amz-Cf-Id") != "" {
		return Result{"cloudfront", 95}, nil
	}

	// Akamai
	if h.Get("X-Akamai-Transformed") != "" || server == "akamaighost" {
		return Result{"akamai", 90}, nil
	}

	// Nginx
	if strings.Contains(server, "nginx") {
		return Result{"nginx", 90}, nil
	}

	// Envoy
	if server == "envoy" || h.Get("X-Envoy-Upstream-Service-Time") != "" {
		return Result{"envoy", 90}, nil
	}

	// Apache
	if strings.Contains(server, "apache") {
		return Result{"apache", 90}, nil
	}

	// IIS
	if strings.Contains(server, "iis") || h.Get("X-Powered-By") != "" {
		return Result{"iis", 85}, nil
	}

	return Result{}, nil
}

// Reorder reorders techniques based on detected frontend.
func Reorder(fp Result, techs []string) []string {
	if fp.Type == "" {
		return techs
	}

	priority := map[string][]string{
		"cloudflare": {"headers", "endpaths", "encoding"},
		"aws-alb":    {"headers", "raw", "endpaths"},
		"cloudfront": {"headers", "endpaths"},
		"nginx":      {"endpaths", "midpaths", "encoding"},
		"envoy":      {"raw", "headers"},
		"apache":     {"endpaths", "headers"},
		"iis":        {"endpaths", "encoding", "headers"},
	}

	wanted := priority[fp.Type]
	if len(wanted) == 0 {
		return techs
	}

	prio := make(map[string]int)
	for i, w := range wanted {
		prio[w] = i
	}

	var high, low []string
	for _, t := range techs {
		if _, ok := prio[t]; ok {
			high = append(high, t)
		} else {
			low = append(low, t)
		}
	}
	return append(high, low...)
}
