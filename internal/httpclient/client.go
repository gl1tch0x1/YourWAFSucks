package httpclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

type Config struct {
	Timeout      time.Duration
	Proxy        string
	Cookie       string
	UserAgent    string
	Headers      map[string]string
	MaxRetries   int
	MaxRequests  int
	AllowedHosts []string
}

var ErrRequestLimit = errors.New("maximum request budget reached")
var ErrHostNotAllowed = errors.New("request host is not in the allowlist")

type Response struct {
	Status      int
	Body        []byte
	Headers     http.Header
	ContentType string
	Time        time.Duration
	Redirect    string
	URL         string
}

type Client struct {
	cfg      Config
	http     *http.Client
	requests atomic.Int64
	initErr  error
}

func New(cfg Config) *Client {
	transport := &http.Transport{
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  false,
	}

	client := &Client{cfg: cfg}
	if cfg.Proxy != "" {
		pu, err := url.Parse(cfg.Proxy)
		if err != nil || pu.Hostname() == "" || (strings.ToLower(pu.Scheme) != "http" && strings.ToLower(pu.Scheme) != "https") {
			client.initErr = errors.New("proxy URL must be a valid HTTP or HTTPS URL")
		} else {
			transport.Proxy = http.ProxyURL(pu)
		}
	}

	// Enable HTTP/2 for HTTPS
	_ = http2.ConfigureTransport(transport)

	client.http = &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !hostAllowed(req.URL.Hostname(), cfg.AllowedHosts) {
				return ErrHostNotAllowed
			}
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return client.reserveRequest()
		},
	}
	return client
}

type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
	Follow  bool
}

func (c *Client) Request(ctx context.Context, r Request) (*Response, error) {
	if c.initErr != nil {
		return nil, c.initErr
	}
	if c.cfg.MaxRetries < 0 {
		return nil, errors.New("maximum retries cannot be negative")
	}
	var lastErr error

	for attempt := 0; attempt <= c.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(time.Duration(attempt) * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}

		resp, err := c.do(ctx, r)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if errors.Is(err, ErrRequestLimit) || errors.Is(err, ErrHostNotAllowed) {
			return nil, err
		}
	}

	return nil, lastErr
}

func (c *Client) reserveRequest() error {
	for {
		current := c.requests.Load()
		if c.cfg.MaxRequests > 0 && current >= int64(c.cfg.MaxRequests) {
			return ErrRequestLimit
		}
		if c.requests.CompareAndSwap(current, current+1) {
			return nil
		}
	}
}

func (c *Client) RequestsMade() int64 {
	return c.requests.Load()
}

func (c *Client) do(ctx context.Context, r Request) (*Response, error) {
	body := bytes.NewReader(r.Body)
	req, err := http.NewRequestWithContext(ctx, r.Method, r.URL, body)
	if err != nil {
		return nil, err
	}
	if !hostAllowed(req.URL.Hostname(), c.cfg.AllowedHosts) {
		return nil, ErrHostNotAllowed
	}

	req.Header.Set("User-Agent", c.cfg.UserAgent)
	if c.cfg.Cookie != "" {
		req.Header.Set("Cookie", c.cfg.Cookie)
	}
	for k, v := range c.cfg.Headers {
		req.Header.Set(k, v)
	}
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}

	// Don't auto-normalize paths (preserve //, .., etc.)
	req.URL.RawPath = req.URL.Path
	req.URL.Opaque = ""
	// Prevent Go from cleaning the path
	req.URL.RawPath = ""

	// Bypass Go's automatic path cleaning by using a custom URL
	// Trick: set Opaque to preserve the raw path
	if req.URL.Path != "" {
		req.URL.Opaque = "//" + req.URL.Host + req.URL.Path
	}

	start := time.Now()
	if err := c.reserveRequest(); err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}

	redirect := ""
	if loc := resp.Header.Get("Location"); loc != "" {
		redirect = loc
	}

	return &Response{
		Status:      resp.StatusCode,
		Body:        respBody,
		Headers:     resp.Header,
		ContentType: resp.Header.Get("Content-Type"),
		Time:        elapsed,
		Redirect:    redirect,
		URL:         r.URL,
	}, nil
}

func hostAllowed(host string, allowedHosts []string) bool {
	if len(allowedHosts) == 0 {
		return true
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, allowed := range allowedHosts {
		if host == strings.TrimSuffix(strings.ToLower(strings.TrimSpace(allowed)), ".") {
			return true
		}
	}
	return false
}
