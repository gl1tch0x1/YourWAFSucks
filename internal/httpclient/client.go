package httpclient

import (
    "bytes"
    "context"
    "crypto/tls"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "time"

    "golang.org/x/net/http2"
)

type Config struct {
    Timeout    time.Duration
    Proxy      string
    Cookie     string
    UserAgent  string
    Headers    map[string]string
    MaxRetries int
}

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
    cfg  Config
    http *http.Client
}

func New(cfg Config) *Client {
    transport := &http.Transport{
        TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
        MaxIdleConns:        200,
        MaxIdleConnsPerHost: 100,
        IdleConnTimeout:     30 * time.Second,
        DisableCompression:  false,
    }

    if cfg.Proxy != "" {
        if pu, err := url.Parse(cfg.Proxy); err == nil {
            transport.Proxy = http.ProxyURL(pu)
        }
    }

    // Enable HTTP/2 for HTTPS
    _ = http2.ConfigureTransport(transport)

    return &Client{
        cfg: cfg,
        http: &http.Client{
            Timeout:   cfg.Timeout,
            Transport: transport,
            CheckRedirect: func(req *http.Request, via []*http.Request) error {
                if len(via) >= 10 {
                    return fmt.Errorf("too many redirects")
                }
                return nil
            },
        },
    }
}

type Request struct {
    Method  string
    URL     string
    Headers map[string]string
    Body    []byte
    Follow  bool
}

func (c *Client) Request(ctx context.Context, r Request) (*Response, error) {
    var lastErr error

    for attempt := 0; attempt <= c.cfg.MaxRetries; attempt++ {
        if attempt > 0 {
            time.Sleep(time.Duration(attempt) * time.Second)
        }

        resp, err := c.do(ctx, r)
        if err == nil {
            return resp, nil
        }
        lastErr = err
    }

    return nil, lastErr
}

func (c *Client) do(ctx context.Context, r Request) (*Response, error) {
    body := bytes.NewReader(r.Body)
    req, err := http.NewRequestWithContext(ctx, r.Method, r.URL, body)
    if err != nil {
        return nil, err
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