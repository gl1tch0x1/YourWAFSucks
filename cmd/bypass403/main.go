package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/calibrate"
	"github.com/gl1tch0x1/YourWAFSucks/internal/config"
	"github.com/gl1tch0x1/YourWAFSucks/internal/fingerprint"
	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
	"github.com/gl1tch0x1/YourWAFSucks/internal/output"
	"github.com/gl1tch0x1/YourWAFSucks/internal/rate"
	"github.com/gl1tch0x1/YourWAFSucks/internal/replay"
	"github.com/gl1tch0x1/YourWAFSucks/internal/score"
	"github.com/gl1tch0x1/YourWAFSucks/internal/techniques"
)

const Version = "1.0.0"

func main() {
	var (
		target         = flag.String("u", "", "Target URL")
		configFile     = flag.String("config", "", "Configuration file path")
		techniquesFlag = flag.String("k", "all", "Comma-separated techniques")
		proxyURL       = flag.String("x", "", "Proxy URL")
		cookie         = flag.String("b", "", "Cookie")
		userAgent      = flag.String("A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36", "User-Agent")
		timeout        = flag.Duration("timeout", 10*time.Second, "Request timeout")
		jobs           = flag.Int("j", 20, "Parallel jobs")
		rateLimit      = flag.Int("rate", 100, "Rate limit (requests per second)")
		outputPath     = flag.String("o", "", "Output JSONL path")
		verbose        = flag.Bool("v", false, "Verbose")
		quiet          = flag.Bool("q", false, "Quiet")
		dryRun         = flag.Bool("n", false, "Dry run")
		noRetest       = flag.Bool("no-retest", false, "Skip replay verification")
		maxRetries     = flag.Int("retries", 2, "Max retries")
		showVer        = flag.Bool("version", false, "Show version")
	)

	// Custom header flags (repeatable)
	var headers headerFlag
	flag.Var(&headers, "H", "Custom header (repeatable)")

	flag.Parse()

	if *showVer {
		fmt.Println(Version)
		os.Exit(0)
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, "[!] Target URL required (-u)")
		flag.Usage()
		os.Exit(3)
	}
	targetURL, err := normalizeTarget(*target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Invalid target URL: %v\n", err)
		os.Exit(3)
	}
	*target = targetURL

	// Load configuration
	cfg, err := config.LoadOrDefault(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to load config: %v\n", err)
		cfg = config.DefaultConfig()
	}

	// Override config with CLI flags
	if *timeout != 10*time.Second {
		cfg.General.Timeout = *timeout
	}
	if *jobs != 20 {
		cfg.General.Workers = *jobs
	}
	if *rateLimit != 100 {
		cfg.General.RateLimit = *rateLimit
	}
	if *proxyURL != "" {
		cfg.Proxy.URL = *proxyURL
	}
	if *cookie != "" {
		// Will be set in client config
	}
	if *verbose {
		cfg.General.Verbose = true
	}
	if *quiet {
		cfg.General.Quiet = true
	}
	if *noRetest {
		cfg.General.NoRetest = true
	}
	if *maxRetries != 2 {
		cfg.General.MaxRetries = *maxRetries
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\n[!] Interrupted")
		cancel()
	}()

	logger := output.NewLogger(os.Stderr, cfg.General.Quiet, cfg.General.Verbose)

	logger.Banner(Version, *target)

	// Initialize rate limiter
	limiter := rate.New(cfg.General.RateLimit, cfg.General.Burst, cfg.Security.AdaptiveRateLimiting)

	// --- HTTP client ---
	clientCfg := httpclient.Config{
		Timeout:    cfg.General.Timeout,
		Proxy:      *proxyURL,
		Cookie:     *cookie,
		UserAgent:  *userAgent,
		Headers:    headers.Map(),
		MaxRetries: cfg.General.MaxRetries,
	}
	client := httpclient.New(clientCfg)

	// --- Fingerprint frontend ---
	fp, err := fingerprint.Detect(ctx, client, *target)
	if err != nil {
		logger.Warn("Fingerprint failed: %v", err)
	} else if fp.Type != "" {
		logger.Info("Frontend: %s (%d%% confidence)", fp.Type, fp.Confidence)
	}

	// --- Baseline + calibration ---
	logger.Info("Establishing baseline...")
	cal, err := calibrate.Run(ctx, client, *target)
	if err != nil {
		logger.Err("Calibration failed: %v", err)
		os.Exit(2)
	}
	logger.Info("Baseline: %d (size=%d, time=%.3fs)",
		cal.BaselineStatus, cal.BaselineSize, cal.BaselineTime.Seconds())
	if cal.Soft404 {
		logger.Warn("Soft-404 detected (%d)", cal.Soft404Status)
	}

	// --- Build technique list ---
	reg := techniques.NewRegistry()
	techniques.RegisterAll(reg)

	// Use config techniques if specified, otherwise use CLI flag
	var selected []string
	if len(cfg.Techniques.Enabled) > 0 && *techniquesFlag == "all" {
		selected = cfg.Techniques.Enabled
	} else {
		selected = parseTechniques(*techniquesFlag, reg.Names())
	}

	if len(selected) == 0 {
		logger.Err("No techniques selected")
		os.Exit(3)
	}

	// Reorder by frontend
	selected = fingerprint.Reorder(fp, selected)

	// --- Generate payloads ---
	logger.Info("Generating payloads for %d techniques...", len(selected))
	var all []techniques.Payload
	for _, name := range selected {
		tech := reg.Get(name)
		if tech == nil {
			continue
		}
		payloads := tech.Generate(techniques.Context{
			Target:   *target,
			BypassIP: cfg.Techniques.Headers.BypassIP,
		})
		all = append(all, payloads...)
	}
	logger.Info("Generated %d test cases", len(all))

	if cfg.General.DryRun || *dryRun {
		for _, p := range all {
			fmt.Fprintf(os.Stderr, "[DRY] %s %s\n", p.Method, p.URL)
		}
		return
	}

	// --- Fuzz ---
	logger.Info("Fuzzing with %d workers...", cfg.General.Workers)

	sem := make(chan struct{}, cfg.General.Workers)
	results := make(chan techniques.Result, cfg.General.Workers)
	var wg sync.WaitGroup

	go func() {
		for _, p := range all {
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
			}

			// Rate limiting
			if err := limiter.Wait(ctx); err != nil {
				return
			}

			wg.Add(1)
			go func(p techniques.Payload) {
				defer wg.Done()
				defer func() { <-sem }()

				req := httpclient.Request{
					Method:  p.Method,
					URL:     p.URL,
					Headers: p.Headers,
					Body:    p.Body,
				}

				resp, err := client.Request(ctx, req)
				if err != nil {
					if cfg.General.Verbose {
						logger.Debug("ERR %s: %v", p.URL, err)
					}
					limiter.RecordError()
					return
				}
				limiter.RecordSuccess()
				sc := score.Compute(resp, cal)
				if sc.Interesting {
					results <- techniques.Result{Payload: p, Response: resp, Score: sc}
				}
			}(p)
		}
		wg.Wait()
		close(results)
	}()

	// --- Collect ---
	var findings []techniques.Result
	for r := range results {
		findings = append(findings, r)
		col := output.ColorFor(r.Response.Status)
		logger.FindingLine(col, r)
	}

	// --- Replay ---
	if !cfg.General.NoRetest && len(findings) > 0 {
		logger.Info("Re-verifying findings...")
		findings = replay.Verify(ctx, client, findings)
	}

	// --- Summary ---
	logger.Summary(findings, cal, fp)

	// --- Write output ---
	outPath := *outputPath
	if outPath == "" && cfg.General.OutputPath != "" {
		outPath = cfg.General.OutputPath
	}
	if outPath != "" {
		if err := output.WriteJSONL(outPath, findings, *target); err != nil {
			logger.Err("Write failed: %v", err)
			os.Exit(2)
		}
		logger.Ok("Findings: %s", outPath)
	}

	if len(findings) > 0 {
		os.Exit(10)
	}
}

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------

type headerFlag []string

func (h *headerFlag) String() string { return strings.Join(*h, ",") }
func (h *headerFlag) Set(v string) error {
	*h = append(*h, v)
	return nil
}
func (h headerFlag) Map() map[string]string {
	m := make(map[string]string)
	for _, kv := range h {
		parts := strings.SplitN(kv, ":", 2)
		if len(parts) == 2 {
			m[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return m
}

func normalizeTarget(target string) (string, error) {
	target = strings.TrimSpace(target)
	if strings.HasPrefix(target, "//") {
		target = "https:" + target
	} else if !strings.Contains(target, "://") {
		target = "https://" + target
	}

	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("target must be an HTTP(S) URL with a host")
	}
	return u.String(), nil
}

func parseTechniques(s string, available []string) []string {
	if s == "all" {
		return available
	}
	m := make(map[string]bool)
	for _, name := range available {
		m[name] = true
	}
	var out []string
	for _, name := range strings.Split(s, ",") {
		name = strings.TrimSpace(name)
		if m[name] {
			out = append(out, name)
		}
	}
	return out
}
