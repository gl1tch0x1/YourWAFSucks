package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/techniques"
)

type Record struct {
	Target      string            `json:"target"`
	ToolVersion string            `json:"tool_version"`
	ScannedAt   time.Time         `json:"scanned_at"`
	Technique   string            `json:"technique"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Description string            `json:"description"`
	Headers     map[string]string `json:"headers,omitempty"`
	Status      int               `json:"status"`
	Size        int               `json:"size"`
	Time        float64           `json:"time"`
	Redirect    string            `json:"redirect,omitempty"`
	Reason      string            `json:"reason"`
	Score       int               `json:"score"`
	ReplayCount int               `json:"replay_count"`
}

func WriteJSONL(path string, findings []techniques.Result, target, version string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	defer w.Flush()

	enc := json.NewEncoder(w)
	scannedAt := time.Now().UTC()
	for _, f := range findings {
		rec := Record{
			Target:      sanitizeURL(target),
			ToolVersion: version,
			ScannedAt:   scannedAt,
			Technique:   f.Payload.Technique,
			Method:      f.Payload.Method,
			URL:         sanitizeURL(f.Payload.URL),
			Description: f.Payload.Description,
			Headers:     f.Payload.Headers,
		}
		if f.Response != nil {
			rec.Status = f.Response.Status
			rec.Size = len(f.Response.Body)
			rec.Time = f.Response.Time.Seconds()
			rec.Redirect = sanitizeURL(f.Response.Redirect)
		}
		rec.Reason = f.Score.Reason
		rec.Score = f.Score.Score
		rec.ReplayCount = f.ReplayCount
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return nil
}

func sanitizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.User = nil
	query := u.Query()
	for key := range query {
		normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
		switch normalized {
		case "token", "access_token", "refresh_token", "api_key", "apikey", "secret", "password", "passwd", "authorization", "session", "cookie":
			query[key] = []string{"[REDACTED]"}
		}
	}
	u.RawQuery = query.Encode()
	return u.String()
}

// Simple logger for stderr
type Logger struct {
	w       *bufio.Writer
	quiet   bool
	verbose bool
	color   bool
	mu      sync.Mutex
}

func NewLogger(f *os.File, quiet, verbose bool) *Logger {
	color := false
	if _, noColor := os.LookupEnv("NO_COLOR"); !noColor && os.Getenv("TERM") != "dumb" {
		if info, err := f.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
			color = true
		}
	}
	return &Logger{w: bufio.NewWriter(f), quiet: quiet, verbose: verbose, color: color}
}

func (l *Logger) paint(code, text string) string {
	if !l.color {
		return text
	}
	return "\033[" + code + "m" + text + "\033[0m"
}

func (l *Logger) Info(format string, args ...interface{}) {
	if l.quiet {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "%s %s\n", l.paint("1;36", "[>]"), fmt.Sprintf(format, args...))
	l.w.Flush()
}

func (l *Logger) Warn(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "%s %s\n", l.paint("1;33", "[!]"), fmt.Sprintf(format, args...))
	l.w.Flush()
}

func (l *Logger) Err(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "%s %s\n", l.paint("1;31", "[x]"), fmt.Sprintf(format, args...))
	l.w.Flush()
}

func (l *Logger) Debug(format string, args ...interface{}) {
	if !l.verbose {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "%s %s\n", l.paint("2;37", "[.]"), fmt.Sprintf(format, args...))
	l.w.Flush()
}

func (l *Logger) Ok(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "%s %s\n", l.paint("1;32", "[+]"), fmt.Sprintf(format, args...))
	l.w.Flush()
}

func (l *Logger) Banner(version, target string) {
	if l.quiet {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "\n  %s\n", l.paint("1;36", "SCAN DETAILS"))
	fmt.Fprintf(l.w, "  %s %s\n", l.paint("1;36", "VERSION"), version)
	fmt.Fprintf(l.w, "  %s %s\n\n", l.paint("1;36", "TARGET "), l.paint("1;37", target))
	l.w.Flush()
}

func (l *Logger) FindingLine(color string, r techniques.Result) {
	l.mu.Lock()
	defer l.mu.Unlock()
	status := ""
	if r.Response != nil {
		status = fmt.Sprintf("[%d]", r.Response.Status)
		if l.color {
			status = color + status + "\033[0m"
		}
	}
	fmt.Fprintf(l.w, "%s %s %s\n", l.paint("1;32", "[HIT]"), status, r.Payload.Description)
	l.w.Flush()
}

func (l *Logger) StatusLine(status int, method, description string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "%s %s %s\n", l.paint("1;33", fmt.Sprintf("[STATUS %d]", status)), method, description)
	l.w.Flush()
}

func (l *Logger) Summary(findings []techniques.Result, cal interface{}, fp interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "\n  %s  %s\n", l.paint("1;36", "SCAN COMPLETE"), l.paint("1;32", fmt.Sprintf("%d findings", len(findings))))
	l.w.Flush()
}

func ColorFor(status int) string {
	switch {
	case status >= 200 && status < 300:
		return "\033[1;32m"
	case status >= 300 && status < 400:
		return "\033[1;36m"
	case status >= 400 && status < 500:
		return "\033[1;33m"
	default:
		return "\033[1;35m"
	}
}
