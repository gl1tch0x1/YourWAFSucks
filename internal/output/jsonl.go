package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/gl1tch0x1/YourWAFSucks/internal/techniques"
)

type Record struct {
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

func WriteJSONL(path string, findings []techniques.Result, target string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	defer w.Flush()

	enc := json.NewEncoder(w)
	for _, f := range findings {
		rec := Record{
			Technique:   f.Payload.Technique,
			Method:      f.Payload.Method,
			URL:         f.Payload.URL,
			Description: f.Payload.Description,
			Headers:     f.Payload.Headers,
		}
		if f.Response != nil {
			rec.Status = f.Response.Status
			rec.Size = len(f.Response.Body)
			rec.Time = f.Response.Time.Seconds()
			rec.Redirect = f.Response.Redirect
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

// Simple logger for stderr
type Logger struct {
	w       *bufio.Writer
	quiet   bool
	verbose bool
	mu      sync.Mutex
}

func NewLogger(f *os.File, quiet, verbose bool) *Logger {
	return &Logger{w: bufio.NewWriter(f), quiet: quiet, verbose: verbose}
}

func (l *Logger) Info(format string, args ...interface{}) {
	if l.quiet {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "[*] "+format+"\n", args...)
	l.w.Flush()
}

func (l *Logger) Warn(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "[!] "+format+"\n", args...)
	l.w.Flush()
}

func (l *Logger) Err(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "[✗] "+format+"\n", args...)
	l.w.Flush()
}

func (l *Logger) Debug(format string, args ...interface{}) {
	if !l.verbose {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "[·] "+format+"\n", args...)
	l.w.Flush()
}

func (l *Logger) Ok(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "[✓] "+format+"\n", args...)
	l.w.Flush()
}

func (l *Logger) Banner(version, target string) {
	if l.quiet {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "bypass403 v%s\nTarget: %s\n\n", version, target)
	l.w.Flush()
}

func (l *Logger) FindingLine(color string, r techniques.Result) {
	l.mu.Lock()
	defer l.mu.Unlock()
	status := ""
	if r.Response != nil {
		status = fmt.Sprintf("[%d]", r.Response.Status)
	}
	fmt.Fprintf(l.w, "[HIT] %s %s\n", status, r.Payload.Description)
	l.w.Flush()
}

func (l *Logger) Summary(findings []techniques.Result, cal interface{}, fp interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "\nSummary: %d findings\n", len(findings))
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
