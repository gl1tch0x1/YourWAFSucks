// Package api exposes scan findings and scanning through a small REST server.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/sarif"
	"github.com/gl1tch0x1/YourWAFSucks/internal/techniques"
)

// ScanRequest is the body accepted by POST /scan.
type ScanRequest struct {
	URL        string   `json:"url"`
	Techniques []string `json:"techniques,omitempty"`
}

// Options configures a Server.
type Options struct {
	// Target is the default scan target reported by /version.
	Target string
	// Version is reported by /version and embedded in SARIF output.
	Version string
	// Findings returns the most recent findings. May be nil.
	Findings func() []techniques.Result
	// Scan runs a scan. May be nil, in which case POST /scan returns 501.
	Scan func(ctx context.Context, req ScanRequest) ([]techniques.Result, error)
	// Token, when non-empty, is required as a bearer token on every route
	// except /healthz.
	Token string
}

// Server serves the REST API.
type Server struct {
	opts    Options
	handler http.Handler
}

// NewServer constructs a Server and its routing table.
func NewServer(opts Options) *Server {
	s := &Server{opts: opts}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /version", s.handleVersion)
	mux.HandleFunc("GET /findings", s.handleFindings)
	mux.HandleFunc("POST /scan", s.handleScan)
	mux.HandleFunc("GET /findings.sarif", s.handleSARIF)

	var h http.Handler = mux
	if opts.Token != "" {
		h = s.withAuth(mux)
	}
	s.handler = h
	return s
}

// Handler returns the HTTP handler for the server.
func (s *Server) Handler() http.Handler { return s.handler }

// Serve listens on addr until ctx is cancelled, then shuts down gracefully.
func (s *Server) Serve(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			_ = srv.Close()
			return err
		}
		if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) withAuth(next http.Handler) http.Handler {
	want := []byte("Bearer " + s.opts.Token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		got := []byte(r.Header.Get("Authorization"))
		if subtle.ConstantTimeCompare(got, want) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"name":    "YourWAFSucks",
		"version": s.opts.Version,
		"target":  s.opts.Target,
	})
}

func (s *Server) handleFindings(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.findingDTOs())
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if strings.TrimSpace(req.URL) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url is required"})
		return
	}
	if s.opts.Scan == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "scan is not configured"})
		return
	}

	results, err := s.opts.Scan(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, toDTOs(results))
}

func (s *Server) handleSARIF(w http.ResponseWriter, _ *http.Request) {
	var findings []techniques.Result
	if s.opts.Findings != nil {
		findings = s.opts.Findings()
	}
	log, err := sarif.Build(findings, s.opts.Target, s.opts.Version)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/sarif+json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) findingDTOs() []findingDTO {
	if s.opts.Findings == nil {
		return []findingDTO{}
	}
	return toDTOs(s.opts.Findings())
}

type findingDTO struct {
	Technique   string            `json:"technique"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Description string            `json:"description,omitempty"`
	Status      int               `json:"status"`
	Score       int               `json:"score"`
	Severity    string            `json:"severity"`
	Reason      string            `json:"reason,omitempty"`
	ReplayCount int               `json:"replay_count"`
	Headers     map[string]string `json:"headers,omitempty"`
}

func toDTOs(findings []techniques.Result) []findingDTO {
	out := make([]findingDTO, 0, len(findings))
	for _, f := range findings {
		status := 0
		if f.Response != nil {
			status = f.Response.Status
		}
		technique := f.Payload.Technique
		if technique == "" {
			technique = "unknown"
		}
		out = append(out, findingDTO{
			Technique:   technique,
			Method:      f.Payload.Method,
			URL:         redactURL(f.Payload.URL),
			Description: f.Payload.Description,
			Status:      status,
			Score:       f.Score.Score,
			Severity:    severityFor(f.Score.Score),
			Reason:      f.Score.Reason,
			ReplayCount: f.ReplayCount,
			Headers:     sanitizeHeaders(f.Payload.Headers),
		})
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func severityFor(score int) string {
	switch {
	case score >= 90:
		return "critical"
	case score >= 70:
		return "high"
	case score >= 40:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "info"
	}
}

func sanitizeHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	safe := make(map[string]string, len(headers))
	for name, value := range headers {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key", "x-auth-token", "x-access-token":
			safe[name] = "[REDACTED]"
		default:
			safe[name] = value
		}
	}
	return safe
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.User = nil
	query := u.Query()
	for key := range query {
		normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
		switch normalized {
		case "token", "access_token", "refresh_token", "api_key", "apikey", "secret",
			"password", "passwd", "authorization", "session", "cookie":
			query[key] = []string{"[REDACTED]"}
		}
	}
	u.RawQuery = query.Encode()
	return u.String()
}
