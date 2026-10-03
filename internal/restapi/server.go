package restapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/authz"
	"github.com/gl1tch0x1/YourWAFSucks/internal/evidence"
	"github.com/gl1tch0x1/YourWAFSucks/internal/techniques"
)

// Server represents the REST API server
type Server struct {
	sessionManager    *authz.SessionManager
	evidenceCollector *evidence.Collector
	server            *http.Server
}

// NewServer creates a new REST API server
func NewServer() *Server {
	return &Server{
		sessionManager: authz.NewSessionManager(),
		evidenceCollector: evidence.New(evidence.Config{
			OutputDir:        "evidence",
			SaveRequestBody:  false,
			SaveResponseBody: true,
			IncludeHeaders:   true,
			IncludeTiming:    true,
		}),
	}
}

// Start starts the REST API server
func (s *Server) Start(addr string) error {
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/v1/scan", s.handleScan)
	mux.HandleFunc("/api/v1/scan/", s.handleScanResult)
	mux.HandleFunc("/api/v1/authz", s.handleAuthzTest)
	mux.HandleFunc("/api/v1/sessions", s.handleSessions)
	mux.HandleFunc("/api/v1/evidence/", s.handleEvidence)
	mux.HandleFunc("/api/v1/health", s.handleHealth)

	s.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	return s.server.ListenAndServe()
}

// Stop stops the REST API server
func (s *Server) Stop(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

// handleScan handles scan requests
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Start scan (async)
	// TODO: Implement actual scan execution
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ScanResponse{
		ScanID:    generateScanID(),
		Status:    "started",
		Message:   "Scan started successfully",
		Timestamp: time.Now(),
	})
}

// handleScanResult handles scan result requests
func (s *Server) handleScanResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	scanID := r.URL.Path[len("/api/v1/scan/"):]
	if scanID == "" {
		http.Error(w, "Scan ID required", http.StatusBadRequest)
		return
	}

	// TODO: Implement actual scan result retrieval
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ScanResultResponse{
		ScanID:    scanID,
		Status:    "completed",
		Findings:  []techniques.Result{},
		Timestamp: time.Now(),
	})
}

// handleAuthzTest handles authorization test requests
func (s *Server) handleAuthzTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AuthzTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// TODO: Implement actual authz test
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthzTestResponse{
		TestID:    generateTestID(),
		Status:    "completed",
		Results:   []string{}, // Placeholder
		Timestamp: time.Now(),
	})
}

// handleSessions handles session management
func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		sessions := s.sessionManager.ListSessions()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(SessionsResponse{
			Sessions:  sessions,
			Timestamp: time.Now(),
		})
	case http.MethodPost:
		var session authz.SessionContext
		if err := json.NewDecoder(r.Body).Decode(&session); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		if err := s.sessionManager.AddSession(&session); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleEvidence handles evidence retrieval
func (s *Server) handleEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	findingID := r.URL.Path[len("/api/v1/evidence/"):]
	if findingID == "" {
		http.Error(w, "Finding ID required", http.StatusBadRequest)
		return
	}

	// TODO: Implement actual evidence retrieval
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(EvidenceResponse{
		FindingID: findingID,
		Message:   "Evidence retrieval not yet implemented",
		Timestamp: time.Now(),
	})
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now(),
	})
}

// Request/Response types

type ScanRequest struct {
	Target     string   `json:"target"`
	Techniques []string `json:"techniques"`
	Sessions   []string `json:"sessions"`
}

type ScanResponse struct {
	ScanID    string    `json:"scan_id"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

type ScanResultResponse struct {
	ScanID    string              `json:"scan_id"`
	Status    string              `json:"status"`
	Findings  []techniques.Result `json:"findings"`
	Timestamp time.Time           `json:"timestamp"`
}

type AuthzTestRequest struct {
	Target   string   `json:"target"`
	Sessions []string `json:"sessions"`
}

type AuthzTestResponse struct {
	TestID    string    `json:"test_id"`
	Status    string    `json:"status"`
	Results   []string  `json:"results"`
	Timestamp time.Time `json:"timestamp"`
}

type SessionsResponse struct {
	Sessions  []string  `json:"sessions"`
	Timestamp time.Time `json:"timestamp"`
}

type EvidenceResponse struct {
	FindingID string    `json:"finding_id"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

type HealthResponse struct {
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

// Helper functions

func generateScanID() string {
	return fmt.Sprintf("scan-%d", time.Now().UnixNano())
}

func generateTestID() string {
	return fmt.Sprintf("test-%d", time.Now().UnixNano())
}
