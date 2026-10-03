package authz

import (
	"encoding/base64"
	"fmt"
	"sort"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
)

// SessionContext represents a specific authorization context
type SessionContext struct {
	Name        string
	Credentials Credentials
	Description string
}

// Credentials holds authentication information
type Credentials struct {
	Type        string // "none", "cookie", "header", "basic", "bearer", "apikey"
	Cookie      string
	HeaderName  string
	HeaderValue string
	Username    string
	Password    string
	Token       string
	APIKey      string
}

// SessionManager manages multiple authorization contexts
type SessionManager struct {
	sessions       map[string]*SessionContext
	defaultSession *SessionContext
}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*SessionContext),
		defaultSession: &SessionContext{
			Name:        "anonymous",
			Credentials: Credentials{Type: "none"},
		},
	}
}

// AddSession adds a new session context
func (sm *SessionManager) AddSession(session *SessionContext) error {
	if session.Name == "" {
		return fmt.Errorf("session name cannot be empty")
	}
	sm.sessions[session.Name] = session
	return nil
}

// GetSession retrieves a session by name
func (sm *SessionManager) GetSession(name string) (*SessionContext, error) {
	if name == "" {
		return sm.defaultSession, nil
	}
	session, ok := sm.sessions[name]
	if !ok {
		return nil, fmt.Errorf("session not found: %s", name)
	}
	return session, nil
}

// ListSessions returns all available sessions
func (sm *SessionManager) ListSessions() []string {
	names := make([]string, 0, len(sm.sessions))
	for name := range sm.sessions {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// DefaultSession returns the anonymous session used when no session is named.
func (sm *SessionManager) DefaultSession() *SessionContext {
	return sm.defaultSession
}

// All returns every session with the anonymous default first, followed by the
// configured sessions in sorted name order. The result is deterministic.
func (sm *SessionManager) All() []*SessionContext {
	out := make([]*SessionContext, 0, len(sm.sessions)+1)
	out = append(out, sm.defaultSession)
	for _, name := range sm.ListSessions() {
		out = append(out, sm.sessions[name])
	}
	return out
}

// ApplyCredentials applies session credentials to a request
func (sm *SessionManager) ApplyCredentials(session *SessionContext, req *httpclient.Request) {
	ApplyCredentials(session, req)
}

// ApplyCredentials applies a session's credentials to a request. It is a free
// function so the matrix engine can use it without a SessionManager.
func ApplyCredentials(session *SessionContext, req *httpclient.Request) {
	if session == nil {
		return
	}
	switch session.Credentials.Type {
	case "cookie":
		if session.Credentials.Cookie != "" {
			if req.Headers == nil {
				req.Headers = make(map[string]string)
			}
			req.Headers["Cookie"] = session.Credentials.Cookie
		}
	case "header":
		if session.Credentials.HeaderName != "" && session.Credentials.HeaderValue != "" {
			if req.Headers == nil {
				req.Headers = make(map[string]string)
			}
			req.Headers[session.Credentials.HeaderName] = session.Credentials.HeaderValue
		}
	case "basic":
		if session.Credentials.Username != "" || session.Credentials.Password != "" {
			if req.Headers == nil {
				req.Headers = make(map[string]string)
			}
			token := base64.StdEncoding.EncodeToString([]byte(session.Credentials.Username + ":" + session.Credentials.Password))
			req.Headers["Authorization"] = "Basic " + token
		}
	case "bearer":
		if session.Credentials.Token != "" {
			if req.Headers == nil {
				req.Headers = make(map[string]string)
			}
			req.Headers["Authorization"] = "Bearer " + session.Credentials.Token
		}
	case "apikey":
		if session.Credentials.APIKey != "" {
			if req.Headers == nil {
				req.Headers = make(map[string]string)
			}
			req.Headers["X-API-Key"] = session.Credentials.APIKey
		}
	case "none":
		// No credentials
	}
}

// LoadFromConfig loads sessions from configuration
func (sm *SessionManager) LoadFromConfig(config map[string]CredentialsConfig) error {
	for name, cfg := range config {
		session := &SessionContext{
			Name: name,
			Credentials: Credentials{
				Type:        cfg.Type,
				Cookie:      cfg.Cookie,
				HeaderName:  cfg.HeaderName,
				HeaderValue: cfg.HeaderValue,
				Username:    cfg.Username,
				Password:    cfg.Password,
				Token:       cfg.Token,
				APIKey:      cfg.APIKey,
			},
		}
		if err := sm.AddSession(session); err != nil {
			return err
		}
	}
	return nil
}

// CredentialsConfig represents credentials in configuration
type CredentialsConfig struct {
	Type        string `yaml:"type"`
	Cookie      string `yaml:"cookie"`
	HeaderName  string `yaml:"header_name"`
	HeaderValue string `yaml:"header_value"`
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	Token       string `yaml:"token"`
	APIKey      string `yaml:"api_key"`
}
