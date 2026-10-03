package authz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
)

// ============================================
// New AuthzMatrix types (for API testing)
// ============================================

// AuthzMatrix represents an authorization policy matrix
type AuthzMatrix struct {
	Roles     map[string]*Role
	Tests     []*AuthzTest
	Resources map[string]*Resource
}

// Role represents a user role in the system
type Role struct {
	Name        string
	Credentials Credentials
	Description string
}

// Resource represents a protected resource
type Resource struct {
	Path        string
	Method      string
	Description string
}

// AuthzTest represents an authorization test case
type AuthzTest struct {
	ID           string
	Resource     *Resource
	Action       string
	Owner        string
	AllowedRoles []string
	DeniedRoles  []string
}

// AuthzTestResult represents the result of an authorization test
type AuthzTestResult struct {
	TestID       string
	Resource     string
	Action       string
	Session      string
	Expected     string // "allowed" or "denied"
	Actual       string // "allowed" or "denied"
	Status       int
	BodyHash     string
	Passed       bool
	IsBypass     bool
	IsHorizontal bool
	IsVertical   bool
	Confidence   float64
}

// NewAuthzMatrix creates a new authorization matrix
func NewAuthzMatrix() *AuthzMatrix {
	return &AuthzMatrix{
		Roles:     make(map[string]*Role),
		Resources: make(map[string]*Resource),
	}
}

// AddRole adds a role to the matrix
func (am *AuthzMatrix) AddRole(role *Role) error {
	if role.Name == "" {
		return fmt.Errorf("role name cannot be empty")
	}
	am.Roles[role.Name] = role
	return nil
}

// AddResource adds a resource to the matrix
func (am *AuthzMatrix) AddResource(resource *Resource) error {
	key := resource.Method + ":" + resource.Path
	if resource.Path == "" {
		return fmt.Errorf("resource path cannot be empty")
	}
	am.Resources[key] = resource
	return nil
}

// AddTest adds an authorization test case
func (am *AuthzMatrix) AddTest(test *AuthzTest) error {
	if test.Resource == nil {
		return fmt.Errorf("test must have a resource")
	}
	test.ID = generateTestID(test.Resource.Method, test.Resource.Path, test.Action)
	am.Tests = append(am.Tests, test)
	return nil
}

// GetTestsForResource returns all tests for a specific resource
func (am *AuthzMatrix) GetTestsForResource(method, path string) []*AuthzTest {
	var tests []*AuthzTest
	for _, test := range am.Tests {
		if test.Resource.Method == method && test.Resource.Path == path {
			tests = append(tests, test)
		}
	}
	return tests
}

// GetTestsForRole returns all tests relevant to a specific role
func (am *AuthzMatrix) GetTestsForRole(roleName string) []*AuthzTest {
	var tests []*AuthzTest
	for _, test := range am.Tests {
		// Check if role is in allowed or denied
		allowed := false
		denied := false
		for _, r := range test.AllowedRoles {
			if r == roleName {
				allowed = true
				break
			}
		}
		for _, r := range test.DeniedRoles {
			if r == roleName {
				denied = true
				break
			}
		}
		if allowed || denied {
			tests = append(tests, test)
		}
	}
	return tests
}

// ExpectedAccess returns whether a role should have access to a resource
func (am *AuthzMatrix) ExpectedAccess(roleName, method, path string) (string, error) {
	for _, test := range am.Tests {
		if test.Resource.Method == method && test.Resource.Path == path {
			for _, allowed := range test.AllowedRoles {
				if allowed == roleName {
					return "allowed", nil
				}
			}
			for _, denied := range test.DeniedRoles {
				if denied == roleName {
					return "denied", nil
				}
			}
		}
	}
	return "", fmt.Errorf("no policy defined for role %s on %s %s", roleName, method, path)
}

// LoadFromConfig loads authorization matrix from configuration
func (am *AuthzMatrix) LoadFromConfig(config AuthzConfig) error {
	// Load roles
	for name, roleCfg := range config.Roles {
		role := &Role{
			Name: name,
			Credentials: Credentials{
				Type:        roleCfg.Type,
				Cookie:      roleCfg.Cookie,
				HeaderName:  roleCfg.HeaderName,
				HeaderValue: roleCfg.HeaderValue,
				Username:    roleCfg.Username,
				Password:    roleCfg.Password,
				Token:       roleCfg.Token,
				APIKey:      roleCfg.APIKey,
			},
			Description: roleCfg.Description,
		}
		if err := am.AddRole(role); err != nil {
			return err
		}
	}

	// Load resources
	for _, resourceCfg := range config.Resources {
		resource := &Resource{
			Path:        resourceCfg.Path,
			Method:      resourceCfg.Method,
			Description: resourceCfg.Description,
		}
		if err := am.AddResource(resource); err != nil {
			return err
		}
	}

	// Load tests
	for _, testCfg := range config.Tests {
		resource, ok := am.Resources[testCfg.Method+":"+testCfg.Path]
		if !ok {
			// Create resource if not exists
			resource = &Resource{
				Path:   testCfg.Path,
				Method: testCfg.Method,
			}
			if err := am.AddResource(resource); err != nil {
				return err
			}
		}

		test := &AuthzTest{
			Resource:     resource,
			Action:       testCfg.Action,
			Owner:        testCfg.Owner,
			AllowedRoles: testCfg.Allowed,
			DeniedRoles:  testCfg.Denied,
		}
		if err := am.AddTest(test); err != nil {
			return err
		}
	}

	return nil
}

// Validate validates the authorization matrix
func (am *AuthzMatrix) Validate() []string {
	errors := []string{}

	// Check that all referenced roles exist
	for _, test := range am.Tests {
		for _, roleName := range test.AllowedRoles {
			if _, ok := am.Roles[roleName]; !ok {
				errors = append(errors, fmt.Sprintf("test references undefined role in allowed: %s", roleName))
			}
		}
		for _, roleName := range test.DeniedRoles {
			if _, ok := am.Roles[roleName]; !ok {
				errors = append(errors, fmt.Sprintf("test references undefined role in denied: %s", roleName))
			}
		}
	}

	return errors
}

// AuthzConfig represents authorization matrix configuration
type AuthzConfig struct {
	Roles     map[string]RoleConfig `yaml:"roles"`
	Resources []ResourceConfig      `yaml:"resources"`
	Tests     []TestConfig          `yaml:"tests"`
}

// RoleConfig represents role configuration
type RoleConfig struct {
	Type        string `yaml:"type"`
	Cookie      string `yaml:"cookie"`
	HeaderName  string `yaml:"header_name"`
	HeaderValue string `yaml:"header_value"`
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	Token       string `yaml:"token"`
	APIKey      string `yaml:"api_key"`
	Description string `yaml:"description"`
}

// ResourceConfig represents resource configuration
type ResourceConfig struct {
	Path        string `yaml:"path"`
	Method      string `yaml:"method"`
	Description string `yaml:"description"`
}

// TestConfig represents test configuration
type TestConfig struct {
	Path    string   `yaml:"path"`
	Method  string   `yaml:"method"`
	Action  string   `yaml:"action"`
	Owner   string   `yaml:"owner"`
	Allowed []string `yaml:"allowed"`
	Denied  []string `yaml:"denied"`
}

// generateTestID generates a unique test ID
func generateTestID(method, path, action string) string {
	return fmt.Sprintf("%s-%s-%s", strings.ToLower(method),
		strings.ReplaceAll(strings.Trim(path, "/"), "/", "-"),
		strings.ToLower(action))
}

// ============================================
// Legacy Matrix Types (for test compatibility)
// ============================================

// Endpoint is a request target participating in an authorization matrix.
type Endpoint struct {
	Method string
	URL    string
	Label  string
}

// Cell is the observed result of one session against one endpoint.
type Cell struct {
	Session  string  `json:"session"`
	Endpoint string  `json:"endpoint"`
	Method   string  `json:"method"`
	URL      string  `json:"url"`
	Status   int     `json:"status"`
	Size     int     `json:"size"`
	BodyHash string  `json:"body_hash"`
	Time     float64 `json:"time"`
	Error    string  `json:"error,omitempty"`
}

// Matrix is the full sessions x endpoints observation grid.
type Matrix struct {
	Sessions  []string   `json:"sessions"`
	Endpoints []Endpoint `json:"endpoints"`
	Cells     []Cell     `json:"cells"`
}

// MatrixOptions controls matrix execution.
type MatrixOptions struct {
	BaselineSession string
	MaxRequests     int
	Delay           time.Duration
}

// RunMatrix sends every endpoint once per session, applying that session's
// credentials, and returns the observation grid.
func RunMatrix(ctx context.Context, client *httpclient.Client, sessions []*SessionContext, endpoints []Endpoint, opts MatrixOptions) (*Matrix, error) {
	if len(sessions) == 0 {
		return nil, fmt.Errorf("no sessions configured")
	}
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no endpoints configured")
	}

	m := &Matrix{
		Sessions:  make([]string, 0, len(sessions)),
		Endpoints: append([]Endpoint{}, endpoints...),
	}
	for _, s := range sessions {
		m.Sessions = append(m.Sessions, s.Name)
	}

	sent := 0
	for _, ep := range endpoints {
		for _, session := range sessions {
			if err := ctx.Err(); err != nil {
				return m, err
			}
			if opts.MaxRequests > 0 && sent >= opts.MaxRequests {
				return m, nil
			}

			req := httpclient.Request{Method: ep.Method, URL: ep.URL}
			ApplyCredentials(session, &req)

			cell := Cell{
				Session:  session.Name,
				Endpoint: ep.Label,
				Method:   ep.Method,
				URL:      ep.URL,
			}
			resp, err := client.Request(ctx, req)
			sent++
			if err != nil {
				cell.Error = err.Error()
			} else if resp != nil {
				cell.Status = resp.Status
				cell.Size = len(resp.Body)
				cell.BodyHash = hashBody(resp.Body)
				cell.Time = resp.Time.Seconds()
			}
			m.Cells = append(m.Cells, cell)

			if opts.Delay > 0 {
				select {
				case <-ctx.Done():
					return m, ctx.Err()
				case <-time.After(opts.Delay):
				}
			}
		}
	}
	return m, nil
}

// Differential is a meaningful difference between a session and the baseline.
type Differential struct {
	Endpoint        string `json:"endpoint"`
	Method          string `json:"method"`
	URL             string `json:"url"`
	Session         string `json:"session"`
	BaselineSession string `json:"baseline_session"`
	BaselineStatus  int    `json:"baseline_status"`
	Status          int    `json:"status"`
	StatusChanged   bool   `json:"status_changed"`
	BodyChanged     bool   `json:"body_changed"`
	AccessGranted   bool   `json:"access_granted"`
	Severity        string `json:"severity"`
	Reason          string `json:"reason"`
}

// Differentials compares every session's response against the baseline session
// for each endpoint and reports access-control-relevant differences.
func (m *Matrix) Differentials(baseline string) []Differential {
	if baseline == "" {
		baseline = "anonymous"
	}

	var out []Differential
	for _, ep := range m.Endpoints {
		base, ok := m.Cell(baseline, ep.Label)
		if !ok || base.Error != "" {
			continue
		}
		for _, session := range m.Sessions {
			if session == baseline {
				continue
			}
			cur, ok := m.Cell(session, ep.Label)
			if !ok || cur.Error != "" {
				continue
			}

			d := Differential{
				Endpoint:        ep.Label,
				Method:          ep.Method,
				URL:             ep.URL,
				Session:         session,
				BaselineSession: baseline,
				BaselineStatus:  base.Status,
				Status:          cur.Status,
				StatusChanged:   base.Status != cur.Status,
				BodyChanged:     base.BodyHash != cur.BodyHash,
			}
			if d.StatusChanged || d.BodyChanged {
				d.AccessGranted = granted(base.Status, cur.Status)
				d.Severity, d.Reason = classifyDifferential(d, base.Status)
			}
			if d.StatusChanged || d.BodyChanged {
				out = append(out, d)
			}
		}
	}
	return out
}

// Cell returns the observation for a session/endpoint pair.
func (m *Matrix) Cell(session, endpoint string) (Cell, bool) {
	for _, c := range m.Cells {
		if c.Session == session && c.Endpoint == endpoint {
			return c, true
		}
	}
	return Cell{}, false
}

func granted(baselineStatus, status int) bool {
	if !deniedStatus(baselineStatus) {
		return false
	}
	return successStatus(status)
}

func deniedStatus(status int) bool {
	return status == 401 || status == 403
}

func successStatus(status int) bool {
	return (status >= 200 && status < 300) || (status >= 300 && status < 400)
}

func classifyDifferential(d Differential, baselineStatus int) (string, string) {
	switch {
	case granted(baselineStatus, d.Status):
		if d.Status >= 200 && d.Status < 300 {
			return "high", fmt.Sprintf("session %q reached %d from baseline %d (access-control bypass)", d.Session, d.Status, baselineStatus)
		}
		return "medium", fmt.Sprintf("session %q was redirected (%d) from baseline %d", d.Session, d.Status, baselineStatus)
	case deniedStatus(d.Status) && !deniedStatus(baselineStatus):
		return "low", fmt.Sprintf("session %q was denied (%d) while baseline returned %d", d.Session, d.Status, baselineStatus)
	default:
		return "info", fmt.Sprintf("response differs for session %q (%d vs baseline %d)", d.Session, d.Status, baselineStatus)
	}
}

func hashBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:8])
}
