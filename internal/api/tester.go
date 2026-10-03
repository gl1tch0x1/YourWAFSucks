package api

import (
	"context"
	"fmt"
	"strings"

	"github.com/gl1tch0x1/YourWAFSucks/internal/authz"
	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
	"github.com/gl1tch0x1/YourWAFSucks/internal/openapi"
)

// APITester performs API authorization testing
type APITester struct {
	client         *httpclient.Client
	sessionManager *authz.SessionManager
	authzMatrix    *authz.AuthzMatrix
	openapiSpec    *openapi.Spec
}

// TestConfig holds API testing configuration
type TestConfig struct {
	BaseURL             string
	OpenAPIPath         string
	SessionContexts     []string
	TestHorizontal      bool
	TestVertical        bool
	TestTenantIsolation bool
}

// APITestResult represents an API authorization test result
type APITestResult struct {
	Endpoint     string
	Method       string
	Session      string
	Expected     string
	Actual       string
	Status       int
	Passed       bool
	IsBypass     bool
	IsHorizontal bool
	IsVertical   bool
	Confidence   float64
	Details      string
}

// NewAPITester creates a new API tester
func NewAPITester(client *httpclient.Client) *APITester {
	return &APITester{
		client:         client,
		sessionManager: authz.NewSessionManager(),
		authzMatrix:    authz.NewAuthzMatrix(),
	}
}

// LoadOpenAPI loads an OpenAPI specification
func (t *APITester) LoadOpenAPI(data []byte) error {
	spec, err := openapi.Parse(data)
	if err != nil {
		return err
	}
	t.openapiSpec = spec
	return nil
}

// LoadAuthzMatrix loads an authorization matrix
func (t *APITester) LoadAuthzMatrix(config authz.AuthzConfig) error {
	return t.authzMatrix.LoadFromConfig(config)
}

// LoadSessions loads session contexts
func (t *APITester) LoadSessions(config map[string]authz.CredentialsConfig) error {
	return t.sessionManager.LoadFromConfig(config)
}

// TestAuthorization performs authorization testing
func (t *APITester) TestAuthorization(ctx context.Context, config TestConfig) ([]*APITestResult, error) {
	var results []*APITestResult

	// Get endpoints from OpenAPI
	if t.openapiSpec == nil {
		return nil, fmt.Errorf("no OpenAPI spec loaded")
	}
	endpoints := t.openapiSpec.Endpoints()

	// Test each endpoint with each session
	for _, endpoint := range endpoints {
		for _, sessionName := range config.SessionContexts {
			session, err := t.sessionManager.GetSession(sessionName)
			if err != nil {
				continue
			}

			result := t.testEndpoint(ctx, endpoint, session, config)
			results = append(results, result)
		}
	}

	return results, nil
}

// testEndpoint tests a single endpoint with a session
func (t *APITester) testEndpoint(ctx context.Context, endpoint openapi.Endpoint, session *authz.SessionContext, config TestConfig) *APITestResult {
	result := &APITestResult{
		Endpoint: endpoint.Path,
		Method:   endpoint.Method,
		Session:  session.Name,
	}

	// Build request
	req := t.buildRequest(endpoint, session, config)

	// Send request
	resp, err := t.client.Request(ctx, req)
	if err != nil {
		result.Details = fmt.Sprintf("request failed: %v", err)
		return result
	}

	result.Status = resp.Status

	// Determine expected access based on authz matrix
	expected, err := t.authzMatrix.ExpectedAccess(session.Name, endpoint.Method, endpoint.Path)
	if err != nil {
		// No policy defined, use heuristic
		expected = t.heuristicExpectedAccess(endpoint, session)
	}
	result.Expected = expected

	// Determine actual access
	result.Actual = t.determineActualAccess(resp)

	// Check if test passed
	result.Passed = result.Expected == result.Actual

	// Check for bypass
	if !result.Passed && result.Actual == "allowed" && result.Expected == "denied" {
		result.IsBypass = true
		result.Confidence = 0.9
	}

	// Check for horizontal authorization bypass
	if config.TestHorizontal && t.isHorizontalBypass(endpoint, session, result) {
		result.IsHorizontal = true
	}

	// Check for vertical authorization bypass
	if config.TestVertical && t.isVerticalBypass(endpoint, session, result) {
		result.IsVertical = true
	}

	return result
}

// buildRequest builds an HTTP request from an endpoint
func (t *APITester) buildRequest(endpoint openapi.Endpoint, session *authz.SessionContext, config TestConfig) httpclient.Request {
	// Build URL using the existing ResolvePath method
	path := endpoint.ResolvePath(config.BaseURL, nil)

	// Build headers
	headers := make(map[string]string)
	for _, param := range endpoint.Parameters {
		if param.In == "header" && param.Required {
			headers[param.Name] = openapi.SampleValue(param)
		}
	}

	// Apply session credentials
	t.sessionManager.ApplyCredentials(session, &httpclient.Request{
		Headers: headers,
	})

	return httpclient.Request{
		Method:  endpoint.Method,
		URL:     path,
		Headers: headers,
		Body:    []byte("{}"),
	}
}

// heuristicExpectedAccess determines expected access using heuristics
func (t *APITester) heuristicExpectedAccess(endpoint openapi.Endpoint, session *authz.SessionContext) string {
	// If endpoint requires auth and session is anonymous, expect denied
	if endpoint.RequiresAuth && session.Credentials.Type == "none" {
		return "denied"
	}

	// If endpoint doesn't require auth, expect allowed
	if !endpoint.RequiresAuth {
		return "allowed"
	}

	// If endpoint requires auth and session has credentials, expect allowed
	if endpoint.RequiresAuth && session.Credentials.Type != "none" {
		return "allowed"
	}

	return "denied"
}

// determineActualAccess determines actual access from response
func (t *APITester) determineActualAccess(resp *httpclient.Response) string {
	// 2xx = allowed
	if resp.Status >= 200 && resp.Status < 300 {
		return "allowed"
	}

	// 3xx = allowed (redirect)
	if resp.Status >= 300 && resp.Status < 400 {
		return "allowed"
	}

	// 4xx/5xx = denied
	return "denied"
}

// isHorizontalBypass checks for horizontal authorization bypass
func (t *APITester) isHorizontalBypass(endpoint openapi.Endpoint, session *authz.SessionContext, result *APITestResult) bool {
	// Horizontal bypass: user A can access user B's resource
	// This is a simplified check - in reality, would need to track resource ownership

	// Check if path contains user ID pattern
	if strings.Contains(endpoint.Path, "{id}") || strings.Contains(endpoint.Path, "{userId}") {
		// If user can access another user's resource when they shouldn't
		if result.IsBypass && !strings.Contains(session.Name, "admin") {
			return true
		}
	}

	return false
}

// isVerticalBypass checks for vertical authorization bypass
func (t *APITester) isVerticalBypass(endpoint openapi.Endpoint, session *authz.SessionContext, result *APITestResult) bool {
	// Vertical bypass: regular user can access admin-only resources

	// Check if endpoint is tagged as admin
	for _, tag := range endpoint.Tags {
		if strings.ToLower(tag) == "admin" || strings.ToLower(tag) == "administrator" {
			// If non-admin user can access admin endpoint
			if result.IsBypass && !strings.Contains(session.Name, "admin") {
				return true
			}
		}
	}

	return false
}

// GetSummary returns a summary of test results
func (t *APITester) GetSummary(results []*APITestResult) TestSummary {
	summary := TestSummary{
		TotalTests: len(results),
		Passed:     0,
		Failed:     0,
		Bypasses:   0,
		Horizontal: 0,
		Vertical:   0,
		ByMethod:   make(map[string]int),
		BySession:  make(map[string]int),
	}

	for _, result := range results {
		if result.Passed {
			summary.Passed++
		} else {
			summary.Failed++
		}

		if result.IsBypass {
			summary.Bypasses++
		}

		if result.IsHorizontal {
			summary.Horizontal++
		}

		if result.IsVertical {
			summary.Vertical++
		}

		summary.ByMethod[result.Method]++
		summary.BySession[result.Session]++
	}

	return summary
}

// TestSummary represents a summary of API test results
type TestSummary struct {
	TotalTests int
	Passed     int
	Failed     int
	Bypasses   int
	Horizontal int
	Vertical   int
	ByMethod   map[string]int
	BySession  map[string]int
}
