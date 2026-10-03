package transport

import (
	"context"
	"fmt"

	"github.com/gl1tch0x1/YourWAFSucks/internal/httpclient"
)

// Transport defines the interface for HTTP transport implementations
type Transport interface {
	// Send sends a request and returns the response
	Send(ctx context.Context, req Request) (*httpclient.Response, error)

	// Capabilities returns the transport's capabilities
	Capabilities() Capabilities

	// Name returns the transport name
	Name() string
}

// Capabilities describes what a transport can do
type Capabilities struct {
	HTTP1               bool
	HTTP2               bool
	Raw                 bool
	Proxy               bool
	RedirectControl     bool
	HeaderCustomization bool
	PathPreservation    bool
}

// Request represents a transport-agnostic request
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
	Raw     string // For raw HTTP requests
}

// HTTPTransport implements standard HTTP/1.1 and HTTP/2 transport
type HTTPTransport struct {
	client  *httpclient.Client
	version string // "1.1" or "2.0"
}

// NewHTTPTransport creates a new HTTP transport
func NewHTTPTransport(client *httpclient.Client, version string) *HTTPTransport {
	return &HTTPTransport{
		client:  client,
		version: version,
	}
}

func (t *HTTPTransport) Send(ctx context.Context, req Request) (*httpclient.Response, error) {
	// Convert to httpclient.Request
	httpReq := httpclient.Request{
		Method:  req.Method,
		URL:     req.URL,
		Headers: req.Headers,
		Body:    req.Body,
	}

	return t.client.Request(ctx, httpReq)
}

func (t *HTTPTransport) Capabilities() Capabilities {
	return Capabilities{
		HTTP1:               true,
		HTTP2:               t.version == "2.0",
		Raw:                 false,
		Proxy:               true,
		RedirectControl:     false,
		HeaderCustomization: true,
		PathPreservation:    false,
	}
}

func (t *HTTPTransport) Name() string {
	return fmt.Sprintf("HTTP/%s", t.version)
}

// RawTransport implements raw HTTP transport for advanced bypasses
type RawTransport struct {
	client *httpclient.Client
}

// NewRawTransport creates a new raw HTTP transport
func NewRawTransport(client *httpclient.Client) *RawTransport {
	return &RawTransport{
		client: client,
	}
}

func (t *RawTransport) Send(ctx context.Context, req Request) (*httpclient.Response, error) {
	// Raw transport would use custom HTTP client implementation
	// For now, delegate to standard HTTP client with special handling
	// TODO: Implement actual raw HTTP request sending

	httpReq := httpclient.Request{
		Method:  req.Method,
		URL:     req.URL,
		Headers: req.Headers,
		Body:    req.Body,
	}

	return t.client.Request(ctx, httpReq)
}

func (t *RawTransport) Capabilities() Capabilities {
	return Capabilities{
		HTTP1:               true,
		HTTP2:               false,
		Raw:                 true,
		Proxy:               true,
		RedirectControl:     true,
		HeaderCustomization: true,
		PathPreservation:    true,
	}
}

func (t *RawTransport) Name() string {
	return "RawHTTP"
}

// ProtocolTransport implements protocol version switching
type ProtocolTransport struct {
	http1 *HTTPTransport
	http2 *HTTPTransport
}

// NewProtocolTransport creates a new protocol transport
func NewProtocolTransport(client *httpclient.Client) *ProtocolTransport {
	return &ProtocolTransport{
		http1: NewHTTPTransport(client, "1.1"),
		http2: NewHTTPTransport(client, "2.0"),
	}
}

func (t *ProtocolTransport) Send(ctx context.Context, req Request) (*httpclient.Response, error) {
	// Default to HTTP/2, fallback to HTTP/1.1
	resp, err := t.http2.Send(ctx, req)
	if err != nil {
		return t.http1.Send(ctx, req)
	}
	return resp, nil
}

func (t *ProtocolTransport) Capabilities() Capabilities {
	return Capabilities{
		HTTP1:               true,
		HTTP2:               true,
		Raw:                 false,
		Proxy:               true,
		RedirectControl:     false,
		HeaderCustomization: true,
		PathPreservation:    false,
	}
}

func (t *ProtocolTransport) Name() string {
	return "ProtocolSwitch"
}

// Manager manages multiple transports
type Manager struct {
	defaultTransport Transport
	transports       map[string]Transport
}

// NewManager creates a new transport manager
func NewManager(client *httpclient.Client) *Manager {
	http1 := NewHTTPTransport(client, "1.1")
	http2 := NewHTTPTransport(client, "2.0")

	return &Manager{
		defaultTransport: http2,
		transports: map[string]Transport{
			"http1":    http1,
			"http2":    http2,
			"raw":      NewRawTransport(client),
			"protocol": NewProtocolTransport(client),
		},
	}
}

// GetTransport returns a transport by name
func (m *Manager) GetTransport(name string) (Transport, error) {
	t, ok := m.transports[name]
	if !ok {
		return nil, fmt.Errorf("transport not found: %s", name)
	}
	return t, nil
}

// GetDefault returns the default transport
func (m *Manager) GetDefault() Transport {
	return m.defaultTransport
}

// GetTransportForCapabilities returns a transport that supports the required capabilities
func (m *Manager) GetTransportForCapabilities(required Capabilities) (Transport, error) {
	for _, t := range m.transports {
		caps := t.Capabilities()
		if supportsCapabilities(caps, required) {
			return t, nil
		}
	}
	return nil, fmt.Errorf("no transport supports required capabilities")
}

// ListTransports returns all available transports
func (m *Manager) ListTransports() []string {
	names := make([]string, 0, len(m.transports))
	for name := range m.transports {
		names = append(names, name)
	}
	return names
}

// supportsCapabilities checks if a transport supports the required capabilities
func supportsCapabilities(available, required Capabilities) bool {
	if required.HTTP1 && !available.HTTP1 {
		return false
	}
	if required.HTTP2 && !available.HTTP2 {
		return false
	}
	if required.Raw && !available.Raw {
		return false
	}
	if required.Proxy && !available.Proxy {
		return false
	}
	if required.RedirectControl && !available.RedirectControl {
		return false
	}
	if required.HeaderCustomization && !available.HeaderCustomization {
		return false
	}
	if required.PathPreservation && !available.PathPreservation {
		return false
	}
	return true
}
