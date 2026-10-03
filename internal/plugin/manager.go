package plugin

import (
	"context"
	"fmt"
	"plugin"
	"sync"
)

// TechniquePlugin defines the interface for technique plugins
type TechniquePlugin interface {
	Name() string
	Version() string
	Description() string
	Generate(ctx context.Context, payload PluginPayload) ([]PluginPayload, error)
	Initialize(config map[string]interface{}) error
	Cleanup() error
}

// FingerprintPlugin defines the interface for fingerprint plugins
type FingerprintPlugin interface {
	Name() string
	Version() string
	Description() string
	Fingerprint(ctx context.Context, target string) (map[string]interface{}, error)
	Initialize(config map[string]interface{}) error
	Cleanup() error
}

// TransportPlugin defines the interface for transport plugins
type TransportPlugin interface {
	Name() string
	Version() string
	Description() string
	Send(ctx context.Context, req PluginRequest) (*PluginResponse, error)
	Capabilities() map[string]bool
	Initialize(config map[string]interface{}) error
	Cleanup() error
}

// ScoringPlugin defines the interface for scoring plugins
type ScoringPlugin interface {
	Name() string
	Version() string
	Description() string
	Score(ctx context.Context, baseline, mutation PluginResponse) (float64, error)
	Initialize(config map[string]interface{}) error
	Cleanup() error
}

// ReporterPlugin defines the interface for reporter plugins
type ReporterPlugin interface {
	Name() string
	Version() string
	Description() string
	Report(ctx context.Context, findings []PluginFinding) (string, error)
	Initialize(config map[string]interface{}) error
	Cleanup() error
}

// PluginPayload represents a plugin payload
type PluginPayload struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
	Metadata map[string]interface{}
}

// PluginRequest represents a plugin request
type PluginRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    []byte
	Options map[string]interface{}
}

// PluginResponse represents a plugin response
type PluginResponse struct {
	Status      int
	Headers     map[string]string
	Body        []byte
	ContentType string
	Time        float64
	Error       error
}

// PluginFinding represents a plugin finding
type PluginFinding struct {
	ID          string
	Technique   string
	Payload     PluginPayload
	Response    PluginResponse
	Score       float64
	Confidence  float64
	Reason      string
	Metadata    map[string]interface{}
}

// Manager manages loaded plugins
type Manager struct {
	techniquePlugins  map[string]TechniquePlugin
	fingerprintPlugins map[string]FingerprintPlugin
	transportPlugins  map[string]TransportPlugin
	scoringPlugins    map[string]ScoringPlugin
	reporterPlugins   map[string]ReporterPlugin
	mu                sync.RWMutex
}

// NewManager creates a new plugin manager
func NewManager() *Manager {
	return &Manager{
		techniquePlugins:  make(map[string]TechniquePlugin),
		fingerprintPlugins: make(map[string]FingerprintPlugin),
		transportPlugins:  make(map[string]TransportPlugin),
		scoringPlugins:    make(map[string]ScoringPlugin),
		reporterPlugins:   make(map[string]ReporterPlugin),
	}
}

// LoadTechniquePlugin loads a technique plugin from a .so file
func (m *Manager) LoadTechniquePlugin(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	plug, err := plugin.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open plugin: %w", err)
	}

	sym, err := plug.Lookup("New")
	if err != nil {
		return fmt.Errorf("failed to lookup New symbol: %w", err)
	}

	newFunc, ok := sym.(func() TechniquePlugin)
	if !ok {
		return fmt.Errorf("unexpected type from module symbol")
	}

	pluginInstance := newFunc()
	m.techniquePlugins[pluginInstance.Name()] = pluginInstance

	return nil
}

// LoadFingerprintPlugin loads a fingerprint plugin from a .so file
func (m *Manager) LoadFingerprintPlugin(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	plug, err := plugin.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open plugin: %w", err)
	}

	sym, err := plug.Lookup("New")
	if err != nil {
		return fmt.Errorf("failed to lookup New symbol: %w", err)
	}

	newFunc, ok := sym.(func() FingerprintPlugin)
	if !ok {
		return fmt.Errorf("unexpected type from module symbol")
	}

	pluginInstance := newFunc()
	m.fingerprintPlugins[pluginInstance.Name()] = pluginInstance

	return nil
}

// LoadTransportPlugin loads a transport plugin from a .so file
func (m *Manager) LoadTransportPlugin(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	plug, err := plugin.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open plugin: %w", err)
	}

	sym, err := plug.Lookup("New")
	if err != nil {
		return fmt.Errorf("failed to lookup New symbol: %w", err)
	}

	newFunc, ok := sym.(func() TransportPlugin)
	if !ok {
		return fmt.Errorf("unexpected type from module symbol")
	}

	pluginInstance := newFunc()
	m.transportPlugins[pluginInstance.Name()] = pluginInstance

	return nil
}

// LoadScoringPlugin loads a scoring plugin from a .so file
func (m *Manager) LoadScoringPlugin(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	plug, err := plugin.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open plugin: %w", err)
	}

	sym, err := plug.Lookup("New")
	if err != nil {
		return fmt.Errorf("failed to lookup New symbol: %w", err)
	}

	newFunc, ok := sym.(func() ScoringPlugin)
	if !ok {
		return fmt.Errorf("unexpected type from module symbol")
	}

	pluginInstance := newFunc()
	m.scoringPlugins[pluginInstance.Name()] = pluginInstance

	return nil
}

// LoadReporterPlugin loads a reporter plugin from a .so file
func (m *Manager) LoadReporterPlugin(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	plug, err := plugin.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open plugin: %w", err)
	}

	sym, err := plug.Lookup("New")
	if err != nil {
		return fmt.Errorf("failed to lookup New symbol: %w", err)
	}

	newFunc, ok := sym.(func() ReporterPlugin)
	if !ok {
		return fmt.Errorf("unexpected type from module symbol")
	}

	pluginInstance := newFunc()
	m.reporterPlugins[pluginInstance.Name()] = pluginInstance

	return nil
}

// GetTechniquePlugin retrieves a technique plugin by name
func (m *Manager) GetTechniquePlugin(name string) (TechniquePlugin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, ok := m.techniquePlugins[name]
	if !ok {
		return nil, fmt.Errorf("technique plugin not found: %s", name)
	}
	return plugin, nil
}

// GetFingerprintPlugin retrieves a fingerprint plugin by name
func (m *Manager) GetFingerprintPlugin(name string) (FingerprintPlugin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, ok := m.fingerprintPlugins[name]
	if !ok {
		return nil, fmt.Errorf("fingerprint plugin not found: %s", name)
	}
	return plugin, nil
}

// GetTransportPlugin retrieves a transport plugin by name
func (m *Manager) GetTransportPlugin(name string) (TransportPlugin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, ok := m.transportPlugins[name]
	if !ok {
		return nil, fmt.Errorf("transport plugin not found: %s", name)
	}
	return plugin, nil
}

// GetScoringPlugin retrieves a scoring plugin by name
func (m *Manager) GetScoringPlugin(name string) (ScoringPlugin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, ok := m.scoringPlugins[name]
	if !ok {
		return nil, fmt.Errorf("scoring plugin not found: %s", name)
	}
	return plugin, nil
}

// GetReporterPlugin retrieves a reporter plugin by name
func (m *Manager) GetReporterPlugin(name string) (ReporterPlugin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, ok := m.reporterPlugins[name]
	if !ok {
		return nil, fmt.Errorf("reporter plugin not found: %s", name)
	}
	return plugin, nil
}

// ListTechniquePlugins returns all loaded technique plugins
func (m *Manager) ListTechniquePlugins() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.techniquePlugins))
	for name := range m.techniquePlugins {
		names = append(names, name)
	}
	return names
}

// ListFingerprintPlugins returns all loaded fingerprint plugins
func (m *Manager) ListFingerprintPlugins() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.fingerprintPlugins))
	for name := range m.fingerprintPlugins {
		names = append(names, name)
	}
	return names
}

// ListTransportPlugins returns all loaded transport plugins
func (m *Manager) ListTransportPlugins() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.transportPlugins))
	for name := range m.transportPlugins {
		names = append(names, name)
	}
	return names
}

// ListScoringPlugins returns all loaded scoring plugins
func (m *Manager) ListScoringPlugins() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.scoringPlugins))
	for name := range m.scoringPlugins {
		names = append(names, name)
	}
	return names
}

// ListReporterPlugins returns all loaded reporter plugins
func (m *Manager) ListReporterPlugins() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.reporterPlugins))
	for name := range m.reporterPlugins {
		names = append(names, name)
	}
	return names
}

// Cleanup cleans up all loaded plugins
func (m *Manager) Cleanup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errors []error

	for _, plugin := range m.techniquePlugins {
		if err := plugin.Cleanup(); err != nil {
			errors = append(errors, err)
		}
	}

	for _, plugin := range m.fingerprintPlugins {
		if err := plugin.Cleanup(); err != nil {
			errors = append(errors, err)
		}
	}

	for _, plugin := range m.transportPlugins {
		if err := plugin.Cleanup(); err != nil {
			errors = append(errors, err)
		}
	}

	for _, plugin := range m.scoringPlugins {
		if err := plugin.Cleanup(); err != nil {
			errors = append(errors, err)
		}
	}

	for _, plugin := range m.reporterPlugins {
		if err := plugin.Cleanup(); err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors during cleanup: %v", errors)
	}

	return nil
}

// GetStatistics returns plugin statistics
func (m *Manager) GetStatistics() PluginStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return PluginStats{
		TechniquePlugins:  len(m.techniquePlugins),
		FingerprintPlugins: len(m.fingerprintPlugins),
		TransportPlugins:  len(m.transportPlugins),
		ScoringPlugins:    len(m.scoringPlugins),
		ReporterPlugins:   len(m.reporterPlugins),
	}
}

// PluginStats represents plugin statistics
type PluginStats struct {
	TechniquePlugins  int
	FingerprintPlugins int
	TransportPlugins  int
	ScoringPlugins    int
	ReporterPlugins   int
}
