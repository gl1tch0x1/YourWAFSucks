// Package plugin defines a small, portable plugin SDK. Plugins are described
// declaratively by a JSON manifest, so they can be authored and shared without
// recompiling the tool.
package plugin

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gl1tch0x1/YourWAFSucks/internal/techniques"
)

// HeaderSpec injects a single header into a request.
type HeaderSpec struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
}

// PathSpec describes a path mutation. The pattern may contain the {target} and
// {path} placeholders.
type PathSpec struct {
	Pattern     string `json:"pattern"`
	Description string `json:"description,omitempty"`
}

// RawSpec describes a fully-formed request.
type RawSpec struct {
	Method      string `json:"method"`
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
}

// Manifest is the declarative description of a plugin.
type Manifest struct {
	Name        string       `json:"name"`
	Version     string       `json:"version"`
	Description string       `json:"description,omitempty"`
	Headers     []HeaderSpec `json:"headers,omitempty"`
	Paths       []PathSpec   `json:"paths,omitempty"`
	Methods     []string     `json:"methods,omitempty"`
	Raw         []RawSpec    `json:"raw,omitempty"`
}

// Plugin generates payloads for a scan.
type Plugin interface {
	Name() string
	Generate(ctx techniques.Context) []techniques.Payload
}

// ManifestPlugin adapts a Manifest to the Plugin interface.
type ManifestPlugin struct {
	Manifest Manifest
}

// Name returns the manifest name.
func (m ManifestPlugin) Name() string { return m.Manifest.Name }

// Generate expands the manifest into concrete payloads, substituting the
// {target} and {path} placeholders using ctx.Target.
func (m ManifestPlugin) Generate(ctx techniques.Context) []techniques.Payload {
	name := m.Manifest.Name
	methods := m.Manifest.Methods
	if len(methods) == 0 {
		methods = []string{"GET"}
	}

	var out []techniques.Payload

	for _, h := range m.Manifest.Headers {
		out = append(out, techniques.Payload{
			Method:      methods[0],
			URL:         ctx.Target,
			Description: headerDescription(h),
			Detail:      h.Name + ": " + h.Value,
			Headers:     map[string]string{h.Name: h.Value},
			Technique:   name,
		})
	}

	for _, p := range m.Manifest.Paths {
		resolved := resolveURL(substitute(p.Pattern, ctx.Target), ctx.Target)
		for _, method := range methods {
			out = append(out, techniques.Payload{
				Method:      method,
				URL:         resolved,
				Description: pathDescription(p, resolved),
				Detail:      p.Pattern,
				Technique:   name,
			})
		}
	}

	for _, method := range methods {
		out = append(out, techniques.Payload{
			Method:      method,
			URL:         ctx.Target,
			Description: fmt.Sprintf("method %s", method),
			Detail:      method,
			Technique:   name,
		})
	}

	for _, r := range m.Manifest.Raw {
		method := strings.ToUpper(r.Method)
		if method == "" {
			method = "GET"
		}
		out = append(out, techniques.Payload{
			Method:      method,
			URL:         resolveURL(substitute(r.URL, ctx.Target), ctx.Target),
			Description: rawDescription(r),
			Detail:      r.URL,
			Technique:   name,
		})
	}

	return out
}

func headerDescription(h HeaderSpec) string {
	if h.Description != "" {
		return h.Description
	}
	return "inject header " + h.Name
}

func pathDescription(p PathSpec, resolved string) string {
	if p.Description != "" {
		return p.Description
	}
	return "path " + resolved
}

func rawDescription(r RawSpec) string {
	if r.Description != "" {
		return r.Description
	}
	return "raw request"
}

// substitute replaces the {target} and {path} placeholders. {path} expands to
// the path component of target (which may be empty).
func substitute(pattern, target string) string {
	if pattern == "" {
		return pattern
	}
	pattern = strings.ReplaceAll(pattern, "{target}", target)
	if strings.Contains(pattern, "{path}") {
		pattern = strings.ReplaceAll(pattern, "{path}", pathOf(target))
	}
	return pattern
}

func pathOf(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	return u.Path
}

// resolveURL turns a possibly-relative reference into an absolute URL against
// target. Absolute references are returned unchanged.
func resolveURL(raw, target string) string {
	if raw == "" {
		return target
	}
	u, err := url.Parse(raw)
	if err == nil && u.IsAbs() {
		return u.String()
	}
	base, err := url.Parse(target)
	if err != nil {
		return raw
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return base.ResolveReference(ref).String()
}

// LoadManifest reads and parses a single JSON manifest.
func LoadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("plugin: parse %s: %w", path, err)
	}
	return m, nil
}

// LoadDir loads every *.json manifest in dir, validating that each has a name.
func LoadDir(dir string) ([]Plugin, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)

	plugins := make([]Plugin, 0, len(matches))
	for _, path := range matches {
		m, err := LoadManifest(path)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(m.Name) == "" {
			return nil, fmt.Errorf("plugin: %s: name is required", path)
		}
		plugins = append(plugins, ManifestPlugin{Manifest: m})
	}
	return plugins, nil
}

// Registry aggregates plugins by name.
type Registry struct {
	plugins map[string]Plugin
	order   []string
}

// NewRegistry returns an empty plugin registry.
func NewRegistry() *Registry {
	return &Registry{plugins: make(map[string]Plugin)}
}

// Register adds a plugin. Registering a plugin with an existing name replaces
// it while preserving ordering.
func (r *Registry) Register(p Plugin) {
	if p == nil {
		return
	}
	name := p.Name()
	if _, ok := r.plugins[name]; !ok {
		r.order = append(r.order, name)
	}
	r.plugins[name] = p
}

// Generate runs every registered plugin and concatenates their payloads.
func (r *Registry) Generate(ctx techniques.Context) []techniques.Payload {
	var out []techniques.Payload
	for _, name := range r.order {
		out = append(out, r.plugins[name].Generate(ctx)...)
	}
	return out
}

// Names returns the registered plugin names in registration order.
func (r *Registry) Names() []string {
	out := make([]string, len(r.order))
	copy(out, r.order)
	return out
}

// compile-time assertion: ensure ManifestPlugin implements Plugin
var _ Plugin = (*ManifestPlugin)(nil)
