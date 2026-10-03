// Package openapi ingests OpenAPI 3.x and Swagger 2.0 documents and exposes the
// operations they describe as a flat, request-ready endpoint list. It is used by
// the authorization testing engine to discover API attack surface without
// crawling.
package openapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Info holds the document metadata block.
type Info struct {
	Title       string `json:"title" yaml:"title"`
	Version     string `json:"version" yaml:"version"`
	Description string `json:"description" yaml:"description"`
}

// Server describes a base URL (OpenAPI 3).
type Server struct {
	URL         string                    `json:"url" yaml:"url"`
	Description string                    `json:"description" yaml:"description"`
	Variables   map[string]ServerVariable `json:"variables" yaml:"variables"`
}

// ServerVariable is a templated server variable (OpenAPI 3).
type ServerVariable struct {
	Default     string   `json:"default" yaml:"default"`
	Enum        []string `json:"enum" yaml:"enum"`
	Description string   `json:"description" yaml:"description"`
}

// Parameter describes an operation parameter.
type Parameter struct {
	Name        string        `json:"name" yaml:"name"`
	In          string        `json:"in" yaml:"in"`
	Required    bool          `json:"required" yaml:"required"`
	Description string        `json:"description" yaml:"description"`
	Example     string        `json:"example" yaml:"example"`
	Default     interface{}   `json:"default" yaml:"default"`
	Enum        []interface{} `json:"enum" yaml:"enum"`
}

// RequestBody captures an OpenAPI 3 request body (content types only).
type RequestBody struct {
	Required bool               `json:"required" yaml:"required"`
	Content  map[string]Content `json:"content" yaml:"content"`
}

// Content is a media type entry.
type Content struct {
	Schema map[string]interface{} `json:"schema" yaml:"schema"`
}

// Operation is a single method on a path.
type Operation struct {
	OperationID string                `json:"operationId" yaml:"operationId"`
	Summary     string                `json:"summary" yaml:"summary"`
	Description string                `json:"description" yaml:"description"`
	Tags        []string              `json:"tags" yaml:"tags"`
	Parameters  []Parameter           `json:"parameters" yaml:"parameters"`
	Security    []map[string][]string `json:"security" yaml:"security"`
	RequestBody *RequestBody          `json:"requestBody" yaml:"requestBody"`
}

// PathItem groups the operations available on a path.
type PathItem struct {
	Summary    string      `json:"summary" yaml:"summary"`
	Parameters []Parameter `json:"parameters" yaml:"parameters"`

	Get     *Operation `json:"get" yaml:"get"`
	Put     *Operation `json:"put" yaml:"put"`
	Post    *Operation `json:"post" yaml:"post"`
	Delete  *Operation `json:"delete" yaml:"delete"`
	Options *Operation `json:"options" yaml:"options"`
	Head    *Operation `json:"head" yaml:"head"`
	Patch   *Operation `json:"patch" yaml:"patch"`
}

// SecurityScheme describes an authentication mechanism.
type SecurityScheme struct {
	Type         string `json:"type" yaml:"type"`
	Scheme       string `json:"scheme" yaml:"scheme"`
	In           string `json:"in" yaml:"in"`
	Name         string `json:"name" yaml:"name"`
	BearerFormat string `json:"bearerFormat" yaml:"bearerFormat"`
}

// Components is the OpenAPI 3 reusable-object container.
type Components struct {
	SecuritySchemes map[string]SecurityScheme `json:"securitySchemes" yaml:"securitySchemes"`
}

// Spec is a parsed OpenAPI 3.x or Swagger 2.0 document.
type Spec struct {
	OpenAPI string `json:"openapi" yaml:"openapi"`
	Swagger string `json:"swagger" yaml:"swagger"`
	Info    Info   `json:"info" yaml:"info"`

	// OpenAPI 3
	Servers    []Server   `json:"servers" yaml:"servers"`
	Components Components `json:"components" yaml:"components"`

	// Swagger 2.0
	Host                string                    `json:"host" yaml:"host"`
	BasePath            string                    `json:"basePath" yaml:"basePath"`
	Schemes             []string                  `json:"schemes" yaml:"schemes"`
	SecurityDefinitions map[string]SecurityScheme `json:"securityDefinitions" yaml:"securityDefinitions"`

	Paths    map[string]PathItem   `json:"paths" yaml:"paths"`
	Security []map[string][]string `json:"security" yaml:"security"`
}

// Endpoint is a flattened, request-ready operation.
type Endpoint struct {
	Method      string
	Path        string
	OperationID string
	Summary     string
	Tags        []string
	// Security lists the security scheme names required by the operation. An
	// empty slice with RequiresAuth == false means the operation is public.
	Security     []string
	RequiresAuth bool
	Parameters   []Parameter
}

var methodOrder = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}

// Load reads and parses an OpenAPI/Swagger document from disk.
func Load(path string) (*Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("openapi: read %s: %w", path, err)
	}
	spec, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("openapi: parse %s: %w", path, err)
	}
	return spec, nil
}

// Parse accepts either JSON or YAML. JSON is attempted first for better error
// messages on JSON documents; YAML handles the rest.
func Parse(data []byte) (*Spec, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty document")
	}

	var spec Spec
	if trimmed[0] == '{' {
		if err := json.Unmarshal(trimmed, &spec); err != nil {
			return nil, err
		}
	} else if err := yaml.Unmarshal(trimmed, &spec); err != nil {
		return nil, err
	}
	if !spec.isValid() {
		return nil, fmt.Errorf("not an OpenAPI/Swagger document (missing openapi/swagger version)")
	}
	return &spec, nil
}

// ParseReader parses a document from an io.Reader.
func ParseReader(r io.Reader) (*Spec, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

func (s *Spec) isValid() bool {
	return strings.HasPrefix(s.OpenAPI, "3.") || s.Swagger == "2.0"
}

// Version returns the declared specification version (OpenAPI or Swagger).
func (s *Spec) Version() string {
	if s.OpenAPI != "" {
		return s.OpenAPI
	}
	return s.Swagger
}

// Title returns the document title.
func (s *Spec) Title() string { return s.Info.Title }

// SecuritySchemes returns a merged view of OpenAPI 3 and Swagger 2 schemes.
func (s *Spec) SecuritySchemes() map[string]SecurityScheme {
	out := make(map[string]SecurityScheme)
	for k, v := range s.Components.SecuritySchemes {
		out[k] = v
	}
	for k, v := range s.SecurityDefinitions {
		out[k] = v
	}
	return out
}

// Endpoints flattens every operation into a deterministic, method-ordered list.
func (s *Spec) Endpoints() []Endpoint {
	paths := make([]string, 0, len(s.Paths))
	for p := range s.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var out []Endpoint
	for _, p := range paths {
		item := s.Paths[p]
		for _, m := range methodOrder {
			op := item.operation(m)
			if op == nil {
				continue
			}
			params := append(append([]Parameter{}, item.Parameters...), op.Parameters...)
			sec, requires := s.effectiveSecurity(op)
			out = append(out, Endpoint{
				Method:       m,
				Path:         p,
				OperationID:  op.OperationID,
				Summary:      op.Summary,
				Tags:         append([]string{}, op.Tags...),
				Security:     sec,
				RequiresAuth: requires,
				Parameters:   params,
			})
		}
	}
	return out
}

func (item PathItem) operation(method string) *Operation {
	switch method {
	case "GET":
		return item.Get
	case "POST":
		return item.Post
	case "PUT":
		return item.Put
	case "PATCH":
		return item.Patch
	case "DELETE":
		return item.Delete
	case "OPTIONS":
		return item.Options
	case "HEAD":
		return item.Head
	}
	return nil
}

// effectiveSecurity resolves operation-level security against the document
// default. An explicitly empty operation security list means "public".
func (s *Spec) effectiveSecurity(op *Operation) ([]string, bool) {
	req := op.Security
	if req == nil {
		req = s.Security
	}
	if len(req) == 0 {
		return nil, false
	}
	names := make([]string, 0, len(req))
	seen := make(map[string]bool)
	for _, requirement := range req {
		for name := range requirement {
			if !seen[name] {
				names = append(names, name)
				seen[name] = true
			}
		}
	}
	sort.Strings(names)
	return names, len(names) > 0
}

// BaseURL resolves the request origin for the document given a fallback target
// URL. It prefers OpenAPI 3 servers, then Swagger 2 host/basePath, then target.
func (s *Spec) BaseURL(target string) string {
	origin := originOf(target)
	if len(s.Servers) > 0 && s.Servers[0].URL != "" {
		return resolveServer(origin, s.Servers[0])
	}
	if s.Host != "" {
		scheme := "https"
		if len(s.Schemes) > 0 {
			scheme = s.Schemes[0]
		}
		return strings.TrimRight(scheme+"://"+s.Host+s.BasePath, "/")
	}
	return strings.TrimRight(origin+s.BasePath, "/")
}

func resolveServer(origin string, srv Server) string {
	raw := srv.URL
	for name, v := range srv.Variables {
		value := v.Default
		if value == "" && len(v.Enum) > 0 {
			value = v.Enum[0]
		}
		raw = strings.ReplaceAll(raw, "{"+name+"}", value)
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return strings.TrimRight(raw, "/")
	}
	if strings.HasPrefix(raw, "/") {
		return strings.TrimRight(origin+raw, "/")
	}
	return strings.TrimRight(origin+"/"+raw, "/")
}

func originOf(target string) string {
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" {
		return strings.TrimRight(target, "/")
	}
	return u.Scheme + "://" + u.Host
}

// ResolvePath substitutes {param} placeholders with sample values and returns an
// absolute URL under base.
func (e Endpoint) ResolvePath(base string, override map[string]string) string {
	path := e.Path
	for _, p := range e.Parameters {
		if p.In != "path" {
			continue
		}
		value := override[p.Name]
		if value == "" {
			value = SampleValue(p)
		}
		path = strings.ReplaceAll(path, "{"+p.Name+"}", url.PathEscape(value))
	}
	// Substitute any remaining placeholders we have no schema for.
	for {
		start := strings.Index(path, "{")
		if start < 0 {
			break
		}
		end := strings.Index(path[start:], "}")
		if end < 0 {
			break
		}
		path = path[:start] + "1" + path[start+end+1:]
	}
	return strings.TrimRight(base, "/") + ensureLeadingSlash(path)
}

// SampleValue returns a benign value for a parameter, preferring a declared
// example, then default, then the first enum entry, then "1".
func SampleValue(p Parameter) string {
	if p.Example != "" {
		return p.Example
	}
	if p.Default != nil {
		if s, ok := p.Default.(string); ok && s != "" {
			return s
		}
		return fmt.Sprintf("%v", p.Default)
	}
	if len(p.Enum) > 0 {
		if s, ok := p.Enum[0].(string); ok && s != "" {
			return s
		}
		return fmt.Sprintf("%v", p.Enum[0])
	}
	switch p.Name {
	case "id", "userId", "user_id", "accountId", "account_id", "orderId", "order_id":
		return "1"
	}
	return "1"
}

func ensureLeadingSlash(p string) string {
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}
