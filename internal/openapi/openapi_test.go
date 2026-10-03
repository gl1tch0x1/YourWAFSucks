package openapi

import (
	"strings"
	"testing"
)

const openAPI3JSON = `{
  "openapi": "3.0.3",
  "info": {"title": "Demo API", "version": "1.2.3"},
  "servers": [{"url": "https://api.example.com/v1"}],
  "security": [{"bearerAuth": []}],
  "components": {
    "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}
  },
  "paths": {
    "/users/{id}": {
      "get": {
        "operationId": "getUser",
        "tags": ["users"],
        "security": [],
        "parameters": [{"name": "id", "in": "path", "required": true, "example": "42"}]
      },
      "delete": {
        "operationId": "deleteUser",
        "tags": ["users"],
        "parameters": [{"name": "id", "in": "path", "required": true}]
      }
    },
    "/health": {
      "get": {"operationId": "health", "summary": "Health", "security": []}
    },
    "/admin": {
      "post": {
        "operationId": "adminAction",
        "parameters": [{"name": "id", "in": "query"}]
      }
    }
  }
}`

const swagger2YAML = `swagger: "2.0"
info:
  title: Legacy API
  version: "1.0.0"
host: legacy.example.com
basePath: /api
schemes: [https]
securityDefinitions:
  apiKey:
    type: apiKey
    in: header
    name: X-API-Key
security:
  - apiKey: []
paths:
  /items:
    get:
      operationId: listItems
      parameters:
        - name: q
          in: query
  /open:
    get:
      operationId: openEndpoint
      security: []
`

func TestParseOpenAPI3JSON(t *testing.T) {
	spec, err := Parse([]byte(openAPI3JSON))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if spec.Version() != "3.0.3" {
		t.Fatalf("version = %q", spec.Version())
	}
	if spec.Title() != "Demo API" {
		t.Fatalf("title = %q", spec.Title())
	}

	eps := spec.Endpoints()
	if len(eps) != 4 {
		t.Fatalf("expected 4 endpoints, got %d: %+v", len(eps), eps)
	}
	// Deterministic ordering: /admin POST, /health GET, /users/{id} DELETE, GET
	want := []string{"POST /admin", "GET /health", "GET /users/{id}", "DELETE /users/{id}"}
	for i, w := range want {
		got := eps[i].Method + " " + eps[i].Path
		if got != w {
			t.Fatalf("endpoint[%d] = %q, want %q", i, got, w)
		}
	}

	var getUser, adminPost Endpoint
	for _, e := range eps {
		switch e.OperationID {
		case "getUser":
			getUser = e
		case "adminAction":
			adminPost = e
		}
	}
	if getUser.RequiresAuth {
		t.Fatalf("getUser has explicit empty security; must be public")
	}
	if !adminPost.RequiresAuth || len(adminPost.Security) != 1 || adminPost.Security[0] != "bearerAuth" {
		t.Fatalf("adminAction should inherit bearerAuth, got %+v", adminPost)
	}

	if got := spec.BaseURL("https://target.example.com"); got != "https://api.example.com/v1" {
		t.Fatalf("BaseURL = %q", got)
	}
	if got := getUser.ResolvePath(spec.BaseURL("https://target.example.com"), nil); got != "https://api.example.com/v1/users/42" {
		t.Fatalf("ResolvePath = %q", got)
	}
	if got := adminPost.ResolvePath("https://api.example.com/v1", nil); got != "https://api.example.com/v1/admin" {
		t.Fatalf("ResolvePath admin = %q", got)
	}
}

func TestParseSwagger2YAML(t *testing.T) {
	spec, err := Parse([]byte(swagger2YAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if spec.Version() != "2.0" {
		t.Fatalf("version = %q", spec.Version())
	}
	eps := spec.Endpoints()
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(eps))
	}
	if !eps[0].RequiresAuth {
		t.Fatalf("listItems should inherit apiKey, got %+v", eps[0])
	}
	if eps[1].RequiresAuth {
		t.Fatalf("openEndpoint explicit empty security should be public")
	}
	if got := spec.BaseURL("https://target.example.com/x"); got != "https://legacy.example.com/api" {
		t.Fatalf("BaseURL = %q", got)
	}
	if _, ok := spec.SecuritySchemes()["apiKey"]; !ok {
		t.Fatalf("apiKey scheme not resolved")
	}
}

func TestParseRejectsNonSpec(t *testing.T) {
	_, err := Parse([]byte(`{"hello":"world"}`))
	if err == nil {
		t.Fatalf("expected error for non-spec document")
	}
	if !strings.Contains(err.Error(), "OpenAPI") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSampleValuePrefersExample(t *testing.T) {
	p := Parameter{Name: "id", In: "path", Example: "abc"}
	if got := SampleValue(p); got != "abc" {
		t.Fatalf("SampleValue = %q", got)
	}
	p = Parameter{Name: "id", In: "path", Default: "7"}
	if got := SampleValue(p); got != "7" {
		t.Fatalf("SampleValue default = %q", got)
	}
	p = Parameter{Name: "other", In: "path"}
	if got := SampleValue(p); got != "1" {
		t.Fatalf("SampleValue fallback = %q", got)
	}
}
