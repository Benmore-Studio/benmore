//go:build !cli

package main

import (
	"net/http"
	"strings"
)

// bearerTransport injects Authorization header on every request.
type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(req)
}

// newTestClient returns an HTTP client that authenticates with Bearer token.
func newTestClient(token string) *http.Client {
	return &http.Client{
		Timeout: 5 * 1e9,
		Transport: &bearerTransport{token: token, base: http.DefaultTransport},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// smartTestValue generates a realistic test value for a column based on its name and type.
func smartTestValue(col Column) string {
	name := strings.ToLower(col.Name)
	upper := strings.ToUpper(col.Type)

	// Type-based defaults
	switch {
	case strings.Contains(upper, "BOOL"):
		return "0"
	case strings.Contains(upper, "REAL") || strings.Contains(upper, "FLOAT") || strings.Contains(upper, "DOUBLE"):
		return "1.00"
	case strings.Contains(upper, "DATE"):
		return "2026-01-01"
	}

	// Integer types
	if strings.Contains(upper, "INT") {
		return "1"
	}

	// Name-based smart values (handles validation rules)
	switch {
	case name == "email" || strings.HasSuffix(name, "_email"):
		return "test@example.com"
	case name == "phone" || strings.HasSuffix(name, "_phone"):
		return "555-0199"
	case name == "url" || name == "website" || strings.HasSuffix(name, "_url"):
		return "https://example.com"
	case name == "name" || strings.HasSuffix(name, "_name"):
		return "Test Name"
	case name == "title":
		return "Test Title"
	case name == "description" || name == "notes" || name == "body" || name == "content":
		return "Test description text"
	case name == "status" || name == "state":
		return "active"
	case name == "type" || name == "kind" || name == "category":
		return "default"
	case name == "stage":
		return "new"
	case name == "priority":
		return "medium"
	case name == "company" || name == "organization":
		return "Test Company"
	case name == "address" || name == "street":
		return "123 Test St"
	case name == "city":
		return "Denver"
	case name == "state" || name == "region":
		return "CO"
	case name == "zip" || name == "postal_code":
		return "80202"
	case name == "country":
		return "US"
	case name == "password":
		return "testpass123"
	case name == "color" || name == "hex":
		return "#2563eb"
	case strings.Contains(name, "amount") || strings.Contains(name, "price") || strings.Contains(name, "value") || strings.Contains(name, "cost"):
		return "100.00"
	case strings.Contains(name, "count") || strings.Contains(name, "quantity") || strings.Contains(name, "number"):
		return "1"
	case strings.Contains(name, "date") || strings.Contains(name, "time"):
		return "2026-01-01"
	case strings.HasSuffix(name, "_id"):
		return "1"
	default:
		return "test_" + col.Name
	}
}
