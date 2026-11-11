//go:build !cli

package main

import (
	"strings"
	"testing"
)

// A <fetch> tag's url= and headers= are sent by the server, often with the
// app's credentials. Values rendered into them were HTML-escaped only, so a
// request value could add path segments (`../../admin`), parameters
// (`a&admin=1`), pick another host (`evil.com/#`) or add a header. Each value
// is now escaped for the part it lands in, or refused.
func TestFetchAttributeValuesAreEscapedByPosition(t *testing.T) {
	render := func(tmpl string, data map[string]any) string {
		t.Helper()
		return RenderMustache(tmpl, data)
	}
	cases := []struct {
		name, tmpl string
		data       map[string]any
		want       string // substring of the rendered tag
		refused    bool
	}{
		{"path traversal is one escaped segment", `<fetch url="https://api.vendor.test/v1/items/{{id}}"></fetch>`, map[string]any{"id": "../../v1/admin/export?"}, "items/..%2F..%2Fv1%2Fadmin%2Fexport%3F", false},
		{"dot-dot segment refused", `<fetch url="https://api.vendor.test/v1/items/{{id}}"></fetch>`, map[string]any{"id": ".."}, "", true},
		{"query value cannot add a parameter", `<fetch url="https://api.vendor.test/v1/items?q={{q}}"></fetch>`, map[string]any{"q": "a&admin=1#x"}, "q=a%26admin%3D1%23x", false},
		{"host label value stays a label", `<fetch url="https://{{region}}.vendor.test/x"></fetch>`, map[string]any{"region": "eu-west"}, "https://eu-west.vendor.test/x", false},
		{"host value cannot pick another host", `<fetch url="https://{{region}}.vendor.test/x"></fetch>`, map[string]any{"region": "evil.test/#"}, "", true},
		{"header value cannot add a header", `<fetch url="https://api.vendor.test/x" headers="X-Tenant: {{t}}"></fetch>`, map[string]any{"t": "a, X-HTTP-Method-Override: DELETE"}, "", true},
		{"plain header value kept", `<fetch url="https://api.vendor.test/x" headers="X-Tenant: {{t}}"></fetch>`, map[string]any{"t": "acme"}, `headers="X-Tenant: acme"`, false},
	}
	for _, tc := range cases {
		got := render(tc.tmpl, tc.data)
		if tc.refused {
			if !strings.Contains(got, fetchRefusedValue) {
				t.Errorf("%s: rendered %q, want the value refused", tc.name, got)
			}
			continue
		}
		if !strings.Contains(got, tc.want) || strings.Contains(got, fetchRefusedValue) {
			t.Errorf("%s: rendered %q, want it to contain %q", tc.name, got, tc.want)
		}
	}
}
