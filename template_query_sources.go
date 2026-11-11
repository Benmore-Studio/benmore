//go:build !cli

package main

import (
	"bytes"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// reportSource deliberately has no SQL, interpolation or caller-selected source
// expressions. The native query builder owns all identifiers and projections.
type reportSource struct {
	querySpec   `yaml:",inline"`
	TenantScope string `yaml:"tenant_scope"`
	Overflow    string `yaml:"overflow"`
}

func (s *reportSource) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("report source must be a single-table query mapping")
	}
	// Decode mapping presence before decoding into zero-valued strings: YAML
	// merges can inherit an explicit null/blank that must not mean "omitted".
	// The decoder resolves merge precedence and retains its alias/cycle guards.
	var declared map[string]yaml.Node
	if err := node.Decode(&declared); err != nil {
		return fmt.Errorf("report source: %w", err)
	}
	for key, want := range map[string]string{"tenant_scope": "current", "overflow": "error"} {
		value, exists := declared[key]
		if !exists {
			continue
		}
		var decoded any
		if err := value.Decode(&decoded); err != nil {
			return fmt.Errorf("report source %s: %w", key, err)
		}
		text, ok := decoded.(string)
		if !ok || text != want {
			return fmt.Errorf("report source %s must be %s", key, want)
		}
	}
	encoded, err := yaml.Marshal(node)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(encoded))
	dec.KnownFields(true)
	// Avoid recursively invoking this unmarshaler while retaining KnownFields.
	type plainReportSource reportSource
	var spec plainReportSource
	if err := dec.Decode(&spec); err != nil {
		return fmt.Errorf("report source: %w", err)
	}
	if strings.TrimSpace(spec.Table) == "" {
		return fmt.Errorf("report source requires table")
	}
	*s = reportSource(spec)
	return s.validate()
}

func (s reportSource) validate() error {
	if s.TenantScope != "" && s.TenantScope != "current" {
		return fmt.Errorf("report source tenant_scope must be current")
	}
	if s.Overflow != "" && s.Overflow != "error" {
		return fmt.Errorf("report source overflow must be error")
	}
	if s.Overflow == "error" && (s.Limit < 0 || s.Limit > 1000) {
		return fmt.Errorf("report source overflow: error requires limit 1..1000 or the default 200")
	}
	return nil
}

func validateReportSources(fm *Frontmatter) error {
	if len(fm.Sources) == 0 {
		return nil
	}
	if fm.Engine != "gotmpl" {
		return fmt.Errorf("frontmatter sources require engine: gotmpl")
	}
	if _, exists := fm.Queries["sources"]; exists {
		return fmt.Errorf("frontmatter query name sources conflicts with report sources")
	}
	for name, source := range fm.Sources {
		if !safeAlias(name) {
			return fmt.Errorf("invalid report source name: %q", name)
		}
		if strings.TrimSpace(source.Table) == "" {
			return fmt.Errorf("report source %q requires table", name)
		}
		if err := source.validate(); err != nil {
			return err
		}
	}
	return nil
}

// reportSourceFailure captures only the existing executor's failure response.
// A page must not turn a denied/invalid report into an empty successful result,
// or change its 401/403/404/400 into a generic rendering 500. Keeping the native
// response also retains sanitized server errors and request-id headers.
type reportSourceFailure struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (f *reportSourceFailure) Header() http.Header { return f.header }
func (f *reportSourceFailure) WriteHeader(status int) {
	if f.status == 0 {
		f.status = status
	}
}
func (f *reportSourceFailure) Write(data []byte) (int, error) {
	if f.status == 0 {
		f.WriteHeader(http.StatusOK)
	}
	return f.body.Write(data)
}
func (f *reportSourceFailure) Error() string {
	return fmt.Sprintf("report source failed (HTTP %d)", f.status)
}
func (f *reportSourceFailure) writeTo(w http.ResponseWriter) {
	for key, values := range f.header {
		w.Header()[key] = append([]string(nil), values...)
	}
	// A source error returns before servePage sets its normal dynamic-page
	// cache policy. In particular an actor-specific 404 must not be cached.
	w.Header().Set("Cache-Control", "no-store, must-revalidate")
	w.WriteHeader(f.status)
	_, _ = w.Write(f.body.Bytes())
}

func runReportSources(app *App, page *Page, ctx *RenderContext, fm *Frontmatter) error {
	if len(fm.Sources) == 0 {
		return nil
	}
	if ctx.Request == nil {
		return fmt.Errorf("report sources require the original HTTP request")
	}
	names := make([]string, 0, len(fm.Sources))
	for name := range fm.Sources {
		names = append(names, name)
	}
	sort.Strings(names)
	results := make(map[string][]map[string]any, len(names))
	for _, name := range names {
		failure := &reportSourceFailure{header: make(http.Header)}
		source := fm.Sources[name]
		rows, ok := executeAuthorizedQueryWithPolicy(failure, ctx.Request, app, source.querySpec, queryReadPolicy{
			ownerOnly: page.Scope == "owner", currentTenant: source.TenantScope == "current", rejectOverflow: source.Overflow == "error",
		})
		if !ok {
			return failure
		}
		results[name] = rows
		ctx.QueryCount++
	}
	ctx.Data["sources"] = results
	return nil
}
