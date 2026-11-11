//go:build !cli

package main

// Flow routes share one ServeMux with the framework's own routes, and
// http.ServeMux.HandleFunc panics when two patterns match the same requests
// with neither more specific. buildAppRouteMux registers every framework
// route before any authored route (flows, then pages), so a collision always
// lands on the authored side: RegisterFlows recovers it, skips the flow and
// records the framework route it hit.
//
// The write gate and `benmore check` ask the same question by running that
// registration over the app's source (buildAppRouteMux with initialize=false,
// no database), so the reserved set is whatever the framework actually
// registers - auto-CRUD and its per-table sub-routes (share, permissions,
// versions, revert, lock, transition, ...) and every framework path - and
// cannot drift from a hand-kept list.

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// routeRegistrationPanic is a panic raised while an app's routes registered:
// in practice ServeMux refusing a pattern that collides with one already
// registered. A flow's collision is recovered where the flow registers
// (RegisterFlows); this is every other one, which nothing recovered.
type routeRegistrationPanic struct{ recovered string }

func (e *routeRegistrationPanic) Error() string {
	return "route registration failed: " + e.recovered
}

// routePanicSourceRe matches the "(registered at /build/path/file.go:35)"
// ServeMux adds to a conflict: always the registrar's own line here.
var routePanicSourceRe = regexp.MustCompile(` \(registered at [^)]*\)`)

func newRouteRegistrationPanic(recovered any) *routeRegistrationPanic {
	text := routePanicSourceRe.ReplaceAllString(fmt.Sprint(recovered), "")
	return &routeRegistrationPanic{recovered: strings.Join(strings.Fields(text), " ")}
}

// routePreflightFindings is what `benmore check` reports for a failed route
// preflight. A registration that panics would stop the app from loading, so
// it is an error; it used to be dropped with every other preflight failure.
// A schema or app.yaml that does not parse is its own validator's finding.
func routePreflightFindings(err error) []CheckFinding {
	var panicked *routeRegistrationPanic
	if !errors.As(err, &panicked) {
		return nil
	}
	message := panicked.Error() + ". The app registers the same routes when it starts and on every reload, so it cannot start as written."
	if strings.Contains(panicked.recovered, "conflicts with pattern") {
		message += " That route is registered twice: by two parts of the app's configuration, or by one part and the framework itself (for example a table named like a framework path). Rename or remove the one that repeats it; see api({at:'recovery'}) → route_registration."
	}
	return []CheckFinding{{Severity: "error", Source: "routes", Message: message}}
}

// flowRouteCollision is an http flow the runtime skips because its route
// collides with one registered before it.
type flowRouteCollision struct {
	Flow     string // flow name
	File     string // the flow's source file, when known
	Route    string // as authored: "POST /api/notes/:id/share"
	Pattern  string // ServeMux pattern: "POST /api/notes/{id}/share"
	Conflict string // the registered pattern it collides with; "" when Pattern itself is malformed
	Source   string // "permissions.go:151" for a framework route, "flow <name>" for another flow
	SameFile bool   // the other flow is another job of the same file's trigger
}

// flowMuxPattern is the ServeMux pattern RegisterFlows registers for an http
// trigger: `:param` segments become Go 1.22 `{param}` wildcards.
func flowMuxPattern(method, path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if strings.HasPrefix(part, ":") {
			parts[i] = "{" + strings.TrimPrefix(part, ":") + "}"
		}
	}
	return fmt.Sprintf("%s %s", method, strings.Join(parts, "/"))
}

// routePatternValid reports whether ServeMux accepts pattern on its own.
func routePatternValid(pattern string) (valid bool) {
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	http.NewServeMux().HandleFunc(pattern, http.NotFound)
	return true
}

// routePatternsConflict reports whether ServeMux refuses to hold both
// patterns (identical, or overlapping with neither more specific). Both must
// be valid on their own.
func routePatternsConflict(registered, candidate string) (conflict bool) {
	defer func() {
		if recover() != nil {
			conflict = true
		}
	}()
	mux := http.NewServeMux()
	mux.HandleFunc(registered, http.NotFound)
	mux.HandleFunc(candidate, http.NotFound)
	return false
}

// conflictingRoute names the already-registered pattern that pattern
// collides with, and where it was registered. Empty when pattern is
// malformed rather than colliding.
func (mux *appRouteMux) conflictingRoute(pattern string) (string, string) {
	if !routePatternValid(pattern) {
		return "", ""
	}
	for _, registered := range mux.patterns {
		if routePatternsConflict(registered, pattern) {
			return registered, mux.sources[registered]
		}
	}
	return "", ""
}

// beginAuthoredRoutes marks the end of framework registration: every pattern
// registered before this call is framework-owned.
func (mux *appRouteMux) beginAuthoredRoutes() {
	mux.authoredFrom = len(mux.patterns)
}

// frameworkFeature names the framework feature that registered a route, by the
// file that registered it, and the api(at:) topic documenting it.
func (c flowRouteCollision) frameworkFeature() (feature, topic string) {
	file, _, _ := strings.Cut(c.Source, ":")
	switch file {
	case "crud.go":
		return "auto-CRUD, registered for every table", "scoping"
	case "permissions.go":
		return "record sharing, registered for every table", "permissions"
	case "versioning.go":
		return "version history, registered for every versioned table", "versioning"
	case "locks.go":
		return "record locks, registered for every table", "locks"
	case "workflows.go":
		return "workflow transitions, registered for every workflow table", "workflows"
	}
	return "framework route", ""
}

// summary is the one-line description load logs and validators share.
// withLine keeps the registering source line (operators); app builders get
// the file only.
func (c flowRouteCollision) summary(withLine bool) string {
	switch {
	case c.Conflict == "":
		return fmt.Sprintf("flow %q route %s is not a valid route pattern (%s)", c.Flow, c.Route, c.Pattern)
	case strings.HasPrefix(c.Source, "flow "):
		return fmt.Sprintf("flow %q route %s collides with %s at %s", c.Flow, c.Route, c.Source, c.Conflict)
	}
	feature, _ := c.frameworkFeature()
	source := c.Source
	if !withLine {
		source, _, _ = strings.Cut(source, ":")
	}
	if source != "" {
		source = ", " + source
	}
	return fmt.Sprintf("flow %q route %s collides with the framework route %s (%s%s)", c.Flow, c.Route, c.Conflict, feature, source)
}

// loadHint is what the load log tells the author to do about the skipped
// flow. It used to say "move the flow to a path the framework does not
// register" for every collision, also when the route belonged to another of
// the app's own flows.
func (c flowRouteCollision) loadHint() string {
	where := ""
	if c.File != "" {
		where = " (" + c.File + ")"
	}
	switch {
	case c.Conflict == "":
		return "Use `/segment/:param` path syntax in the flow's file" + where + "."
	case c.SameFile:
		return "A request trigger with several jobs becomes one flow per job on the same route" + where + "; put every step in one job, or move each job to its own file and path."
	case strings.HasPrefix(c.Source, "flow "):
		return fmt.Sprintf("Two flows cannot serve the same route: give this flow%s or %s a different method or path.", where, c.Source)
	}
	return "Move the flow" + where + " to a path the framework does not register (`benmore check` names one)."
}

// suggestedFlowPath proposes a path that does not collide: the last literal
// segment gets a suffix, checked against what the framework registers.
// Empty when no candidate is free.
func suggestedFlowPath(mux *appRouteMux, method, path string) string {
	parts := strings.Split(path, "/")
	last := -1
	for i := len(parts) - 1; i >= 0; i-- {
		p := parts[i]
		if p != "" && p != "api" && !strings.HasPrefix(p, ":") && !strings.HasPrefix(p, "{") {
			last = i
			break
		}
	}
	if last < 0 {
		return ""
	}
	for _, suffix := range []string{"-custom", "-action", "-flow"} {
		next := append([]string(nil), parts...)
		next[last] += suffix
		candidate := strings.Join(next, "/")
		if mux == nil {
			return candidate
		}
		if conflict, _ := mux.conflictingRoute(flowMuxPattern(method, candidate)); conflict == "" && routePatternValid(flowMuxPattern(method, candidate)) {
			return candidate
		}
	}
	return ""
}

// message is the write-gate refusal: what collides, why it can't load, and a
// path that would.
func (c flowRouteCollision) message(file string, mux *appRouteMux) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s.", file, c.summary(false))
	if c.Conflict == "" {
		b.WriteString(" The runtime cannot register it, so the flow would never receive a request. Use `/segment/:param` path syntax.")
		return b.String()
	}
	if c.SameFile {
		b.WriteString(" A request trigger with several jobs becomes one flow per job, all on the same route; the runtime registers one of them, chosen arbitrarily, and skips the rest. Put every step in one job, or move each job to its own file and path.")
		return b.String()
	}
	if strings.HasPrefix(c.Source, "flow ") {
		b.WriteString(" Two flows cannot serve the same route: the runtime registers one and skips the other. Give one of them a different method or path.")
		return b.String()
	}
	b.WriteString(" Framework routes register before flows, so the runtime would skip this flow at load and it would never receive a request.")
	if _, topic := c.frameworkFeature(); topic != "" {
		fmt.Fprintf(&b, " If the built-in route does what you need, remove the flow and call it instead - see api(at:%q).", topic)
	}
	method, path, _ := strings.Cut(c.Route, " ")
	if alt := suggestedFlowPath(mux, method, path); alt != "" {
		fmt.Fprintf(&b, " Otherwise move the flow to a path the framework does not register, e.g. %s %s.", method, alt)
	} else {
		b.WriteString(" Otherwise move the flow to a path the framework does not register.")
	}
	return b.String()
}

// routeCandidateApp stages the route-relevant configuration of the app at dir
// from source - schema tables, app.yaml, workflows, pages, connector
// presence - without opening its database, as `benmore mcp inspect` does.
// Configuration is read with readOptionalConfig, which the hosted router
// confines to the tenant's own regular files.
func routeCandidateApp(dir string) (*App, []string, error) {
	definitions, err := appMCPSchemaTableDefinitions(dir)
	if err != nil {
		return nil, nil, err
	}
	eligible := eligibleCRUDTables(definitions)
	tables := make([]string, 0, len(eligible))
	for name := range eligible {
		tables = append(tables, name)
	}
	sort.Strings(tables)
	appYAML, err := readOptionalConfig(dir, "app.yaml")
	if err != nil {
		return nil, nil, err
	}
	raw, _, err := parseAppConfigDocument(appYAML)
	if err != nil {
		return nil, nil, err
	}
	var design *DesignConfig
	if raw != nil {
		design = designFromAppYAML(raw)
	}
	access, err := parseAccessConfig(appYAML)
	if err != nil {
		return nil, nil, err
	}
	workflowsYAML, err := readOptionalConfig(dir, "workflows.yaml")
	if err != nil {
		return nil, nil, err
	}
	workflows, err := parseWorkflowsYAML(workflowsYAML)
	if err != nil {
		return nil, nil, err
	}
	pages, _, err := LoadPages(dir)
	if err != nil {
		pages = nil
	}
	app := &App{Dir: dir, Pages: pages, Paths: DiscoverAuthPaths(pages), Design: design,
		Workflows: workflows, Group: parseGroupConfig(appYAML), Access: access,
		// A visitor password can be set at any time without a source
		// change, so its login route is always reserved. No env is read.
		routeEnv: map[string]string{"DEMO_PASSWORD": "route preflight"}}
	if mcp, err := readOptionalConfig(dir, "mcp.yaml"); err == nil && mcp != nil {
		// The connector's reserved routes register either way; the withheld
		// set needs no reviewed manifest.
		app.mcpWithheld = "route preflight"
	}
	return app, tables, nil
}

// flowRouteCollisionsIn registers flows after every framework route of the
// app at dir, exactly as buildAppRouteMux does at load (in both dev and
// production mode), and returns the flows the runtime would skip. The mux
// that produced each collision is returned for suggestions.
func flowRouteCollisionsIn(dir string, flows []Flow) (collisions []flowRouteCollision, mux *appRouteMux, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			collisions, mux, err = nil, nil, newRouteRegistrationPanic(recovered)
		}
	}()
	app, tables, err := routeCandidateApp(dir)
	if err != nil {
		return nil, nil, err
	}
	app.Flows = flows
	seen := map[string]bool{}
	for _, dev := range []bool{false, true} {
		app.DevMode = dev
		candidate := buildAppRouteMux(app, dev, "", false, tables)
		if mux == nil {
			mux = candidate
		}
		for _, c := range candidate.flowCollisions {
			key := c.Flow + "\x00" + c.Pattern
			if seen[key] {
				continue
			}
			seen[key] = true
			collisions = append(collisions, c)
		}
	}
	return collisions, mux, nil
}

// flowHTTPTriggers extracts the http flows a flows file declares, named as the
// loader names them, without running the loader (which logs). Command
// declarations register no ordinary route and are left out.
func flowHTTPTriggers(path, content string) []Flow {
	if commandDeclarationPresent(content) {
		return nil
	}
	source := filepath.ToSlash(path)
	var gha FlowFileGHA
	if yamlUnmarshal([]byte(content), &gha) == nil && gha.Jobs != nil {
		if gha.On.Request == nil {
			return nil
		}
		method := strings.ToUpper(strings.TrimSpace(gha.On.Request.Method))
		if method == "" {
			method = "POST"
		}
		stem := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		names := make([]string, 0, len(gha.Jobs))
		if len(gha.Jobs) == 1 && stem != "flows" {
			names = append(names, stem)
		} else {
			for name := range gha.Jobs {
				names = append(names, name)
			}
			sort.Strings(names)
		}
		out := make([]Flow, 0, len(names))
		for _, name := range names {
			out = append(out, Flow{Name: name, Source: source, Trigger: FlowTrigger{Type: "http", Method: method, Path: gha.On.Request.Path}})
		}
		return out
	}
	if strings.ToLower(filepath.Base(path)) != "flows.yaml" {
		return nil
	}
	var legacy map[string]FlowYAML
	if yamlUnmarshal([]byte(content), &legacy) != nil {
		return nil
	}
	names := make([]string, 0, len(legacy))
	for name := range legacy {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []Flow
	for _, name := range names {
		parts := strings.Fields(legacy[name].Trigger)
		if len(parts) < 2 || !strings.HasPrefix(parts[1], "/") {
			continue
		}
		out = append(out, Flow{Name: name, Source: source, Trigger: FlowTrigger{Type: "http", Method: strings.ToUpper(parts[0]), Path: parts[1]}})
	}
	return out
}

// routeCheckedFlows drops the flows an earlier validator already refuses for
// their route (a reserved framework prefix, an auto-CRUD path), so each
// problem is reported once.
func routeCheckedFlows(flows []Flow, tables map[string]bool) []Flow {
	out := flows[:0:0]
	for _, f := range flows {
		if detectReservedPath(f.Trigger.Path) != "" || matchAutoCRUDPath(f.Trigger.Method, f.Trigger.Path, tables) != "" {
			continue
		}
		out = append(out, f)
	}
	return out
}

// appRelativeFile names path relative to appDir when it lies inside it.
func appRelativeFile(appDir, path string) string {
	if filepath.IsAbs(path) {
		if rel, err := filepath.Rel(appDir, path); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(path)
}

// flowRouteCollisionViolation is the write-gate check for one flows file:
// every http flow in content must register after the app's framework routes.
func flowRouteCollisionViolation(appDir, path, content string) string {
	if appDir == "" {
		return ""
	}
	flows := routeCheckedFlows(flowHTTPTriggers(path, content), loadSchemaTableNames(appDir))
	if len(flows) == 0 {
		return ""
	}
	collisions, mux, err := flowRouteCollisionsIn(appDir, flows)
	if err != nil || len(collisions) == 0 {
		// A schema or app.yaml that does not parse is reported by its own validator.
		return ""
	}
	file := appRelativeFile(appDir, path)
	messages := make([]string, 0, len(collisions))
	for _, c := range collisions {
		messages = append(messages, c.message(file, mux))
	}
	return strings.Join(messages, "\n")
}

// appRouteFlows is every http flow the loader registers for the app at dir
// (flows.yaml, then flows/*.yaml in name order), without running the loader.
func appRouteFlows(dir string) []Flow {
	paths := []string{"flows.yaml"}
	if entries, err := os.ReadDir(filepath.Join(dir, "flows")); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yaml") {
				paths = append(paths, "flows/"+entry.Name())
			}
		}
	}
	var flows []Flow
	for _, path := range paths {
		data, err := readOptionalConfig(dir, path)
		if err != nil || data == nil {
			continue
		}
		flows = append(flows, flowHTTPTriggers(path, string(data))...)
	}
	return routeCheckedFlows(flows, loadSchemaTableNames(dir))
}

// flowRouteCollisionFindings is the `benmore check` form: every flows file
// the loader reads, registered together in load order, so a collision
// between two flow files is found too.
func flowRouteCollisionFindings(dir string) []CheckFinding {
	// Without flows too: the registration itself must not panic.
	collisions, mux, err := flowRouteCollisionsIn(dir, appRouteFlows(dir))
	if err != nil {
		return routePreflightFindings(err)
	}
	findings := make([]CheckFinding, 0, len(collisions))
	for _, c := range collisions {
		findings = append(findings, CheckFinding{Severity: "error", Source: "routes", File: c.File, Message: c.message(c.File, mux)})
	}
	return findings
}
