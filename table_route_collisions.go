//go:build !cli

package main

// A table's own routes - auto-CRUD at /api/<table>, record locks, sharing -
// register in the same ServeMux as the framework's routes, and ServeMux
// refuses two patterns that match the same requests with neither more
// specific. A table named like a framework path (`_upload`, `_schema`,
// `_query`, `_jobs`, `_notifications`, `_auth`, ...) passed the write gate
// and `benmore check`, and then the app could not register its routes: it
// did not load, and stayed down until the table was dropped from its
// database (routes come from the tables the database has).
//
// The reserved names are not a list kept here. Like route_collisions.go does
// for flows, the check registers the app's routes from source
// (buildAppRouteMux with initialize=false, no database) and asks whether the
// patterns the per-table registrars add for a table can register next to the
// framework's. So it refuses exactly the names that cannot load, for the
// features this app has on, and nothing else: `_foo` registers and is
// accepted, and a table that gets no routes (`_benmore_*`, `sqlite_*`,
// virtual tables: eligibleCRUDTables) is never looked at.

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// tableRouteCollision is a table whose routes cannot register next to a
// framework route.
type tableRouteCollision struct {
	Table    string // "_upload"
	Pattern  string // the table's route: "POST /api/_upload"
	Conflict string // the framework route it collides with
	Suggest  string // a table name that registers; "" when none was found
}

// tableRoutePatterns is every pattern the per-table registrars (record locks,
// auto-CRUD, sharing) add for table, in registration order. The routes those
// registrars add whatever the tables are (POST /api/_transaction) are left
// out: they are the framework's.
func tableRoutePatterns(app *App, table string) []string {
	record := func(tables []string) []string {
		recorder := &appRouteMux{preflight: true}
		registerLockTables(recorder, app, tables)
		registerCRUDTables(recorder, app, tables)
		registerPermissionTables(recorder, app, tables)
		return recorder.patterns
	}
	fixed := map[string]int{}
	for _, pattern := range record(nil) {
		fixed[pattern]++
	}
	var own []string
	for _, pattern := range record([]string{table}) {
		if fixed[pattern] > 0 {
			fixed[pattern]--
			continue
		}
		own = append(own, pattern)
	}
	return own
}

// tableRoutesRegister reports whether the app's routes register with tables,
// by running the registration the load runs.
func tableRoutesRegister(app *App, dev bool, tables []string) (registered bool) {
	defer func() {
		if recover() != nil {
			registered = false
		}
	}()
	app.DevMode = dev
	buildAppRouteMux(app, dev, "", false, tables)
	return true
}

// tableRouteCollisionWith names the framework route one of table's routes
// collides with: the same route when there is one (POST /api/_upload twice),
// else the first overlapping pair.
func tableRouteCollisionWith(app *App, framework []string, table string) (tableRouteCollision, bool) {
	var first *tableRouteCollision
	for _, pattern := range tableRoutePatterns(app, table) {
		for _, registered := range framework {
			if !routePatternsConflict(registered, pattern) {
				continue
			}
			if registered == pattern {
				return tableRouteCollision{Table: table, Pattern: pattern, Conflict: registered}, true
			}
			if first == nil {
				first = &tableRouteCollision{Table: table, Pattern: pattern, Conflict: registered}
			}
		}
	}
	if first == nil {
		return tableRouteCollision{}, false
	}
	return *first, true
}

// tableRouteCollisionsIn returns the tables whose routes collide with a
// framework route of the app at dir, in dev or production mode. tables are
// the candidate schema's auto-CRUD tables.
func tableRouteCollisionsIn(dir string, tables []string) (collisions []tableRouteCollision) {
	defer func() {
		if recover() != nil {
			// Routes that cannot register without any table are not a
			// table's doing; whoever registers them twice reports it.
			collisions = nil
		}
	}()
	app, _, err := routeCandidateApp(dir)
	if err != nil {
		// A schema or app.yaml that does not parse is its own validator's finding.
		return nil
	}
	taken := map[string]bool{}
	for _, table := range tables {
		taken[sqliteIdentifierFold(table)] = true
	}
	found := map[string]bool{}
	for _, dev := range []bool{false, true} {
		if tableRoutesRegister(app, dev, tables) {
			continue
		}
		app.DevMode = dev
		framework := buildAppRouteMux(app, dev, "", false, nil)
		owned := framework.patterns[:framework.authoredFrom]
		for _, table := range tables {
			if found[table] || tableRoutesRegister(app, dev, []string{table}) {
				continue
			}
			collision, ok := tableRouteCollisionWith(app, owned, table)
			if !ok {
				continue
			}
			found[table] = true
			bare := strings.TrimLeft(table, "_")
			for _, name := range []string{bare, "app_" + bare} {
				if bare == "" || taken[sqliteIdentifierFold(name)] || crudInternalName.MatchString(sqliteIdentifierFold(name)) {
					continue
				}
				if tableRoutesRegister(app, false, []string{name}) && tableRoutesRegister(app, true, []string{name}) {
					collision.Suggest = name
					break
				}
			}
			collisions = append(collisions, collision)
		}
	}
	return collisions
}

// message is the refusal for one table. model is the Prisma model that maps
// to it ("" for schema.sql).
func (c tableRouteCollision) message(file, model string) string {
	var b strings.Builder
	if model != "" {
		fmt.Fprintf(&b, "%s: model %s maps to table %q, ", file, model, c.Table)
	} else {
		fmt.Fprintf(&b, "%s: table %q: ", file, c.Table)
	}
	if c.Pattern == c.Conflict {
		fmt.Fprintf(&b, "whose route %s is a route the framework registers itself.", c.Pattern)
	} else {
		fmt.Fprintf(&b, "whose route %s collides with the framework route %s (both match some requests and neither is more specific).", c.Pattern, c.Conflict)
	}
	b.WriteString(" The app cannot register both, so it would not load, and it would stay down until the table is dropped from its database.")
	example := c.Suggest
	if example == "" {
		example = "<name>"
	}
	if model != "" {
		fmt.Fprintf(&b, " Give the table another name: put `@@map(%q)` in the model (the model can keep its name).", example)
	} else {
		fmt.Fprintf(&b, " Give the table another name, for example %q.", example)
	}
	b.WriteString(" Every table is served at /api/<table>, and /api/_... is where the framework's own endpoints live, so a table name should not start with `_`.")
	return b.String()
}

// tableRouteCollisionViolation is the write-gate and `benmore check` refusal
// for a schema file (schema.prisma, or schema.sql when the app has no
// schema.prisma): every table in content whose routes cannot register next to
// the framework's. The load does not run this check; it fails on such a table.
func tableRouteCollisionViolation(appDir, path, content string) string {
	if appDir == "" {
		return ""
	}
	file := appRelativeFile(appDir, filepath.Clean(path))
	models := map[string]string{} // table -> model
	switch file {
	case "schema.prisma":
		parsed, err := ParsePrismaSchema(content)
		if err != nil {
			return "" // validateSchemaPrisma reports the parse error
		}
		for _, model := range parsed {
			models[model.Table] = model.Name
		}
	case "schema.sql":
		if prisma, err := readOptionalConfig(appDir, "schema.prisma"); err != nil || prisma != nil {
			return "" // schema.prisma is the schema the app loads
		}
	default:
		return ""
	}
	definitions, err := appMCPSchemaTableDefinitionsWithReader(func(name string) ([]byte, error) {
		if name == file {
			return []byte(content), nil
		}
		return readOptionalConfig(appDir, name)
	})
	if err != nil {
		return ""
	}
	eligible := eligibleCRUDTables(definitions)
	tables := make([]string, 0, len(eligible))
	for name := range eligible {
		tables = append(tables, name)
	}
	if len(tables) == 0 {
		return ""
	}
	sort.Strings(tables)
	collisions := tableRouteCollisionsIn(appDir, tables)
	messages := make([]string, 0, len(collisions))
	for _, c := range collisions {
		messages = append(messages, c.message(file, models[c.Table]))
	}
	return strings.Join(messages, "\n")
}
