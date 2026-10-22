//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Register the same canonical handlers without executing them or starting workers.
// Registration panics/skips and more-specific routes must not become tool bindings.
func validateAppMCPRouteBindings(m *AppMCPManifest, flows []Flow, tables map[string]bool) (err error) {
	if m == nil {
		return nil
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("mcp.yaml: canonical route registration failed")
		}
	}()
	mux := http.NewServeMux()
	names := make([]string, 0, len(tables))
	for name := range tables {
		reserved, routeErr := appMCPReservedRoute("/api/" + name)
		if routeErr != nil {
			return fmt.Errorf("mcp.yaml: invalid table route escaping")
		}
		if reserved {
			return fmt.Errorf("mcp.yaml: table collides with reserved connector route")
		}
		if !strings.HasPrefix(name, "_benmore_") && !strings.HasPrefix(strings.ToLower(name), "sqlite_") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	app := &App{Flows: flows}
	registerCRUDTables(mux, app, names)
	registerAppMCPRouteReservation(mux)
	for _, flow := range flows {
		reserved, routeErr := appMCPReservedRoute(flow.Trigger.Path)
		if routeErr != nil {
			return fmt.Errorf("mcp.yaml: invalid flow route escaping")
		}
		if flow.Trigger.Type == "http" && reserved {
			return fmt.Errorf("mcp.yaml: flow %q collides with reserved connector route", flow.Name)
		}
	}
	registered := RegisterFlows(mux, app, flows)
	commandRoutes := map[string]bool{}
	for _, flow := range flows {
		if flow.Command == nil || flow.Command.Request == nil {
			continue
		}
		route := flow.Command.Request
		reserved, routeErr := appMCPReservedRoute(route.Path)
		if routeErr != nil || reserved {
			return fmt.Errorf("mcp.yaml: command %q has invalid or reserved private route", flow.Name)
		}
		key := route.Method + " " + route.Path
		if commandRoutes[key] {
			return fmt.Errorf("mcp.yaml: duplicate private command route %q", key)
		}
		commandRoutes[key] = true
		for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
			req, reqErr := http.NewRequest(method, route.Path, nil)
			if reqErr != nil {
				return fmt.Errorf("mcp.yaml: invalid command route")
			}
			if _, pattern := mux.Handler(req); pattern != "" {
				return fmt.Errorf("mcp.yaml: command route %q collides with an ordinary route", key)
			}
		}
	}
	patterns := make([]string, 0, len(registered))
	for _, pattern := range registered {
		patterns = append(patterns, pattern)
	}
	return validateAppMCPRegisteredBindings(m, flows, mux, registered, patterns)
}

func validateAppMCPRegisteredBindings(m *AppMCPManifest, flows []Flow, mux *http.ServeMux, registered map[string]string, patterns []string) error {
	for _, tool := range m.Tools {
		if tool.Handler.Operation == "command" || tool.Handler.Kind == "external" {
			continue
		}
		if tool.Effect == "write" && tool.Handler.Operation == "table.update" {
			// Direct table updates stay private; public writes use reviewed
			// commands with first-party approval and durable recovery.
			continue
		}
		method, path, expected := "GET", "/api/"+tool.Handler.Table, "GET /api/"+tool.Handler.Table
		if tool.Handler.Operation == "table.read" {
			path += "/{id}"
			expected += "/"
		}
		if tool.Handler.Operation == "flow.call" {
			count := 0
			for _, flow := range flows {
				if flow.Name == tool.Handler.Flow {
					count++
					method = flow.Trigger.Method
				}
			}
			pattern, ok := registered[tool.Handler.Flow]
			if count != 1 || !ok {
				return fmt.Errorf("mcp.yaml: tool %q has no uniquely registered flow handler", tool.Name)
			}
			expected = pattern
			_, path, _ = strings.Cut(pattern, " ")
			if !strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") || strings.Contains(path, "...") || strings.Contains(path, "{$}") {
				return fmt.Errorf("mcp.yaml: tool %q has unsupported flow route", tool.Name)
			}
		}
		target := http.NewServeMux()
		target.HandleFunc(method+" "+path, http.NotFound)
		probes := []string{appMCPRouteProbe(path, path)}
		for _, pattern := range patterns {
			_, other, hasMethod := strings.Cut(pattern, " ")
			if !hasMethod {
				other = pattern
			}
			probe := appMCPRouteProbe(other, path)
			probes = append(probes, probe, strings.TrimSuffix(probe, "/"))
			if strings.HasSuffix(other, "...}") || strings.HasSuffix(other, "{$}") {
				root, _, _ := strings.Cut(other, "{")
				probes = append(probes, strings.TrimSuffix(root, "/"))
			}
		}
		validated := false
		for _, probe := range probes {
			escapedProbe, escapeErr := appMCPProbeURL(probe)
			if escapeErr != nil {
				return fmt.Errorf("mcp.yaml: invalid route escaping")
			}
			request, requestErr := http.NewRequest(method, escapedProbe, nil)
			if requestErr != nil {
				return fmt.Errorf("mcp.yaml: tool %q has invalid route", tool.Name)
			}
			_, targetPattern := target.Handler(request)
			if targetPattern == "" {
				continue
			}
			validated = true
			_, actualPattern := mux.Handler(request)
			if actualPattern != expected {
				return fmt.Errorf("mcp.yaml: tool %q canonical handler is shadowed or unresolved", tool.Name)
			}
		}
		if !validated {
			return fmt.Errorf("mcp.yaml: tool %q has no resolvable canonical route", tool.Name)
		}
	}
	return nil
}

// Fill wildcards with an intersection witness: literal target segments wherever
// possible, otherwise a stable dummy ID. ServeMux decides whether it matches.
func appMCPRouteProbe(path, target string) string {
	parts, targetParts := strings.Split(path, "/"), strings.Split(target, "/")
	for i, part := range parts {
		if !strings.HasPrefix(part, "{") {
			continue
		}
		if strings.HasSuffix(part, "...}") {
			if i < len(targetParts) {
				parts = append(parts[:i], targetParts[i:]...)
			} else {
				parts[i] = "__mcp_probe__"
			}
			break
		}
		parts[i] = "__mcp_probe__"
		if i < len(targetParts) && !strings.HasPrefix(targetParts[i], "{") {
			parts[i] = targetParts[i]
		}
	}
	for i, part := range parts {
		if strings.HasPrefix(part, "{") {
			parts[i] = "__mcp_probe__"
		}
	}
	return strings.Join(parts, "/")
}

func validateAppMCPDatabaseBindings(dir string, m *AppMCPManifest, flows []Flow, db *sql.DB) error {
	if m == nil {
		return nil
	}
	tables, err := appMCPCandidateTables(dir, db)
	if err != nil {
		return err
	}
	return validateAppMCPRouteBindings(m, flows, tables)
}

func appMCPCandidateTables(dir string, db *sql.DB) (map[string]bool, error) {
	return appMCPCandidateTablesWithSchema(dir, db, func(name string) ([]byte, error) { return readOptionalConfig(dir, name) }, nil)
}
func appMCPCandidateTablesWithSchema(dir string, db *sql.DB, readSource func(string) ([]byte, error), migrations map[string][]byte) (map[string]bool, error) {
	source, err := appMCPSchemaTableDefinitionsWithReader(readSource)
	if err != nil {
		return nil, err
	}
	// Prisma can generate a destructive migration before the pending-file pass.
	// ponytail: reject table removals until destructive schema transitions are projected.
	prisma, err := readSource("schema.prisma")
	if os.IsNotExist(err) {
		prisma, err = nil, nil
	}
	if err != nil {
		return nil, err
	} else if prisma != nil {
		var ledger int
		if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND lower(name)='_benmore_migrations'").Scan(&ledger); err != nil {
			return nil, fmt.Errorf("mcp.yaml: cannot inspect Prisma migration ledger")
		}
		if ledger > 0 {
			var previous string
			err := db.QueryRow("SELECT source FROM _benmore_migrations ORDER BY id DESC LIMIT 1").Scan(&previous)
			if err != nil && err != sql.ErrNoRows {
				return nil, fmt.Errorf("mcp.yaml: cannot inspect Prisma migration source")
			}
			oldModels, oldErr := ParsePrismaSchema(previous)
			newModels, newErr := ParsePrismaSchema(string(prisma))
			if oldErr != nil || newErr != nil || len(DiffSchemas(oldModels, newModels).TablesDropped) > 0 {
				return nil, fmt.Errorf("mcp.yaml: destructive Prisma schema transition is unsupported")
			}
		}
	}
	existing, err := readCRUDTableDefinitions(db)
	if err != nil {
		return nil, fmt.Errorf("mcp.yaml: cannot resolve current database routes")
	}
	byName := map[string]crudTableDefinition{}
	for _, definition := range source {
		byName[sqliteIdentifierFold(definition.name)] = definition
	}
	for _, current := range existing {
		key := sqliteIdentifierFold(current.name)
		if next, ok := byName[key]; ok {
			// Non-destructive migration retains current columns and identifier spelling.
			if current.columns == nil {
				current.columns = map[string]bool{}
			}
			identities := map[string]bool{}
			for column := range current.allColumns {
				identities[sqliteIdentifierFold(column)] = true
			}
			for column := range current.columns {
				identities[sqliteIdentifierFold(column)] = true
			}
			// ponytail: reject generated metadata additions until migration preserves generated clauses.
			for _, column := range versionMetadataColumns {
				if next.allColumns[column] && !next.columns[column] && !identities[sqliteIdentifierFold(column)] && strings.HasSuffix(current.name, "_history") {
					return nil, fmt.Errorf("mcp.yaml: generated history metadata additions are unsupported by canonical migration")
				}
			}
			for column := range next.columns {
				if !identities[sqliteIdentifierFold(column)] {
					current.columns[column] = true
				}
			}
			// CREATE IF NOT EXISTS preserves an existing table's actual kind.

		}
		byName[key] = current
	}
	combined := make([]crudTableDefinition, 0, len(byName))
	for _, definition := range byName {
		combined = append(combined, definition)
	}
	combined, err = appMCPPendingMigrationTablesFromSources(dir, db, combined, migrations)
	if err != nil {
		return nil, err
	}
	return eligibleCRUDTables(combined), nil
}

// Stage the full canonical mux before migrations or retiring the live generation.
func validateAppMCPCandidateRoutes(dir string, config *runtimeConfig, db *sql.DB, environment map[string]string) (err error) {
	if config.mcp == nil {
		return nil
	}
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("mcp.yaml: candidate route registration failed")
		}
	}()
	if config.migrations == nil {
		return fmt.Errorf("mcp.yaml: missing captured migration inputs")
	}
	tables, err := appMCPCandidateTablesWithSchema(dir, db, func(name string) ([]byte, error) { return config.schemaSource(dir, name) }, config.migrations)
	if err != nil {
		return err
	}
	if err := validateAppMCPRouteBindings(config.mcp, config.flows, tables); err != nil {
		return err
	}
	pages := config.pages
	if pages == nil {
		pages, _, err = LoadPages(dir)
		if err != nil {
			return fmt.Errorf("mcp.yaml: cannot load candidate pages")
		}
	}
	for route := range pages {
		reserved, routeErr := appMCPReservedRoute(route)
		if routeErr != nil {
			return fmt.Errorf("mcp.yaml: invalid page route escaping")
		}
		if reserved {
			return fmt.Errorf("mcp.yaml: page collides with reserved connector route")
		}
	}
	names := make([]string, 0, len(tables))
	for name := range tables {
		names = append(names, name)
	}
	sort.Strings(names)
	candidate := &App{Dir: dir, DB: db, Pages: pages, Paths: DiscoverAuthPaths(pages), Design: config.design,
		Flows: config.flows, Workflows: config.workflows, Hooks: config.hooks, MCP: config.mcp, sourceFiles: config.sourceFiles,
		Group: config.group, Access: config.access, routeEnv: environment}
	// Loading occurs before the server chooses dev mode. Contracts must bind in both.
	for _, dev := range []bool{false, true} {
		candidate.DevMode = dev
		mux := buildAppRouteMux(candidate, dev, "", false, names)
		if err := validateAppMCPRegisteredBindings(config.mcp, config.flows, mux.ServeMux, mux.flows, mux.patterns); err != nil {
			return err
		}
	}
	return nil
}

func appMCPProbeURL(path string) (string, error) {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		decoded, err := url.PathUnescape(part)
		if err != nil {
			return "", err
		}
		parts[i] = url.PathEscape(decoded)
	}
	return strings.Join(parts, "/"), nil
}

// appMCPFirstBootMarker names the file that keeps a database on the fresh-boot
// path until one load completes (the first boot's own schema creation would
// otherwise make a retried first boot look like an existing database).
func appMCPFirstBootMarker(dir string) string {
	return filepath.Join(dir, ".benmore", "mcp_first_boot")
}

// appMCPDatabaseIsFresh reports a database with no application tables and no
// applied migrations: nothing is serving routes from it, so its pending
// migrations may run before the manifest is checked against the result.
// An unreadable catalog is treated as not fresh (the strict path).
func appMCPDatabaseIsFresh(db *sql.DB) bool {
	var tables int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE '\\_benmore\\_%' ESCAPE '\\' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'").Scan(&tables); err != nil || tables > 0 {
		return false
	}
	var ledger int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_benmore_migrations'").Scan(&ledger); err != nil {
		return false
	}
	if ledger == 0 {
		return true
	}
	var applied int
	return db.QueryRow("SELECT count(*) FROM _benmore_migrations").Scan(&applied) == nil && applied == 0
}

// Include pending CREATE TABLE inventory in canonical application order.
// ponytail: reject other route-changing migration DDL until its physical projection is supported.
func appMCPPendingMigrationTables(dir string, db *sql.DB, current []crudTableDefinition) ([]crudTableDefinition, error) {
	return appMCPPendingMigrationTablesFromSources(dir, db, current, nil)
}
func appMCPPendingMigrationTablesFromSources(dir string, db *sql.DB, current []crudTableDefinition, captured map[string][]byte) ([]crudTableDefinition, error) {
	names, err := migrationSourceNames(dir, captured)
	if err != nil {
		return nil, fmt.Errorf("mcp.yaml: cannot inspect pending migrations")
	}
	if names == nil {
		return current, nil
	}

	var ledger int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND lower(name)='_benmore_migrations'").Scan(&ledger); err != nil {
		return nil, fmt.Errorf("mcp.yaml: cannot inspect migration ledger")
	}
	seen := map[string]bool{}
	for _, definition := range current {
		seen[sqliteIdentifierFold(definition.name)] = true
	}
	for _, name := range names {
		if ledger > 0 {
			var applied int
			if err := db.QueryRow("SELECT count(*) FROM _benmore_migrations WHERE name=?", name).Scan(&applied); err != nil {
				return nil, fmt.Errorf("mcp.yaml: cannot inspect migration status")
			}
			if applied > 0 {
				continue
			}
		}
		data, err := readMigrationSource(dir, name, captured)
		if err != nil {
			return nil, fmt.Errorf("mcp.yaml: cannot read pending migration")
		}
		up, _ := extractMigrationSection(string(data))
		err = splitSQLStatements(strings.NewReader(up), func(statement string) error {
			tokens := sqlTokenize(statement)
			if len(tokens) == 0 {
				return nil
			}
			switch strings.ToUpper(tokens[0].text) {
			case "ALTER", "DROP", "PRAGMA", "ATTACH", "DETACH", "VACUUM":
				return fmt.Errorf("mcp.yaml: pending route-changing migration DDL is unsupported")
			case "CREATE":
				if len(tokens) < 2 || strings.EqualFold(tokens[1].text, "TEMP") || strings.EqualFold(tokens[1].text, "TEMPORARY") {
					return fmt.Errorf("mcp.yaml: temporary or unresolved migration DDL is unsupported")
				}
			}
			for _, token := range tokens {
				if token.kind != sqlTokLiteral && (strings.EqualFold(token.text, "sqlite_master") || strings.EqualFold(token.text, "sqlite_schema")) {
					return fmt.Errorf("mcp.yaml: direct schema mutation is unsupported")
				}
			}
			definitions, err := appMCPSQLTableDefinitions(statement)
			if err != nil {
				return err
			}
			for _, definition := range definitions {
				key := sqliteIdentifierFold(definition.name)
				if !seen[key] {
					current = append(current, definition)
					seen[key] = true
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return current, nil
}

func appMCPReservedRoute(path string) (bool, error) {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		decoded, err := url.PathUnescape(part)
		if err != nil {
			return false, err
		}
		parts[i] = decoded
	}
	return len(parts) >= 3 && parts[0] == "" && parts[1] == "api" && parts[2] == "_mcp", nil
}
