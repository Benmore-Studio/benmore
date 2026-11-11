//go:build !cli

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"time"
)

// AggregateConfig represents a single materialized aggregate definition.
type AggregateConfig struct {
	Name    string
	SQL     string        // developer-authored SQL (trusted, like hooks.yaml)
	Refresh time.Duration // how often to recompute
}

// aggregatesTableSQL is the cache of each aggregate's current value. value is
// NULL when the aggregate's SQL gives NULL or no row.
const aggregatesTableSQL = `CREATE TABLE IF NOT EXISTS %s (
		name TEXT PRIMARY KEY,
		value TEXT,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

// EnsureAggregatesTable creates the _benmore_aggregates table if it doesn't
// exist. A table from before NULL values (value TEXT NOT NULL) is rebuilt with
// a nullable value, keeping what it holds; otherwise every NULL refresh would
// fail and leave the previous value standing as current.
func EnsureAggregatesTable(db *sql.DB) {
	if _, err := db.Exec(fmt.Sprintf(aggregatesTableSQL, "_benmore_aggregates")); err != nil {
		log.Printf("  aggregates: create table: %s", err)
		return
	}
	if err := upgradeAggregatesTable(db); err != nil {
		log.Printf("  aggregates: allow NULL values: %s", err)
	}
}

func aggregatesValueNotNull(q interface {
	QueryRow(string, ...any) *sql.Row
}) (bool, error) {
	var notNull int
	err := q.QueryRow(`SELECT "notnull" FROM pragma_table_info('_benmore_aggregates') WHERE name = 'value'`).Scan(&notNull)
	return notNull != 0, err
}

func upgradeAggregatesTable(db *sql.DB) error {
	if notNull, err := aggregatesValueNotNull(db); err != nil || !notNull {
		return err
	}
	tx, err := db.BeginTx(withLongWriteTx(context.Background(), "aggregates table upgrade"), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Re-read under the write lock: another process sharing the database
	// may have rebuilt it already.
	if notNull, err := aggregatesValueNotNull(tx); err != nil || !notNull {
		return err
	}
	for _, statement := range []string{
		fmt.Sprintf(aggregatesTableSQL, "_benmore_aggregates_nullable"),
		`INSERT INTO _benmore_aggregates_nullable (name, value, updated_at) SELECT name, value, updated_at FROM _benmore_aggregates`,
		`DROP TABLE _benmore_aggregates`,
		`ALTER TABLE _benmore_aggregates_nullable RENAME TO _benmore_aggregates`,
	} {
		if _, err := tx.Exec(statement); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LoadAggregateConfig reads the aggregates: section from app.yaml.
func LoadAggregateConfig(dir string) []AggregateConfig {
	path := dir + "/app.yaml"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseAggregateConfig(data)
}

func parseAggregateConfig(data []byte) []AggregateConfig {
	var raw map[string]any
	if err := yamlUnmarshal(data, &raw); err != nil {
		return nil
	}
	aggRaw, ok := raw["aggregates"].(map[string]any)
	if !ok {
		return nil
	}

	var configs []AggregateConfig
	for name, v := range aggRaw {
		entry := readAggregateEntry(name, v)
		if entry.problem != "" {
			// Not refreshed, so it has no value anywhere. The write gate
			// refuses the declaration (aggregatesSectionViolation); a
			// deployed app.yaml keeps loading without it.
			log.Printf("  aggregates: skipping %q (%s)", name, entry.problem)
			continue
		}
		if entry.clamped != "" {
			log.Printf("  aggregates: %q %s", name, entry.clamped)
		}
		configs = append(configs, entry.config)
	}
	return configs
}

// aggregateYAML is one entry of app.yaml's aggregates: map. Its tags are the
// keys an aggregate takes (aggregateKeys).
type aggregateYAML struct {
	SQL     string `yaml:"sql"`
	Refresh string `yaml:"refresh"`
}

var aggregateKeys = yamlStructKeys(aggregateYAML{})

// aggregateDeclaration is one aggregates: entry as the load reads it.
type aggregateDeclaration struct {
	config  AggregateConfig
	problem string   // why the load does not run it; "" when it does
	clamped string   // the refresh interval was moved into 1m..24h
	unknown []string // keys the entry carries that an aggregate does not take
}

// readAggregateEntry is the one reader of an aggregates: entry: the load
// (parseAggregateConfig) and the write gate (aggregatesSectionViolation) both
// use it, so the gate refuses exactly what the load would not run.
func readAggregateEntry(name string, v any) aggregateDeclaration {
	var entry aggregateDeclaration
	m, ok := v.(map[string]any)
	if !ok {
		entry.problem = "it must be a mapping with sql and refresh"
		return entry
	}
	for _, key := range slices.Sorted(maps.Keys(m)) {
		if !aggregateKeys[key] {
			entry.unknown = append(entry.unknown, key)
		}
	}
	sqlStr, _ := m["sql"].(string)
	refreshStr, _ := m["refresh"].(string)
	switch {
	case sqlStr == "":
		entry.problem = "missing sql: the SELECT that gives its value"
		return entry
	case refreshStr == "":
		entry.problem = "missing refresh: a duration in quotes such as \"5m\" or \"1h\""
		if _, present := m["refresh"]; present {
			entry.problem = fmt.Sprintf("refresh %v is not a duration: write it with a unit and in quotes, such as \"5m\" or \"1h\"", m["refresh"])
		}
		return entry
	}
	refresh, err := time.ParseDuration(refreshStr)
	if err != nil {
		entry.problem = fmt.Sprintf("bad refresh duration %q: use s, m or h, such as \"5m\" or \"24h\"", refreshStr)
		return entry
	}
	// Validate refresh is between 1 minute and 24 hours
	if refresh < 1*time.Minute {
		entry.clamped = fmt.Sprintf("refresh clamped to 1m (was %s)", refreshStr)
		refresh = 1 * time.Minute
	}
	if refresh > 24*time.Hour {
		entry.clamped = fmt.Sprintf("refresh clamped to 24h (was %s)", refreshStr)
		refresh = 24 * time.Hour
	}
	entry.config = AggregateConfig{Name: name, SQL: sqlStr, Refresh: refresh}
	return entry
}

// aggregateSQLProblem says why an aggregate's SQL may not run, or "". An
// aggregate is a cached read: one SELECT. The refresher and the write gate
// both ask it, and the refresher's connection is read-only besides.
func aggregateSQLProblem(query string) string {
	if _, ok := sqlRunnableText(query); !ok {
		return "an aggregate is one read-only SELECT (it holds no SQL statement)"
	}
	if problem := sqlSingleSelectProblem(query); problem != "" {
		return "an aggregate is one read-only SELECT (" + problem + ")"
	}
	return ""
}

// aggregatesSectionViolation is the write gate for app.yaml's aggregates:
// section: a declaration the load would drop, a key an aggregate does not
// take, and SQL that is not one read-only SELECT. "" when the section is
// clean or absent.
func aggregatesSectionViolation(content string) string {
	var raw map[string]any
	if err := yamlUnmarshal([]byte(content), &raw); err != nil {
		return ""
	}
	section, _ := raw["aggregates"].(map[string]any)
	var lines []string
	for _, name := range slices.Sorted(maps.Keys(section)) {
		entry := readAggregateEntry(name, section[name])
		for _, key := range entry.unknown {
			lines = append(lines, fmt.Sprintf("app.yaml: aggregate %q has the key %q, which an aggregate does not take; its keys are %s.", name, key, sortedKeyList(aggregateKeys)))
		}
		if entry.problem != "" {
			lines = append(lines, fmt.Sprintf("app.yaml: aggregate %q is never refreshed, so it has no value: %s.", name, entry.problem))
			continue
		}
		if problem := aggregateSQLProblem(entry.config.SQL); problem != "" {
			lines = append(lines, fmt.Sprintf("app.yaml: aggregate %q: %s. Its SQL runs on a read-only connection at every start and refresh; to change rows on a schedule use cron.yaml and a flow.", name, problem))
		}
	}
	return strings.Join(lines, "\n")
}

// aggregateQueryTimeout bounds one aggregate's SELECT. Refreshes run on
// background workers at intervals of a minute or more, so the bound is
// generous; it only stops a query that would hold its connection for good.
var aggregateQueryTimeout = 30 * time.Second

// refreshAggregate executes the aggregate SQL and stores the result. A NULL
// result (MAX over no rows) or no row at all is stored as NULL: the aggregate
// has no value now. Scanning it into a string failed every refresh, so the
// aggregate was missing from /api/_aggregates or, once it had a value, kept
// serving that old value as current.
//
// The SQL is the app author's and may only read. It ran on an ordinary
// connection, where `INSERT ... RETURNING` wrote a row at every refresh; it
// now runs the way a hook `when:` does (queryRowReadOnly: a held connection
// with query_only and the SELECT-only authorizer), after the text itself has
// been checked to be one SELECT.
func refreshAggregate(db *sql.DB, config AggregateConfig) error {
	var value sql.NullString
	query, ok := sqlRunnableText(config.SQL)
	if !ok {
		return fmt.Errorf("aggregate %q: %w", config.Name, errNoSQLStatement)
	}
	if problem := aggregateSQLProblem(query); problem != "" {
		return fmt.Errorf("aggregate %q: %s", config.Name, problem)
	}
	ctx, cancel := context.WithTimeout(context.Background(), aggregateQueryTimeout)
	defer cancel()
	err := queryRowReadOnly(ctx, db, query, nil, &value)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("aggregate %q: %w", config.Name, err)
	}

	_, err = db.Exec(
		`INSERT INTO _benmore_aggregates (name, value, updated_at) VALUES (?, ?, datetime('now'))
		 ON CONFLICT(name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		config.Name, value,
	)
	return err
}

// StartAggregateWorker runs background goroutines that refresh aggregates on schedule.
func StartAggregateWorker(app *App, configs []AggregateConfig) {
	if len(configs) == 0 {
		return
	}

	EnsureAggregatesTable(app.DB)

	// Do an initial refresh for all aggregates
	for _, config := range configs {
		if err := refreshAggregateTracked(app, config); err != nil {
			log.Printf("  aggregate refresh error: %s", err)
		}
	}

	// Start per-aggregate ticker goroutines
	for _, config := range configs {
		c := config
		app.startWorker("aggregates.refresh:"+c.Name, func(stop <-chan struct{}) {
			ticker := time.NewTicker(c.Refresh)
			defer ticker.Stop()
			for {
				select {
				case <-stop:
					return // hot reload / shutdown - don't leak a refresher per push
				case <-ticker.C:
					select {
					case <-stop:
						return
					default:
					}
					if err := refreshAggregateTracked(app, c); err != nil {
						log.Printf("  aggregate refresh error: %s", err)
					}
				}
			}
		})
	}

	log.Printf("  aggregates: %d materialized aggregates started", len(configs))
}

// LoadAggregateValues reads all cached aggregate values from the database.
func LoadAggregateValues(db *sql.DB) map[string]any {
	values := make(map[string]any)
	rows, err := db.Query("SELECT name, value FROM _benmore_aggregates")
	if err != nil {
		return values
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		var value sql.NullString
		if err := rows.Scan(&name, &value); err == nil {
			if !value.Valid {
				values[name] = nil // no value now (NULL result)
				continue
			}
			// The _benmore_aggregates.value column is TEXT (the stored
			// form), but aggregates are overwhelmingly numeric (SUM,
			// COUNT, AVG, …). Serve a clean numeric value AS A NUMBER so
			// `bm.aggregate('x')` and `{{aggregate.x}}` give the caller a
			// number, not the string "9.12" that blew up `.toFixed()`.
			// Non-numeric aggregates (e.g. MAX(name)) stay strings.
			values[name] = coerceNumericBind(value.String)
		}
	}
	return values
}

// RegisterAggregateRoutes sets up the GET /api/_aggregates endpoint.
func RegisterAggregateRoutes(mux appRouteRegistrar, app *App) {
	mux.HandleFunc("GET /api/_aggregates", func(w http.ResponseWriter, r *http.Request) {
		// Auth required
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}

		// Admin-only for listing all aggregates via API
		if !session.IsAdminConsole() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return
		}

		rows, err := queryMetadataRows(app.DB, "SELECT name, value, updated_at FROM _benmore_aggregates ORDER BY name")
		if err != nil {
			serverErrorJSON(w, r, app, "_aggregates", err, "query failed")
			return
		}
		// value is a TEXT column, so QueryRows returns it as a string;
		// coerce clean numeric values to numbers so the API serves
		// numbers for numeric aggregates (matches LoadAggregateValues).
		for _, row := range rows {
			if v, ok := row["value"]; ok {
				row["value"] = coerceNumericBind(v)
			}
		}

		// Configured aggregates only, each marked stale when its last
		// refresh failed (aggregates_served.go).
		httpJSON(w, http.StatusOK, map[string]any{"aggregates": servedAggregateRows(app, rows)})
	})

	// POST /api/_aggregates/refresh - force refresh all aggregates (admin only)
	mux.HandleFunc("POST /api/_aggregates/refresh", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		if !session.IsAdminConsole() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return
		}

		// Validate CSRF for mutation
		if !isBearerAuth(r) {
			if !validateCSRF(r) {
				httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
				return
			}
		}

		configs := app.aggregateConfig()
		var refreshed []string
		failed := []string{}
		for _, c := range configs {
			if err := refreshAggregateTracked(app, c); err != nil {
				log.Printf("  aggregate refresh error: %s", err)
				failed = append(failed, c.Name)
			} else {
				refreshed = append(refreshed, c.Name)
			}
		}
		sort.Strings(failed)

		httpJSON(w, http.StatusOK, map[string]any{"refreshed": refreshed, "failed": failed})
	})
}

// InjectAggregateData loads aggregate values into the render context for {{aggregate.*}} templates.
func InjectAggregateData(ctx *RenderContext) {
	if ctx.App == nil || ctx.App.DB == nil {
		return
	}

	// Check if aggregates table exists (avoid errors if feature not used)
	var count int
	err := ctx.App.DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_benmore_aggregates'").Scan(&count)
	if err != nil || count == 0 {
		return
	}

	values := servedAggregateValues(ctx.App, LoadAggregateValues(ctx.App.DB))
	if len(values) > 0 {
		ctx.Data["aggregate"] = values
	}
}
