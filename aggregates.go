//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// AggregateConfig represents a single materialized aggregate definition.
type AggregateConfig struct {
	Name    string
	SQL     string        // developer-authored SQL (trusted, like hooks.yaml)
	Refresh time.Duration // how often to recompute
}

// EnsureAggregatesTable creates the _benmore_aggregates table if it doesn't exist.
func EnsureAggregatesTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_aggregates (
		name TEXT PRIMARY KEY,
		value TEXT NOT NULL DEFAULT '',
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
}

// LoadAggregateConfig reads the aggregates: section from app.yaml.
func LoadAggregateConfig(dir string) []AggregateConfig {
	path := dir + "/app.yaml"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil
	}
	aggRaw, ok := raw["aggregates"].(map[string]any)
	if !ok {
		return nil
	}

	var configs []AggregateConfig
	for name, v := range aggRaw {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		sqlStr, _ := m["sql"].(string)
		refreshStr, _ := m["refresh"].(string)
		if sqlStr == "" || refreshStr == "" {
			log.Printf("  aggregates: skipping %q (missing sql or refresh)", name)
			continue
		}

		refresh, err := time.ParseDuration(refreshStr)
		if err != nil {
			log.Printf("  aggregates: skipping %q (bad refresh duration %q)", name, refreshStr)
			continue
		}

		// Validate refresh is between 1 minute and 24 hours
		if refresh < 1*time.Minute {
			log.Printf("  aggregates: %q refresh clamped to 1m (was %s)", name, refreshStr)
			refresh = 1 * time.Minute
		}
		if refresh > 24*time.Hour {
			log.Printf("  aggregates: %q refresh clamped to 24h (was %s)", name, refreshStr)
			refresh = 24 * time.Hour
		}

		configs = append(configs, AggregateConfig{
			Name:    name,
			SQL:     sqlStr,
			Refresh: refresh,
		})
	}
	return configs
}

// refreshAggregate executes the aggregate SQL and stores the result.
func refreshAggregate(db *sql.DB, config AggregateConfig) error {
	var value string
	err := db.QueryRow(config.SQL).Scan(&value)
	if err != nil {
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
		if err := refreshAggregate(app.DB, config); err != nil {
			log.Printf("  aggregate refresh error: %s", err)
		}
	}

	// Start per-aggregate ticker goroutines
	for _, config := range configs {
		c := config
		safeGo("aggregates.refresh:"+c.Name, func() {
			stop := app.Stop // capture once: hot reload reassigns app.Stop; reading the field in the loop would race the swap and could miss the close (goroutine leak)
			ticker := time.NewTicker(c.Refresh)
			defer ticker.Stop()
			for {
				select {
				case <-stop:
					return // hot reload / shutdown - don't leak a refresher per push
				case <-ticker.C:
					if err := refreshAggregate(app.DB, c); err != nil {
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
		var name, value string
		if err := rows.Scan(&name, &value); err == nil {
			// The _benmore_aggregates.value column is TEXT (the stored
			// form), but aggregates are overwhelmingly numeric (SUM,
			// COUNT, AVG, …). Serve a clean numeric value AS A NUMBER so
			// `bm.aggregate('x')` and `{{agg.x}}` give the caller a
			// number, not the string "9.12" that blew up `.toFixed()`.
			// Non-numeric aggregates (e.g. MAX(name)) stay strings.
			values[name] = coerceNumericBind(value)
		}
	}
	return values
}

// RegisterAggregateRoutes sets up the GET /api/_aggregates endpoint.
func RegisterAggregateRoutes(mux *http.ServeMux, app *App) {
	mux.HandleFunc("GET /api/_aggregates", func(w http.ResponseWriter, r *http.Request) {
		// Auth required
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}

		// Admin-only for listing all aggregates via API
		if !session.IsAdmin() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return
		}

		rows, err := QueryRows(app.DB, "SELECT name, value, updated_at FROM _benmore_aggregates ORDER BY name")
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
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

		httpJSON(w, http.StatusOK, map[string]any{"aggregates": rows})
	})

	// POST /api/_aggregates/refresh - force refresh all aggregates (admin only)
	mux.HandleFunc("POST /api/_aggregates/refresh", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		if !session.IsAdmin() {
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

		configs := LoadAggregateConfig(app.Dir)
		var refreshed []string
		for _, c := range configs {
			if err := refreshAggregate(app.DB, c); err != nil {
				log.Printf("  aggregate refresh error: %s", err)
			} else {
				refreshed = append(refreshed, c.Name)
			}
		}

		httpJSON(w, http.StatusOK, map[string]any{"refreshed": refreshed})
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

	values := LoadAggregateValues(ctx.App.DB)
	if len(values) > 0 {
		ctx.Data["aggregate"] = values
	}
}
