//go:build !cli

package main

// Which materialized aggregates are served, and whether each is current.
//
// app.yaml `aggregates:` is the only source of aggregates. One removed from it
// kept its _benmore_aggregates row and was served by GET /api/_aggregates and
// {{aggregate.<name>}} forever. Now the served mux publishes the configured
// names at every load and reload (publishAggregateConfig), the removed rows
// are deleted, and only configured names are served, even if a refresher of
// the previous configuration that was mid-run or another process on the same
// database writes a row afterwards.
//
// An aggregate whose SQL fails kept serving its last value as current. It
// still keeps that value (a passing error such as a locked database must not
// blank a dashboard, and the value is what the SQL last gave), but GET
// /api/_aggregates marks it: `stale: true`, `stale_since` (the first failure
// since its last successful refresh) and `error`; `updated_at` stays the time
// of its last successful refresh. A configured aggregate that has failed
// without ever storing a value is listed with value null. Every listed
// aggregate carries `stale`. Templates keep rendering the last value.

import (
	"database/sql"
	"log"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"
)

type aggregateServing struct {
	mu sync.Mutex
	// configured is app.yaml's aggregate names as the served mux last
	// published them; nil until one has, and then every stored row is served.
	configured map[string]bool
	// failures holds each aggregate whose last refresh failed.
	failures map[string]aggregateFailure
}

type aggregateFailure struct {
	since time.Time // first failure since the last successful refresh
	err   string
}

// publishAggregateConfig makes configs the app's served aggregates and deletes
// the stored rows of any other. Called when a served mux is built (startup and
// every reload), before the aggregate workers start.
func publishAggregateConfig(app *App, configs []AggregateConfig) {
	names := make(map[string]bool, len(configs))
	for _, c := range configs {
		names[c.Name] = true
	}
	s := &app.aggregates
	s.mu.Lock()
	s.configured = names
	s.failures = nil // the new workers' first refresh records them again
	s.mu.Unlock()
	pruneAggregateRows(app.DB, names)
}

// pruneAggregateRows deletes the stored values of aggregates app.yaml no
// longer configures.
func pruneAggregateRows(db *sql.DB, configured map[string]bool) {
	if db == nil {
		return
	}
	var tables int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='_benmore_aggregates'`).Scan(&tables); err != nil || tables == 0 {
		return
	}
	where := ``
	var args []any
	if len(configured) > 0 {
		where = ` WHERE name NOT IN (?` + strings.Repeat(`,?`, len(configured)-1) + `)`
		for _, name := range slices.Sorted(maps.Keys(configured)) {
			args = append(args, name)
		}
	}
	// Look first: a load or reload with nothing to delete takes no write lock.
	var removed int
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM _benmore_aggregates`+where+`)`, args...).Scan(&removed); err != nil || removed == 0 {
		return
	}
	result, err := db.Exec(`DELETE FROM _benmore_aggregates`+where, args...)
	if err != nil {
		log.Printf("  aggregates: delete the values of aggregates removed from app.yaml: %s", err)
		return
	}
	if n, _ := result.RowsAffected(); n > 0 {
		log.Printf("  aggregates: deleted the stored values of %d aggregate(s) no longer in app.yaml", n)
	}
}

// refreshAggregateTracked is refreshAggregate for the served app: it records
// a failure (keeping the time of the first one) and clears it on success.
func refreshAggregateTracked(app *App, config AggregateConfig) error {
	err := refreshAggregate(app.DB, config)
	s := &app.aggregates
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		delete(s.failures, config.Name)
		return nil
	}
	failure, failing := s.failures[config.Name]
	if !failing {
		failure.since = time.Now().UTC()
	}
	failure.err = jobErrorText(app, err.Error())
	if s.failures == nil {
		s.failures = map[string]aggregateFailure{}
	}
	s.failures[config.Name] = failure
	return err
}

// servedAggregateConfigured reports whether name is served: configured in
// app.yaml as last published (everything before a served mux publishes).
func servedAggregateConfigured(configured map[string]bool, name string) bool {
	return configured == nil || configured[name]
}

// servedAggregateRows is the GET /api/_aggregates list from the stored rows:
// configured aggregates only, each with stale (and stale_since and error when
// its last refresh failed), plus failing aggregates that have no stored value.
func servedAggregateRows(app *App, rows []map[string]any) []map[string]any {
	s := &app.aggregates
	s.mu.Lock()
	configured, failures := s.configured, maps.Clone(s.failures)
	s.mu.Unlock()
	out := make([]map[string]any, 0, len(rows)+len(failures))
	listed := map[string]bool{}
	for _, row := range rows {
		name := aggregateRowName(row["name"])
		if !servedAggregateConfigured(configured, name) {
			continue
		}
		listed[name] = true
		out = append(out, annotateAggregateFreshness(row, failures, name))
	}
	for _, name := range slices.Sorted(maps.Keys(failures)) {
		if listed[name] || !servedAggregateConfigured(configured, name) {
			continue
		}
		out = append(out, annotateAggregateFreshness(map[string]any{"name": name, "value": nil, "updated_at": nil}, failures, name))
	}
	slices.SortFunc(out, func(a, b map[string]any) int {
		return strings.Compare(aggregateRowName(a["name"]), aggregateRowName(b["name"]))
	})
	return out
}

func annotateAggregateFreshness(row map[string]any, failures map[string]aggregateFailure, name string) map[string]any {
	failure, failing := failures[name]
	row["stale"] = failing
	if failing {
		row["stale_since"] = failure.since.Format(time.RFC3339)
		row["error"] = failure.err
	}
	return row
}

func aggregateRowName(v any) string {
	switch name := v.(type) {
	case string:
		return name
	case []byte:
		return string(name)
	}
	return ""
}

// servedAggregateValues drops the template values of aggregates app.yaml does
// not configure.
func servedAggregateValues(app *App, values map[string]any) map[string]any {
	s := &app.aggregates
	s.mu.Lock()
	configured := s.configured
	s.mu.Unlock()
	for name := range values {
		if !servedAggregateConfigured(configured, name) {
			delete(values, name)
		}
	}
	return values
}
