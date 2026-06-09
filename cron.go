//go:build !cli

package main

// User-facing cron. Apps declare scheduled jobs in cron.yaml; the
// framework runs them in-process on the same scheduler that powers
// backups and prerender refresh. No external scheduler service
// required.
//
// Two YAML shapes are accepted - pick whichever feels natural:
//
//   1. Array shape (explicit jobs: list):
//
//      jobs:
//        - id: daily_digest
//          schedule: "0 9 * * 1"
//          run:
//            - sql: "SELECT id FROM contacts WHERE digest_enabled = 1"
//              name: targets
//            - for_each: targets
//              as: t
//              steps:
//                - email: { to: "{{t.email}}", template: "digest" }
//
//   2. Map shape (job-name → config, like flows.yaml top-level):
//
//      daily_digest:
//        schedule: "0 9 * * 1"
//        run:
//          - sql: "..."
//      sync_carriers:
//        schedule: "every 15m"
//        flow: sync_all         # reference a flow by name from flows.yaml
//
// The `flow: <name>` form looks up a named flow at execution time and
// runs its steps. Eliminates step duplication between cron.yaml and
// flows.yaml. The flow's HTTP/async wrapping is bypassed - only the
// step bodies execute, same as if the cron entry inlined them.
//
// Schedule supports cron's standard 5-field syntax plus the common
// "@hourly", "@daily", "@weekly", "@monthly" shortcuts and "every <N>m"
// duration form. Step shape mirrors flows.yaml - same step types
// (sql/api/email/webhook/ws/respond/for_each/if/set) work here.
//
// Jobs run with no session, so SQL has no {{user_id}}. Use the row
// context from a previous step instead.

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// CronJob is one scheduled job. Mirrors flow shape so step execution
// reuses execStep / interpolateCtx. Either Steps OR Flow is set; when
// Flow is non-empty, the runner resolves it against app.Flows at
// execution time and runs that flow's steps.
type CronJob struct {
	ID       string
	Schedule string
	Steps    []FlowStep
	Flow     string // optional: name of a flow from flows.yaml to run instead of Steps
}

// CronConfig holds an app's parsed cron.yaml. Stored on App so the
// scheduler can iterate without re-parsing on every tick.
type CronConfig struct {
	Jobs []CronJob
}

// cronJobYAML mirrors the YAML shape; converted to CronJob via
// convertSteps (already used by flows).
//
// Both `run:` and `steps:` are accepted as the step list to match the
// GitHub Actions vocabulary the agent already knows from flows.yaml.
// Originally cron.yaml only supported `run:`; that inconsistency with
// flows.yaml (`steps:`) routinely tripped agents writing both files.
// When BOTH keys are present the file is rejected at write time by
// the cross-file validator.
type cronJobYAML struct {
	ID       string         `yaml:"id"`
	Schedule string         `yaml:"schedule"`
	Run      []FlowStepYAML `yaml:"run"`
	Steps    []FlowStepYAML `yaml:"steps"`
	Flow     string         `yaml:"flow"` // optional: reference a named flow from flows.yaml
}

type cronConfigYAML struct {
	Jobs []cronJobYAML `yaml:"jobs"`
}

// cronMapEntry is the map-shape entry: cron.yaml as a top-level map of
// job_name → config. Matches what the agent's intuition produces.
//
// Three ways to express what the job DOES (pick one):
//   - flow:  name of a flow from flows.yaml (resolved at fire time)
//   - sql:   one-liner SQL string - sugar for run: [{sql: "..."}]
//   - run:   inline step list (or `steps:` as an alias)
type cronMapEntry struct {
	Schedule string         `yaml:"schedule"`
	Run      []FlowStepYAML `yaml:"run"`
	Steps    []FlowStepYAML `yaml:"steps"`
	Flow     string         `yaml:"flow"`
	SQL      string         `yaml:"sql"` // one-liner shortcut
}

// LoadCron parses cron.yaml. Accepts both the array shape (`jobs: [...]`)
// and the map shape (`<job_name>: { schedule, flow|run|steps }`); returns
// nil when the file is missing OR present-but-parses-to-zero-jobs (with
// a loud WARN on the latter so silent format mismatches are noticed).
func LoadCron(dir string) *CronConfig {
	path := filepath.Join(dir, "cron.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	// Try the explicit `jobs: [...]` array shape first.
	var arr cronConfigYAML
	jobs := []cronJobYAML(nil)
	if err := yaml.Unmarshal(data, &arr); err == nil && len(arr.Jobs) > 0 {
		jobs = arr.Jobs
	} else {
		// Fall back to the map shape: top-level keys are job names.
		// Ignore the `jobs` key if it accidentally co-exists (a doc with
		// only `jobs:` reaches us here via len(arr.Jobs)==0).
		var m map[string]cronMapEntry
		if err := yaml.Unmarshal(data, &m); err == nil {
			for name, entry := range m {
				if name == "jobs" {
					continue
				}
				if entry.Schedule == "" {
					continue
				}
				steps := entry.Run
				if len(steps) == 0 {
					steps = entry.Steps
				}
				// `sql: "..."` is sugar for run: [{ sql: "..." }] - common
				// one-liner shape for cleanup jobs.
				if len(steps) == 0 && entry.SQL != "" {
					steps = []FlowStepYAML{{SQL: entry.SQL}}
				}
				jobs = append(jobs, cronJobYAML{
					ID:       name,
					Schedule: entry.Schedule,
					Run:      steps,
					Flow:     entry.Flow,
				})
			}
		}
	}

	if len(jobs) == 0 {
		log.Printf("WARN: cron.yaml at %s parsed but yielded 0 jobs.", path)
		log.Printf("      Expected one of:")
		log.Printf("        jobs: [ { id: NAME, schedule: '...', flow: FLOW_NAME } ]")
		log.Printf("        NAME: { schedule: '...', flow: FLOW_NAME }   (map shape)")
		log.Printf("      Each job needs a schedule and either flow:<name> or run:[steps].")
		return nil
	}

	out := &CronConfig{}
	for _, j := range jobs {
		if j.ID == "" || j.Schedule == "" {
			continue
		}
		stepsYAML := j.Run
		if len(stepsYAML) == 0 {
			stepsYAML = j.Steps
		}
		out.Jobs = append(out.Jobs, CronJob{
			ID:       j.ID,
			Schedule: j.Schedule,
			Steps:    convertSteps(stepsYAML),
			Flow:     j.Flow,
		})
	}
	if len(out.Jobs) == 0 {
		log.Printf("WARN: cron.yaml at %s had entries but all were missing id/schedule.", path)
		return nil
	}
	return out
}

// StartCronScheduler launches a single ticker that checks every job
// every minute. Last-fire times are persisted to _benmore_cron_state
// so process restarts don't re-fire jobs that already ran in the
// current schedule window. Before persistence, restart loops would
// re-fire every job whose schedule matched the current minute, on
// EVERY restart - during a write-burst that meant the same `every 15m`
// sync ran every 5 seconds, hammering upstream APIs.
//
// SIGHUP-safe (v2.7.40 fix): called from both first-boot AND every
// hot reload (server.go reloadAppConfig). On reload, it closes the
// previous instance's CronStop channel before spawning a fresh
// goroutine. Pre-fix, the prior goroutine listened only on app.Stop
// (process exit) and kept ticking with its own stale lastFire
// snapshot - so a flurry of edits left N tickers all racing to
// re-fire `every 15m` jobs every minute. The visible symptom was
// "cron jobs reset / re-fire on every edit."
func StartCronScheduler(app *App) {
	// Cancel any prior scheduler goroutine BEFORE checking the new
	// config - even if the new cron.yaml is empty (the agent removed
	// all jobs), we still want to retire the old goroutine.
	if app != nil && app.CronStop != nil {
		select {
		case <-app.CronStop:
			// already closed (idempotent - repeated calls from buggy
			// callers don't double-close)
		default:
			close(app.CronStop)
		}
		app.CronStop = nil
	}
	if app == nil {
		return
	}
	// Merge flow-level `trigger.cron` declarations into app.Cron.Jobs
	// so they get the same persistent lastFire treatment as cron.yaml
	// entries. v2.7.41 fix: pre-fix, trigger.cron flows ran via a
	// legacy `for { time.Sleep(interval); ... }` goroutine spawned
	// from RegisterFlows on every hot reload - each SIGHUP started a
	// FRESH 15m sleep from now, so the agent-visible symptom was
	// "every time I edit a file, the cron timer resets" (the
	// most-recent goroutine was the one the agent was watching, and
	// it always started counting from the edit). Routing through
	// app.Cron means the persistent _benmore_cron_state table is the
	// source of truth - SIGHUP can't reset the schedule window.
	mergeFlowCronsIntoConfig(app)
	if app.Cron == nil || len(app.Cron.Jobs) == 0 {
		return
	}
	// Ensure the persistence table exists. Best-effort - if it fails
	// (read-only DB, weird perms) we fall back to in-memory and just
	// lose the restart-survival guarantee. Cron still fires.
	if err := ensureCronStateTable(app); err != nil {
		log.Printf("cron: state table init failed (%s) - falling back to in-memory last-fire", err)
	}
	state := newCronState(app)
	stop := make(chan struct{})
	app.CronStop = stop
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		// First tick: run any job that was scheduled in the last minute
		// so a deploy doesn't miss a job that should have just fired.
		// Persisted last-fire prevents this from re-firing jobs that
		// already ran in their current schedule window - covered by
		// cronShouldFire's lastFire arg below.
		state.tick(app, time.Now())
		for {
			select {
			case now := <-t.C:
				state.tick(app, now)
			case <-stop:
				// Hot reload retired this scheduler instance - a fresh
				// one is already running with the latest cron.yaml.
				return
			case <-app.Stop:
				// Process shutdown.
				return
			}
		}
	}()
	log.Printf("  cron: %d job(s) scheduled", len(app.Cron.Jobs))
}

type cronState struct {
	mu       sync.Mutex
	lastFire map[string]time.Time
	jobs     []CronJob
	app      *App
}

func newCronState(app *App) *cronState {
	s := &cronState{
		lastFire: map[string]time.Time{},
		jobs:     app.Cron.Jobs,
		app:      app,
	}
	// Hydrate from persisted table on startup so restart-loops can't
	// re-fire `every 15m` jobs every 5 seconds.
	rows, err := app.DB.Query(`SELECT job_id, last_fire FROM _benmore_cron_state`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, ts string
			if rows.Scan(&id, &ts) == nil {
				if t, perr := time.Parse(time.RFC3339, ts); perr == nil {
					s.lastFire[id] = t
				}
			}
		}
	}
	return s
}

// mergeFlowCronsIntoConfig promotes flows declared with
// `trigger.cron: …` into entries on app.Cron.Jobs so the persistent
// scheduler in StartCronScheduler picks them up alongside cron.yaml
// jobs. The synthesized job's ID is the flow name; its Schedule is
// the trigger.cron expression; its Flow field points back at the
// flow so runCronJob resolves steps at fire time (same path
// cron.yaml entries with `flow:` use). Idempotent - if a CronJob
// with the same ID already exists (the agent put the cron in BOTH
// flows.yaml AND cron.yaml, or this is the second call from a hot
// reload), the existing entry wins.
func mergeFlowCronsIntoConfig(app *App) {
	if app == nil || len(app.Flows) == 0 {
		return
	}
	if app.Cron == nil {
		app.Cron = &CronConfig{}
	}
	have := map[string]bool{}
	for _, j := range app.Cron.Jobs {
		have[j.ID] = true
	}
	for i := range app.Flows {
		f := &app.Flows[i]
		if f.Trigger.Type != "cron" || strings.TrimSpace(f.Trigger.Cron) == "" {
			continue
		}
		if have[f.Name] {
			continue
		}
		app.Cron.Jobs = append(app.Cron.Jobs, CronJob{
			ID:       f.Name,
			Schedule: strings.TrimSpace(f.Trigger.Cron),
			Flow:     f.Name,
		})
	}
}

// ensureCronStateTable creates _benmore_cron_state if missing.
// One row per cron job_id. The whole table is at most O(jobs) rows -
// small and fast to scan on every startup.
func ensureCronStateTable(app *App) error {
	_, err := app.DB.Exec(`
		CREATE TABLE IF NOT EXISTS _benmore_cron_state (
			job_id     TEXT PRIMARY KEY,
			last_fire  TEXT NOT NULL,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`)
	return err
}

// persistCronFire upserts the last_fire time for a job. Best-effort:
// failure here just means a future restart might re-fire the job, not
// a runtime crash. Logged but not returned.
func persistCronFire(app *App, jobID string, t time.Time) {
	if app == nil || app.DB == nil {
		return
	}
	_, err := app.DB.Exec(`
		INSERT INTO _benmore_cron_state (job_id, last_fire, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(job_id) DO UPDATE SET last_fire = excluded.last_fire, updated_at = CURRENT_TIMESTAMP
	`, jobID, t.UTC().Format(time.RFC3339))
	if err != nil {
		log.Printf("cron: persist last_fire for %s failed: %s", jobID, err)
	}
}

func (s *cronState) tick(app *App, now time.Time) {
	s.mu.Lock()
	jobs := s.jobs
	s.mu.Unlock()
	for _, j := range jobs {
		s.mu.Lock()
		last := s.lastFire[j.ID]
		s.mu.Unlock()
		if !cronShouldFire(j.Schedule, now, last) {
			continue
		}
		stamp := now.Truncate(time.Minute)
		s.mu.Lock()
		s.lastFire[j.ID] = stamp
		s.mu.Unlock()
		// Persist BEFORE the goroutine launches so a crash mid-run still
		// records "we fired at this minute" - at-most-once semantics
		// matter more than at-least-once for `every 15m` carrier syncs.
		persistCronFire(app, j.ID, stamp)
		go runCronJob(app, j)
	}
}

func runCronJob(app *App, j CronJob) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("CRON [%s] panic: %v", j.ID, r)
		}
	}()

	// Resolve the step list. If the job was authored as `flow: <name>`,
	// look up that flow at execution time so authors can edit the flow
	// without restarting the scheduler. We bypass the flow's async/HTTP
	// wrapping - the cron tick runs the step bodies directly, same as
	// if the cron entry had inlined them.
	steps := j.Steps
	if j.Flow != "" {
		var found *Flow
		for i := range app.Flows {
			if app.Flows[i].Name == j.Flow {
				found = &app.Flows[i]
				break
			}
		}
		if found == nil {
			log.Printf("CRON [%s] flow %q not found in flows.yaml - skipping fire", j.ID, j.Flow)
			return
		}
		if len(found.Steps) == 0 {
			log.Printf("CRON [%s] flow %q has zero steps - skipping fire", j.ID, j.Flow)
			return
		}
		steps = found.Steps
	}

	log.Printf("CRON [%s] firing (steps=%d, flow=%q)", j.ID, len(steps), j.Flow)
	// Initialize both maps - flow steps freely assign to ctx.Params (path
	// param binding) AND ctx.Data (step outputs), and a nil Params from
	// an HTTP-less cron path panics on first assignment.
	ctx := &FlowContext{
		App:    app,
		Data:   map[string]any{"job_id": j.ID, "fired_at": time.Now().UTC().Format(time.RFC3339)},
		Params: map[string]string{},
	}
	for i := range steps {
		if err := executeStep(ctx, &steps[i]); err != nil {
			log.Printf("CRON [%s] step %d failed: %s", j.ID, i, err)
			return
		}
	}
}

// cronShouldFire evaluates the schedule expression against `now`.
// Supports:
//   - "@hourly", "@daily", "@weekly", "@monthly", "@yearly"
//   - "every Nm" / "every Nh" / "every Nd" - fixed interval since
//     framework start; uses lastFire to decide
//   - Standard 5-field cron: "min hour day month weekday" with
//     "*", "*/N", lists, and ranges
func cronShouldFire(expr string, now, lastFire time.Time) bool {
	expr = strings.TrimSpace(expr)
	// Don't fire twice in the same minute.
	if !lastFire.IsZero() && now.Sub(lastFire) < 55*time.Second {
		return false
	}

	// Named shortcuts
	switch expr {
	case "@hourly":
		return now.Minute() == 0
	case "@daily", "@midnight":
		return now.Hour() == 0 && now.Minute() == 0
	case "@weekly":
		return now.Weekday() == time.Sunday && now.Hour() == 0 && now.Minute() == 0
	case "@monthly":
		return now.Day() == 1 && now.Hour() == 0 && now.Minute() == 0
	case "@yearly", "@annually":
		return now.Month() == time.January && now.Day() == 1 && now.Hour() == 0 && now.Minute() == 0
	}

	// "every Nm" / "every 2h" / etc.
	if strings.HasPrefix(expr, "every ") {
		dur, err := time.ParseDuration(strings.TrimPrefix(expr, "every "))
		if err == nil && dur > 0 {
			if lastFire.IsZero() {
				return true
			}
			return now.Sub(lastFire) >= dur
		}
	}

	// 5-field cron: min hour day month weekday
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return false
	}
	if !cronMatch(fields[0], now.Minute(), 0, 59) {
		return false
	}
	if !cronMatch(fields[1], now.Hour(), 0, 23) {
		return false
	}
	if !cronMatch(fields[2], now.Day(), 1, 31) {
		return false
	}
	if !cronMatch(fields[3], int(now.Month()), 1, 12) {
		return false
	}
	if !cronMatch(fields[4], int(now.Weekday()), 0, 6) {
		return false
	}
	return true
}

// cronMatch handles a single field - "*", "*/N", "N", "N,M", "N-M".
// Good enough for ~all practical schedules; not a full cron spec.
func cronMatch(field string, val, min, max int) bool {
	if field == "*" {
		return true
	}
	// */N
	if strings.HasPrefix(field, "*/") {
		n, err := strconv.Atoi(field[2:])
		if err != nil || n == 0 {
			return false
		}
		return (val-min)%n == 0
	}
	// Comma list
	for _, part := range strings.Split(field, ",") {
		// Range a-b
		if strings.Contains(part, "-") {
			ab := strings.SplitN(part, "-", 2)
			a, e1 := strconv.Atoi(ab[0])
			b, e2 := strconv.Atoi(ab[1])
			if e1 == nil && e2 == nil && val >= a && val <= b {
				return true
			}
			continue
		}
		// Literal
		n, err := strconv.Atoi(part)
		if err == nil && n == val {
			return true
		}
	}
	_ = fmt.Sprint // silence unused import in some builds
	return false
}
