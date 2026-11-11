//go:build !cli

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// CronMonitor is deliberately opt-in. The custom decoder is shared by load,
// write-time validation and benmore check, so unknown/ignored settings fail.
type CronMonitor struct {
	CheckinMargin int  `json:"checkin_margin"`
	MaxRuntime    int  `json:"max_runtime"`
	off           bool // monitor: false
}

// enabled is the monitor a job runs with: nil when absent or `monitor: false`.
func (m *CronMonitor) enabled() *CronMonitor {
	if m == nil || m.off {
		return nil
	}
	return m
}

func (m *CronMonitor) UnmarshalYAML(node *yaml.Node) error {
	*m = CronMonitor{CheckinMargin: 5, MaxRuntime: 30}
	if node.Kind == yaml.ScalarNode && node.Tag == "!!bool" {
		var enabled bool
		if node.Decode(&enabled) == nil {
			m.off = !enabled
			return nil
		}
	}
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("monitor must be true, false or a map of checkin_margin/max_runtime minutes (1..1440)")
	}
	seen := map[string]bool{}
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i].Value, node.Content[i+1]
		if seen[key] {
			return fmt.Errorf("monitor repeats %s", key)
		}
		seen[key] = true
		if key != "checkin_margin" && key != "max_runtime" {
			return fmt.Errorf("monitor has unknown setting %q", key)
		}
		var n int
		if value.Tag != "!!int" || value.Decode(&n) != nil || n < 1 || n > 1440 {
			return fmt.Errorf("monitor %s must be an integer number of minutes (1..1440)", key)
		}
		if key == "checkin_margin" {
			m.CheckinMargin = n
		} else {
			m.MaxRuntime = n
		}
	}
	return nil
}

var cronMonitorSlugRE = regexp.MustCompile(`[^a-z0-9]+`)

// yaml.v3 treats null as an omitted pointer and never calls UnmarshalYAML.
// Reject it explicitly so a misspelled/empty opt-in cannot silently do nothing.
func validateCronMonitorShape(shape map[string]any) error {
	check := func(raw any) error {
		entry, _ := raw.(map[string]any)
		if value, present := entry["monitor"]; present && value == nil {
			return fmt.Errorf("cron.yaml: monitor must be true or a map, not null")
		}
		return nil
	}
	if raw, ok := shape["jobs"]; ok {
		jobs, _ := raw.([]any)
		for _, job := range jobs {
			if err := check(job); err != nil {
				return err
			}
		}
	} else {
		for _, job := range shape {
			if err := check(job); err != nil {
				return err
			}
		}
	}
	return nil
}

func cronMonitorSlug(sub, id string) string {
	digest := sha256.Sum256([]byte(LogicalSubdomain(sub) + "\x00" + id))
	s := cronMonitorSlugRE.ReplaceAllString(strings.ToLower(LogicalSubdomain(sub)+"-"+id), "-")
	s = strings.Trim(s, "-")
	if len(s) > 33 {
		s = strings.TrimRight(s[:33], "-")
	}
	if s == "" {
		s = "cron"
	}
	return s + "-" + hex.EncodeToString(digest[:8])
}

func cronMonitorSchedule(schedule string) map[string]any {
	schedule = strings.TrimSpace(schedule)
	aliases := map[string]string{"@hourly": "0 * * * *", "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@weekly": "0 0 * * 0", "@monthly": "0 0 1 * *", "@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *"}
	if expr, ok := aliases[schedule]; ok {
		schedule = expr
	}
	if strings.HasPrefix(schedule, "every ") {
		d, _ := time.ParseDuration(strings.TrimPrefix(schedule, "every "))
		// The scheduler ticks once per minute. Round up exactly as its next
		// eligible tick does, including sub-minute duration schedules.
		minutes := int64(d / time.Minute)
		if d%time.Minute != 0 {
			minutes++
		}
		if minutes < 1 {
			minutes = 1
		}
		return map[string]any{"type": "interval", "value": minutes, "unit": "minute"}
	}
	fields := strings.Fields(schedule)
	// Benmore intersects the day fields; Sentry takes their union when
	// neither begins with a wildcard. Do not promise a different schedule.
	if len(fields) == 5 && !strings.HasPrefix(fields[2], "*") && !strings.HasPrefix(fields[4], "*") {
		return nil
	}
	return map[string]any{"type": "crontab", "value": schedule}
}

// cronShouldFire uses time.Local. Resolve that same IANA zone, rather than
// labelling a local-time schedule UTC. A copied, unnamed zone cannot safely be
// guessed from today's numeric offset (DST may change it).
func cronMonitorTimezone() string {
	if name := time.Local.String(); name != "Local" {
		if _, err := time.LoadLocation(name); err == nil {
			return name
		}
	}
	if path, err := filepath.EvalSymlinks("/etc/localtime"); err == nil {
		if _, name, ok := strings.Cut(filepath.ToSlash(path), "/zoneinfo/"); ok {
			if _, err := time.LoadLocation(name); err == nil {
				return name
			}
		}
	}
	if b, err := os.ReadFile("/etc/timezone"); err == nil {
		name := strings.TrimSpace(string(b))
		if name != "Local" {
			if _, err := time.LoadLocation(name); err == nil {
				return name
			}
		}
	}
	return ""
}

type cronCheckIn struct {
	ID       string
	Job      CronJob
	Status   string
	Duration float64
}

func beginCronMonitor(app *App, job CronJob) func(error) {
	noop := func(error) {}
	if job.Monitor == nil || GetEnv(app.Dir, "SENTRY_DSN") == "" {
		return noop
	}
	if cronMonitorSchedule(job.Schedule) == nil {
		log.Printf("cron monitor: restricted day-of-month and weekday cannot be represented; monitoring skipped")
		return noop
	}
	r := app.getErrorReporter()
	if r.state.forDSN(GetEnv(app.Dir, "SENTRY_DSN")).muted("monitor") {
		return noop
	}
	id := newSentryEventID()
	if id == "" {
		return noop
	}
	started := time.Now()
	if !enqueueCronCheckIn(r, cronCheckIn{ID: id, Job: job, Status: "in_progress"}) {
		return noop
	}
	return func(err error) {
		status := "ok"
		if err != nil {
			status = "error"
		}
		// A reload during the run stops the reporter captured above; the
		// closing check-in goes through the current one, or Sentry reports a
		// timeout for a run that finished.
		enqueueCronCheckIn(app.getErrorReporter(), cronCheckIn{ID: id, Job: job, Status: status, Duration: time.Since(started).Seconds()})
	}
}

func enqueueCronCheckIn(r *errorReporter, item cronCheckIn) bool {
	select {
	case <-r.done:
		return false
	default:
	}
	select {
	case r.queue <- errorEvent{checkIn: &item}:
		return true
	default:
		r.counters.dropped.Add(1)
		return false
	}
}

func (r *errorReporter) sendCheckIn(ctx context.Context, item *cronCheckIn) {
	dsn := GetEnv(r.app.Dir, "SENTRY_DSN")
	if dsn == "" {
		return
	}
	sub := LogicalSubdomain(GetEnv(r.app.Dir, "BENMORE_APP_NAME"))
	slug := cronMonitorSlug(errorExportIdentity(r.app, "app", sub), errorExportIdentity(r.app, "job", item.Job.ID))
	env, release := errorEnvironment(r.app)
	payload := map[string]any{"check_in_id": item.ID, "monitor_slug": slug, "status": item.Status,
		"environment": errorExportIdentity(r.app, "env", env), "release": errorExportIdentity(r.app, "release", release)}
	if item.Status != "in_progress" {
		payload["duration"] = item.Duration
	}
	schedule := cronMonitorSchedule(item.Job.Schedule)
	if schedule == nil || item.Job.Monitor == nil {
		r.counters.rejected.Add(1)
		return
	}
	zone := cronMonitorTimezone()
	if zone == "" && schedule["type"] == "crontab" {
		log.Printf("cron monitor: cannot identify the scheduler's IANA timezone; configure the host TZ before enabling monitoring")
		r.counters.rejected.Add(1)
		return
	}
	config := map[string]any{"schedule": schedule, "checkin_margin": item.Job.Monitor.CheckinMargin, "max_runtime": item.Job.Monitor.MaxRuntime}
	if zone != "" {
		config["timezone"] = zone
	}
	configJSON, _ := json.Marshal(config)
	configHash := sha256.Sum256(configJSON)
	key := dsn + "\x00" + slug
	r.app.errorReporterMu.Lock()
	configured := r.app.errorMonitorsConfigured[key] == configHash
	r.app.errorReporterMu.Unlock()
	if !configured {
		payload["monitor_config"] = config
	}
	b, err := json.Marshal(payload)
	if err != nil {
		r.counters.failed.Add(1)
		return
	}
	if result := r.deliver(ctx, "monitor", "monitor:"+item.Job.ID, item.ID, envelopeItem{Type: "check_in", Payload: b}); result.OK && !configured {
		r.app.errorReporterMu.Lock()
		if r.app.errorMonitorsConfigured == nil {
			r.app.errorMonitorsConfigured = make(map[string][32]byte)
		}
		if _, exists := r.app.errorMonitorsConfigured[key]; exists || len(r.app.errorMonitorsConfigured) < 2000 {
			r.app.errorMonitorsConfigured[key] = configHash
		}
		r.app.errorReporterMu.Unlock()
	}
}

func cronMonitorFindings(dir string) []CheckFinding {
	b, err := readOptionalConfig(dir, "cron.yaml")
	if err != nil || len(b) == 0 {
		return nil
	}
	cfg, err := parseCronYAML(b)
	if err != nil || cfg == nil {
		return nil
	}
	vars := map[string]string{}
	if data, err := readOptionalConfig(dir, "env.yaml"); err == nil && len(data) > 0 {
		_ = decodeConfigYAML(data, &vars)
	}
	var out []CheckFinding
	for _, job := range cfg.Jobs {
		if job.Monitor == nil {
			continue
		}
		if cronMonitorSchedule(job.Schedule) == nil {
			out = append(out, CheckFinding{Severity: "warning", Source: "environment", File: "cron.yaml", Message: fmt.Sprintf("cron %s: monitoring skipped because restricted day-of-month and weekday have different Sentry semantics", job.ID)})
		}
		if vars["SENTRY_DSN"] == "" && GetEnv(dir, "SENTRY_DSN") == "" {
			out = append(out, CheckFinding{Severity: "warning", Source: "environment", File: "cron.yaml", Message: fmt.Sprintf("cron %s: monitor: true has no effect without SENTRY_DSN", job.ID)})
		}
		if cronMonitorSchedule(job.Schedule)["type"] == "crontab" && cronMonitorTimezone() == "" {
			out = append(out, CheckFinding{Severity: "warning", Source: "environment", File: "cron.yaml", Message: "cron monitor requires an identifiable IANA host timezone (TZ)"})
		}
	}
	return out
}
