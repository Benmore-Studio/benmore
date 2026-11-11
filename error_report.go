//go:build !cli

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type errorCause struct {
	Type    string `json:"type"`
	Message string `json:"value"`
}
type breadcrumb struct {
	Timestamp string         `json:"timestamp,omitempty"`
	Type      string         `json:"type,omitempty"`
	Category  string         `json:"category,omitempty"`
	Message   string         `json:"message,omitempty"`
	Data      map[string]any `json:"data,omitempty"`
}
type errorEvent struct {
	clientBody  *clientErrorBody              `json:"-"`
	testReply   chan errorReportingTestResult `json:"-"`
	Level       string                        `json:"level"`
	Source      string                        `json:"source"`
	Kind        string                        `json:"kind"`
	Type        string                        `json:"type"`
	Message     string                        `json:"message"`
	Route       string                        `json:"route,omitempty"`
	Method      string                        `json:"method,omitempty"`
	RequestID   string                        `json:"request_id,omitempty"`
	Mechanism   string                        `json:"mechanism"`
	Frames      []errorFrame                  `json:"frames,omitempty"`
	Causes      []errorCause                  `json:"causes,omitempty"`
	Tags        map[string]string             `json:"tags,omitempty"`
	UserID      int64                         `json:"user_id,omitempty"`
	Handled     bool                          `json:"handled"`
	Breadcrumbs []breadcrumb                  `json:"breadcrumbs,omitempty"`
	Extra       map[string]any                `json:"extra,omitempty"`
	UserEmail   string                        `json:"-"`
	UserAgent   string                        `json:"-"`
	flush       chan struct{}                 `json:"-"`
	// pcs are a failed request's call stack, resolved into Frames by the
	// worker so the request pays only runtime.Callers.
	pcs     []uintptr    `json:"-"`
	checkIn *cronCheckIn `json:"-"`
}

type errorCounters struct {
	captured, dropped, throttled, forwarded, failed, muted, rejected atomic.Int64
}

func (c *errorCounters) snapshot() map[string]int64 {
	return map[string]int64{"captured": c.captured.Load(), "dropped": c.dropped.Load(), "throttled": c.throttled.Load(), "forwarded": c.forwarded.Load(), "failed": c.failed.Load(), "muted": c.muted.Load(), "rejected": c.rejected.Load()}
}

type errorReporterGeneration struct {
	once     sync.Once
	stop     <-chan struct{}
	reporter *errorReporter
}
type errorReporter struct {
	app        *App
	queue      chan errorEvent
	done       <-chan struct{}
	counters   errorCounters
	state      clientSentryState
	client     *http.Client
	now        func() time.Time
	limiter    *RateLimiter
	lastReport map[string]int64
	// tableReady is false until _benmore_error_groups exists; the worker
	// retries creating it on later events instead of stopping.
	tableReady bool
}

func (app *App) getErrorReporter() *errorReporter {
	app.errorReporterMu.Lock()
	defer app.errorReporterMu.Unlock()
	app.mu.Lock()
	if app.Stop == nil {
		app.Stop = make(chan struct{})
	}
	stop := app.Stop
	app.mu.Unlock()
	g := app.errorReporter
	if g == nil || g.stop != stop {
		g = &errorReporterGeneration{stop: stop}
		app.errorReporter = g
	}
	g.once.Do(func() {
		r := &errorReporter{app: app, queue: make(chan errorEvent, 256), client: sentryHTTPClient(), now: time.Now, lastReport: map[string]int64{}, limiter: NewRateLimiterStoppable(30, time.Minute, stop)}
		g.reporter = r
		r.done = app.startWorker("errors.reporter", func(<-chan struct{}) { r.run(stop) })
	})
	return g.reporter
}

// Only the worker performs scrubbing, SQLite or network I/O. A broken reporting
// path must never replace the original failure or block an application request.
func reportError(app *App, ev errorEvent) {
	defer func() { _ = recover() }()
	if app == nil || app.DB == nil {
		return
	}
	r := app.getErrorReporter()
	select {
	case <-r.done:
		r.counters.dropped.Add(1)
		return
	default:
	}
	// Anonymous browser reports may fill only half the queue: the rest stays
	// free for server, job, cron and check-in events, which a beacon flood
	// would otherwise push out.
	if ev.clientBody != nil && len(r.queue) >= cap(r.queue)/2 {
		r.counters.dropped.Add(1)
		return
	}
	select {
	case r.queue <- ev:
		r.counters.captured.Add(1)
	default:
		r.counters.dropped.Add(1)
	}
}

func (r *errorReporter) run(stop <-chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Cancel even an in-flight sink after the two-second shutdown grace period.
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-stop:
		}
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
		case <-timer.C:
			cancel()
		}
	}()
	r.ensureTable(ctx)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			for {
				select {
				case <-ctx.Done():
					return
				case ev := <-r.queue:
					r.process(ctx, ev)
				default:
					return
				}
			}
		case ev := <-r.queue:
			r.process(ctx, ev)
		case <-ticker.C:
			r.sendClientReport(ctx)
		}
	}
}

// ensureTable creates the group table once. A failure is logged and retried
// on the next event: stopping the worker would silently drop every later
// report, including the database failures the owner most needs exported.
func (r *errorReporter) ensureTable(ctx context.Context) {
	if r.tableReady {
		return
	}
	if err := ensureErrorGroupsContext(ctx, r.app.DB); err != nil {
		r.counters.failed.Add(1)
		log.Printf("errors: creating the error group table failed (retried on the next event): %v", err)
		return
	}
	r.tableReady = true
}

func (r *errorReporter) allow(budget string) bool {
	return r.limiter.Allow(budget)
}

// errorBudget names the per-minute delivery budget of one stream. Browser
// reports, which anyone can send, never spend the budget of server failures,
// and Slack never spends Sentry's; cron check-ins have one per monitored job
// (sendCheckIn).
func errorBudget(stream, source string) string {
	if source == "client" {
		return stream + ":client"
	}
	return stream
}

func (r *errorReporter) process(ctx context.Context, ev errorEvent) {
	if ev.clientBody != nil {
		body := *ev.clientBody
		body.Frames, body.Stale = symbolicateFrames(r.app, parseJSStack(body.Stack, body.host))
		if len(body.Frames) != 0 && body.rowID != 0 {
			// The legacy row keeps the caller's stack mapped through the public
			// bundle's sourcemap (no source context lines); stack_raw keeps it as sent.
			_, _ = r.app.DB.ExecContext(ctx, `UPDATE _benmore_client_errors SET stack=? WHERE id=?`, formatErrorFrames(body.Frames), body.rowID)
		}
		scrubClientErrorContext(r.app, &body)
		ev = clientReportedEvent(body)
	}
	if len(ev.pcs) != 0 && len(ev.Frames) == 0 {
		ev.Frames = goFramesFromPCs(ev.pcs)
	}
	if ev.testReply != nil {
		r.processTest(ctx, ev.testReply)
		return
	}
	if ev.checkIn != nil {
		r.sendCheckIn(ctx, ev.checkIn)
		return
	}
	if ev.flush != nil {
		close(ev.flush)
		return
	}
	ev = scrubErrorEvent(r.app, ev)
	dsn := GetEnv(r.app.Dir, "SENTRY_DSN")
	levelEligible := ev.Level == "fatal" || ev.Level == "error" || GetEnv(r.app.Dir, "SENTRY_MIN_LEVEL") == "warning"
	muted := dsn != "" && r.state.forDSN(dsn).muted("error")
	eligible := dsn != "" && !muted && levelEligible
	if muted && levelEligible {
		r.counters.muted.Add(1)
	}
	r.ensureTable(ctx)
	forward, since, err := recordGroupEligible(ctx, r.app, ev, r.now(), eligible)
	recorded := err == nil
	if err != nil {
		if errors.Is(err, errErrorAccountPurged) {
			r.counters.dropped.Add(1)
			return
		}
		// A locked or failing database is exactly what the owner configured
		// Sentry and Slack for: export anyway, without the group's per-group
		// claim; the per-minute budgets still bound a storm.
		r.counters.failed.Add(1)
		log.Printf("errors: recording the error group failed (exported anyway): %v", err)
		forward = eligible
	}
	if eligible && !forward {
		r.counters.throttled.Add(1)
	}
	if ev.Level == "fatal" || ev.Level == "error" {
		r.sendSlack(ctx, ev, recorded)
	}
	if !forward {
		return
	}
	if ev.Extra == nil {
		ev.Extra = map[string]any{}
	}
	ev.Extra["occurrences_since_last_report"] = since
	r.sendEvent(ctx, ev)
}

func (r *errorReporter) sendEvent(ctx context.Context, ev errorEvent) deliveryResult {
	return r.sendEventBudget(ctx, ev, errorBudget("forward", ev.Source))
}

func (r *errorReporter) sendEventBudget(ctx context.Context, ev errorEvent, budget string) deliveryResult {
	event := errorSentryEvent(r.app, ev, r.now())
	payload, err := json.Marshal(event)
	if err != nil {
		r.counters.failed.Add(1)
		return deliveryResult{}
	}
	return r.deliver(ctx, "error", budget, event["event_id"].(string), envelopeItem{Type: "event", Payload: payload})
}

func (r *errorReporter) deliver(ctx context.Context, category, budget, id string, item envelopeItem) deliveryResult {
	deliveryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raw := GetEnv(r.app.Dir, "SENTRY_DSN")
	if raw == "" || r.app.errorDeliveryOff.Load() {
		return deliveryResult{}
	}
	d, err := parseSentryDSN(raw)
	if err != nil || isPrivateURLContext(deliveryCtx, d.envelopeURL()) {
		r.counters.rejected.Add(1)
		return deliveryResult{Rejected: true}
	}
	mute := r.state.forDSN(raw)
	if mute.muted(category) {
		r.counters.muted.Add(1)
		return deliveryResult{MutedCategories: []string{category}}
	}
	if !r.allow(budget) {
		r.counters.throttled.Add(1)
		return deliveryResult{MutedCategories: []string{category}}
	}
	result := deliverEnvelope(deliveryCtx, r.client, d, buildEnvelope(id, item))
	mute.apply(result)
	if result.OK {
		r.counters.forwarded.Add(1)
	} else {
		r.counters.failed.Add(1)
	}
	if result.Rejected {
		r.counters.rejected.Add(1)
	}
	return result
}

func (r *errorReporter) sendClientReport(ctx context.Context) {
	current := r.counters.snapshot()
	var discarded []map[string]any
	for key, reason := range map[string]string{"dropped": "queue_overflow", "throttled": "sample_rate", "muted": "ratelimit_backoff"} {
		if n := current[key] - r.lastReport[key]; n > 0 {
			discarded = append(discarded, map[string]any{"reason": reason, "category": "error", "quantity": n})
		}
	}
	if len(discarded) == 0 {
		return
	}
	payload, _ := json.Marshal(map[string]any{"timestamp": r.now().UTC().Format(time.RFC3339Nano), "discarded_events": discarded})
	if result := r.deliver(ctx, "internal", "internal", "", envelopeItem{Type: "client_report", Payload: payload}); result.OK {
		r.lastReport = current
	}
}

func errorSentryEvent(app *App, ev errorEvent, now time.Time) map[string]any {
	env, release := errorEnvironment(app)
	tags := map[string]string{"app": errorExportIdentity(app, "app", LogicalSubdomain(GetEnv(app.Dir, "BENMORE_APP_NAME"))), "source": ev.Source, "kind": ev.Kind, "benmore.version": version}
	for k, v := range ev.Tags {
		if _, reserved := tags[k]; !reserved && k != "request_id" && k != "group_key" {
			tags[k] = v
		}
	}
	if ev.RequestID != "" {
		tags["request_id"] = ev.RequestID
	}
	key := errorGroupKey(ev)
	tags["group_key"] = key
	user := map[string]string{}
	if ev.UserID != 0 {
		user["id"] = strconv.FormatInt(ev.UserID, 10)
	}
	if GetEnv(app.Dir, "SENTRY_SEND_PII") == "1" && ev.UserEmail != "" {
		user["email"] = ev.UserEmail
	}
	values := make([]any, 0, len(ev.Causes)+1)
	for i := len(ev.Causes) - 1; i >= 0; i-- {
		values = append(values, map[string]any{"type": ev.Causes[i].Type, "value": ev.Causes[i].Message})
	}
	values = append(values, map[string]any{"type": ev.Type, "value": ev.Message, "mechanism": map[string]any{"type": ev.Mechanism, "handled": ev.Handled}, "stacktrace": map[string]any{"frames": ev.Frames}})
	platform, logger := "go", "benmore"
	if ev.Source == "client" {
		platform, logger = "javascript", "bm.js"
	}
	event := map[string]any{"event_id": newSentryEventID(), "timestamp": now.UTC().Format(time.RFC3339Nano), "platform": platform, "logger": logger, "level": ev.Level,
		"environment": errorExportIdentity(app, "env", env), "release": errorExportIdentity(app, "release", release), "tags": tags, "user": user,
		"request":   map[string]any{"url": ev.Route, "method": ev.Method, "headers": map[string]string{"User-Agent": ev.UserAgent}},
		"exception": map[string]any{"values": values}, "breadcrumbs": map[string]any{"values": ev.Breadcrumbs}, "extra": ev.Extra, "fingerprint": []string{key}}
	if ev.Source != "client" {
		event["contexts"] = map[string]any{"runtime": map[string]string{"name": "go", "version": runtime.Version()}, "os": map[string]string{"name": runtime.GOOS}}
	}
	return event
}

func goFrames(skip int) []errorFrame {
	pcs := make([]uintptr, 64)
	n := runtime.Callers(skip+2, pcs)
	return goFramesFromPCs(pcs[:n])
}
func goFramesFromPCs(pcs []uintptr) []errorFrame {
	root := ""
	if info, ok := debug.ReadBuildInfo(); ok {
		root = info.Main.Path
	}
	var frames []errorFrame
	iter := runtime.CallersFrames(pcs)
	for len(pcs) > 0 {
		f, more := iter.Next()
		file := filepath.ToSlash(f.File)
		if root != "" && strings.Contains(file, root+"/") {
			file = file[strings.LastIndex(file, root+"/")+len(root)+1:]
		} else {
			parts := strings.Split(file, "/")
			if len(parts) > 2 {
				file = strings.Join(parts[len(parts)-2:], "/")
			}
		}
		frames = append(frames, errorFrame{Filename: file, Function: f.Function, Line: f.Line, InApp: strings.HasPrefix(f.Function, "main.")})
		if !more || len(frames) >= 64 {
			break
		}
	}
	for i, j := 0, len(frames)-1; i < j; i, j = i+1, j-1 {
		frames[i], frames[j] = frames[j], frames[i]
	}
	return frames
}

// The YAML harness uses a queue barrier before querying asynchronous diagnostics.
// It does not close the reporter or require delivery of any later event.
func flushErrorReports(ctx context.Context, app *App) error {
	r := app.getErrorReporter()
	done := make(chan struct{})
	select {
	case r.queue <- errorEvent{flush: done}:
	case <-ctx.Done():
		return ctx.Err()
	case <-r.done:
		return fmt.Errorf("error reporter stopped")
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-r.done:
		return fmt.Errorf("error reporter stopped")
	}
}
