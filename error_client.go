//go:build !cli

package main

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type clientErrorBody struct {
	Kind, Message, Stack, Source, URL, Release string
	Line, Col, Status                          int
	Level, Method, Path                        string
	RequestID                                  string            `json:"request_id"`
	Tags                                       map[string]string `json:"tags"`
	Breadcrumbs                                []breadcrumb      `json:"breadcrumbs"`
	Frames                                     []errorFrame      `json:"-"`
	Stale                                      bool              `json:"-"`
	UserID                                     int64             `json:"-"`
	UserEmail                                  string            `json:"-"`
	UA                                         string            `json:"-"`
	// host is the request's Host (parseJSStack's own-host rule) and rowID the
	// _benmore_client_errors row whose stack the worker rewrites once mapped.
	host  string
	rowID int64
}

// Allowed breadcrumb types and data keys (validateClientErrorContext).
var clientCrumbTypes = map[string]bool{"navigation": true, "http": true, "console": true, "click": true}
var clientCrumbDataKeys = map[string]bool{"method": true, "path": true, "level": true, "status": true, "ms": true}

// boundClientErrorBody caps what one anonymous beacon keeps while it waits in
// the reporter queue. The body is at most 64 KiB, but thousands of tiny
// breadcrumbs decode to megabytes of maps (about 1.6 MiB per event), so the
// counts and shapes the worker would keep are applied here. Strings keep
// their length until the worker has scrubbed them: cutting first could leave
// the prefix of an environment secret that the scrubber no longer recognizes
// (exportScrubber.scrub); together they are bounded by the body size.
func boundClientErrorBody(body *clientErrorBody) {
	body.Stack = truncateRunes(body.Stack, clientErrorStackMax)
	tags := make(map[string]string)
	for key, value := range body.Tags {
		if len(tags) == 10 {
			break
		}
		if clientErrorTagRE.MatchString(key) && utf8.RuneCountInString(value) <= 200 {
			tags[key] = value
		}
	}
	body.Tags = tags
	var crumbs []breadcrumb
	for i := len(body.Breadcrumbs) - 1; i >= 0 && len(crumbs) < 30; i-- {
		crumb := body.Breadcrumbs[i]
		if !clientCrumbTypes[crumb.Type] {
			continue
		}
		data := make(map[string]any)
		for key, value := range crumb.Data {
			switch value.(type) {
			case string, float64:
				if clientCrumbDataKeys[key] {
					data[key] = value
				}
			}
		}
		crumb.Data = data
		crumbs = append(crumbs, crumb)
	}
	for i, j := 0, len(crumbs)-1; i < j; i, j = i+1, j-1 {
		crumbs[i], crumbs[j] = crumbs[j], crumbs[i]
	}
	body.Breadcrumbs = crumbs
}

func errorEnvironment(app *App) (env, release string) {
	env, release = GetEnv(app.Dir, "SENTRY_ENVIRONMENT"), GetEnv(app.Dir, "SENTRY_RELEASE")
	sub := GetEnv(app.Dir, "BENMORE_APP_NAME")
	if env == "" {
		env = "production"
		if IsDevSubdomain(sub) {
			env = "dev"
		}
	}
	if release == "" {
		if published := GetEnv(app.Dir, "BENMORE_PUBLISHED_AT"); published != "" && sub != "" {
			release = LogicalSubdomain(sub) + "@" + published
		} else {
			release = "benmore@" + version
		}
	}
	return env, release
}

var clientExceptionTypeRE = regexp.MustCompile(`^[A-Za-z_$][\w$.]*$`)
var clientRequestIDRE = regexp.MustCompile(`^[0-9a-f]{8,32}$`)
var clientErrorTagRE = regexp.MustCompile(`^[a-z0-9_.]{1,32}$`)

// Browser context is untrusted. Retain only the bounded fields the SDK emits;
// the reporter subsequently scrubs every retained string before persistence.
func validateClientErrorContext(body *clientErrorBody) {
	if !clientRequestIDRE.MatchString(body.RequestID) {
		body.RequestID = ""
	}
	switch body.Level {
	case "warning", "error", "fatal":
	default:
		body.Level = "error"
	}
	switch body.Method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
	default:
		body.Method = ""
	}
	body.Path = truncateRunes(clientErrorLocation(body.Path), 500)
	tags := make(map[string]string)
	for key, value := range body.Tags {
		if len(tags) == 10 {
			break
		}
		if clientErrorTagRE.MatchString(key) && utf8.RuneCountInString(value) <= 200 {
			tags[key] = value
		}
	}
	body.Tags = tags
	crumbs := make([]breadcrumb, 0, 30)
	for _, crumb := range body.Breadcrumbs {
		if !clientCrumbTypes[crumb.Type] {
			continue
		}
		crumb.Timestamp = errorBreadcrumbTimestamp(crumb.Timestamp)
		crumb.Category = truncateRunes(crumb.Category, 300)
		crumb.Message = truncateRunes(crumb.Message, 300)
		if crumb.Type == "navigation" {
			crumb.Message = truncateRunes(clientErrorLocation(crumb.Message), 300)
		}
		data := make(map[string]any)
		for key, value := range crumb.Data {
			switch key {
			case "method", "path", "level":
				if text, ok := value.(string); ok {
					if key == "path" {
						text = clientErrorLocation(text)
					}
					data[key] = truncateRunes(text, 300)
				}
			case "status", "ms":
				if number, ok := value.(float64); ok && number >= 0 && number <= 1e9 {
					data[key] = number
				}
			}
		}
		crumb.Data = data
		crumbs = append(crumbs, crumb)
		if len(crumbs) > 30 {
			crumbs = crumbs[1:]
		}
	}
	body.Breadcrumbs = crumbs
}

// The request body is bounded before decoding. Scrub complete fields before
// the smaller storage limits can split an environment secret.
func scrubClientErrorContext(app *App, body *clientErrorBody) {
	sc := newExportScrubber(app)
	body.Kind = truncateRunes(sc.scrub(body.Kind), 40)
	body.Message = truncateRunes(sc.scrub(body.Message), clientErrorMessageMax)
	body.Path = sc.scrub(body.Path)
	body.Source = sc.scrub(clientErrorLocation(body.Source))
	body.URL = sc.scrub(clientErrorLocation(body.URL))
	body.Breadcrumbs = append([]breadcrumb(nil), body.Breadcrumbs...)
	for i := range body.Breadcrumbs {
		b := &body.Breadcrumbs[i]
		b.Category = sc.scrub(b.Category)
		b.Message = sc.scrub(b.Message)
		b.Data = sc.fields(b.Data, 0)
	}
	validateClientErrorContext(body)
}

func clientSentryEvent(app *App, body clientErrorBody) map[string]any {
	return errorSentryEvent(app, scrubErrorEvent(app, clientReportedEvent(body)), time.Now())
}

func clientReportedEvent(body clientErrorBody) errorEvent {
	typ, message := "Error", body.Message
	if prefix, rest, found := strings.Cut(body.Message, ": "); found && clientExceptionTypeRE.MatchString(prefix) {
		typ, message = prefix, rest
	}
	mechanism := "onerror"
	if body.Kind == "unhandledrejection" || body.Kind == "promise" {
		mechanism = "onunhandledrejection"
	}
	level := body.Level
	if level == "" {
		level = "error"
	}
	route := clientErrorLocation(body.URL)
	if body.Path != "" {
		route = body.Path
	}
	handled := body.Kind == "manual" || body.Kind == "message" || body.Kind == "http"
	if handled {
		mechanism = body.Kind
	}
	return errorEvent{Level: level, Source: "client", Kind: body.Kind, Type: typ, Message: message, Mechanism: mechanism, Handled: handled, Frames: body.Frames,
		Route: route, Method: body.Method, RequestID: body.RequestID, Tags: body.Tags, Breadcrumbs: body.Breadcrumbs,
		UserID: body.UserID, UserEmail: body.UserEmail, UserAgent: body.UA, Extra: map[string]any{"status": body.Status, "bundle_stale": body.Stale, "occurrences_since_last_report": 0}}
}

// One app generation retains only its current DSN's rate-limit state.
type clientSentryState struct {
	mu   sync.Mutex
	dsn  string
	mute *sentryMuteState
}

func (s *clientSentryState) forDSN(dsn string) *sentryMuteState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mute == nil || s.dsn != dsn {
		s.dsn, s.mute = dsn, &sentryMuteState{}
	}
	return s.mute
}

func formatErrorFrames(frames []errorFrame) string {
	var out strings.Builder
	// Keep the familiar newest-first display in the legacy client-errors table.
	for i := len(frames) - 1; i >= 0; i-- {
		f := frames[i]
		fmt.Fprintf(&out, "    at %s (%s:%d:%d)\n", f.Function, f.Filename, f.Line, f.Col)
	}
	return truncateRunes(out.String(), clientErrorStackMax)
}
