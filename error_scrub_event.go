//go:build !cli

package main

import "time"

func errorBreadcrumbTimestamp(value string) string {
	stamp, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return ""
	}
	return stamp.UTC().Format(time.RFC3339Nano)
}

func scrubErrorEvent(app *App, ev errorEvent) errorEvent {
	sc := newExportScrubber(app)
	if ev.Level != "fatal" && ev.Level != "warning" {
		ev.Level = "error"
	}
	if ev.Source != "client" {
		ev.Source = "server"
	}
	if ev.Kind == "" {
		ev.Kind = "server"
	}
	if ev.Type == "" {
		ev.Type = "Error"
	}
	if ev.Mechanism == "" {
		ev.Mechanism = "generic"
	}
	ev.Type = sc.scrub(ev.Type)
	ev.Message = sc.scrub(ev.Message)
	ev.Route = sc.scrub(clientErrorLocation(ev.Route))
	ev.Method = sc.scrub(ev.Method)
	ev.Kind = sc.scrub(ev.Kind)
	ev.Mechanism = sc.scrub(ev.Mechanism)
	ev.UserAgent = sc.scrub(ev.UserAgent)
	ev.Frames = sc.frames(ev.Frames)
	ev.Causes = append([]errorCause(nil), ev.Causes...)
	for i := range ev.Causes {
		ev.Causes[i].Type = sc.scrub(ev.Causes[i].Type)
		ev.Causes[i].Message = sc.scrub(ev.Causes[i].Message)
	}
	tags := map[string]string{}
	for k, v := range ev.Tags {
		tags[sc.scrub(k)] = sc.scrub(v)
	}
	ev.Tags = tags
	ev.Breadcrumbs = append([]breadcrumb(nil), ev.Breadcrumbs...)
	for i := range ev.Breadcrumbs {
		b := &ev.Breadcrumbs[i]
		b.Timestamp = errorBreadcrumbTimestamp(b.Timestamp)
		b.Message = sc.scrub(b.Message)
		b.Category = sc.scrub(b.Category)
		b.Type = sc.scrub(b.Type)
		b.Data = sc.fields(b.Data, 0)
	}
	ev.Extra = sc.fields(ev.Extra, 0)
	return ev
}

func (sc *exportScrubber) fields(input map[string]any, depth int) map[string]any {
	if input == nil || depth > 4 {
		return nil
	}
	out := map[string]any{}
	for k, v := range input {
		if len(out) >= 64 {
			break
		}
		key := sc.scrub(k)
		switch v := v.(type) {
		case string:
			out[key] = sc.scrub(v)
		case bool, int, int64, float64:
			out[key] = v
		case map[string]any:
			out[key] = sc.fields(v, depth+1)
		}
	}
	return out
}
