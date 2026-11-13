//go:build !cli

package main

import (
	"maps"
	"reflect"
	"slices"
	"strings"
	"unsafe"
)

// A flow response never carries a blind-index column, and neither does what
// a delivery step sends out of the app.
//
// `<col>_blind` is the deterministic HMAC of an encrypted column: equal for
// equal plaintexts, so whoever holds it can tell which rows share a value.
// Every response the framework builds strips it. A flow's `SELECT *`,
// `t.*` or `RETURNING *` returned it in the step's rows, and a respond step
// that passed the rows on sent it to every caller of the flow; a webhook,
// api, email, sms, broadcast or notify step handed the rows sent it to
// whoever receives those.
//
// The step's rows are left alone: the steps of the flow read and bind the
// value as before. What changes is what a respond step writes and what one
// of those delivery steps sends. Keys named like a blind column the app's
// encrypted config DECLARES (any table) are left out at every depth of it:
//
//   - a json / json list body and a body that is one reference lose the keys
//     from the resolved value (flowResponseValue), copy-on-write, so the
//     step outputs they alias keep theirs;
//   - text rendered for it (a text body, a header, text inside a json value,
//     a message's subject or text, with or without a pipe) reads lists and
//     objects from a view of the lookup table whose composite values have
//     lost the keys (flowResponseFlat). A single value keeps its path, so a
//     reference to `steps.x.outputs.first.<col>_blind` still resolves;
//   - a form field or query parameter the step names like one is not sent
//     (flowResponseDropsKey), and the whole flow context a webhook with no
//     body posts loses them too (flowResponseContext).
//
// A column that only ends in `_blind`, a blind value selected under another
// name, and a single value referenced on its own under another key are the
// author's and stay. An app that declares no blind index is not touched.
// `run: enqueue` queues a job of the same app and is left alone.

// flowResponseBlindKeys is the lowercased set of `<col>_blind` names the app's
// encrypted config declares, over every table.
func flowResponseBlindKeys(app *App) map[string]bool {
	if app == nil || app.Encrypted == nil {
		return nil
	}
	var hidden map[string]bool
	for table := range app.Encrypted.Fields {
		for _, col := range blindIndexSiblingColumns(app, table) {
			if hidden == nil {
				hidden = map[string]bool{}
			}
			hidden[strings.ToLower(col)] = true
		}
	}
	return hidden
}

// flowResponseBlindKey reports whether a response key names a declared blind
// column. SQLite matches identifiers without regard to case, and a result
// column is named as the query wrote it.
func flowResponseBlindKey(key string, hidden map[string]bool) bool {
	n := len(key) - len(blindColSuffix)
	return n > 0 && strings.EqualFold(key[n:], blindColSuffix) && hidden[strings.ToLower(key)]
}

// withoutBlindKeys returns v without the hidden keys at any depth, and
// whether anything was removed. v is never modified: a map or list that
// loses a key somewhere below is copied, everything else is shared.
func withoutBlindKeys(v any, hidden map[string]bool) (any, bool) {
	switch t := v.(type) {
	case map[string]any:
		var out map[string]any
		for k, child := range t {
			if flowResponseBlindKey(k, hidden) {
				if out == nil {
					out = maps.Clone(t)
				}
				delete(out, k)
				continue
			}
			if clean, changed := withoutBlindKeys(child, hidden); changed {
				if out == nil {
					out = maps.Clone(t)
				}
				out[k] = clean
			}
		}
		if out != nil {
			return out, true
		}
	case []map[string]any:
		var out []map[string]any
		for i, row := range t {
			if clean, changed := withoutBlindKeys(row, hidden); changed {
				if out == nil {
					out = slices.Clone(t)
				}
				out[i] = clean.(map[string]any)
			}
		}
		if out != nil {
			return out, true
		}
	case []any:
		var out []any
		for i, item := range t {
			if clean, changed := withoutBlindKeys(item, hidden); changed {
				if out == nil {
					out = slices.Clone(t)
				}
				out[i] = clean
			}
		}
		if out != nil {
			return out, true
		}
	}
	return v, false
}

// flowResponseView is the lookup table a respond step renders text from: the
// run's table with the hidden keys removed from its lists and objects. It is
// rebuilt when the table it was made from is replaced.
type flowResponseView struct {
	hidden map[string]bool
	src    unsafe.Pointer
	flat   map[string]any
}

// beginFlowResponse marks ctx as rendering what leaves the app (a response
// for the caller, or what a delivery step sends) until the returned function
// runs. It does nothing for an app with no blind index. Every step that
// sends step data out calls it around the point where it builds what it
// sends: respond, webhook, api, email, sms, broadcast, notify.
func beginFlowResponse(ctx *FlowContext) (end func()) {
	hidden := flowResponseBlindKeys(ctx.App)
	if len(hidden) == 0 {
		return func() {}
	}
	ctx.flatCache.mu.Lock()
	ctx.response = flowResponseView{hidden: hidden}
	ctx.flatCache.mu.Unlock()
	return func() {
		ctx.flatCache.mu.Lock()
		ctx.response = flowResponseView{}
		ctx.flatCache.mu.Unlock()
	}
}

// flowResponseFlat is flat as a response may read it. The caller holds
// ctx.flatCache.mu. flat is shared and is not modified: the view is a copy
// when anything had to be removed, flat itself otherwise.
func (ctx *FlowContext) flowResponseFlat(flat map[string]any) map[string]any {
	view := &ctx.response
	if len(view.hidden) == 0 {
		return flat
	}
	src := reflect.ValueOf(flat).UnsafePointer()
	if view.flat != nil && view.src == src {
		return view.flat
	}
	out, copied := flat, false
	for k, v := range flat {
		clean, changed := withoutBlindKeys(v, view.hidden)
		if !changed {
			continue
		}
		if !copied {
			out, copied = maps.Clone(flat), true
		}
		out[k] = clean
	}
	view.src, view.flat = src, out
	return out
}

// flowResponseValue is a resolved response value as the caller receives it.
func flowResponseValue(ctx *FlowContext, v any) any {
	if ctx == nil || len(ctx.response.hidden) == 0 {
		return v
	}
	clean, _ := withoutBlindKeys(v, ctx.response.hidden)
	return clean
}

// flowResponseDropsKey reports whether a field the step itself names (a form
// field, a query parameter) is left out of what it sends.
func flowResponseDropsKey(ctx *FlowContext, key string) bool {
	return ctx != nil && flowResponseBlindKey(key, ctx.response.hidden)
}

// flowResponseContext is the whole flow context as a step may send it. data
// is the caller's own copy at the top level. Besides the keys
// flowResponseValue removes, the context holds flattened paths
// (`row.<col>_blind` for a loop variable, `<step>.json.<col>_blind`), which
// go by their last segment.
func flowResponseContext(ctx *FlowContext, data map[string]any) map[string]any {
	if ctx == nil || len(ctx.response.hidden) == 0 {
		return data
	}
	hidden := ctx.response.hidden
	for k, v := range data {
		if flowResponseBlindKey(k[strings.LastIndexByte(k, '.')+1:], hidden) {
			delete(data, k)
			continue
		}
		if clean, changed := withoutBlindKeys(v, hidden); changed {
			data[k] = clean
		}
	}
	return data
}
