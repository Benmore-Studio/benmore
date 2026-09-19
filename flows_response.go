//go:build !cli

package main

// HTTP response, redirect, and private-upload delivery steps.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func execStepRedirect(ctx *FlowContext, step *FlowStep) error {
	if ctx.Writer == nil || ctx.Request == nil {
		return nil // not an HTTP-triggered flow
	}
	url := interpolateCtx(step.Redirect, ctx)
	http.Redirect(ctx.Writer, ctx.Request, url, http.StatusSeeOther)
	ctx.Stopped = true
	return nil
}

// execStepServeFile streams a file from the app's uploads/ directory as
// the terminal response. The flow itself is the authorization gate - it
// reads the bytes off disk directly, bypassing the /uploads/ HTTP route
// - so a flow that has already validated (e.g.) a data-room share token
// can serve a PRIVATE file (uploads/private/...) to an anonymous caller
// WITHOUT minting a signed URL. No signed URL escapes to be reshared;
// the gate is the only path to the bytes.
func execStepServeFile(ctx *FlowContext, step *FlowStep) error {
	if ctx.Writer == nil || ctx.Request == nil {
		return nil // not an HTTP-triggered flow
	}
	if step.ServeFile == nil || step.ServeFile.Path == "" {
		return fmt.Errorf("serve_file step missing `path:` - point at an uploaded file, e.g. path: ${{ steps.item.outputs.file_url }}")
	}
	raw := strings.TrimSpace(interpolateCtx(step.ServeFile.Path, ctx))
	if raw == "" {
		http.Error(ctx.Writer, "Not found", http.StatusNotFound)
		ctx.Stopped = true
		return nil
	}
	cfg := getPlatformMedia()

	// Compute the local-disk candidate once (traversal-guarded to uploads/).
	rel := filepath.Clean(strings.TrimPrefix(strings.TrimPrefix(raw, "/"), "uploads/"))
	uploadsRoot := filepath.Join(ctx.App.Dir, "uploads")
	fullPath := filepath.Join(uploadsRoot, rel)
	inUploads := fullPath == uploadsRoot || strings.HasPrefix(fullPath, uploadsRoot+string(os.PathSeparator))
	localExists := false
	if inUploads {
		if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
			localExists = true
		}
	}
	isCDNURL := cfg != nil && strings.HasPrefix(raw, "https://"+cfg.CDNDomain+"/")

	// CDN backend: serve via a CloudFront redirect - SIGNED + short-TTL for
	// private files (the flow has already authorized this request), plain
	// for public. Bytes never transit the app; the URL is on the cookieless
	// origin. Prefer a still-present LOCAL file over a maybe-missing S3
	// object (pre-migration window): only go to CDN for an actual CDN URL,
	// or a logical path whose local file is absent (migrated / new upload).
	if cfg != nil && (isCDNURL || !localExists) {
		if url, isPrivate, ok := cdnURLForServe(ctx.App, raw, cfg); ok {
			target := url
			if isPrivate {
				expires := time.Now().Add(120 * time.Second).Unix()
				signed, err := signCloudFrontURL(url, expires, cfg.KeyPairID, cfg.PrivateKey)
				if err != nil {
					http.Error(ctx.Writer, "media signing unavailable", http.StatusInternalServerError)
					ctx.Stopped = true
					return nil
				}
				target = signed
			}
			http.Redirect(ctx.Writer, ctx.Request, target, http.StatusFound)
			ctx.Stopped = true
			return nil
		}
	}

	// Local-disk serve (file present on disk, or CDN not configured).
	if !inUploads || !localExists {
		http.Error(ctx.Writer, "Not found", http.StatusNotFound)
		ctx.Stopped = true
		return nil
	}
	// XSS-safe content-type/disposition defaults (forces attachment for
	// active content like .html/.svg even when inline is requested).
	applyUploadDispositionHeaders(ctx.Writer, fullPath)
	// Explicit attachment override (the "Download" affordance) wins.
	if strings.EqualFold(step.ServeFile.Disposition, "attachment") {
		name := step.ServeFile.Filename
		if name == "" {
			name = filepath.Base(fullPath)
		}
		ctx.Writer.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, name))
	} else if step.ServeFile.Filename != "" {
		// Inline with a suggested filename (only set if the safety helper
		// left it inline - i.e. it didn't force an attachment).
		if ctx.Writer.Header().Get("Content-Disposition") == "" {
			ctx.Writer.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename=%q`, step.ServeFile.Filename))
		}
	}
	// http.ServeFile handles Content-Type, Range requests, and caching.
	http.ServeFile(ctx.Writer, ctx.Request, fullPath)
	ctx.Stopped = true
	return nil
}

func execStepDeleteUpload(ctx *FlowContext, step *FlowStep) error {
	if step.DeleteUpload == "" {
		return fmt.Errorf("delete_upload step missing `path:`")
	}
	return deletePrivateUpload(ctx.App, interpolateCtx(step.DeleteUpload, ctx))
}

func execStepRespond(ctx *FlowContext, step *FlowStep) error {
	if ctx.Writer == nil {
		return nil
	}
	r := step.Respond
	if r == nil {
		return nil
	}
	status := r.Status
	if status == 0 {
		status = 200
	}
	// Bare-template body shortcut. When body is a single `{{var}}` or
	// `{{var.path}}` reference, resolve it from context - including
	// dotted/indexed paths through flattenData - and marshal the
	// resolved value as JSON directly. Closes the gap where every
	// agent's "respond with the rows from my SQL query" intent had to
	// be wrapped as `json: { rows: "{{rows}}" }`.
	if r.Body != "" {
		trimmed := strings.TrimSpace(r.Body)
		if strings.HasPrefix(trimmed, "{{") && strings.HasSuffix(trimmed, "}}") && strings.Count(trimmed, "{{") == 1 {
			key := strings.TrimSpace(trimmed[2 : len(trimmed)-2])
			// Try the flattened path map first so dotted/indexed
			// accesses like `stories.0`, `user.email` resolve.
			flat := flattenData(ctx.Data)
			if ctxVal, ok := flat[key]; ok {
				ctx.Writer.Header().Set("Content-Type", "application/json")
				ctx.Writer.WriteHeader(status)
				json.NewEncoder(ctx.Writer).Encode(ctxVal)
				ctx.Stopped = true
				return nil
			}
			if ctxVal, ok := ctx.Data[key]; ok {
				ctx.Writer.Header().Set("Content-Type", "application/json")
				ctx.Writer.WriteHeader(status)
				json.NewEncoder(ctx.Writer).Encode(ctxVal)
				ctx.Stopped = true
				return nil
			}
			// Bare template that didn't resolve. Fail loudly with a
			// diagnostic that names the missing key + what's actually
			// in ctx.Data. Pre-v2.3.2 we fell through and wrote the
			// literal `{{key}}` to the response - the storyforge
			// debugging session was filled with this footgun.
			keys := make([]string, 0, len(ctx.Data))
			for k := range ctx.Data {
				keys = append(keys, k)
			}
			ctx.Writer.Header().Set("Content-Type", "application/json")
			ctx.Writer.WriteHeader(500)
			json.NewEncoder(ctx.Writer).Encode(map[string]any{
				"error":          "template_unresolved",
				"unresolved_key": key,
				"available_keys": keys,
				"hint":           "the body template referenced {{" + key + "}} but no step produced that key. Check (a) the step that should produce it has `id: <name>` set, (b) the path matches (steps.<id>.outputs / steps.<id>.outputs.rows / steps.<id>.outputs[0]), (c) the step actually ran (no prior step errored). Run describe_flows to see the resolved step list.",
			})
			ctx.Stopped = true
			return nil
		}
	}
	wrote := false
	// Render into a buffer first, then check ctx.MissingRefs, THEN write
	// the response. Pre-v2.7.5 we wrote headers + status before
	// interpolation finished - by the time the dispatcher noticed the
	// unresolved `${{ ... }}` references, a 200 + half-broken body was
	// already on the wire. Now: if any reference failed to resolve, we
	// emit a 500 with a structured `template_unresolved` envelope
	// instead of the half-broken success response.
	if r.JSONArray != nil {
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(r.JSONArray); err != nil {
			return err
		}
		if missing := ctx.takeMissingRefs(); len(missing) > 0 {
			writeRespondUnresolved(ctx.Writer, missing, ctx.Data)
			ctx.Stopped = true
			return nil
		}
		ctx.Writer.Header().Set("Content-Type", "application/json")
		ctx.Writer.WriteHeader(status)
		_, _ = ctx.Writer.Write(buf.Bytes())
		wrote = true
	} else if r.JSON != nil {
		// Interpolate {{var}} placeholders in JSON values before encoding
		resolved := interpolateJSONValues(r.JSON, ctx)
		if missing := ctx.takeMissingRefs(); len(missing) > 0 {
			writeRespondUnresolved(ctx.Writer, missing, ctx.Data)
			ctx.Stopped = true
			return nil
		}
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(resolved); err != nil {
			return err
		}
		ctx.Writer.Header().Set("Content-Type", "application/json")
		ctx.Writer.WriteHeader(status)
		_, _ = ctx.Writer.Write(buf.Bytes())
		wrote = true
	} else if r.Body != "" {
		rendered := interpolateCtx(r.Body, ctx)
		if missing := ctx.takeMissingRefs(); len(missing) > 0 {
			writeRespondUnresolved(ctx.Writer, missing, ctx.Data)
			ctx.Stopped = true
			return nil
		}
		ctx.Writer.WriteHeader(status)
		_, _ = ctx.Writer.Write([]byte(rendered))
		wrote = true
	}
	if wrote {
		ctx.Stopped = true
	}
	// If we got here without writing, fall through to the global
	// default-response path in executeFlow (which now emits a 500
	// + flow_no_response diagnostic instead of "status: ok").
	return nil
}

// writeRespondUnresolved emits the 500 envelope the dispatcher uses for
// respond steps whose template body referenced unresolved `${{ ... }}`
// expressions. Lists the missing refs + a sorted snapshot of what was
// in ctx.Data, so the agent can see whether the missing key is a typo,
// a step that didn't run, or a name they expected the framework to
// provide automatically (e.g. an unresolved `${{ user.first_name }}`
// when auth wasn't required on the route).
func writeRespondUnresolved(w http.ResponseWriter, missing []string, data map[string]any) {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(500)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":           "template_unresolved",
		"unresolved_refs": missing,
		"available_keys":  keys,
		"hint":            "the respond step's body referenced template variables that didn't resolve. Most common: (a) the step you reference has no `id:` set, (b) you used `${{ steps.<id>.outputs.<col> }}` but the upstream SQL was INSERT/UPDATE without RETURNING - add RETURNING <col> so the value is captured, (c) you referenced `${{ user.<field> }}` on a route without `auth: required`. Pre-v2.7.5 the literal placeholder text would have been baked into the response - now it's surfaced explicitly here.",
	})
}
