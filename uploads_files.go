//go:build !cli

package main

// Standalone file uploads for SPA mode.
//
// POST /api/_files
//   Body:    multipart/form-data with a single `file` field
//   Returns: {"url": "/uploads/_files/<hash>.<ext>", "name": "...", "size": N, "type": "..."}
//
// Use case: an SPA needs to let the user pick an image / attachment and
// only later decide what record to attach it to (avatar before user
// signup, image before composing a post, etc.). The per-table multipart
// flow in handleCreate ties the file to a specific row at write time,
// which is fine for forms but awkward for "upload first" workflows.
//
// All the safety checks from HandleFileUpload apply here: 50MB cap,
// MIME-from-content detection, dangerous-MIME blocklist, UUID
// filenames. CSRF + auth gated the same as CRUD writes.

import (
	"encoding/json"
	"net/http"
	"strings"
)

// RegisterFileUploadRoute mounts the generic /api/_files endpoint.
// Auth-gated when the app has any auth config - anonymous file uploads
// open the storage volume to drive-by spam, which is rarely what an
// app actually wants. Apps that intentionally accept anon uploads can
// either set up their own /api/<table> multipart flow or grant a
// public role via roles in app.yaml.
func RegisterFileUploadRoute(mux appRouteRegistrar, app *App) {
	authRequired := NeedsAuth(app)

	mux.HandleFunc("POST /api/_files", func(w http.ResponseWriter, r *http.Request) {
		if !app.FeatureEnabled("uploads") {
			http.NotFound(w, r)
			return
		}
		// Authenticate before taking one of the process's upload slots (the
		// session comes from headers and cookies, not the body), as
		// /api/_upload does: otherwise anonymous slow bodies could hold every
		// slot and turn all uploads away with 503.
		if authRequired {
			if session := getSession(app, r); session == nil {
				httpError(w, "authentication required", http.StatusUnauthorized)
				return
			}
		}
		// Cap and parse the body before the CSRF check, which is the first
		// form access and would otherwise parse an unbounded body.
		release, ok := limitUploadBody(w, r, uploadClientKey(app, r))
		if !ok {
			return
		}
		defer release()
		if !validateCSRF(r) && !isBearerAuth(r) {
			httpError(w, "CSRF validation failed", http.StatusForbidden)
			return
		}

		// The body was capped and parsed by limitUploadBody above
		// (ParseMultipartForm's argument is only the in-memory threshold;
		// without the cap file parts spill to disk with no ceiling). This
		// call returns the earlier parse result, so we can pull the file
		// header for the response payload. HandleFileUpload re-reads via
		// r.FormFile against the same parsed form.
		if err := r.ParseMultipartForm(uploadMemoryThreshold); err != nil {
			httpError(w, "multipart parse failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		f, header, err := r.FormFile("file")
		if err != nil {
			httpError(w, "missing 'file' field (POST multipart/form-data with name=\"file\")", http.StatusBadRequest)
			return
		}
		// Close the temp handle - HandleFileUpload will open its own.
		f.Close()

		path, err := HandleFileUpload(app, r, "file", "_files", 0, nil)
		if err != nil {
			httpError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if path == "" {
			httpError(w, "no file received", http.StatusBadRequest)
			return
		}

		// path is either a site-relative "/uploads/..." or an absolute CDN
		// URL; never prefix another "/" (that produced a protocol-relative
		// "//uploads/..." or "/https://..." URL).
		url := path
		if !strings.HasPrefix(url, "/") && !strings.HasPrefix(url, "https://") {
			url = "/" + url
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"url":  url,
			"name": header.Filename,
			"size": header.Size,
			"type": header.Header.Get("Content-Type"),
		})
	})
}
