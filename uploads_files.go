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
)

// RegisterFileUploadRoute mounts the generic /api/_files endpoint.
// Auth-gated when the app has any auth config - anonymous file uploads
// open the storage volume to drive-by spam, which is rarely what an
// app actually wants. Apps that intentionally accept anon uploads can
// either set up their own /api/<table> multipart flow or grant a
// public role via roles in app.yaml.
func RegisterFileUploadRoute(mux *http.ServeMux, app *App) {
	authRequired := NeedsAuth(app)

	mux.HandleFunc("POST /api/_files", func(w http.ResponseWriter, r *http.Request) {
		// CSRF first (cheap), then auth (DB hit).
		if !validateCSRF(r) && !isBearerAuth(r) {
			httpError(w, "CSRF validation failed", http.StatusForbidden)
			return
		}
		if authRequired {
			if session := getSession(app, r); session == nil {
				httpError(w, "authentication required", http.StatusUnauthorized)
				return
			}
		}

		// Cap the request body BEFORE parsing. ParseMultipartForm's
		// argument is only the in-memory threshold; anything larger
		// streams to a temp file with no ceiling. MaxBytesReader makes
		// the read itself fail closed once the body exceeds the cap, so
		// an oversized upload can't spill unbounded bytes to disk.
		r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

		// Parse multipart up front so we can pull the file header for
		// the response payload. HandleFileUpload will re-read via
		// r.FormFile internally - both calls work against the same
		// parsed form.
		if err := r.ParseMultipartForm(maxUploadSize); err != nil {
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

		url := "/" + path
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"url":  url,
			"name": header.Filename,
			"size": header.Size,
			"type": header.Header.Get("Content-Type"),
		})
	})
}
