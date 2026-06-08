//go:build !cli

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// pdfLimiter enforces 10 PDFs/minute per user/IP — PDF generation is expensive.
var pdfLimiter = NewRateLimiter(10, time.Minute)

// safeFilenameRe strips anything that is not alphanumeric, dash, or underscore.
var safeFilenameRe = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

// findChrome locates a Chrome or Chromium binary on the local system.
// Returns "" if none is available. Used by PDF rendering and any other
// headless-Chrome consumer.
func findChrome() string {
	macPaths := []string{
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
	}
	for _, p := range macPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	for _, name := range []string{"google-chrome", "chromium", "chromium-browser"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return ""
}

// RegisterPDFRoutes registers GET /pdf/{page...} for rendering any page to PDF.
func RegisterPDFRoutes(mux *http.ServeMux, app *App) {
	mux.HandleFunc("GET /pdf/{page...}", func(w http.ResponseWriter, r *http.Request) {
		handlePDFRender(w, r, app)
	})
}

func handlePDFRender(w http.ResponseWriter, r *http.Request, app *App) {
	// Rate limit: identify by user ID if authenticated, otherwise by IP
	rateLimitKey := r.RemoteAddr
	session := getSession(app, r)
	if session != nil {
		rateLimitKey = fmt.Sprintf("user:%d", session.UserID)
	}
	if !pdfLimiter.Allow(rateLimitKey) {
		http.Error(w, "Too many PDF requests — try again later", http.StatusTooManyRequests)
		return
	}

	// Resolve the requested page path
	pageParam := r.PathValue("page")
	pagePath := "/" + pageParam
	if pagePath == "/" {
		pagePath = "/"
	}

	// Validate page exists — no path traversal, must be in app.Pages
	page, ok := app.Pages[pagePath]
	if !ok {
		http.NotFound(w, r)
		return
	}

	// Auth check — same rules as page rendering
	if page.Auth == "required" || page.Require != "" {
		if session == nil {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
	}

	// Role check
	requiredRole := extractPageRole(page.RawHTML)
	if requiredRole != "" {
		if session == nil {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		userRole := getUserRole(app.DB, session.UserID)
		if !hasRole(userRole, requiredRole) {
			http.Error(w, "Forbidden — insufficient permissions", http.StatusForbidden)
			return
		}
	}

	// Require check (generic user field gating: "plan:pro,enterprise verified:1")
	if page.Require != "" {
		userMap := LoadUserFields(app.DB, session.UserID)
		if userMap == nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if !checkRequireFields(page.Require, userMap) {
			http.Error(w, "Forbidden — requirements not met", http.StatusForbidden)
			return
		}
	}

	// Find Chrome — check once, fail fast
	chromePath := findChrome()
	if chromePath == "" {
		http.Error(w, "PDF generation unavailable — Chrome not installed", http.StatusNotImplemented)
		return
	}

	// Build render context (mirrors servePage in server.go)
	ctx := &RenderContext{
		Data:    make(map[string]any),
		User:    session,
		Request: r,
		App:     app,
		Page:    page,
	}
	ctx.Data["current_user"] = session
	if session != nil {
		ctx.Data["logged_in"] = true
		userMap := LoadUserFields(app.DB, session.UserID)
		if userMap == nil {
			userMap = make(map[string]any)
		}
		userMap["id"] = session.UserID
		userMap["email"] = session.Email
		userMap["role"] = session.Role
		if session.HasGroup() {
			userMap["org_id"] = session.GroupID
		}
		ctx.Data["user"] = userMap
		ctx.Data["user_email"] = session.Email
		ctx.Data["user_id"] = session.UserID
		ctx.Data["user_role"] = session.Role
		if session.HasGroup() {
			ctx.Data["user_group_id"] = session.GroupID
		}
	}
	ctx.Data["page_title"] = page.Title
	ctx.Data["current_path"] = pagePath

	// Populate query params
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			ctx.Data["param_"+k] = v[0]
		}
	}

	// Render the page HTML
	content, err := RenderTemplate(app, page, ctx)
	if err != nil {
		log.Printf("PDF ERROR [%s]: render failed: %s", pagePath, err.Error())
		if app.DevMode {
			http.Error(w, fmt.Sprintf("PDF render error: %s", err.Error()), http.StatusInternalServerError)
		} else {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	// Inject CSRF tokens (for form display consistency)
	content = InjectCSRF(content)

	title := page.Title
	if title == "" {
		title = strings.Title(strings.TrimPrefix(page.Route, "/"))
	}

	fullHTML := WrapLayoutWithPage(content, title, app, session, page)

	// Harden against local-file exfiltration. Headless Chrome renders this
	// from a file:// origin, where a `<iframe src="file:///.../env.yaml">`
	// (or img/object/link) in injected page content would read app-local
	// files (env.yaml, data.db) INTO the PDF. Inject a print-time CSP that
	// forbids file: subresources. We deliberately omit 'self' — on a file://
	// origin 'self' IS file://, which would re-allow the very loads we block.
	// https:/data:/inline cover legitimate PDF assets; frame/object are off
	// (PDFs don't need them and they're the primary exfil vector).
	const pdfCSP = `<meta http-equiv="Content-Security-Policy" content="default-src https: data: 'unsafe-inline'; img-src https: data:; style-src https: 'unsafe-inline'; font-src https: data:; script-src 'unsafe-inline' https:; frame-src 'none'; object-src 'none'; child-src 'none'">`
	if idx := strings.Index(strings.ToLower(fullHTML), "<head>"); idx >= 0 {
		fullHTML = fullHTML[:idx+len("<head>")] + pdfCSP + fullHTML[idx+len("<head>"):]
	} else {
		fullHTML = pdfCSP + fullHTML
	}

	// Write HTML to temp file
	tmpFile, err := os.CreateTemp("", "benmore-pdf-*.html")
	if err != nil {
		log.Printf("PDF ERROR: failed to create temp file: %s", err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(fullHTML); err != nil {
		tmpFile.Close()
		log.Printf("PDF ERROR: failed to write temp file: %s", err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	tmpFile.Close()

	// Chrome --print-to-pdf with 30-second timeout
	pdfPath := tmpFile.Name() + ".pdf"
	defer os.Remove(pdfPath)

	chromeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(chromeCtx, chromePath,
		"--headless=new",
		"--disable-gpu",
		"--no-sandbox",
		"--print-to-pdf="+pdfPath,
		"file://"+tmpFile.Name(),
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		if chromeCtx.Err() == context.DeadlineExceeded {
			log.Printf("PDF ERROR [%s]: Chrome timed out after 30s", pagePath)
			http.Error(w, "PDF generation timed out", http.StatusGatewayTimeout)
			return
		}
		log.Printf("PDF ERROR [%s]: Chrome failed: %s\n%s", pagePath, err.Error(), string(output))
		if app.DevMode {
			http.Error(w, fmt.Sprintf("PDF generation failed: %s\n%s", err.Error(), string(output)), http.StatusInternalServerError)
		} else {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	// Verify the PDF file was actually created
	if _, err := os.Stat(pdfPath); err != nil {
		log.Printf("PDF ERROR [%s]: PDF file not created", pagePath)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Build a safe filename for the download
	filename := sanitizePDFFilename(pagePath)

	// Stream the PDF response
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.pdf"`, filename))
	http.ServeFile(w, r, pdfPath)
}

// sanitizePDFFilename produces a safe filename from a page path.
// e.g., "/contacts" → "contacts", "/" → "index", "/reports/monthly" → "reports-monthly"
func sanitizePDFFilename(pagePath string) string {
	name := strings.TrimPrefix(pagePath, "/")
	if name == "" {
		return "index"
	}
	// Replace path separators with dashes
	name = strings.ReplaceAll(name, "/", "-")
	// Strip unsafe characters
	name = safeFilenameRe.ReplaceAllString(name, "")
	if name == "" {
		return "page"
	}
	return name
}

// checkRequireFields validates user fields against page require="" rules.
// Format: "plan:pro,enterprise verified:1" — space-separated, each is field:val1,val2.
func checkRequireFields(require string, userMap map[string]any) bool {
	parts := strings.Fields(require)
	for _, part := range parts {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		field := kv[0]
		allowedVals := strings.Split(kv[1], ",")

		userVal := fmt.Sprintf("%v", userMap[field])
		matched := false
		for _, allowed := range allowedVals {
			if strings.TrimSpace(allowed) == userVal {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}
