//go:build !cli

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// pdfLimiter enforces 10 PDFs/minute per user/IP - PDF generation is expensive.
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
func RegisterPDFRoutes(mux appRouteRegistrar, app *App) {
	mux.HandleFunc("GET /pdf/{page...}", func(w http.ResponseWriter, r *http.Request) {
		handlePDFRender(w, r, app)
	})
}

// pdfServerError keeps a PDF failure in the request log (the PDF ERROR line
// is the journal's copy) and answers: devText in dev mode, as before; the
// generic text and the request id otherwise.
func pdfServerError(w http.ResponseWriter, r *http.Request, app *App, status int, err error, devText string) {
	id := recordRequestError(r, serverErrorDetail("pdf "+r.URL.Path, err))
	w.Header().Set(requestIDHeader, id)
	if serverErrorDevMode(app) && devText != "" {
		http.Error(w, devText, status)
		return
	}
	public := "Internal Server Error"
	if status == http.StatusGatewayTimeout {
		public = "PDF generation timed out"
	}
	http.Error(w, publicServerErrorText(public, id), status)
}

func handlePDFRender(w http.ResponseWriter, r *http.Request, app *App) {
	if !app.FeatureEnabled("exports") {
		http.NotFound(w, r)
		return
	}
	// Rate limit: identify by user ID if authenticated, otherwise by the
	// client's address bucket (never RemoteAddr: its port changes with every
	// connection, and behind the router the peer is loopback).
	rateLimitKey := appLimiterKey(app, "pdf", clientRateBucket(rateLimitClientHost(r)))
	session := getSession(app, r)
	if session != nil {
		rateLimitKey = appLimiterKey(app, "pdf", fmt.Sprintf("user:%d", session.UserID))
	}
	if !pdfLimiter.Allow(rateLimitKey) {
		http.Error(w, "Too many PDF requests - try again later", http.StatusTooManyRequests)
		return
	}

	// Resolve the requested page path
	pageParam := r.PathValue("page")
	pagePath := "/" + pageParam
	if pagePath == "/" {
		pagePath = "/"
	}

	// Validate page exists - no path traversal, must be in app.Pages
	page, ok := app.Pages[pagePath]
	if !ok {
		http.NotFound(w, r)
		return
	}

	// Auth check - same rules as page rendering
	if page.Auth == "required" || page.Require != "" {
		if session == nil {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
	}

	// Role check
	requiredRole := pageRole(page)
	if requiredRole != "" {
		if session == nil {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		if !pageRoleAllowed(app, session, requiredRole) {
			http.Error(w, "Forbidden - insufficient permissions", http.StatusForbidden)
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
			http.Error(w, "Forbidden - requirements not met", http.StatusForbidden)
			return
		}
	}

	// Role-based redirect, as servePage applies it: a page that sends this
	// caller elsewhere (or is taken offline with redirect="*:/") is not
	// printed either.
	if page.Redirect != "" {
		role := ""
		if session != nil {
			role = session.Role
		}
		if target := matchRoleRedirect(page.Redirect, role); target != "" {
			http.Redirect(w, r, target, http.StatusSeeOther)
			return
		}
	}

	// Find Chrome - check once, fail fast
	chromePath := findChrome()
	if chromePath == "" {
		http.Error(w, "PDF generation unavailable - Chrome not installed", http.StatusNotImplemented)
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
		pdfServerError(w, r, app, http.StatusInternalServerError, fmt.Errorf("render failed: %w", err), fmt.Sprintf("PDF render error: %s", err.Error()))
		return
	}

	// Inject CSRF tokens (for form display consistency)
	content = InjectCSRF(content)

	title := page.Title
	if title == "" {
		title = strings.Title(strings.TrimPrefix(page.Route, "/"))
	}

	fullHTML := WrapLayoutWithPage(content, title, app, session, page)

	// Render inside the sandbox (pdf_sandbox.go): the document is served
	// from an isolated http origin and every request Chrome makes goes
	// through a proxy that serves only this document and tunnels HTTPS only
	// to the hosts the page CSP names.
	csp, hosts := pdfPolicy(app)
	sandbox, err := newPDFSandbox([]byte(fullHTML), csp, hosts)
	if err != nil {
		log.Printf("PDF ERROR: sandbox: %s", err.Error())
		pdfServerError(w, r, app, http.StatusInternalServerError, fmt.Errorf("sandbox: %w", err), "")
		return
	}
	defer sandbox.Close()

	workDir, err := os.MkdirTemp("", "benmore-pdf-*")
	if err != nil {
		log.Printf("PDF ERROR: failed to create work dir: %s", err.Error())
		pdfServerError(w, r, app, http.StatusInternalServerError, fmt.Errorf("work dir: %w", err), "")
		return
	}
	defer os.RemoveAll(workDir)
	pdfPath := filepath.Join(workDir, "out.pdf")

	// Chrome --print-to-pdf with 30-second timeout
	chromeCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(chromeCtx, chromePath,
		pdfChromeArgs(sandbox.ProxyAddr(), sandbox.DocURL(), pdfPath, filepath.Join(workDir, "profile"))...)
	// Chrome's helper processes can outlive a killed parent and hold the
	// output pipe open; stop waiting for them shortly after the timeout.
	cmd.WaitDelay = 5 * time.Second

	output, err := runPDFChrome(chromeCtx, cmd, pdfPath)
	if err != nil {
		if chromeCtx.Err() == context.DeadlineExceeded {
			log.Printf("PDF ERROR [%s]: Chrome timed out after 30s: %v", pagePath, err)
			pdfServerError(w, r, app, http.StatusGatewayTimeout, fmt.Errorf("Chrome timed out after 30s: %w", err), "PDF generation timed out")
			return
		}
		log.Printf("PDF ERROR [%s]: Chrome failed: %s\n%s", pagePath, err.Error(), string(output))
		pdfServerError(w, r, app, http.StatusInternalServerError, fmt.Errorf("Chrome failed: %w: %s", err, output), fmt.Sprintf("PDF generation failed: %s\n%s", err.Error(), string(output)))
		return
	}

	// Verify the PDF file was actually created
	if !pdfOutputComplete(pdfPath) {
		log.Printf("PDF ERROR [%s]: PDF file not created", pagePath)
		pdfServerError(w, r, app, http.StatusInternalServerError, errors.New("PDF file not created"), "")
		return
	}

	// Build a safe filename for the download
	filename := sanitizePDFFilename(pagePath)

	// Stream the PDF response
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.pdf"`, filename))
	http.ServeFile(w, r, pdfPath)
}

// Chrome can finish printing while desktop helper processes keep it alive.
// Reuse the existing process-group cancellation, and stop the private job only
// after a complete PDF and the same settling period used by the sandbox test.
func runPDFChrome(ctx context.Context, cmd *exec.Cmd, path string) (result []byte, resultErr error) {
	// Chrome's --user-data-dir does not contain desktop caches (fontconfig,
	// dconf and XDG helpers). Keep those in this private job too, including
	// when startup fails before a PDF exists. The callers own the output dir.
	home, err := os.MkdirTemp(filepath.Dir(path), "chrome-home-")
	if err != nil {
		return nil, fmt.Errorf("PDF runtime home: %w", err)
	}
	// Registered before process cleanup, so cancellation and Wait complete
	// before removing the runtime home. Retain both errors if rendering failed.
	defer func() {
		if cleanupErr := os.RemoveAll(home); cleanupErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("PDF runtime home cleanup: %w", cleanupErr))
		}
	}()
	runtimeDirs := map[string]string{
		"HOME":            home,
		"XDG_CACHE_HOME":  filepath.Join(home, "cache"),
		"XDG_CONFIG_HOME": filepath.Join(home, "config"),
		"XDG_DATA_HOME":   filepath.Join(home, "data"),
		"XDG_RUNTIME_DIR": filepath.Join(home, "runtime"),
	}
	for _, dir := range runtimeDirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("PDF runtime directory: %w", err)
		}
	}
	env := cmd.Environ()
	cmd.Env = make([]string, 0, len(env)+len(runtimeDirs))
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if _, replaced := runtimeDirs[key]; !replaced {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	for key, dir := range runtimeDirs {
		cmd.Env = append(cmd.Env, key+"="+dir)
	}
	setTranscribeProcAttrs(cmd)
	if cmd.WaitDelay == 0 {
		cmd.WaitDelay = 5 * time.Second
	}
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	defer cmd.Cancel() // Clean helpers even when the direct child exits first.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			if ctx.Err() != nil {
				return output.Bytes(), ctx.Err()
			}
			return output.Bytes(), err
		case <-ctx.Done():
			_ = cmd.Cancel()
			<-done
			return output.Bytes(), ctx.Err()
		case <-ticker.C:
			if !pdfOutputComplete(path) {
				continue
			}
			settle := time.NewTimer(500 * time.Millisecond)
			select {
			case err := <-done:
				settle.Stop()
				if ctx.Err() != nil {
					return output.Bytes(), ctx.Err()
				}
				return output.Bytes(), err
			case <-ctx.Done():
				_ = cmd.Cancel()
				settle.Stop()
				<-done
				return output.Bytes(), ctx.Err()
			case <-settle.C:
			}
			if !pdfOutputComplete(path) {
				continue
			}
			// Wait always completes before exposing output or removing the
			// profile; caller WaitDelay bounds inherited pipe cleanup.
			stopErr := cmd.Cancel()
			waitErr := <-done
			if ctx.Err() != nil {
				return output.Bytes(), ctx.Err()
			}
			if stopErr != nil && waitErr != nil {
				return output.Bytes(), waitErr
			}
			var exitErr *exec.ExitError
			if waitErr != nil && !errors.As(waitErr, &exitErr) {
				return output.Bytes(), waitErr
			}
			return output.Bytes(), nil
		}
	}
}

// Check only the fixed header and tail; polling never rereads a whole report.
func pdfOutputComplete(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	var header [5]byte
	if _, err := io.ReadFull(file, header[:]); err != nil || string(header[:]) != "%PDF-" {
		return false
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 10 {
		return false
	}
	n := info.Size()
	if n > 1024 {
		n = 1024
	}
	tail := make([]byte, n)
	if _, err := file.ReadAt(tail, info.Size()-n); err != nil {
		return false
	}
	return bytes.HasSuffix(bytes.TrimSpace(tail), []byte("%%EOF"))
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
// Format: "plan:pro,enterprise verified:1" - space-separated, each is field:val1,val2.
func checkRequireFields(require string, userMap map[string]any) bool {
	parts := strings.Fields(require)
	// A require= made only of malformed parts ("plan=pro", ":pro") used to
	// check nothing and admit every signed-in user. A gate that names no
	// field it can check refuses instead.
	valid := 0
	for _, part := range parts {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 || kv[0] == "" {
			continue
		}
		valid++
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
	return valid > 0
}
