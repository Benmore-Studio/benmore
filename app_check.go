//go:build !cli

package main

// Unified validation entry point. Both the CLI (`benmore check`) and
// the MCP (write_file / edit_file response) call into RunCompleteCheck
// so the agent and a human running the CLI see the EXACT same findings
// for the same app state.
//
// The design philosophy this commit codifies: the validators ARE the
// docs. Instead of telling the agent "here's how flows.yaml works"
// across a 12-page reference, the framework says "go ahead and write
// what you think it should look like, and on every mistake the loop
// returns the corrected shape with an example." The corpus already
// knows ~95% of what to do; the validators close the remaining 5%
// gap one wrong write at a time.
//
// A complete check has four layers, run in order:
//
//   1. Per-file syntactic validation (ValidateOnWrite)
//      Reuses the dispatcher that runs in write_file/edit_file. Each
//      file type gets its dedicated validator: Prisma parser, GHA
//      flow parser, gotmpl template parser, hooks key set, app.yaml
//      key set.
//
//   2. Cross-file orphan-ref validation (CrossFileWarnings)
//      Walks hooks.yaml / workflows.yaml / flows.yaml inline SQL and
//      warns when they reference tables not declared in schema.prisma.
//
//   3. App-load smoke test
//      Calls loadApp(dir) and surfaces any error. Catches schema
//      migration failures, flow shape errors that slipped past the
//      static parser, computed-field SQL that fails to compile, etc.
//
//   4. Schema drift detection (DetectSchemaDrift)
//      Compares declared schema against the live database. Catches
//      manual ALTERs, skipped migrations, divergent state.
//
// Each layer can produce errors (the build is broken - agent must
// fix) or warnings (the build runs but the agent should know). Layers
// 3 + 4 only fire if layers 1 + 2 pass - there's no point trying to
// load an app whose schema.prisma doesn't parse.

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CheckFinding is a single validation result. The agent's job is to
// fix every Severity="error" before deploy. Severity="warning"
// findings shouldn't block but should surface in tool responses.
type CheckFinding struct {
	Severity string `json:"severity"` // "error" | "warning"
	Source   string `json:"source"`   // which validator produced this ("syntax" | "cross_file" | "app_load" | "drift")
	File     string `json:"file,omitempty"`
	Message  string `json:"message"`
}

// CheckReport is the full output of RunCompleteCheck.
type CheckReport struct {
	Findings []CheckFinding `json:"findings"`
	// Errors / Warnings split for convenience - equivalent to
	// counting Severity values, but pre-computed because the agent
	// often wants "did anything block?" without iterating.
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
}

// Clean returns true if no errors were produced (warnings are fine).
func (r CheckReport) Clean() bool { return r.Errors == 0 }

// RunCompleteCheck validates one app directory and returns a structured
// report. If `writtenPath` is non-empty, it's the file the caller just
// touched - that file's syntactic validators get priority in the report
// ordering so the agent sees their feedback first.
func RunCompleteCheck(dir, writtenPath string) CheckReport {
	var findings []CheckFinding

	// Layer 1: per-file syntactic validation. Walk every file the
	// dispatcher knows about; each gets its validator. Threading the
	// app dir through gives the gotmpl validator partial-loading and
	// any future cross-file syntactic check the context it needs.
	for _, fileCheck := range walkAppFiles(dir) {
		if msg := ValidateOnWriteIn(dir, fileCheck.relPath, fileCheck.content); msg != "" {
			findings = append(findings, CheckFinding{
				Severity: "error",
				Source:   "syntax",
				File:     fileCheck.relPath,
				Message:  msg,
			})
		}
	}

	// Layer 2: cross-file warnings.
	for _, msg := range CrossFileWarnings(dir, writtenPath) {
		findings = append(findings, CheckFinding{
			Severity: "warning",
			Source:   "cross_file",
			Message:  msg,
		})
	}

	// Layer 2.5: protected-column-name collisions (v2.7.164). A column
	// named `role` / `password_hash` on an app table collides with the
	// framework's mass-assignment protection: client-supplied values are
	// SILENTLY stripped on POST/PATCH (only the X-Stripped-Fields header
	// signals it), so the field stores empty/default and the agent burns
	// a debugging cycle. Warning, not error - the column is legal and
	// server-side writes (flows, hooks, SQL) work fine.
	findings = append(findings, protectedColumnWarnings(dir)...)

	// If we already have syntax errors there's no point trying to
	// load the app - the load will just rediscover them with worse
	// error messages.
	if countErrors(findings) == 0 {
		// Layer 3: app load. Catches schema errors, flow runtime
		// rejections, etc.
		if loadErr := tryLoadApp(dir); loadErr != "" {
			// DB-ping errors against a per-edit probe routinely
			// surface as transient false positives - the running
			// app's CRUD against the same file is healthy, the per-
			// edit check just races the WAL/SHM open or hits a
			// stale handle from the previous reload. Pre-2.7.31 this
			// flipped ok:false on the write response and produced a
			// scary `disk I/O error: no such file or directory`
			// finding for every edit while the corruption window
			// was open. Beacon + news + chat all logged this same
			// false-error pattern. Downgrade to a warning when the
			// data.db file actually exists on disk so the agent
			// doesn't burn turns chasing a phantom.
			severity := "error"
			if isTransientDBPingError(dir, loadErr) {
				severity = "warning"
			}
			findings = append(findings, CheckFinding{
				Severity: severity,
				Source:   "app_load",
				Message:  loadErr,
			})
		}

		// Layer 4: drift detection. Only meaningful when there's a
		// live database to compare against - fresh apps without a
		// data.db still produce a clean report. extra_column drift
		// is benign noise during active schema iteration (agent
		// removes a field, the live column lingers until pruned) and
		// stays suppressed. extra_table USED to be suppressed for the
		// same reason, but in practice orphaned tables DO change app
		// behavior - auto-CRUD still mounts /api/<table> against them,
		// which can shadow or panic-collide with a flow at the same
		// path, and agents that hit "unfamiliar table in describe"
		// reach for hallucinated explanations ("framework template
		// inference") instead of cleanup. Surface them as warnings
		// with a prescriptive fix (prisma_prune).
		if drifts := tryDriftCheck(dir); len(drifts) > 0 {
			for _, d := range drifts {
				// extra_column stays suppressed - really is benign.
				if d.Kind == "extra_column" {
					continue
				}
				where := d.Table
				if d.Column != "" {
					where = d.Table + "." + d.Column
				}
				findings = append(findings, CheckFinding{
					Severity: "warning",
					Source:   "drift",
					Message:  fmt.Sprintf("[%s] %s: %s", d.Kind, where, d.Detail),
				})
			}
		}
	}

	rpt := CheckReport{Findings: findings}
	for _, f := range findings {
		if f.Severity == "error" {
			rpt.Errors++
		} else {
			rpt.Warnings++
		}
	}
	return rpt
}

// FormatReport renders a CheckReport for human consumption (CLI). The
// MCP path uses the structured Findings directly so the agent can
// react per-issue.
func FormatReport(rpt CheckReport) string {
	if rpt.Clean() && rpt.Warnings == 0 {
		return "check: clean - no issues found.\n"
	}
	var b strings.Builder
	if rpt.Errors > 0 {
		fmt.Fprintf(&b, "check: %d error(s)", rpt.Errors)
		if rpt.Warnings > 0 {
			fmt.Fprintf(&b, ", %d warning(s)", rpt.Warnings)
		}
		b.WriteByte('\n')
	} else {
		fmt.Fprintf(&b, "check: %d warning(s)\n", rpt.Warnings)
	}
	for _, f := range rpt.Findings {
		label := strings.ToUpper(f.Severity)
		if f.File != "" {
			fmt.Fprintf(&b, "\n%s [%s] %s:\n", label, f.Source, f.File)
		} else {
			fmt.Fprintf(&b, "\n%s [%s]:\n", label, f.Source)
		}
		// Indent the message for readability.
		for _, line := range strings.Split(f.Message, "\n") {
			fmt.Fprintf(&b, "  %s\n", line)
		}
	}
	return b.String()
}

// walkAppFiles returns the contents of every file in the app
// directory that has a dedicated validator. We don't try to validate
// every file (CSS, static assets, etc.) - only the ones whose
// per-file validator is wired up in ValidateOnWrite.
// serveBootCheck runs the unified validators at `benmore serve` boot
// and prints findings to stderr (v2.7.164). Non-fatal: serve still
// boots; the point is that a broken flow file no longer loads silently
// only to be rejected later at push time. The validator stack now lives
// in the shared (`!cli`) build, so this runs in the framework and cloud
// editions too - the old platform-only no-op shim was removed.
func serveBootCheck(dir string) {
	report := RunCompleteCheck(dir, "")
	if len(report.Findings) == 0 {
		return
	}
	fmt.Fprintln(os.Stderr, FormatReport(report))
	if report.Errors > 0 {
		fmt.Fprintf(os.Stderr, "⚠ %d error(s) above - the app will boot, but these would be rejected by `benmore push` / the platform write gate.\n\n", report.Errors)
	}
}

// protectedColumnWarnings scans schema.prisma for column names that
// collide with the framework's protected-field strip list. See the
// Layer 2.5 comment in RunCompleteCheck.
func protectedColumnWarnings(dir string) []CheckFinding {
	data, err := os.ReadFile(filepath.Join(dir, "schema.prisma"))
	if err != nil {
		return nil
	}
	models, err := ParsePrismaSchema(string(data))
	if err != nil {
		return nil // parse errors are Layer 1's job
	}
	// Only the names whose stripping is genuinely surprising. user_id /
	// created_at / updated_at are framework-managed on purpose and
	// their semantics are what an agent wants when declaring them.
	collisions := map[string]string{
		"role":          "rename it to something domain-specific (member_role, applicant_role, …)",
		"password_hash": "the framework manages credentials in _benmore_users; store app-level secrets under a different name",
	}
	var findings []CheckFinding
	for _, m := range models {
		for _, f := range m.Fields {
			if fix, hit := collisions[strings.ToLower(f.Column)]; hit {
				findings = append(findings, CheckFinding{
					Severity: "warning",
					Source:   "schema",
					File:     "schema.prisma",
					Message: fmt.Sprintf("%s.%s collides with a framework-protected field name: client-supplied values are silently stripped on POST/PATCH (the row saves with the column empty/default; only the X-Stripped-Fields response header signals it). If clients need to write this field, %s. Server-side writes (flows, hooks, benmore sql) are unaffected.",
						m.Table, f.Column, fix),
				})
			}
		}
	}
	return findings
}

func walkAppFiles(dir string) []fileCheck {
	candidates := []string{
		"schema.prisma",
		"schema.sql",
		"app.yaml",
		"flows.yaml",
		"hooks.yaml",
		"workflows.yaml",
		"computed.yaml",
		"encrypted.yaml",
		"retention.yaml",
	}
	var out []fileCheck
	for _, rel := range candidates {
		if data, err := os.ReadFile(filepath.Join(dir, rel)); err == nil {
			out = append(out, fileCheck{relPath: rel, content: string(data)})
		}
	}
	// HTML pages - scan the top-level directory only (the page loader
	// is also flat).
	entries, err := os.ReadDir(dir)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".html") {
				continue
			}
			if data, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil {
				out = append(out, fileCheck{relPath: e.Name(), content: string(data)})
			}
		}
	}
	// partials/*.html - each gets its own validation pass so a broken
	// partial surfaces independently rather than only as a vague
	// "no such template" error in every page that uses it. Layouts
	// and emails get the same treatment because they're agent-written
	// HTML with the same failure modes.
	for _, sub := range []string{"partials", "layouts", "emails"} {
		subEntries, err := os.ReadDir(filepath.Join(dir, sub))
		if err != nil {
			continue
		}
		for _, e := range subEntries {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".html") {
				continue
			}
			rel := filepath.Join(sub, e.Name())
			if data, err := os.ReadFile(filepath.Join(dir, rel)); err == nil {
				out = append(out, fileCheck{relPath: rel, content: string(data)})
			}
		}
	}
	// tests/*.yaml - developer-written test cases. The YAML fallback
	// validator catches indentation/syntax mistakes before the runner
	// rejects them with a less-useful error.
	testEntries, err := os.ReadDir(filepath.Join(dir, "tests"))
	if err == nil {
		for _, e := range testEntries {
			if e.IsDir() || !(strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
				continue
			}
			rel := filepath.Join("tests", e.Name())
			if data, err := os.ReadFile(filepath.Join(dir, rel)); err == nil {
				out = append(out, fileCheck{relPath: rel, content: string(data)})
			}
		}
	}

	// src/**/*.{tsx,jsx,ts,js} - the React+TS bundle source. Recursive
	// because larger apps split into src/components/, src/lib/, etc.
	// The dispatcher runs detectFrameworkAntipatterns for SPA source
	// (CDN imports, ReactDOM.createRoot, localStorage auth, bare fetch
	// mutations, npm-package imports, etc.).
	srcDir := filepath.Join(dir, "src")
	filepath.WalkDir(srcDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || d == nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".tsx" && ext != ".jsx" && ext != ".ts" && ext != ".js" {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return nil
		}
		if data, err := os.ReadFile(path); err == nil {
			out = append(out, fileCheck{relPath: rel, content: string(data)})
		}
		return nil
	})

	// tsconfig.json - strict-mode + JSX factory check. tsc is editor-
	// only (esbuild does the actual build), but the agent occasionally
	// flips "jsx": "react-jsx" thinking it's a free upgrade - that
	// breaks the globals plugin. validateTSConfig surfaces it.
	if data, err := os.ReadFile(filepath.Join(dir, "tsconfig.json")); err == nil {
		out = append(out, fileCheck{relPath: "tsconfig.json", content: string(data)})
	}

	// Forbidden paths - package.json, node_modules/, lock files, etc.
	// Surface their EXISTENCE as a finding regardless of content. The
	// dispatcher's validateForbiddenPath checks the path string; we
	// just need to feed it any path that matches.
	for _, name := range []string{"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", ".npmrc", "webpack.config.js", "vite.config.js", "vite.config.ts"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			out = append(out, fileCheck{relPath: name, content: ""})
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "node_modules")); err == nil {
		out = append(out, fileCheck{relPath: "node_modules", content: ""})
	}
	return out
}

type fileCheck struct {
	relPath string
	content string
}

func countErrors(fs []CheckFinding) int {
	n := 0
	for _, f := range fs {
		if f.Severity == "error" {
			n++
		}
	}
	return n
}

// isTransientDBPingError reports whether loadErr looks like a
// per-probe DB-ping race rather than a true app-load failure. The
// pattern shows up across sessions as `ping database (corrupt + no
// usable backup): disk I/O error: no such file or directory` while
// the running app's CRUD against the same data.db keeps working -
// usually because the probe opens a fresh handle and races a hot-
// reload that's mid-rebinding WAL/SHM.
//
// We're conservative on what we demote: ONLY ping-error shapes, and
// ONLY when the data.db file actually exists on disk. Anything else
// (e.g. "schema error", "flow runtime rejection") stays an error.
func isTransientDBPingError(dir, loadErr string) bool {
	if !strings.Contains(loadErr, "ping database") &&
		!strings.Contains(loadErr, "disk I/O error: no such file") {
		return false
	}
	if st, err := os.Stat(filepath.Join(dir, "data.db")); err != nil || st.Size() == 0 {
		// Genuinely missing or zero-byte DB → keep the error.
		return false
	}
	return true
}

// tryLoadApp returns an error string if loading the app fails. Uses
// loadApp from main.go but routes any DB it opens to a temp location
// so a stale data.db on disk doesn't poison subsequent calls (most
// tests run inside t.TempDir() anyway; CLI users hit the real db
// which is the right behavior for `benmore check`).
func tryLoadApp(dir string) string {
	app, err := loadApp(dir)
	if err != nil {
		return err.Error()
	}
	if app != nil && app.DB != nil {
		app.DB.Close()
	}
	return ""
}

// tryDriftCheck reads the declared schema, opens the live database
// (if present), and returns drift findings. Errors during the
// drift check itself are swallowed - the check is best-effort and
// shouldn't fail the whole report.
func tryDriftCheck(dir string) []SchemaDrift {
	dbPath := filepath.Join(dir, "data.db")
	if _, err := os.Stat(dbPath); err != nil {
		return nil
	}
	models, err := LoadSchemaModelsForDrift(dir)
	if err != nil || len(models) == 0 {
		return nil
	}
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil
	}
	defer db.Close()
	drifts, err := DetectSchemaDrift(db, models)
	if err != nil {
		return nil
	}
	return drifts
}
