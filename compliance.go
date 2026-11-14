//go:build !cli

package main

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// complianceHIPAA is the one value of app.yaml `compliance:` (a single
// opt-in enum; unset keeps today's behavior). Each stricter default that
// applies only under it is listed in api(at:"compliance").
const complianceHIPAA = "hipaa"

// complianceAppYAMLProblem is the one check of the `compliance:` key, shared
// by the write gate and `benmore check` (validateAppYAML) and by the loader,
// so an app.yaml hand-edited onto a host cannot run with a value the gates
// refuse. It returns "" for an unset key.
func complianceAppYAMLProblem(doc map[string]any) string {
	v, present := doc["compliance"]
	if !present {
		return ""
	}
	if s, ok := v.(string); !ok || s != complianceHIPAA {
		return fmt.Sprintf("app.yaml: compliance = %v is not recognized. The only value is `hipaa` (stricter defaults for apps holding PHI; api(at:\"compliance\"), or `benmore docs compliance` for the summary). Remove the key to keep the standard behavior.", v)
	}
	if rec, _ := doc["recording"].(map[string]any); rec != nil {
		for _, key := range []string{"enabled", "production"} {
			if on, _ := canonicalAuthFlag(anyToString(rec[key])); on == "true" {
				return fmt.Sprintf("app.yaml: compliance: hipaa keeps the session recorder off (DOM snapshots and input events would capture PHI); remove recording.%s.", key)
			}
		}
	}
	auth, _ := doc["auth"].(map[string]any)
	if v, set := auth["idle_timeout"]; set {
		lo, hi := idleTimeoutText(minIdleTimeout), idleTimeoutText(hipaaMaxIdleTimeout)
		d, ok := parseIdleTimeout(anyToString(v))
		if !ok && d == 0 { // not a duration at all (a bare number, a word); parseIdleTimeout returns 0 for those
			return fmt.Sprintf("app.yaml: auth.idle_timeout = %v is not a duration: write a number with a unit (s, m or h), e.g. \"10m\". compliance: hipaa requires a value between %s and %s (default %s). Remove the key to take the default.", v, lo, hi, hi)
		}
		if !ok || d <= 0 || d > hipaaMaxIdleTimeout {
			return fmt.Sprintf("app.yaml: compliance: hipaa requires auth.idle_timeout between %s and %s (default %s); got %v. Remove the key to take the default.", lo, hi, hi, v)
		}
	}
	if v, set := auth["read_audit_sync"]; set {
		if on, _ := canonicalAuthFlag(anyToString(v)); on != "true" {
			return fmt.Sprintf("app.yaml: compliance: hipaa writes every read-audit event before the read answers (a failed write fails the read), so auth.read_audit_sync cannot be turned off; got %v. Remove the key.", v)
		}
	}
	if v, set := auth["read_audit"]; set && !hipaaReadAuditValueValid(v) {
		return fmt.Sprintf("app.yaml: compliance: hipaa audits reads of every table by default, so auth.read_audit must be \"*\" or a comma-separated list of table names; got %v, which would audit none. Remove the key (every table) or list the tables that hold PHI.", v)
	}
	if v, set := auth["require_mfa_for_roles"]; set && !listsAllRoles(anyToString(v)) {
		return fmt.Sprintf("app.yaml: compliance: hipaa requires every account to enroll MFA, so auth.require_mfa_for_roles must be \"*\" (or include it); got %v. Remove the key to take the default.", v)
	}
	return ""
}

// hipaaReadAuditValueValid accepts auth.read_audit under hipaa: "*" or a
// non-empty comma list of plain identifiers (a YAML boolean, "," or an empty
// entry would audit nothing). Whether each name is a declared table is checked
// where the schema is at hand (hipaaReadAuditTablesProblem); at run time a
// name that is no table makes IsReadAudited audit every table.
func hipaaReadAuditValueValid(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	if strings.TrimSpace(s) == "*" {
		return true
	}
	for _, part := range strings.Split(s, ",") {
		if !membershipIdentRe.MatchString(strings.TrimSpace(part)) {
			return false
		}
	}
	return true
}

// hipaaReadAuditTablesProblem refuses a hipaa auth.read_audit list naming a
// table the app's schema does not declare (write gate and `benmore check`).
// Without a readable schema it is not checked.
func hipaaReadAuditTablesProblem(appDir, content string) string {
	var doc map[string]any
	if err := decodeConfigYAML([]byte(content), &doc); err != nil || doc["compliance"] != complianceHIPAA {
		return ""
	}
	auth, _ := doc["auth"].(map[string]any)
	list, _ := auth["read_audit"].(string)
	if list == "" || strings.TrimSpace(list) == "*" {
		return ""
	}
	db := whenSchemaDB(appDir)
	if db == nil {
		return ""
	}
	defer db.Close()
	for _, name := range splitComma(list) {
		if cols, err := tableColumnsWith(db, name); err != nil || len(cols) == 0 {
			return fmt.Sprintf("app.yaml: compliance: hipaa: auth.read_audit names %q, which is not a table in the schema, so its reads would not be audited. List declared tables, or remove the key to audit every table.", name)
		}
	}
	return ""
}

// listsAllRoles reports whether a comma-separated role list includes "*".
func listsAllRoles(list string) bool {
	for _, r := range strings.Split(list, ",") {
		if strings.TrimSpace(r) == "*" {
			return true
		}
	}
	return false
}

// appYAMLDeclaresHIPAA reports whether an app.yaml sets `compliance: hipaa`.
// It decodes the document generically and reads only that key, so a file the
// full config parser refuses for an unrelated section still answers; a file
// that is not a YAML mapping at all is an error, never "no".
func appYAMLDeclaresHIPAA(data []byte) (bool, error) {
	var doc map[string]any
	if err := decodeConfigYAML(data, &doc); err != nil {
		return false, err
	}
	return doc["compliance"] == complianceHIPAA, nil
}

// hipaaStickyForAppDir reports whether the platform has recorded the app whose
// instance directory is appDir as `compliance: hipaa` (compliance_sticky.go).
// It is nil outside the platform edition and answers false in any process
// without the control database (a tenant app, `benmore serve`).
var hipaaStickyForAppDir func(appDir string) bool

// complianceRemovalProblem refuses an app.yaml without `compliance: hipaa` for
// an app the platform has recorded as hipaa: the switch only turns on, because
// the router-side refusals (refresh_dev data copies, GitHub sync) must not be
// lifted by an editor deleting one line. Shared by the write gate and
// `benmore check` through validateOnWriteIn.
func complianceRemovalProblem(appDir, content string) string {
	if appDir == "" || hipaaStickyForAppDir == nil {
		return ""
	}
	if hipaa, err := appYAMLDeclaresHIPAA([]byte(content)); err != nil || hipaa {
		return "" // a parse error is validateAppYAML's to report
	}
	if !hipaaStickyForAppDir(appDir) {
		return ""
	}
	return "app.yaml: this app is recorded as `compliance: hipaa`, so the key cannot be removed or changed: keep `compliance: hipaa`. The record is permanent from the app's side; a platform operator clears it after confirming the app holds no PHI (release runbook, \"HIPAA compliance record\")."
}

// hipaaMaxIdleTimeout is both the default and the ceiling of auth.idle_timeout
// under `compliance: hipaa`.
const hipaaMaxIdleTimeout = 15 * time.Minute

// hipaaMinAuditRetention is the shortest audit retention a hipaa app accepts
// (6 years, the HIPAA documentation retention period).
const hipaaMinAuditRetention = 6 * 365 * 24 * time.Hour

// mfaRequiredRoles is auth.require_mfa_for_roles, which `compliance: hipaa`
// defaults to "*" (every account) for an app that has sign-in at all. Resolved
// here, not written into Design.Auth, because the presence of auth keys means
// "auth is configured" elsewhere (NeedsAuth); an app with no auth: block and no
// page that needs a session has no accounts to enroll.
func mfaRequiredRoles(app *App) string {
	if app == nil || app.Design == nil {
		return ""
	}
	if v, set := app.Design.Auth["require_mfa_for_roles"]; set || !app.hipaa() || !NeedsAuth(app) {
		return strings.TrimSpace(v)
	}
	return "*"
}

// hipaa reports whether the app opted into `compliance: hipaa`.
func (a *App) hipaa() bool {
	design := a.designConfig()
	return design != nil && design.Compliance == complianceHIPAA
}

// hipaaPublicUploadRefusal is the answer to a public upload kind in a hipaa app.
func hipaaPublicUploadRefusal(kind string) string {
	return fmt.Sprintf("upload kind %q is a PUBLIC folder, and compliance: hipaa stores every upload privately (signed URLs only). Omit kind (the default is private) or use kind=private; api(at:\"uploads\").", kind)
}

// uploadKindLiterals finds upload kinds written as literals in an upload
// call: bm.upload(file, {kind: 'x'}) (the options inside the call's own
// parentheses), and formData.append('kind', 'x') or an HTML
// <input name="kind" value="x"> in a file that sends to /api/_upload or
// /api/_files (uploadFormKindLiterals). A kind: or a 'kind' field elsewhere
// (a toast's kind, a feedback form) is not an upload kind.
// shortcut: literal kinds only (a kind built at runtime, or an options
// object holding a call before kind:, is not seen); the runtime refusal in
// POST /api/_upload is the control, this catches the usual spelling at write
// time.
var uploadKindLiterals = []*regexp.Regexp{
	regexp.MustCompile(`\bupload\s*\([^;()]{0,400}?\bkind\s*:\s*['"]([^'"]*)['"]`),
}

var uploadFormKindLiterals = []*regexp.Regexp{
	regexp.MustCompile(`append\(\s*['"]kind['"]\s*,\s*['"]([^'"]*)['"]`),
	regexp.MustCompile(`(?i)<input[^>]*\bname\s*=\s*['"]kind['"][^>]*\bvalue\s*=\s*['"]([^'"]*)['"]`),
}

// hipaaUploadKindProblem refuses app source that asks POST /api/_upload for
// a public kind in an app whose app.yaml sets compliance: hipaa (the request
// would be refused at run time). Shared by the write gate and `benmore check`
// through validateOnWriteIn.
func hipaaUploadKindProblem(appDir, path, content string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".ts", ".tsx", ".js", ".jsx", ".mjs", ".html":
	default:
		return ""
	}
	if appDir == "" {
		return ""
	}
	if hipaa, _ := appYAMLDeclaresHIPAA(readAppFileOrNil(appDir, "app.yaml")); !hipaa {
		return ""
	}
	patterns := uploadKindLiterals
	if strings.Contains(content, "/api/_upload") || strings.Contains(content, "/api/_files") {
		patterns = append(append([]*regexp.Regexp{}, patterns...), uploadFormKindLiterals...)
	}
	for _, re := range patterns {
		for _, m := range re.FindAllStringSubmatch(content, -1) {
			if m[1] == "" {
				continue // an empty kind is the private default
			}
			if kind, err := normalizeUploadKind(m[1]); err != nil || kind != "private" {
				return path + ": " + hipaaPublicUploadRefusal(m[1])
			}
		}
	}
	return ""
}
