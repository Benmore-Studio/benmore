//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"weak"
)

// inferColumnValidation generates validation rules from column name and type.
//
// "required" means the client MUST send a value. A NOT NULL column with a
// DEFAULT expression doesn't need a client-supplied value - the database
// fills in the default if the column is omitted from the INSERT. Marking
// such columns as required would force the client to send a redundant
// hidden input for every defaulted column, which is exactly the failure
// agents keep hitting on tables like `todos(done INTEGER NOT NULL DEFAULT 0)`.
func inferColumnValidation(col Column) string {
	var rules []string
	if col.NotNull && col.Default == "" {
		rules = append(rules, "required")
	}
	name := strings.ToLower(col.Name)
	if strings.Contains(name, "email") {
		rules = append(rules, "email")
	}
	if strings.Contains(name, "phone") {
		rules = append(rules, "phone")
	}
	if strings.Contains(name, "url") || strings.Contains(name, "website") {
		rules = append(rules, "url")
	}
	if len(rules) == 0 {
		return ""
	}
	return ` :validate="` + strings.Join(rules, ",") + `"`
}

var (
	validateAttrRe = regexp.MustCompile(`:validate="([^"]+)"`)
	emailRe        = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	phoneRe        = regexp.MustCompile(`^[\d\s\-\+\(\)]{7,20}$`)
	urlRe          = regexp.MustCompile(`^https?://[^\s/$.?#].[^\s]*$`)

	// A field's name and its :validate rules, in either attribute order.
	validateNameFirstRe = regexp.MustCompile(`name="([^"]+)"[^>]*:validate="([^"]+)"`)
	validateNameLastRe  = regexp.MustCompile(`:validate="([^"]+)"[^>]*name="([^"]+)"`)
)

// ValidationError represents a single field validation failure.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

type validationMetadataError struct{ cause error }

func (e *validationMetadataError) Error() string {
	return "field validation metadata could not be read"
}
func (e *validationMetadataError) Unwrap() error { return e.cause }

// ExtractValidationRules parses :validate attributes from page HTML for a given table.
func ExtractValidationRules(app *App, table string) map[string]string {
	rules, _ := ExtractValidationRulesWith(app, table, app.DB)
	return rules
}

// ExtractValidationRulesWith uses the caller's query connection so a mutation
// transaction never borrows the application pool while holding its only slot.
//
// Scanning every page's HTML used to run on every create/batch/ingest; the
// page-derived part is now computed once per table per loaded page set
// (pageValidationRulesFor). Schema-inferred rules for auto forms still read
// the columns through q on every call.
func ExtractValidationRulesWith(app *App, table string, q mutationQuerier) (map[string]string, error) {
	pr := pageValidationRulesFor(app, table)
	rules := make(map[string]string, len(pr.attrs))
	if pr.auto {
		// Generate rules from schema
		cols, err := mainTableColumnsWith(q, table)
		if err != nil {
			return nil, &validationMetadataError{cause: err}
		}
		for _, col := range cols {
			if col.PK || col.Name == "user_id" || col.Name == "created_at" || col.Name == "updated_at" {
				continue
			}
			v := inferColumnValidation(col)
			if v != "" {
				// Extract just the rules from :validate="rules"
				v = strings.TrimPrefix(v, ` :validate="`)
				v = strings.TrimSuffix(v, `"`)
				rules[col.Name] = v
			}
		}
	}
	// Explicit :validate attributes win over schema-inferred rules.
	for field, r := range pr.attrs {
		rules[field] = r
	}
	return rules, nil
}

// pageValidationRules is what the app's pages say about one table's
// validation: whether some page renders an auto form for it (schema rules
// apply), and the :validate rules declared on fields of its :create forms.
// Read-only once built.
type pageValidationRules struct {
	auto  bool
	attrs map[string]string
}

// validationRulesCacheEntry holds pageValidationRules for one app, built
// from one generation of app.Pages (a load or reload assigns a new map).
// The entry keeps that map itself, not just its address: once a collected
// generation's address is reused by a later map, an address-only key would
// match it and serve the old generation's rules.
type validationRulesCacheEntry struct {
	mu     sync.Mutex
	pages  map[string]*Page
	tables map[string]*pageValidationRules
}

// validationRulesMaxTables bounds the per-app cache: table names come from
// request paths, and a miss past the bound is computed without caching.
const validationRulesMaxTables = 1024

// validationRulesCache maps a weak *App to its entry; the entry is dropped
// when the App is collected.
var validationRulesCache sync.Map // weak.Pointer[App] -> *validationRulesCacheEntry

func pageValidationRulesFor(app *App, table string) *pageValidationRules {
	if app.DevMode {
		// Dev mode re-reads a page's source in place on each request
		// (server.go), which the map identity below can't see.
		return scanPageValidationRules(app.Pages, table)
	}
	// Read app.Pages once: a concurrent reload must not pair one
	// generation's identity with another's scan.
	pages := app.Pages
	key := weak.Make(app)
	v, loaded := validationRulesCache.Load(key)
	if !loaded {
		v, loaded = validationRulesCache.LoadOrStore(key, &validationRulesCacheEntry{})
		if !loaded {
			runtime.AddCleanup(app, func(k weak.Pointer[App]) { validationRulesCache.Delete(k) }, key)
		}
	}
	entry := v.(*validationRulesCacheEntry)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.tables == nil || reflect.ValueOf(entry.pages).Pointer() != reflect.ValueOf(pages).Pointer() {
		entry.pages, entry.tables = pages, map[string]*pageValidationRules{}
	}
	if pr, ok := entry.tables[table]; ok {
		return pr
	}
	pr := scanPageValidationRules(pages, table)
	if len(entry.tables) < validationRulesMaxTables {
		entry.tables[table] = pr
	}
	return pr
}

func scanPageValidationRules(pages map[string]*Page, table string) *pageValidationRules {
	pr := &pageValidationRules{attrs: map[string]string{}}
	modelAttr, createAttr := fmt.Sprintf(`:model="%s"`, table), fmt.Sprintf(`:create="%s"`, table)
	for _, page := range pages {
		// Check for auto-generated forms: <crud :model="table" /> or <form :create="table" auto />
		if strings.Contains(page.RawHTML, modelAttr) && strings.Contains(page.RawHTML, "<crud") ||
			strings.Contains(page.RawHTML, createAttr) && strings.Contains(page.RawHTML, "auto") {
			pr.auto = true
			continue
		}

		// Find all inputs with :validate that are inside a :create="table" form
		if !strings.Contains(page.RawHTML, createAttr) {
			continue
		}

		// Extract all :validate attributes with their field names
		for _, m := range validateNameFirstRe.FindAllStringSubmatch(page.RawHTML, -1) {
			pr.attrs[m[1]] = m[2]
		}
		for _, m := range validateNameLastRe.FindAllStringSubmatch(page.RawHTML, -1) {
			pr.attrs[m[2]] = m[1]
		}
	}
	return pr
}

// validateRegexCache holds compiled `regex:` rule patterns (nil for an
// invalid pattern). Patterns come from page HTML, so the set is small; the
// bound only stops an unexpected stream of distinct patterns from growing
// it, and patterns past it are compiled per use.
var (
	validateRegexMu    sync.Mutex
	validateRegexCache = map[string]*regexp.Regexp{}
)

const validateRegexCacheMax = 512

func validateRuleRegex(pattern string) *regexp.Regexp {
	validateRegexMu.Lock()
	re, ok := validateRegexCache[pattern]
	validateRegexMu.Unlock()
	if ok {
		return re
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		re = nil
	}
	validateRegexMu.Lock()
	if len(validateRegexCache) < validateRegexCacheMax {
		validateRegexCache[pattern] = re
	}
	validateRegexMu.Unlock()
	return re
}

// ValidateFields checks form values against validation rules.
func ValidateFields(r *http.Request, rules map[string]string) []ValidationError {
	var errors []ValidationError

	for field, ruleStr := range rules {
		value := strings.TrimSpace(r.FormValue(field))
		fieldRules := strings.Split(ruleStr, ",")

		for _, rule := range fieldRules {
			rule = strings.TrimSpace(rule)

			if err := validateRule(field, value, rule); err != nil {
				errors = append(errors, *err)
				break // One error per field
			}
		}
	}

	return errors
}

func validateRule(field, value, rule string) *ValidationError {
	// Parse rules with parameters: "min:8", "max:100", "in:a,b,c"
	parts := strings.SplitN(rule, ":", 2)
	ruleName := parts[0]
	ruleParam := ""
	if len(parts) == 2 {
		ruleParam = parts[1]
	}

	label := formatColName(field)

	switch ruleName {
	case "required":
		if value == "" {
			return &ValidationError{Field: field, Message: fmt.Sprintf("%s is required", label)}
		}

	case "email":
		if value != "" && !emailRe.MatchString(value) {
			return &ValidationError{Field: field, Message: "Must be a valid email address"}
		}

	case "phone":
		if value != "" && !phoneRe.MatchString(value) {
			return &ValidationError{Field: field, Message: "Must be a valid phone number"}
		}

	case "url":
		if value != "" && !urlRe.MatchString(value) {
			return &ValidationError{Field: field, Message: "Must be a valid URL"}
		}

	case "number":
		if value != "" {
			if _, err := strconv.ParseFloat(value, 64); err != nil {
				return &ValidationError{Field: field, Message: fmt.Sprintf("%s must be a number", label)}
			}
		}

	case "min":
		if value != "" && ruleParam != "" {
			minVal, _ := strconv.ParseFloat(ruleParam, 64)
			numVal, err := strconv.ParseFloat(value, 64)
			if err == nil && numVal < minVal {
				return &ValidationError{Field: field, Message: fmt.Sprintf("%s must be at least %s", label, ruleParam)}
			}
		}

	case "max":
		if value != "" && ruleParam != "" {
			maxVal, _ := strconv.ParseFloat(ruleParam, 64)
			numVal, err := strconv.ParseFloat(value, 64)
			if err == nil && numVal > maxVal {
				return &ValidationError{Field: field, Message: fmt.Sprintf("%s must be at most %s", label, ruleParam)}
			}
		}

	case "minlen":
		if ruleParam != "" {
			minLen, _ := strconv.Atoi(ruleParam)
			if len(value) < minLen {
				return &ValidationError{Field: field, Message: fmt.Sprintf("%s must be at least %s characters", label, ruleParam)}
			}
		}

	case "maxlen":
		if value != "" && ruleParam != "" {
			maxLen, _ := strconv.Atoi(ruleParam)
			if len(value) > maxLen {
				return &ValidationError{Field: field, Message: fmt.Sprintf("%s must be at most %s characters", label, ruleParam)}
			}
		}

	case "in":
		if value != "" && ruleParam != "" {
			allowed := strings.Split(ruleParam, "|")
			found := false
			for _, a := range allowed {
				if strings.TrimSpace(a) == value {
					found = true
					break
				}
			}
			if !found {
				return &ValidationError{Field: field, Message: fmt.Sprintf("%s must be one of: %s", label, strings.Join(allowed, ", "))}
			}
		}

	case "regex":
		if value != "" && ruleParam != "" {
			if re := validateRuleRegex(ruleParam); re != nil && !re.MatchString(value) {
				return &ValidationError{Field: field, Message: fmt.Sprintf("%s format is invalid", label)}
			}
		}
	}

	return nil
}

// FormatValidationErrors returns an HTMX-friendly or JSON error response.
func FormatValidationErrors(w http.ResponseWriter, r *http.Request, errors []ValidationError) {
	if isHTMX(r) {
		// Return HTML with error messages that HTMX can display
		var sb strings.Builder
		sb.WriteString(`<div class="validation-errors">`)
		for _, e := range errors {
			sb.WriteString(fmt.Sprintf(`<div class="rounded-lg border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive">%s</div>`, e.Message))
		}
		sb.WriteString(`</div>`)
		w.Header().Set("HX-Retarget", ".validation-errors, form .alert-error, form")
		w.Header().Set("HX-Reswap", "innerHTML")
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(sb.String()))
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		resp := struct {
			Errors []ValidationError `json:"errors"`
		}{Errors: errors}
		json.NewEncoder(w).Encode(resp)
	}
}
