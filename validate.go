//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
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
)

// ValidationError represents a single field validation failure.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ExtractValidationRules parses :validate attributes from page HTML for a given table.
func ExtractValidationRules(app *App, table string) map[string]string {
	rules := make(map[string]string)

	for _, page := range app.Pages {
		// Check for auto-generated forms: <crud :model="table" /> or <form :create="table" auto />
		if strings.Contains(page.RawHTML, fmt.Sprintf(`:model="%s"`, table)) && strings.Contains(page.RawHTML, "<crud") ||
			strings.Contains(page.RawHTML, fmt.Sprintf(`:create="%s"`, table)) && strings.Contains(page.RawHTML, "auto") {
			// Generate rules from schema
			cols, _ := GetTableColumns(app.DB, table)
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
			continue
		}

		// Find all inputs with :validate that are inside a :create="table" form
		if !strings.Contains(page.RawHTML, fmt.Sprintf(`:create="%s"`, table)) {
			continue
		}

		// Extract all :validate attributes with their field names
		nameRe := regexp.MustCompile(`name="([^"]+)"[^>]*:validate="([^"]+)"`)
		for _, m := range nameRe.FindAllStringSubmatch(page.RawHTML, -1) {
			rules[m[1]] = m[2]
		}
		nameRe2 := regexp.MustCompile(`:validate="([^"]+)"[^>]*name="([^"]+)"`)
		for _, m := range nameRe2.FindAllStringSubmatch(page.RawHTML, -1) {
			rules[m[2]] = m[1]
		}
	}

	return rules
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
			re, err := regexp.Compile(ruleParam)
			if err == nil && !re.MatchString(value) {
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
