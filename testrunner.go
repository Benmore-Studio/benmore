//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ===== App Test Types =====

// AppTestFile represents a collection of named test cases (from YAML or generated).
type AppTestFile struct {
	Name  string // filename without extension, or "_framework_*" for generated
	Tests map[string]AppTestCase
}

// AppTestCase represents a single named test case.
type AppTestCase struct {
	Setup  []AppTestSetup `yaml:"setup"`
	Steps  []AppTestStep  `yaml:"steps"`
	Users  []string       `yaml:"users"`   // pre-create these users before running steps (for multi-actor tests)
	AsUser string         `yaml:"as_user"`
	AsRole string         `yaml:"as_role"` // "admin" to create user with admin role (default: "user")
	Anon   bool           `yaml:"anon"`    // true = no auth, no CSRF injection
}

// AppTestSetup is a setup step (SQL or seed data).
type AppTestSetup struct {
	SQL string `yaml:"sql"`
}

// AppTestStep is a single test action + assertions.
type AppTestStep struct {
	// Action (one of these)
	API     string         `yaml:"api"`      // "POST /api/contacts" or "GET /api/contacts"
	Get     string         `yaml:"get"`      // shorthand for GET
	Post    string         `yaml:"post"`     // shorthand for POST
	SQL     string         `yaml:"sql"`      // execute SQL and check results
	Flush   string         `yaml:"flush"`    // drain async queue: "jobs" flushes the job worker
	SetAuth string         `yaml:"set_auth"` // switch Bearer token: "{{my_token}}" or "none" for anonymous
	Data  map[string]any `yaml:"data"`  // form data for POST/PATCH
	JSON  map[string]any `yaml:"json"`  // JSON object body for POST/PATCH

	// JSONArray sends a raw JSON array body (e.g., for batch endpoints)
	JSONArray []any `yaml:"json_array"`

	// NDJSON sends newline-delimited JSON (one object per line, for streaming ingest)
	NDJSON []map[string]any `yaml:"ndjson"`

	// Modifiers
	Bearer bool              `yaml:"bearer"` // use Bearer token instead of cookie
	Save   map[string]string `yaml:"save"`   // capture response fields as named variables. e.g., save: {contact_id: "id", token: "token"}

	// Assertions
	Expect AppTestExpect `yaml:"expect"`
}

// AppTestExpect defines what to assert about the response.
type AppTestExpect struct {
	Status      int               `yaml:"status"`
	Redirect    string            `yaml:"redirect"`
	Contains    any               `yaml:"contains"`     // string or []string
	NotContains any               `yaml:"not_contains"` // string or []string
	JSONField   map[string]any    `yaml:"json"`         // exact field match
	JSONLength  int               `yaml:"json_length"`  // array length
	Rows        int               `yaml:"rows"`         // for SQL steps
	Headers     map[string]string `yaml:"headers"`
	MaxDuration string            `yaml:"max_duration"` // e.g., "5ms", "100ms"
}

// expectContains returns the contains values as a string slice.
func expectContains(v any) []string {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case string:
		if val == "" {
			return nil
		}
		return []string{val}
	case []any:
		var out []string
		for _, item := range val {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return val
	}
	return nil
}

// AppTestResult represents the outcome of one test case.
type AppTestResult struct {
	File     string              `json:"file"`
	Test     string              `json:"test"`
	Pass     bool                `json:"pass"`
	Message  string              `json:"message,omitempty"`
	Duration string              `json:"duration,omitempty"`
	Steps    []AppTestStepResult `json:"steps,omitempty"`
}

// AppTestStepResult is the result of one step within a test.
type AppTestStepResult struct {
	Action  string `json:"action"`
	Pass    bool   `json:"pass"`
	Message string `json:"message,omitempty"`
}

// ===== Unified Test Runner =====

// RunAllTests runs both generated framework tests and developer-written YAML tests.
// Developer tests run first so their test users get predictable auto-increment IDs.
func RunAllTests(app *App, generated []AppTestFile, includeDisk bool) []AppTestResult {
	var testFiles []AppTestFile

	// Developer tests first (predictable user IDs)
	if includeDisk {
		diskFiles := loadTestFilesFromDisk(app.Dir)
		testFiles = append(testFiles, diskFiles...)
	}

	// Framework tests second
	testFiles = append(testFiles, generated...)

	if len(testFiles) == 0 {
		return []AppTestResult{{
			File: "tests/", Test: "discovery", Pass: false,
			Message: "No tests to run",
		}}
	}

	// Start test server
	mux := buildTestMux(app)
	handler := securityHeaders(mux, true, app)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return []AppTestResult{{Test: "server", Pass: false, Message: "Cannot start test server"}}
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	server := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", port), Handler: handler}
	go server.ListenAndServe()
	defer server.Close()
	time.Sleep(300 * time.Millisecond)

	base := fmt.Sprintf("http://localhost:%d", port)

	// Run tests
	var results []AppTestResult
	for _, tf := range testFiles {
		for testName, tc := range tf.Tests {
			result := runSingleTest(app, base, tf.Name, testName, tc)
			results = append(results, result)
		}
	}

	// Summary
	passed := 0
	for _, r := range results {
		if r.Pass {
			passed++
		}
	}
	results = append(results, AppTestResult{
		File: "SUMMARY", Test: "TOTAL", Pass: passed == len(results),
		Message: fmt.Sprintf("%d/%d tests passed", passed, len(results)),
	})

	return results
}

// RunAppTests discovers and runs developer-written test files from tests/ directory.
func RunAppTests(app *App) []AppTestResult {
	diskFiles := loadTestFilesFromDisk(app.Dir)
	if len(diskFiles) == 0 {
		return []AppTestResult{{
			File: "tests/", Test: "discovery", Pass: false,
			Message: fmt.Sprintf("No tests/ directory or no .yaml files in %s", app.Dir),
		}}
	}
	return RunAllTests(app, nil, true)
}

// loadTestFilesFromDisk reads all .yaml/.yml files from the tests/ directory.
func loadTestFilesFromDisk(dir string) []AppTestFile {
	testsDir := filepath.Join(dir, "tests")
	entries, err := os.ReadDir(testsDir)
	if err != nil {
		return nil
	}

	var testFiles []AppTestFile
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(testsDir, entry.Name()))
		if err != nil {
			continue
		}

		var tests map[string]AppTestCase
		if err := yaml.Unmarshal(data, &tests); err != nil {
			continue
		}

		name := strings.TrimSuffix(strings.TrimSuffix(entry.Name(), ".yaml"), ".yml")
		testFiles = append(testFiles, AppTestFile{Name: name, Tests: tests})
	}

	return testFiles
}

func buildTestMux(app *App) *http.ServeMux {
	return buildAppMux(app, true, "http://localhost")
}

func runSingleTest(app *App, base, fileName, testName string, tc AppTestCase) AppTestResult {
	start := time.Now()
	result := AppTestResult{
		File: fileName,
		Test: testName,
		Pass: true,
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Get auth if as_user specified (before setup so {{user_id}} is available)
	var cookies []*http.Cookie
	var bearerToken string
	var testUserID int64

	if !tc.Anon && tc.AsUser != "" {
		role := "user"
		if tc.AsRole != "" {
			role = tc.AsRole
		}
		cookies, bearerToken, testUserID = loginTestUser(app, tc.AsUser, role)
	}

	// Run setup steps ({{user_id}} is substituted with the authenticated user's ID)
	for _, setup := range tc.Setup {
		if setup.SQL != "" {
			sql := setup.SQL
			if testUserID > 0 {
				sql = strings.ReplaceAll(sql, "{{user_id}}", fmt.Sprintf("%d", testUserID))
			}
			if _, err := app.DB.Exec(sql); err != nil {
				result.Pass = false
				result.Message = fmt.Sprintf("Setup failed: %s", err)
				result.Duration = time.Since(start).String()
				return result
			}
		}
	}

	// Pre-create declared test users
	for _, email := range tc.Users {
		loginTestUser(app, email, "user")
	}

	// Run test steps with variable capture and substitution.
	// Steps can capture IDs via `save: "var_name"`, referenced as {{var_name}}.
	// {{last_id}} is always the most recently captured ID.
	// {{user_id}} is always the authenticated user's ID.
	vars := make(map[string]string)
	if testUserID > 0 {
		vars["user_id"] = fmt.Sprintf("%d", testUserID)
	}
	anon := tc.Anon
	for i, step := range tc.Steps {
		step = substituteVars(step, vars)

		// set_auth: switch the auth context for this and all subsequent steps
		if step.SetAuth != "" {
			if step.SetAuth == "none" {
				cookies = nil
				bearerToken = ""
				anon = true
			} else {
				// Use the value as a Bearer token (e.g., an API token from a saved variable)
				cookies = nil
				bearerToken = step.SetAuth
				anon = false
			}
			result.Steps = append(result.Steps, AppTestStepResult{Action: "set_auth", Pass: true})
			continue
		}

		stepResult, responseData := executeTestStepWithCapture(app, base, client, cookies, bearerToken, anon, step)

		// Extract save variables from response data
		if responseData != nil && len(step.Save) > 0 {
			for varName, fieldName := range step.Save {
				if val, ok := responseData[fieldName]; ok && val != nil {
					vars[varName] = fmt.Sprintf("%v", val)
				}
			}
		}
		result.Steps = append(result.Steps, stepResult)
		if !stepResult.Pass {
			result.Pass = false
			result.Message = fmt.Sprintf("Step %d failed: %s", i+1, stepResult.Message)
			break
		}
	}

	result.Duration = time.Since(start).String()
	return result
}

// executeTestStepWithCapture runs a step and returns the response data as a map
// for the step loop to extract save variables from.
func executeTestStepWithCapture(app *App, base string, client *http.Client, cookies []*http.Cookie, bearerToken string, anon bool, step AppTestStep) (AppTestStepResult, map[string]any) {
	// SQL steps
	if step.SQL != "" {
		sqlResult := executeSQLTestStep(app, step)
		upper := strings.TrimSpace(strings.ToUpper(step.SQL))
		if strings.HasPrefix(upper, "SELECT") {
			rows, err := QueryRows(app.DB, step.SQL)
			if err == nil && len(rows) > 0 {
				return sqlResult, rows[0]
			}
		}
		return sqlResult, nil
	}

	result, body := executeTestStepRaw(app, base, client, cookies, bearerToken, anon, step)
	if len(body) > 0 {
		var parsed map[string]any
		if err := json.Unmarshal(body, &parsed); err == nil {
			return result, parsed
		}
	}
	return result, nil
}

// substituteVars replaces all {{var_name}} references in step strings with captured values.
func substituteVars(step AppTestStep, vars map[string]string) AppTestStep {
	replace := func(s string) string {
		for k, v := range vars {
			s = strings.ReplaceAll(s, "{{"+k+"}}", v)
		}
		return s
	}
	step.API = replace(step.API)
	step.Get = replace(step.Get)
	step.Post = replace(step.Post)
	step.SQL = replace(step.SQL)
	step.SetAuth = replace(step.SetAuth)
	// Substitute in JSON body values (for transaction IDs, etc.)
	if step.JSON != nil {
		step.JSON = substituteVarsInMap(step.JSON, vars)
	}
	if step.Data != nil {
		step.Data = substituteVarsInMap(step.Data, vars)
	}
	if step.NDJSON != nil {
		for i, obj := range step.NDJSON {
			step.NDJSON[i] = substituteVarsInMap(obj, vars)
		}
	}
	return step
}

// substituteVarsInMap recursively replaces {{var}} in map string values.
func substituteVarsInMap(m map[string]any, vars map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		switch val := v.(type) {
		case string:
			replaced := val
			for vk, vv := range vars {
				replaced = strings.ReplaceAll(replaced, "{{"+vk+"}}", vv)
			}
			out[k] = replaced
		case map[string]any:
			out[k] = substituteVarsInMap(val, vars)
		case []any:
			out[k] = substituteVarsInSlice(val, vars)
		default:
			out[k] = v
		}
	}
	return out
}

// substituteVarsInSlice recursively replaces {{var}} in slice elements.
func substituteVarsInSlice(s []any, vars map[string]string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		switch val := v.(type) {
		case string:
			replaced := val
			for vk, vv := range vars {
				replaced = strings.ReplaceAll(replaced, "{{"+vk+"}}", vv)
			}
			out[i] = replaced
		case map[string]any:
			out[i] = substituteVarsInMap(val, vars)
		case []any:
			out[i] = substituteVarsInSlice(val, vars)
		default:
			out[i] = v
		}
	}
	return out
}

func executeTestStepRaw(app *App, base string, client *http.Client, cookies []*http.Cookie, bearerToken string, anon bool, step AppTestStep) (AppTestStepResult, []byte) {
	// Determine method and path
	method := "GET"
	path := ""

	if step.API != "" {
		parts := strings.SplitN(step.API, " ", 2)
		if len(parts) == 2 {
			method = parts[0]
			path = parts[1]
		} else {
			path = parts[0]
		}
	} else if step.Get != "" {
		method = "GET"
		path = step.Get
	} else if step.Post != "" {
		method = "POST"
		path = step.Post
	} else if step.SQL != "" {
		return executeSQLTestStep(app, step), nil
	} else if step.Flush != "" {
		return executeFlushStep(app, step), nil
	}

	action := fmt.Sprintf("%s %s", method, path)
	stepStart := time.Now()

	// Build request
	var body io.Reader
	contentType := ""

	// Use Bearer auth if explicitly requested OR if we have a token but no cookies
	// (set_auth switches to token-only auth)
	useBearer := bearerToken != "" && (step.Bearer || len(cookies) == 0)

	if step.NDJSON != nil {
		var lines []string
		for _, obj := range step.NDJSON {
			line, _ := json.Marshal(obj)
			lines = append(lines, string(line))
		}
		body = strings.NewReader(strings.Join(lines, "\n"))
		contentType = "application/x-ndjson"
	} else if step.JSONArray != nil {
		data, _ := json.Marshal(step.JSONArray)
		body = strings.NewReader(string(data))
		contentType = "application/json"
	} else if step.JSON != nil {
		data, _ := json.Marshal(step.JSON)
		body = strings.NewReader(string(data))
		contentType = "application/json"
	} else if step.Data != nil {
		formData := url.Values{}
		// Add CSRF unless anon or Bearer
		if !anon && !useBearer {
			formData.Set("_csrf", generateCSRFToken())
		}
		for k, v := range step.Data {
			formData.Set(k, fmt.Sprintf("%v", v))
		}
		body = strings.NewReader(formData.Encode())
		contentType = "application/x-www-form-urlencoded"
	} else if method == "POST" || method == "PATCH" || method == "DELETE" {
		// Add CSRF even without data (unless anon or Bearer)
		if !anon && !useBearer {
			formData := url.Values{"_csrf": {generateCSRFToken()}}
			body = strings.NewReader(formData.Encode())
			contentType = "application/x-www-form-urlencoded"
		}
	}

	req, err := http.NewRequest(method, base+path, body)
	if err != nil {
		return AppTestStepResult{Action: action, Pass: false, Message: fmt.Sprintf("Request error: %s", err)}, nil
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	// Auth: Bearer token or cookies (never both, never for anon)
	if !anon {
		if useBearer {
			req.Header.Set("Authorization", "Bearer "+bearerToken)
		} else {
			for _, c := range cookies {
				req.AddCookie(c)
			}
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return AppTestStepResult{Action: action, Pass: false, Message: fmt.Sprintf("Request failed: %s", err)}, nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	elapsed := time.Since(stepStart)

	// Run assertions
	return checkAssertions(action, resp, respBody, step.Expect, elapsed), respBody
}

func executeSQLTestStep(app *App, step AppTestStep) AppTestStepResult {
	action := fmt.Sprintf("SQL: %s", truncate(step.SQL, 60))

	rows, err := QueryRows(app.DB, step.SQL)
	if err != nil {
		return AppTestStepResult{Action: action, Pass: false, Message: fmt.Sprintf("SQL error: %s", err)}
	}

	// Check row count expectation
	if step.Expect.Rows > 0 {
		if len(rows) != step.Expect.Rows {
			return AppTestStepResult{
				Action: action, Pass: false,
				Message: fmt.Sprintf("Expected %d rows, got %d", step.Expect.Rows, len(rows)),
			}
		}
	}

	return AppTestStepResult{Action: action, Pass: true}
}

func executeFlushStep(app *App, step AppTestStep) AppTestStepResult {
	switch step.Flush {
	case "jobs":
		FlushJobs(app)
		return AppTestStepResult{Action: "flush: jobs", Pass: true}
	case "retention":
		RunRetentionNow(app)
		return AppTestStepResult{Action: "flush: retention", Pass: true}
	default:
		return AppTestStepResult{
			Action:  "flush: " + step.Flush,
			Pass:    false,
			Message: fmt.Sprintf("unknown flush target '%s' (valid: jobs, retention)", step.Flush),
		}
	}
}

func checkAssertions(action string, resp *http.Response, body []byte, expect AppTestExpect, elapsed time.Duration) AppTestStepResult {
	// Status code
	if expect.Status > 0 && resp.StatusCode != expect.Status {
		return AppTestStepResult{
			Action: action, Pass: false,
			Message: fmt.Sprintf("Expected status %d, got %d. Body: %s", expect.Status, resp.StatusCode, truncate(string(body), 200)),
		}
	}

	// Default: expect 200 for GET, 200/201 for POST
	if expect.Status == 0 {
		if resp.StatusCode >= 400 {
			return AppTestStepResult{
				Action: action, Pass: false,
				Message: fmt.Sprintf("HTTP %d. Body: %s", resp.StatusCode, truncate(string(body), 200)),
			}
		}
	}

	// Redirect
	if expect.Redirect != "" {
		loc := resp.Header.Get("Location")
		if !strings.Contains(loc, expect.Redirect) {
			return AppTestStepResult{
				Action: action, Pass: false,
				Message: fmt.Sprintf("Expected redirect to '%s', got '%s'", expect.Redirect, loc),
			}
		}
	}

	// Body contains (supports string or list of strings)
	for _, want := range expectContains(expect.Contains) {
		if !strings.Contains(string(body), want) {
			return AppTestStepResult{
				Action: action, Pass: false,
				Message: fmt.Sprintf("Body does not contain '%s'", want),
			}
		}
	}

	// Body not contains (supports string or list of strings)
	for _, reject := range expectContains(expect.NotContains) {
		if strings.Contains(string(body), reject) {
			return AppTestStepResult{
				Action: action, Pass: false,
				Message: fmt.Sprintf("Body should not contain '%s'", reject),
			}
		}
	}

	// JSON field assertions
	if expect.JSONField != nil {
		var parsed any
		if err := json.Unmarshal(body, &parsed); err != nil {
			return AppTestStepResult{
				Action: action, Pass: false,
				Message: fmt.Sprintf("Response is not valid JSON: %s", err),
			}
		}

		for key, expectedVal := range expect.JSONField {
			actualVal := jsonLookup(parsed, key)
			expected := fmt.Sprintf("%v", expectedVal)
			actual := fmt.Sprintf("%v", actualVal)
			if actual != expected {
				return AppTestStepResult{
					Action: action, Pass: false,
					Message: fmt.Sprintf("JSON field '%s': expected '%s', got '%s'", key, expected, actual),
				}
			}
		}
	}

	// JSON array length
	if expect.JSONLength > 0 {
		var parsed any
		if err := json.Unmarshal(body, &parsed); err != nil {
			return AppTestStepResult{Action: action, Pass: false, Message: "Response is not valid JSON"}
		}
		if arr, ok := parsed.([]any); ok {
			if len(arr) != expect.JSONLength {
				return AppTestStepResult{
					Action: action, Pass: false,
					Message: fmt.Sprintf("Expected JSON array length %d, got %d", expect.JSONLength, len(arr)),
				}
			}
		}
	}

	// Headers
	for key, expected := range expect.Headers {
		actual := resp.Header.Get(key)
		if actual != expected {
			return AppTestStepResult{
				Action: action, Pass: false,
				Message: fmt.Sprintf("Header '%s': expected '%s', got '%s'", key, expected, actual),
			}
		}
	}

	// Max duration
	if expect.MaxDuration != "" {
		maxDur, err := time.ParseDuration(expect.MaxDuration)
		if err == nil && elapsed > maxDur {
			return AppTestStepResult{
				Action: action, Pass: false,
				Message: fmt.Sprintf("Took %s, max allowed %s", elapsed, maxDur),
			}
		}
	}

	return AppTestStepResult{Action: action, Pass: true, Message: elapsed.String()}
}

// jsonLookup extracts a value from parsed JSON using dot notation.
// Supports: "status", "errors[0].field", "[0].name"
func jsonLookup(data any, path string) any {
	parts := strings.Split(path, ".")
	current := data

	for _, part := range parts {
		if current == nil {
			return nil
		}

		// Array index: "errors[0]" or "[0]"
		if idx := strings.Index(part, "["); idx >= 0 {
			key := part[:idx]
			idxStr := strings.TrimSuffix(part[idx+1:], "]")
			var arrIdx int
			fmt.Sscanf(idxStr, "%d", &arrIdx)

			if key != "" {
				if m, ok := current.(map[string]any); ok {
					current = m[key]
				}
			}

			if arr, ok := current.([]any); ok && arrIdx < len(arr) {
				current = arr[arrIdx]
			} else {
				return nil
			}
			continue
		}

		// Object field
		if m, ok := current.(map[string]any); ok {
			current = m[part]
		} else {
			return nil
		}
	}

	return current
}

// loginTestUser creates a test user with the given role and returns cookies, bearer token, and user ID.
func loginTestUser(app *App, email string, role string) ([]*http.Cookie, string, int64) {
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)

	var id int64
	err := app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email = ?", email).Scan(&id)
	if err != nil {
		hash, _ := generateBcryptHash([]byte("testpass123"))
		username := GenerateUniqueUsername(app.DB, strings.Split(email, "@")[0], 0)
		result, insertErr := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, role) VALUES (?, ?, ?, ?)", username, email, string(hash), role)
		if insertErr != nil {
			// Retry once — database may be locked by concurrent operations
			time.Sleep(100 * time.Millisecond)
			result, insertErr = app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, role) VALUES (?, ?, ?, ?)", username, email, string(hash), role)
		}
		if result != nil {
			id, _ = result.LastInsertId()
		}
	}

	groupID := ResolveGroupID(app.DB, app.Group, email)
	sessionID := CreateSession(app.DB, id, email, groupID, app.SessionDuration)

	cookies := []*http.Cookie{{
		Name:  sessionCookieName,
		Value: sessionID,
	}}

	return cookies, sessionID, id
}
