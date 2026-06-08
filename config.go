//go:build !cli

package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// AppYAML represents the top-level app.yaml config.
type AppYAML struct {
	Name     string                       `yaml:"name"`
	Theme    string                       `yaml:"theme"`
	Mode     string                       `yaml:"mode"`
	Font     string                       `yaml:"font"`
	Brand    string                       `yaml:"brand"`
	CSS      string                       `yaml:"css"`
	Auth     map[string]string            `yaml:"auth"`
	Database DatabaseConfig               `yaml:"database"`
	SEO      map[string]string            `yaml:"seo"`
	CSP      map[string]string            `yaml:"csp"`
	Models   map[string][]string          `yaml:"models"`
	Pages    map[string]string            `yaml:"pages"`
}

// DatabaseConfig holds database settings.
type DatabaseConfig struct {
	Mode   string   `yaml:"mode"`   // "shared", "per_user", "per_org"
	Shared []string `yaml:"shared"` // tables that live in global.db
}

// HooksYAML represents hooks.yaml parsed with real YAML.
type HooksYAML struct {
	OnInsert     map[string][]HookEntryYAML `yaml:"on_insert"`
	OnUpdate     map[string][]HookEntryYAML `yaml:"on_update"`
	OnDelete     map[string][]HookEntryYAML `yaml:"on_delete"`
	BeforeInsert map[string][]HookEntryYAML `yaml:"before_insert"`
	BeforeUpdate map[string][]HookEntryYAML `yaml:"before_update"`
	BeforeDelete map[string][]HookEntryYAML `yaml:"before_delete"`
}

// HookEntryYAML represents a single hook entry.
type HookEntryYAML struct {
	Webhook     string `yaml:"webhook"`
	Body        string `yaml:"body"`
	SQL         string `yaml:"sql"`
	When        string `yaml:"when"`
	Notify      string `yaml:"notify"`       // target user_id (short form)
	NotifyTitle string `yaml:"notify_title"` // optional
	NotifyBody  string `yaml:"notify_body"`  // optional
	NotifyLink  string `yaml:"notify_link"`  // optional
	NotifyType  string `yaml:"notify_type"`  // info|success|warning|error
	Email       *struct {
		To       string `yaml:"to"`
		Subject  string `yaml:"subject"`
		Template string `yaml:"template"`
	} `yaml:"email"`
	WS *struct {
		Room    string `yaml:"room"`
		Payload string `yaml:"payload"` // JSON-stringifiable template
	} `yaml:"ws"`
}

// FlowYAML represents a flow in flows.yaml.
type FlowYAML struct {
	Trigger     string         `yaml:"trigger"`
	Verify      string         `yaml:"verify"`
	Secret      string         `yaml:"secret"`
	Transaction bool           `yaml:"transaction"`
	Auth        string         `yaml:"auth"`
	Role        string         `yaml:"role"`
	Steps       []FlowStepYAML `yaml:"steps"`
}

// FlowStepYAML represents a step in a flow.
type FlowStepYAML struct {
	Name        string            `yaml:"name"`
	SQL         string            `yaml:"sql"`
	If          string            `yaml:"if"`
	ForEach     string            `yaml:"for_each"`
	As          string            `yaml:"as"`
	Parse       string            `yaml:"parse"`
	Redirect    string            `yaml:"redirect"`
	Webhook     string            `yaml:"webhook"`
	WebhookBody string            `yaml:"body"`
	Set         map[string]string `yaml:"set"`
	Retry       int               `yaml:"retry"`
	RetryDelay  string            `yaml:"retry_delay"`
	Timeout     string            `yaml:"timeout"`
	Steps       []FlowStepYAML    `yaml:"steps"`
	Else        []FlowStepYAML    `yaml:"else"`
	OnError     []FlowStepYAML    `yaml:"on_error"`
	API         *FlowAPIYAML      `yaml:"api"`
	Email       *FlowEmailYAML    `yaml:"email"`
	Respond     *FlowRespondYAML  `yaml:"respond"`
	WS          *FlowWSYAML       `yaml:"ws"`
	Enqueue     *FlowEnqueueYAML  `yaml:"enqueue"`
}

// FlowEnqueueYAML is the YAML shape for an enqueue step.
type FlowEnqueueYAML struct {
	Flow  string            `yaml:"flow"`
	With  map[string]string `yaml:"with"`
	RunAt string            `yaml:"run_at"`
}

// FlowWSYAML represents a WebSocket broadcast step.
type FlowWSYAML struct {
	Room    string `yaml:"room"`
	Payload string `yaml:"payload"`
}

// FlowAPIYAML represents an API call step.
type FlowAPIYAML struct {
	Method   string                 `yaml:"method"`
	URL      string                 `yaml:"url"`
	Auth     string                 `yaml:"auth"`
	Headers  map[string]string      `yaml:"headers"`
	JSON     map[string]string      `yaml:"json"`
	Form     map[string]string      `yaml:"form"`
	Body     string                 `yaml:"body"`
	Paginate *FlowAPIPaginateYAML   `yaml:"paginate"`
}

// FlowAPIPaginateYAML mirrors FlowAPIPaginate for YAML parsing.
type FlowAPIPaginateYAML struct {
	Strategy    string `yaml:"strategy"`
	CursorParam string `yaml:"cursor_param"`
	CursorField string `yaml:"cursor_field"`
	PageParam   string `yaml:"page_param"`
	PageStart   int    `yaml:"page_start"`
	ItemsField  string `yaml:"items_field"`
	MaxPages    int    `yaml:"max_pages"`
}

// FlowEmailYAML represents an email step.
type FlowEmailYAML struct {
	To       string            `yaml:"to"`
	Subject  string            `yaml:"subject"`
	Template string            `yaml:"template"`
	Data     map[string]string `yaml:"data"`
}

// FlowRespondYAML represents a respond step.
type FlowRespondYAML struct {
	Status int            `yaml:"status"`
	JSON   map[string]any `yaml:"json"`
	Body   string         `yaml:"body"`
}

// BackupConfig holds scheduled backup settings from app.yaml.
type BackupConfig struct {
	Interval time.Duration // how often to create a scheduled backup
	Keep     int           // max number of scheduled backups to retain
}

// LoadBackupConfig reads the backup: section from app.yaml.
// generateUUID creates a v4 UUID using crypto/rand.
func generateUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// loadOrCreateAppID reads or creates a persistent UUID for the app.
// Stored in .benmore/app_id so it stays the same across restarts and deploys.
func loadOrCreateAppID(dir string) string {
	benDir := filepath.Join(dir, ".benmore")
	os.MkdirAll(benDir, 0700)
	idPath := filepath.Join(benDir, "app_id")
	if data, err := os.ReadFile(idPath); err == nil {
		id := strings.TrimSpace(string(data))
		if len(id) == 36 { // valid UUID length
			return id
		}
	}
	// Generate new UUID (v4)
	id := generateUUID()
	os.WriteFile(idPath, []byte(id), 0600)
	return id
}

func LoadBackupConfig(dir string) *BackupConfig {
	path := filepath.Join(dir, "app.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil
	}
	m, ok := raw["backup"].(map[string]any)
	if !ok {
		return nil
	}
	config := &BackupConfig{
		Keep: 20, // default
	}
	if v, ok := m["interval"].(string); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 1*time.Minute {
			return nil // invalid or too frequent interval
		}
		config.Interval = d
	} else {
		return nil // interval is required
	}
	if v, ok := m["keep"].(int); ok && v > 0 {
		config.Keep = v
	}
	return config
}

// ===== Loaders =====

// LoadAppConfigYAML reads app.yaml with the real YAML parser.
func LoadAppConfigYAML(dir string) *DesignConfig {
	path := filepath.Join(dir, "app.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return LoadAppConfig(dir) // fallback to old parser
	}

	config := &DesignConfig{
		Colors:     make(map[string]string),
		Typography: make(map[string]string),
		Spacing:    make(map[string]string),
		Nav:        make(map[string]string),
		Table:      make(map[string]any),
		SEO:        make(map[string]string),
		Auth:       make(map[string]string),
		PWA:        make(map[string]string),
		Recording:  make(map[string]string),
	}

	if v, ok := raw["theme"].(string); ok { config.Colors["_theme"] = v }
	if v, ok := raw["mode"].(string); ok { config.Colors["_mode"] = v }
	if v, ok := raw["font"].(string); ok { config.Colors["_font"] = v }
	if v, ok := raw["brand"].(string); ok { config.Colors["_brand"] = v }
	if v, ok := raw["css"].(string); ok { config.CSS = v }
	if v, ok := raw["radius"].(string); ok { config.Radius = v }
	if v, ok := raw["shadow"].(string); ok { config.Shadow = v }

	if m, ok := raw["colors"].(map[string]any); ok {
		for k, v := range m { config.Colors[k] = anyToString(v) }
	}
	if m, ok := raw["typography"].(map[string]any); ok {
		for k, v := range m { config.Typography[k] = anyToString(v) }
	}
	if m, ok := raw["spacing"].(map[string]any); ok {
		for k, v := range m { config.Spacing[k] = anyToString(v) }
	}
	if m, ok := raw["nav"].(map[string]any); ok {
		for k, v := range m { config.Nav[k] = anyToString(v) }
	}
	if m, ok := raw["seo"].(map[string]any); ok {
		for k, v := range m { config.SEO[k] = anyToString(v) }
	}
	// Top-level `csp:` block — per-directive allowlist extensions.
	// Only the recognised directives are stored; unknown keys are
	// dropped silently here (the write-time validator surfaces them
	// as antipatterns, so the agent sees the typo before reaching
	// runtime).
	if m, ok := raw["csp"].(map[string]any); ok {
		if config.CSP == nil {
			config.CSP = make(map[string]string)
		}
		for k, v := range m {
			switch k {
			case "script_src", "style_src", "img_src", "font_src", "connect_src", "frame_src":
				config.CSP[k] = anyToString(v)
			}
		}
	}
	// external_id: optional identifier for external system integration
	if v, ok := raw["external_id"].(string); ok {
		config.SEO["external_id"] = v
	}
	if m, ok := raw["auth"].(map[string]any); ok {
		for k, v := range m { config.Auth[k] = anyToString(v) }
	}
	if m, ok := raw["pwa"].(map[string]any); ok {
		for k, v := range m { config.PWA[k] = anyToString(v) }
	}
	if m, ok := raw["recording"].(map[string]any); ok {
		for k, v := range m { config.Recording[k] = anyToString(v) }
	}
	if m, ok := raw["table"].(map[string]any); ok {
		config.Table = m
	}
	if m, ok := raw["database"].(map[string]any); ok {
		if mode, ok := m["mode"].(string); ok {
			config.Colors["_db_mode"] = mode
		}
	}

	// Parse features: section for opt-in/opt-out of framework features
	if m, ok := raw["features"].(map[string]any); ok {
		config.Features = parseFeaturesConfig(m)
	}

	// Parse auto_memberships: shorthand for "every active user is
	// auto-enrolled into every row on <parent>" — synthesized into
	// on_insert hooks at app load time. See auto_membership.go.
	if m, ok := raw["auto_memberships"].(map[string]any); ok {
		config.AutoMemberships = parseAutoMembershipConfig(m)
	}

	return config
}

// parseAutoMembershipConfig walks the auto_memberships: block and
// returns the typed map. Each parent table's entry is a map of
// table/parent/user_field/members → strings. Empty values pick up
// defaults at hook-synthesize time (fillMembershipDefaults).
func parseAutoMembershipConfig(m map[string]any) map[string]AutoMembershipConfig {
	out := map[string]AutoMembershipConfig{}
	for parent, raw := range m {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		cfg := AutoMembershipConfig{}
		if v, ok := entry["table"].(string); ok {
			cfg.Table = v
		}
		if v, ok := entry["parent"].(string); ok {
			cfg.Parent = v
		}
		if v, ok := entry["user_field"].(string); ok {
			cfg.UserField = v
		}
		if v, ok := entry["members"].(string); ok {
			cfg.Members = v
		}
		out[parent] = cfg
	}
	return out
}

// parseFeaturesConfig parses the features: section from app.yaml.
// Supports both boolean values and map values (e.g., search: { tables: [...] }).
func parseFeaturesConfig(m map[string]any) *FeaturesConfig {
	fc := &FeaturesConfig{}

	parseBoolFeature := func(key string) *bool {
		v, ok := m[key]
		if !ok {
			return nil
		}
		switch val := v.(type) {
		case bool:
			return &val
		case string:
			// String values like "auth" or "public" mean the feature is enabled
			b := val != "false"
			return &b
		case map[string]any:
			// A map means enabled (e.g., search: { tables: [...] })
			b := true
			return &b
		default:
			return nil
		}
	}

	fc.Admin = parseBoolFeature("admin")
	fc.SSE = parseBoolFeature("sse")
	fc.WS = parseBoolFeature("ws")
	fc.Docs = parseBoolFeature("docs")
	fc.Testing = parseBoolFeature("testing")
	fc.Analytics = parseBoolFeature("analytics")
	fc.WSAnonymous = parseBoolFeature("ws_anonymous")

	// Parse docs visibility: "public" (default) or "auth" (requires login)
	if v, ok := m["docs"].(string); ok && v == "auth" {
		fc.DocsVisibility = "auth"
	}

	return fc
}

// LoadGroupConfig reads the org: section from app.yaml for group-level data scoping.
func LoadGroupConfig(dir string) *GroupConfig {
	path := filepath.Join(dir, "app.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil
	}
	m, ok := raw["groups"].(map[string]any)
	if !ok {
		return nil
	}
	table, _ := m["table"].(string)
	key, _ := m["key"].(string)
	userField, _ := m["user_field"].(string)
	if table == "" || key == "" || userField == "" {
		return nil
	}
	return &GroupConfig{Table: table, Key: key, UserField: userField}
}

// LoadScopes reads the per-table read-filter overrides from
// app.yaml's `scopes:` section. Returns nil when the section is
// missing or empty so apps without overrides pay zero cost.
//
// Shape:
//   scopes:
//     stories:
//       public_read_when: "status = 'published'"
func LoadScopes(dir string) map[string]ScopeConfig {
	path := filepath.Join(dir, "app.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var raw struct {
		Scopes map[string]ScopeConfig `yaml:"scopes"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil
	}
	if len(raw.Scopes) == 0 {
		return nil
	}
	// Drop empty entries — agents who declare a table key but no
	// public_read_when shouldn't accidentally lock out their own
	// owner-scoped reads.
	out := make(map[string]ScopeConfig, len(raw.Scopes))
	for t, sc := range raw.Scopes {
		if sc.PublicReadWhen != "" {
			out[t] = sc
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// LoadHooksYAML reads hooks.yaml with the real YAML parser.
func LoadHooksYAML(dir string) *HookConfig {
	path := filepath.Join(dir, "hooks.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var raw HooksYAML
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return LoadHooks(dir) // fallback
	}

	config := &HookConfig{
		OnInsert:     make(map[string][]Hook),
		OnUpdate:     make(map[string][]Hook),
		OnDelete:     make(map[string][]Hook),
		BeforeInsert: make(map[string][]Hook),
		BeforeUpdate: make(map[string][]Hook),
		BeforeDelete: make(map[string][]Hook),
	}

	for table, entries := range raw.OnInsert {
		for _, e := range entries {
			config.OnInsert[table] = append(config.OnInsert[table], hookFromYAML(e))
		}
	}
	for table, entries := range raw.OnUpdate {
		for _, e := range entries {
			config.OnUpdate[table] = append(config.OnUpdate[table], hookFromYAML(e))
		}
	}
	for table, entries := range raw.OnDelete {
		for _, e := range entries {
			config.OnDelete[table] = append(config.OnDelete[table], hookFromYAML(e))
		}
	}
	for table, entries := range raw.BeforeInsert {
		for _, e := range entries {
			config.BeforeInsert[table] = append(config.BeforeInsert[table], hookFromYAML(e))
		}
	}
	for table, entries := range raw.BeforeUpdate {
		for _, e := range entries {
			config.BeforeUpdate[table] = append(config.BeforeUpdate[table], hookFromYAML(e))
		}
	}
	for table, entries := range raw.BeforeDelete {
		for _, e := range entries {
			config.BeforeDelete[table] = append(config.BeforeDelete[table], hookFromYAML(e))
		}
	}

	return config
}

func hookFromYAML(e HookEntryYAML) Hook {
	h := Hook{
		Webhook: e.Webhook,
		Body:    e.Body,
		SQL:     e.SQL,
		When:    e.When,
	}
	if e.Email != nil {
		h.Email = &EmailHook{
			To:       e.Email.To,
			Subject:  e.Email.Subject,
			Template: e.Email.Template,
		}
	}
	if e.Notify != "" {
		h.Notify = &NotifyHook{
			UserID: e.Notify,
			Title:  e.NotifyTitle,
			Body:   e.NotifyBody,
			Link:   e.NotifyLink,
			Type:   e.NotifyType,
		}
	}
	if e.WS != nil && e.WS.Room != "" {
		h.WS = &WSHook{
			Room:    e.WS.Room,
			Payload: e.WS.Payload,
		}
	}
	return h
}

// LoadFlowsYAML reads flows.yaml with the real YAML parser. We try
// the new GHA-shaped front-end first (on:/jobs:/steps:); if that yields
// nothing we fall back to the legacy per-flow map shape, then finally
// to the line-based parser in flows.go.
func LoadFlowsYAML(dir string) []Flow {
	if gha := LoadFlowsGHA(dir); len(gha) > 0 {
		return gha
	}

	path := filepath.Join(dir, "flows.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var raw map[string]FlowYAML
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return LoadFlows(dir) // fallback
	}

	var flows []Flow
	for name, fy := range raw {
		flow := Flow{
			Name:        name,
			Trigger:     parseTrigger(fy.Trigger),
			Verify:      fy.Verify,
			Secret:      fy.Secret,
			Transaction: fy.Transaction,
			Auth:        fy.Auth,
			Role:        fy.Role,
			Steps:       convertSteps(fy.Steps),
		}
		flows = append(flows, flow)
	}
	return flows
}

func convertSteps(yamlSteps []FlowStepYAML) []FlowStep {
	var steps []FlowStep
	for _, ys := range yamlSteps {
		step := FlowStep{
			Name:        ys.Name,
			Set:         ys.Set,
			WebhookBody: ys.WebhookBody,
		}

		switch {
		case ys.SQL != "":
			step.Type = "sql"
			step.SQL = ys.SQL
		case ys.API != nil:
			step.Type = "api"
			step.API = &FlowAPICall{
				Method:  ys.API.Method,
				URL:     ys.API.URL,
				Auth:    ys.API.Auth,
				Headers: ys.API.Headers,
				JSON:    ys.API.JSON,
				Form:    ys.API.Form,
				Body:    ys.API.Body,
			}
		case ys.Webhook != "":
			step.Type = "webhook"
			step.Webhook = ys.Webhook
		case ys.WS != nil:
			step.Type = "ws"
			step.WS = &FlowWS{
				Room:    ys.WS.Room,
				Payload: ys.WS.Payload,
			}
		case ys.Enqueue != nil:
			step.Type = "enqueue"
			step.Enqueue = &FlowEnqueue{
				Flow:  ys.Enqueue.Flow,
				With:  ys.Enqueue.With,
				RunAt: ys.Enqueue.RunAt,
			}
		case ys.Email != nil:
			step.Type = "email"
			step.Email = &FlowEmail{
				To:       ys.Email.To,
				Subject:  ys.Email.Subject,
				Template: ys.Email.Template,
			}
		case ys.Redirect != "":
			step.Type = "redirect"
			step.Redirect = ys.Redirect
		case ys.Respond != nil:
			step.Type = "respond"
			step.Respond = &FlowRespond{
				Status: ys.Respond.Status,
				JSON:   ys.Respond.JSON,
				Body:   ys.Respond.Body,
			}
		case ys.If != "":
			step.Type = "if"
			step.Condition = ys.If
			step.Steps = convertSteps(ys.Steps)
			step.ElseSteps = convertSteps(ys.Else)
		case ys.ForEach != "":
			step.Type = "for_each"
			step.ForEach = ys.ForEach
			step.ForAs = ys.As
			step.Steps = convertSteps(ys.Steps)
		case ys.Parse != "":
			step.Type = "parse"
			step.Parse = ys.Parse
		case ys.Set != nil:
			step.Type = "set"
		}

		step.Retry = ys.Retry
		if ys.RetryDelay != "" {
			step.RetryDelay, _ = time.ParseDuration(ys.RetryDelay)
		}
		if ys.Timeout != "" {
			step.Timeout, _ = time.ParseDuration(ys.Timeout)
		}
		if len(ys.OnError) > 0 {
			step.OnError = convertSteps(ys.OnError)
		}

		steps = append(steps, step)
	}
	return steps
}

func anyToString(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

// ===== Workflow YAML Loading =====

// WorkflowYAML is the raw YAML representation of a workflow.
type WorkflowYAML struct {
	Table        string                                `yaml:"table"`
	Field        string                                `yaml:"field"`
	Initial      string                                `yaml:"initial"`
	Transitions  map[string]map[string]TransitionYAML  `yaml:"transitions"`
	OnTransition map[string][]HookEntryYAML            `yaml:"on_transition"`
	Timeout      map[string]TimeoutYAML                `yaml:"timeout"`
}

// TransitionYAML is the raw YAML for a single transition rule.
type TransitionYAML struct {
	Role string `yaml:"role"`
	When string `yaml:"when"`
}

// TimeoutYAML is the raw YAML for a timeout auto-transition.
type TimeoutYAML struct {
	After string `yaml:"after"` // "7d", "24h", "30m"
	To    string `yaml:"to"`
}

// LoadWorkflowsYAML reads workflows.yaml and returns WorkflowConfig.
func LoadWorkflowsYAML(dir string) *WorkflowConfig {
	path := filepath.Join(dir, "workflows.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var raw map[string]WorkflowYAML
	if err := yaml.Unmarshal(data, &raw); err != nil {
		log.Printf("WARN: workflows.yaml parse error: %s", err)
		return nil
	}

	if len(raw) == 0 {
		return nil
	}

	config := &WorkflowConfig{
		Workflows: make(map[string]*Workflow),
	}

	for name, wy := range raw {
		wf := &Workflow{
			Name:         name,
			Table:        wy.Table,
			Field:        wy.Field,
			Initial:      wy.Initial,
			Transitions:  make(map[string]map[string]Transition),
			OnTransition: make(map[string][]Hook),
			Timeouts:     make(map[string]WorkflowTimeout),
		}

		// Build states list + transitions map
		stateSet := make(map[string]bool)
		for from, targets := range wy.Transitions {
			stateSet[from] = true
			wf.Transitions[from] = make(map[string]Transition)
			for to, rule := range targets {
				stateSet[to] = true
				wf.Transitions[from][to] = Transition{
					Role: rule.Role,
					When: rule.When,
				}
			}
		}
		for s := range stateSet {
			wf.States = append(wf.States, s)
		}

		// On-transition hooks (reuse hookFromYAML)
		for state, entries := range wy.OnTransition {
			for _, e := range entries {
				wf.OnTransition[state] = append(wf.OnTransition[state], hookFromYAML(e))
			}
		}

		// Timeouts
		for state, ty := range wy.Timeout {
			wf.Timeouts[state] = WorkflowTimeout{
				After: parseWorkflowDuration(ty.After),
				To:    ty.To,
			}
		}

		config.Workflows[name] = wf
	}

	return config
}

// parseWorkflowDuration parses durations like "7d", "24h", "30m".
func parseWorkflowDuration(s string) time.Duration {
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	// Handle "Nd" (days) format
	var n int
	if _, err := fmt.Sscanf(s, "%dd", &n); err == nil && n > 0 {
		return time.Duration(n) * 24 * time.Hour
	}
	return 0
}

// ===== Computed Fields YAML Loading =====

// ComputedFieldYAML is a single computed field in YAML.
type ComputedFieldYAML struct {
	Expr     string                    `yaml:"expr"`
	SQL      string                    `yaml:"sql"`
	Triggers []ComputedTriggerDefYAML  `yaml:"triggers"`
}

// ComputedTriggerDefYAML is a trigger definition in YAML.
type ComputedTriggerDefYAML struct {
	Table string   `yaml:"table"`
	On    []string `yaml:"on"`
	FK    string   `yaml:"fk"`
}

// LoadComputedFieldsYAML reads computed.yaml and returns ComputedFieldConfig.
// Accepts two formats:
//
// 1. Nested map (legacy):
//
//	orders:
//	  total:
//	    expr: "quantity * price"
//
// 2. Flat list under `fields:` (used by most client apps — clearer to
//    read top-to-bottom when an app has many computed fields):
//
//	fields:
//	  - table: orders
//	    column: total
//	    expr: "quantity * price"
func LoadComputedFieldsYAML(dir string) *ComputedFieldConfig {
	path := filepath.Join(dir, "computed.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	config := &ComputedFieldConfig{
		Fields: make(map[string]map[string]*ComputedField),
	}

	// Try flat-list format first (most common in client apps)
	var listWrapper struct {
		Fields []struct {
			Table    string                   `yaml:"table"`
			Column   string                   `yaml:"column"`
			Expr     string                   `yaml:"expr"`
			SQL      string                   `yaml:"sql"`
			Triggers []ComputedTriggerDefYAML `yaml:"triggers"`
		} `yaml:"fields"`
	}
	if err := yaml.Unmarshal(data, &listWrapper); err == nil && len(listWrapper.Fields) > 0 {
		for _, f := range listWrapper.Fields {
			if f.Table == "" || f.Column == "" {
				continue
			}
			if config.Fields[f.Table] == nil {
				config.Fields[f.Table] = make(map[string]*ComputedField)
			}
			cf := &ComputedField{
				Table:  f.Table,
				Column: f.Column,
				Expr:   f.Expr,
				SQL:    f.SQL,
			}
			for _, t := range f.Triggers {
				cf.Triggers = append(cf.Triggers, ComputedTriggerDef{
					Table: t.Table,
					On:    t.On,
					FK:    t.FK,
				})
			}
			config.Fields[f.Table][f.Column] = cf
		}
		if len(config.Fields) > 0 {
			return config
		}
	}

	// Fall back to nested-map format
	var raw map[string]map[string]ComputedFieldYAML
	if err := yaml.Unmarshal(data, &raw); err != nil {
		log.Printf("WARN: computed.yaml parse error: %s", err)
		return nil
	}

	if len(raw) == 0 {
		return nil
	}

	for tableName, columns := range raw {
		config.Fields[tableName] = make(map[string]*ComputedField)
		for colName, def := range columns {
			cf := &ComputedField{
				Table:  tableName,
				Column: colName,
				Expr:   def.Expr,
				SQL:    def.SQL,
			}
			for _, t := range def.Triggers {
				cf.Triggers = append(cf.Triggers, ComputedTriggerDef{
					Table: t.Table,
					On:    t.On,
					FK:    t.FK,
				})
			}
			config.Fields[tableName][colName] = cf
		}
	}

	return config
}

// ===== Roles Config Loading =====

// LoadRolesConfig reads the roles: section from app.yaml.
// Roles define default scopes for each developer-defined role.
func LoadRolesConfig(dir string) *RolesConfig {
	path := filepath.Join(dir, "app.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil
	}
	rolesRaw, ok := raw["roles"].(map[string]any)
	if !ok {
		return nil
	}

	config := &RolesConfig{
		Roles: make(map[string]RoleDef),
	}
	for roleName, v := range rolesRaw {
		def := RoleDef{}
		switch val := v.(type) {
		case map[string]any:
			// `scopes:` accepts a string OR a list of strings. YAML
			// lists are the natural idiom many agents reach for
			// (`scopes: ["*"]`, `scopes: [contacts:read, deals:write]`),
			// and pre-v2.5.11 a list silently fell through to empty
			// scopes which the auth gate then translated to
			// "_none_:read" — every CRUD call 403'd. Now we accept
			// both forms and concatenate list entries with spaces
			// (matches the framework's space-separated scope string
			// format throughout scopes.go).
			switch s := val["scopes"].(type) {
			case string:
				def.Scopes = s
			case []any:
				parts := make([]string, 0, len(s))
				for _, item := range s {
					if str, ok := item.(string); ok && str != "" {
						parts = append(parts, str)
					}
				}
				def.Scopes = strings.Join(parts, " ")
			}
			// `inherits:` accepts a string OR a list of strings.
			// Inheritance unions the parent's scopes into this role.
			switch inh := val["inherits"].(type) {
			case string:
				if inh != "" {
					def.Inherits = []string{inh}
				}
			case []any:
				for _, item := range inh {
					if s, ok := item.(string); ok && s != "" {
						def.Inherits = append(def.Inherits, s)
					}
				}
			}
		case string:
			// Shorthand: "admin: '*'" or "viewer: 'contacts:read'"
			def.Scopes = val
		case []any:
			// Shorthand list: "admin: [*]" or "viewer: [contacts:read]"
			parts := make([]string, 0, len(val))
			for _, item := range val {
				if str, ok := item.(string); ok && str != "" {
					parts = append(parts, str)
				}
			}
			def.Scopes = strings.Join(parts, " ")
		}
		config.Roles[roleName] = def
	}
	return config
}

// ResolveRoleScopes returns the effective scope string for a role
// after walking `inherits:` transitively. Cycles are detected and
// broken (a parent that re-enters the chain is silently skipped).
// `*` short-circuits to full access. Returns empty string when the
// role is unknown.
func (rc *RolesConfig) ResolveRoleScopes(role string) string {
	if rc == nil {
		return ""
	}
	if _, ok := rc.Roles[role]; !ok {
		return ""
	}
	seen := make(map[string]bool)
	scopes := make(map[string]bool)
	var walk func(name string)
	walk = func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		def, ok := rc.Roles[name]
		if !ok {
			return
		}
		for _, tok := range strings.Fields(def.Scopes) {
			scopes[tok] = true
		}
		for _, parent := range def.Inherits {
			walk(parent)
		}
	}
	walk(role)
	if scopes["*"] {
		return "*"
	}
	out := make([]string, 0, len(scopes))
	for s := range scopes {
		out = append(out, s)
	}
	// Stable ordering — predictable for tests + audit logs.
	sortStrings(out)
	return strings.Join(out, " ")
}

// ResolveScopesForRoles returns the unioned scope string across the
// given set of role names. Each role is expanded through its
// inheritance chain. `*` in any role short-circuits to full access.
func (rc *RolesConfig) ResolveScopesForRoles(roles []string) string {
	if rc == nil || len(roles) == 0 {
		return ""
	}
	combined := make(map[string]bool)
	for _, r := range roles {
		s := rc.ResolveRoleScopes(r)
		if s == "*" {
			return "*"
		}
		for _, tok := range strings.Fields(s) {
			combined[tok] = true
		}
	}
	out := make([]string, 0, len(combined))
	for s := range combined {
		out = append(out, s)
	}
	sortStrings(out)
	return strings.Join(out, " ")
}

// KnownRoles returns the configured role names (for /api/_auth/roles).
func (rc *RolesConfig) KnownRoles() []string {
	if rc == nil {
		return nil
	}
	out := make([]string, 0, len(rc.Roles))
	for name := range rc.Roles {
		out = append(out, name)
	}
	sortStrings(out)
	return out
}

// sortStrings is a tiny shim so we can sort without dragging sort
// into the import section here (config.go already pulls a lot in).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// ScopesForRole returns the default scopes for a role, or empty string if not configured.
func (rc *RolesConfig) ScopesForRole(role string) string {
	if rc == nil {
		return ""
	}
	if def, ok := rc.Roles[role]; ok {
		return def.Scopes
	}
	return ""
}

// LoadAuthPaths is deprecated — use DiscoverAuthPaths(pages) instead.
// Auth paths are now discovered from page type="" attributes.
