//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// AppContext is a single-shot dump of everything an LLM needs to understand and modify an app.
type AppContext struct {
	AppDir     string            `json:"app_dir"`
	Schema     []TableContext    `json:"schema"`
	Routes     []RouteContext    `json:"routes"`
	API        []string          `json:"api_endpoints"`
	Hooks      map[string]int    `json:"hooks"`
	Flows      []string          `json:"flows"`
	EnvVars    []string          `json:"env_vars"`
	Design     map[string]string `json:"design"`
	Auth       AuthContext       `json:"auth"`
	Components []string          `json:"available_components"`
	Pipes      []string          `json:"available_pipes"`
	Files      []FileContext     `json:"files"`
	Issues     []string          `json:"issues"`
}

type TableContext struct {
	Name        string   `json:"name"`
	Columns     []string `json:"columns"`
	RowCount    int64    `json:"rows"`
	ForeignKeys []string `json:"foreign_keys,omitempty"`
}

type RouteContext struct {
	Path     string   `json:"path"`
	File     string   `json:"file"`
	Auth     string   `json:"auth"`
	Role     string   `json:"role,omitempty"`
	Title    string   `json:"title,omitempty"`
	Type     string   `json:"type,omitempty"`
	Features []string `json:"features,omitempty"`
}

type AuthContext struct {
	Enabled   bool     `json:"enabled"`
	OAuth     []string `json:"oauth_providers,omitempty"`
	UserCount int64    `json:"user_count"`
	HasAdmin  bool     `json:"has_admin"`
}

type FileContext struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Lines int    `json:"lines"`
}

// BuildContext generates the full app context for LLM consumption.
func BuildContext(app *App) AppContext {
	ctx := AppContext{
		AppDir: app.Dir,
		Hooks:  make(map[string]int),
		Design: make(map[string]string),
	}

	// Schema
	tableNames, _ := GetTableNames(app.DB)
	for _, name := range tableNames {
		if strings.HasPrefix(name, "_benmore_") {
			continue
		}
		cols, _ := GetTableColumns(app.DB, name)
		var colStrs []string
		for _, c := range cols {
			s := c.Name + " " + c.Type
			if c.PK {
				s += " PK"
			}
			if c.NotNull {
				s += " NOT NULL"
			}
			if c.Default != "" {
				s += " DEFAULT " + c.Default
			}
			colStrs = append(colStrs, s)
		}
		var count int64
		app.DB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", name)).Scan(&count)

		fks, _ := GetForeignKeys(app.DB, name)
		var fkStrs []string
		for col, fk := range fks {
			fkStrs = append(fkStrs, fmt.Sprintf("%s → %s.%s", col, fk.Table, fk.Column))
		}

		ctx.Schema = append(ctx.Schema, TableContext{
			Name: name, Columns: colStrs, RowCount: count, ForeignKeys: fkStrs,
		})
	}

	// Routes
	for route, page := range app.Pages {
		rc := RouteContext{
			Path: route, File: page.File, Auth: page.Auth, Title: page.Title,
			Role: extractPageRole(page.RawHTML), Type: page.Type,
		}
		rc.Features = detectPageFeatures2(page.RawHTML)
		ctx.Routes = append(ctx.Routes, rc)
	}

	// API
	for _, name := range tableNames {
		if !strings.HasPrefix(name, "_benmore_") {
			ctx.API = append(ctx.API, fmt.Sprintf("/api/%s [GET POST PATCH DELETE]", name))
		}
	}

	// Hooks
	if app.Hooks != nil {
		for table, hooks := range app.Hooks.OnInsert {
			ctx.Hooks["on_insert:"+table] = len(hooks)
		}
		for table, hooks := range app.Hooks.OnUpdate {
			ctx.Hooks["on_update:"+table] = len(hooks)
		}
		for table, hooks := range app.Hooks.OnDelete {
			ctx.Hooks["on_delete:"+table] = len(hooks)
		}
	}

	// Flows
	for _, flow := range app.Flows {
		trigger := flow.Trigger.Type
		if flow.Trigger.Path != "" {
			trigger += " " + flow.Trigger.Method + " " + flow.Trigger.Path
		}
		if flow.Trigger.Table != "" {
			trigger += " " + flow.Trigger.Table
		}
		if flow.Trigger.Cron != "" {
			trigger += " " + flow.Trigger.Cron
		}
		ctx.Flows = append(ctx.Flows, fmt.Sprintf("%s → %s (%d steps)", flow.Name, trigger, len(flow.Steps)))
	}

	// Env vars (names only, not values)
	for k := range EnvVars {
		ctx.EnvVars = append(ctx.EnvVars, k)
	}

	// Design
	if app.Design != nil {
		if t, ok := app.Design.Colors["_theme"]; ok {
			ctx.Design["theme"] = t
		}
		if m, ok := app.Design.Colors["_mode"]; ok {
			ctx.Design["mode"] = m
		}
		if f, ok := app.Design.Colors["_font"]; ok {
			ctx.Design["font"] = f
		}
		if b, ok := app.Design.Colors["_brand"]; ok {
			ctx.Design["brand"] = b
		}
	}

	// Auth
	ctx.Auth.Enabled = NeedsAuth(app)
	ctx.Auth.OAuth = GetConfiguredProviders(app.Dir)
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_users").Scan(&ctx.Auth.UserCount)
	var adminCount int64
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_users WHERE role = 'admin'").Scan(&adminCount)
	ctx.Auth.HasAdmin = adminCount > 0

	// Available components
	ctx.Components = []string{
		`<table :model="x" search sort paginate />`,
		`<board :model="x" by="field" />`,
		`<stat label="X" sql="..." prefix="$" />`,
		`<chart type="bar" sql="..." x="col" y="col" />`,
		`<card title="X">content</card>`,
		`<modal id="x" title="X">content</modal>`,
		`<tabs><tab label="X">content</tab></tabs>`,
		`<grid cols="3">content</grid>`,
		`<badge text="X" color="primary|success|warning|danger" />`,
		`<detail :model="x" :id="N" />`,
		`<list :model="x" />`,
		`<avatar name="X" />`,
		`<empty message="X" />`,
		`<skeleton rows="5" />`,
		`<alert type="info|warning|error|success" message="X" />`,
		`<progress value="75" max="100" />`,
		`<breadcrumb items="Home:/,Page:/page" />`,
		`<pagination total="100" page="1" per_page="20" />`,
		`<timeline :model="x" />`,
		`<toggle name="field" />`,
		`<copy value="X" />`,
		`<separator />`,
		`<search placeholder="X" />`,
		`<icon name="x" size="16" />`,
		`<fetch url="..." as="data" cache="1h">{{#data}}...{{/data}}</fetch>`,
		`<include src="partials/x.html" />`,
	}

	// Available pipes
	ctx.Pipes = []string{
		"currency", "cents", "number", "percent",
		"date", "ago",
		"upper", "lower", "title", "trim", "truncate:N", "slug", "initials",
		"digits", "strip_html", "nl2br",
		"md5", "sha256", "base64", "urlencode",
		"first", "last", "default:X", "pluralize",
	}

	// Files
	entries, _ := os.ReadDir(app.Dir)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ftype := "other"
		switch {
		case name == "schema.sql":
			ftype = "schema"
		case strings.HasSuffix(name, ".html"):
			ftype = "page"
		case name == "app.yaml":
			ftype = "design"
		case name == "hooks.yaml":
			ftype = "hooks"
		case name == "flows.yaml":
			ftype = "flows"
		case name == "env.yaml":
			ftype = "env"
		case name == "seeds.sql":
			ftype = "seeds"
		case name == "head.html":
			ftype = "head"
		case name == "theme.css":
			ftype = "css"
		}
		if ftype == "other" {
			continue
		}

		lines := 0
		if data, err := os.ReadFile(filepath.Join(app.Dir, name)); err == nil {
			lines = strings.Count(string(data), "\n") + 1
		}
		ctx.Files = append(ctx.Files, FileContext{Name: name, Type: ftype, Lines: lines})
	}

	return ctx
}

func detectPageFeatures2(html string) []string {
	var f []string
	if strings.Contains(html, "<stat ") {
		f = append(f, "stat")
	}
	if strings.Contains(html, `:model="`) {
		f = append(f, "model")
	}
	if strings.Contains(html, `<board `) {
		f = append(f, "board")
	}
	if strings.Contains(html, `<chart `) {
		f = append(f, "chart")
	}
	if strings.Contains(html, `:create=`) {
		f = append(f, "create-form")
	}
	if strings.Contains(html, `<query `) {
		f = append(f, "query")
	}
	if strings.Contains(html, `<modal `) {
		f = append(f, "modal")
	}
	if strings.Contains(html, `<fetch `) {
		f = append(f, "fetch")
	}
	return f
}

// PrintContext outputs the context as formatted JSON.
func PrintContext(app *App) {
	ctx := BuildContext(app)
	data, _ := json.MarshalIndent(ctx, "", "  ")
	fmt.Println(string(data))
}
