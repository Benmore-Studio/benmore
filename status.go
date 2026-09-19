//go:build !cli

package main

import (
	"fmt"
)

// BuildStatus creates a full app introspection snapshot.
func BuildStatus(app *App) StatusOutput {
	status := StatusOutput{
		Tables: make(map[string][]string),
	}

	tableNames, _ := GetTableNames(app.DB)
	for _, name := range tableNames {
		cols, _ := GetTableColumns(app.DB, name)
		var colNames []string
		for _, c := range cols {
			colType := c.Type
			if c.PK {
				colType += " PK"
			}
			if c.NotNull {
				colType += " NOT NULL"
			}
			colNames = append(colNames, fmt.Sprintf("%s %s", c.Name, colType))
		}
		status.Tables[name] = colNames
	}

	for route, page := range app.Pages {
		auth := page.Auth
		if auth == "" {
			auth = "none"
		}
		status.Routes = append(status.Routes, RouteInfo{
			Path: route,
			File: page.File,
			Auth: auth,
		})
	}

	for _, name := range tableNames {
		status.API = append(status.API, fmt.Sprintf("/api/%s (GET, POST, PATCH, DELETE)", name))
	}

	for _, name := range tableNames {
		fks, _ := GetForeignKeys(app.DB, name)
		for col, fk := range fks {
			status.Relationships = append(status.Relationships,
				fmt.Sprintf("%s.%s → %s.%s", name, col, fk.Table, fk.Column))
		}
	}

	return status
}

// RenderPage renders a single page route to HTML string.
func RenderPage(app *App, route string) (string, error) {
	page, ok := app.Pages[route]
	if !ok {
		return "", fmt.Errorf("route %s not found (available: %v)", route, pageRoutes(app))
	}

	ctx := &RenderContext{
		Data: make(map[string]any),
		App:  app,
		Page: page,
	}

	return RenderTemplate(app, page, ctx)
}

func pageRoutes(app *App) []string {
	var routes []string
	for r := range app.Pages {
		routes = append(routes, r)
	}
	return routes
}
