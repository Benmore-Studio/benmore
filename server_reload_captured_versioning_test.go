//go:build !cli

package main

import "testing"

func TestReloadCapturedVersioningInstallsOnlyReviewedHistory(t *testing.T) {
	for _, source := range []string{"versioned: [notes]\n", "versioned: []\n"} {
		t.Run(source, func(t *testing.T) {
			app, _ := auditApp(t)
			writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, body TEXT, created_at TEXT);")
			writeTestFile(t, app.Dir, "app.yaml", source)
			writeTestFile(t, app.Dir, "mcp.yaml", appMCPManifestFixture())
			reviewAppMCPFixture(t, app.Dir)
			config, err := loadRuntimeConfig(app.Dir)
			if err != nil {
				t.Fatal(err)
			}
			// The reviewed generation is already captured. A later disk replacement
			// must not alter which tables receive persistent history triggers.
			writeTestFile(t, app.Dir, "app.yaml", "versioned: [orgdocs]\n")
			if err := reloadAppConfigStaged(app, config, nil); err != nil {
				t.Fatal(err)
			}
			var unreviewed int
			if err := app.DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE name='orgdocs_history'").Scan(&unreviewed); err != nil || unreviewed != 0 {
				t.Errorf("unreviewed history installed: count=%d err=%v", unreviewed, err)
			}
			if source == "versioned: []\n" {
				return
			}
			mustExec(t, app.DB, "INSERT INTO notes(id,title) VALUES (51,'before')")
			mustExec(t, app.DB, "UPDATE notes SET title='after' WHERE id=51")
			var title string
			if err := app.DB.QueryRow("SELECT title FROM notes_history WHERE id=51 AND _version=1").Scan(&title); err != nil || title != "before" {
				t.Fatalf("reviewed history was not active: title=%q err=%v", title, err)
			}
		})
	}
}
