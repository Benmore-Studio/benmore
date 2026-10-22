//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestAppMCPCapturedI18nRendersReviewedGeneration(t *testing.T) {
	app, _ := auditApp(t)
	for name, source := range map[string]string{
		"schema.sql":    "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, title TEXT);",
		"index.html":    `<page auth="none" layout="none"><p>{{t "section.greeting"}}</p></page>`,
		"gotmpl.html":   "---\nengine: gotmpl\nauth: none\nlayout: none\n---\n<p>{{t \"section.greeting\"}}</p>",
		"i18n/en.yaml":  "section.greeting: flat English\nonly.english: English only\n",
		"i18n/en.yml":   "section:\n  greeting: reviewed English\n",
		"i18n/es.yaml":  "section:\n  greeting: Espanol revisado\n",
		"i18n/.default": "es\n",
	} {
		writeTestFile(t, app.Dir, name, source)
	}
	writeTestFile(t, app.Dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if config.i18n == nil || config.i18n.DefaultLang != "es" || config.i18n.T("section.greeting", "fr") != "Espanol revisado" {
		t.Fatalf("captured default/fallback: %+v", config.i18n)
	}
	if got := config.i18n.T("section.greeting", "en"); got != "reviewed English" {
		t.Fatalf("lexical yaml/yml override = %q", got)
	}

	if err := os.RemoveAll(filepath.Join(app.Dir, "i18n")); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "i18n/en.yaml", "section.greeting: unreviewed English\nlate.key: late\n")
	writeTestFile(t, app.Dir, "i18n/fr.yaml", "section.greeting: unreviewed French\n")
	writeTestFile(t, app.Dir, "i18n/.default", "fr\n")
	if err := reloadAppConfigStaged(app, config, nil); err != nil {
		t.Fatal(err)
	}
	if got := app.i18nConfig().T("section.greeting", "en"); got != "reviewed English" {
		t.Fatalf("published translation changed with disk: %q", got)
	}
	if app.i18nConfig().DefaultLang != "es" || app.i18nConfig().T("section.greeting", "fr") != "Espanol revisado" {
		t.Fatalf("published default/fallback changed: %+v", app.i18nConfig())
	}

	mux := http.NewServeMux()
	registerAppPageRoutes(mux, app, false)
	for _, tc := range []struct {
		path, want string
	}{{"/?lang=en", "reviewed English"}, {"/gotmpl?lang=en", "reviewed English"}, {"/?lang=fr", "Espanol revisado"}, {"/gotmpl?lang=fr", "Espanol revisado"}} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), tc.want) || strings.Contains(rec.Body.String(), "unreviewed") {
			t.Fatalf("%s: HTTP %d %s", tc.path, rec.Code, rec.Body.String())
		}
	}
	var types strings.Builder
	writeI18nType(&types, app)
	if !strings.Contains(types.String(), `'section.greeting'`) {
		t.Fatalf("I18nKey omitted reviewed key: %s", types.String())
	}
	// The canonical lexical override replaces the whole language dictionary.
	if strings.Contains(types.String(), "only.english") {
		t.Fatalf("I18nKey merged an overridden dictionary: %s", types.String())
	}
	if strings.Contains(types.String(), "late.key") {
		t.Fatalf("I18nKey included an unreviewed key: %s", types.String())
	}
}

func TestAppMCPCapturedEmptyI18nClearsOnReload(t *testing.T) {
	app, _ := auditApp(t)
	app.I18n = &I18n{DefaultLang: "en", Translations: map[string]map[string]string{"en": {"old.key": "old"}}}
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, title TEXT);")
	writeTestFile(t, app.Dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "i18n/en.yaml", "late.key: late on disk\n")
	if config.i18n != nil {
		t.Fatalf("empty reviewed capture loaded disk translations: %+v", config.i18n)
	}
	if err := reloadAppConfigStaged(app, config, nil); err != nil {
		t.Fatal(err)
	}
	if app.i18nConfig() != nil {
		t.Fatalf("checked reload retained previous translations: %+v", app.i18nConfig())
	}
	if got := LoadI18n(app.Dir).T("late.key", "en"); got != "late on disk" {
		t.Fatalf("ordinary disk loader = %q", got)
	}
}

func TestAppMCPRejectsInvalidCapturedI18nBeforeDatabase(t *testing.T) {
	for name, source := range map[string]string{
		"malformed": "section: [unterminated\n",
		"two-docs":  "hello: first\n---\nhello: second\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
			writeTestFile(t, dir, "i18n/en.yaml", source)
			writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
			reviewAppMCPFixture(t, dir)
			if _, err := loadApp(dir); err == nil {
				t.Fatal("invalid reviewed translation accepted")
			}
			if _, err := os.Stat(filepath.Join(dir, "data.db")); !os.IsNotExist(err) {
				t.Fatalf("invalid translation reached database initialization: %v", err)
			}
		})
	}
	for name, setup := range map[string]func(string) error{
		"root-file": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "i18n"), []byte("not a directory"), 0600)
		},
		"case-alias": func(dir string) error { return os.Mkdir(filepath.Join(dir, "I18N"), 0700) },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
			writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
			if err := setup(dir); err != nil {
				t.Fatal(err)
			}
			if _, err := loadApp(dir); err == nil {
				t.Fatal("ambiguous i18n source accepted")
			}
			if _, err := os.Stat(filepath.Join(dir, "data.db")); !os.IsNotExist(err) {
				t.Fatalf("invalid i18n path reached database initialization: %v", err)
			}
		})
	}
}

func TestI18nReadersObserveLockedImmutablePublication(t *testing.T) {
	app := &App{I18n: &I18n{DefaultLang: "en", Translations: map[string]map[string]string{"en": {"key": "first"}}}}
	helper := gotmplHelpers(app, nil)["t"].(func(string) string)
	generations := []*I18n{
		{DefaultLang: "en", Translations: map[string]map[string]string{"en": {"key": "first"}}},
		{DefaultLang: "en", Translations: map[string]map[string]string{"en": {"key": "second"}}},
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for n := 0; n < 3; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 300; i++ {
				if got := app.i18nConfig().T("key", "en"); got != "first" && got != "second" {
					t.Errorf("i18nConfig.T = %q", got)
					return
				}
				if got := helper("key"); got != "first" && got != "second" {
					t.Errorf("gotmpl t = %q", got)
					return
				}
				var types strings.Builder
				writeI18nType(&types, app)
				if !strings.Contains(types.String(), `'key'`) {
					t.Errorf("writeI18nType lost key: %s", types.String())
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 300; i++ {
			app.mu.Lock()
			app.I18n = generations[i%len(generations)]
			app.mu.Unlock()
		}
	}()
	close(start)
	wg.Wait()
}
