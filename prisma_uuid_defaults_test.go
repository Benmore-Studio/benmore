//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The default deployed by Prisma before UUID version/variant correction.
const oldPrismaUUIDDefault = `(lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(2))) || '-' || lower(hex(randomblob(6))))`

var uuid4Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

const uuidDefaultSchema = `model Item {
 id String @id @default(uuid())
 userId Int?
 name String
 reference String? @default(uuid())
}`

func TestPrismaUUID4GeneratedSQL(t *testing.T) {
	models, err := ParsePrismaSchema(uuidDefaultSchema)
	if err != nil {
		t.Fatal(err)
	}
	if got := models[0].Fields[0].Default; got != SQLiteUUID4Default {
		t.Errorf("Prisma UUID default does not use the shared v4 expression: %s", got)
	}
	app := newGateApp(t, EmitSQL(models))
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		var id, reference string
		if err := app.DB.QueryRow(`INSERT INTO items(name) VALUES ('generated') RETURNING id,reference`).Scan(&id, &reference); err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{id, reference} {
			if !uuid4Pattern.MatchString(value) || seen[value] {
				t.Errorf("default is not a unique UUID v4: %q", value)
			}
			seen[value] = true
		}
	}
}

func uuidDefaultFixture(t *testing.T, physicalDefault, source string) (*App, *http.ServeMux, string) {
	t.Helper()
	app := newGateApp(t, fmt.Sprintf(`CREATE TABLE items (id TEXT PRIMARY KEY DEFAULT %s, user_id INTEGER, name TEXT NOT NULL, reference TEXT DEFAULT %s)`, physicalDefault, physicalDefault))
	EnsureJobsTable(app.DB)
	EnsureWebhooksTable(app.DB)
	EnsureImportsTable(app)
	mustExec(t, app.DB, `INSERT INTO items(id,name,reference) VALUES ('existing-non-v4-id','existing','existing-reference')`)
	if source != "" {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		tables, deferred, err := LoadSchema(app.DB, dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := ApplyDeferredDDL(app.DB, deferred); err != nil {
			t.Fatal(err)
		}
		app.Tables = tables
	}
	if got := gateScalar(t, app, `SELECT sql FROM sqlite_master WHERE name='items'`); !strings.Contains(got, "DEFAULT "+physicalDefault) {
		t.Fatalf("schema loading rewrote the physical default: %s", got)
	}
	app.UUIDTables = DetectUUIDTables(app.Tables)
	_, sid := gateUser(t, app, "uuid-default@example.invalid")
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	return app, mux, sid
}

func uuidDefaultImport(t *testing.T, app *App, format, content, id string) {
	t.Helper()
	sum := stageString(t, app, id, content)
	sess := &importSession{ID: id, TableName: "items", Format: format, BytesTotal: int64(len(content)), SHA256: sum, NullAs: `\N`}
	insertSession(t, app, sess)
	if err := runImport(app, sess); err != nil {
		t.Fatal(err)
	}
}

func TestPrismaUUID4ExistingTableNativeCreates(t *testing.T) {
	for _, mode := range []string{"single", "batch", "transaction", "ingest", "import_csv", "import_ndjson"} {
		t.Run(mode, func(t *testing.T) {
			app, mux, sid := uuidDefaultFixture(t, oldPrismaUUIDDefault, uuidDefaultSchema)
			before := gateScalar(t, app, `SELECT sql FROM sqlite_master WHERE name='items'`)
			if strings.HasPrefix(mode, "import_") {
				format := strings.TrimPrefix(mode, "import_")
				content := "name\ngenerated\nsecond\n"
				if format == "ndjson" {
					content = "{\"name\":\"generated\"}\n{\"name\":\"second\"}\n"
				}
				uuidDefaultImport(t, app, format, content, "uuidimport001")
			} else {
				for _, name := range []string{"generated", "second"} {
					w := inventorySchemaRequest(mux, sid, mode, map[string]any{"name": name})
					if w.Code != 200 {
						t.Fatalf("create: %d %s", w.Code, w.Body.String())
					}
				}
			}
			rows, err := app.DB.Query(`SELECT id,reference FROM items WHERE name != 'existing'`)
			if err != nil {
				t.Fatal(err)
			}
			seen := map[string]bool{}
			count := 0
			for rows.Next() {
				var id, reference string
				if err := rows.Scan(&id, &reference); err != nil {
					t.Fatal(err)
				}
				count++
				for _, value := range []string{id, reference} {
					if !uuid4Pattern.MatchString(value) || seen[value] {
						t.Errorf("native default is not a unique UUID v4: %q", value)
					}
					seen[value] = true
				}
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if err := rows.Close(); err != nil {
				t.Fatal(err)
			}
			if count != 2 {
				t.Fatalf("created %d rows, want 2", count)
			}
			if got := gateScalar(t, app, `SELECT id || ':' || reference FROM items WHERE name='existing'`); got != "existing-non-v4-id:existing-reference" {
				t.Fatalf("stored identity rewritten: %q", got)
			}
			if after := gateScalar(t, app, `SELECT sql FROM sqlite_master WHERE name='items'`); after != before {
				t.Fatal("native insert rebuilt the existing table")
			}
		})
	}
}

func TestPrismaUUID4ExplicitValuesAndCustomDefaults(t *testing.T) {
	for _, mode := range []string{"single", "batch", "transaction", "ingest"} {
		t.Run(mode, func(t *testing.T) {
			app, mux, sid := uuidDefaultFixture(t, oldPrismaUUIDDefault, uuidDefaultSchema)
			for i, value := range []any{"caller-reference", nil} {
				name := fmt.Sprintf("explicit-%d", i)
				w := inventorySchemaRequest(mux, sid, mode, map[string]any{"name": name, "reference": value, "id": "native-caller-id"})
				if w.Code != 200 {
					t.Fatalf("explicit value: %d %s", w.Code, w.Body.String())
				}
				if got := gateScalar(t, app, fmt.Sprintf("SELECT reference FROM items WHERE name='%s'", name)); got != fmt.Sprint(value) {
					t.Fatalf("explicit default replaced: %q want %v", got, value)
				}
				// Native CRUD has always protected the primary key. A request
				// cannot opt out of that policy by naming its own id.
				if got := gateScalar(t, app, fmt.Sprintf("SELECT id FROM items WHERE name='%s'", name)); !uuid4Pattern.MatchString(got) {
					t.Fatalf("native id protection changed: %q", got)
				}
			}
			mustExec(t, app.DB, `INSERT INTO items(id,name,reference) VALUES ('caller-id','sql-explicit','caller-sql-reference')`)
			if gateScalar(t, app, `SELECT id FROM items WHERE name='sql-explicit'`) != "caller-id" {
				t.Fatal("explicit SQL identity changed")
			}
		})
	}
	for _, format := range []string{"csv", "ndjson"} {
		t.Run("import_explicit_"+format, func(t *testing.T) {
			app, _, _ := uuidDefaultFixture(t, oldPrismaUUIDDefault, uuidDefaultSchema)
			content := "name,reference\nexplicit,caller-reference\nnull,\\N\n"
			if format == "ndjson" {
				content = "{\"name\":\"explicit\",\"reference\":\"caller-reference\"}\n{\"name\":\"null\",\"reference\":null}\n"
			}
			uuidDefaultImport(t, app, format, content, "uuidexplicit001")
			if gateScalar(t, app, `SELECT reference FROM items WHERE name='explicit'`) != "caller-reference" || gateScalar(t, app, `SELECT reference FROM items WHERE name='null'`) != "<nil>" {
				t.Fatal("import replaced explicit reference or null")
			}
		})
	}
	for _, tc := range []struct{ name, physical, source, pattern string }{
		{"custom_sql", `('custom-' || lower(hex(randomblob(8))))`, "", `^custom-[0-9a-f]{16}$`},
		{"custom_physical", `('custom-' || lower(hex(randomblob(8))))`, uuidDefaultSchema, `^custom-[0-9a-f]{16}$`},
		{"cuid", `(strftime('%Y%m%d%H%M%S', 'now') || lower(hex(randomblob(6))))`, strings.ReplaceAll(uuidDefaultSchema, "uuid()", "cuid()"), `^[0-9]{14}[0-9a-f]{12}$`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, mux, sid := uuidDefaultFixture(t, tc.physical, tc.source)
			w := inventorySchemaRequest(mux, sid, "single", map[string]any{"name": "custom"})
			if w.Code != 200 {
				t.Fatalf("custom default: %d %s", w.Code, w.Body.String())
			}
			if got := gateScalar(t, app, `SELECT id FROM items WHERE name='custom'`); !regexp.MustCompile(tc.pattern).MatchString(got) {
				t.Fatalf("custom identity contract changed: %q", got)
			}
			uuidDefaultImport(t, app, "csv", "name\nimport-custom\n", "uuidcustom001")
			if got := gateScalar(t, app, `SELECT id FROM items WHERE name='import-custom'`); !regexp.MustCompile(tc.pattern).MatchString(got) {
				t.Fatalf("import custom identity contract changed: %q", got)
			}
		})
	}
}

func TestPrismaUUID4DefaultsEvaluateOnceWithHooks(t *testing.T) {
	for _, mode := range []string{"single", "batch", "transaction", "ingest"} {
		t.Run(mode, func(t *testing.T) {
			app, mux, sid := uuidDefaultFixture(t, oldPrismaUUIDDefault, uuidDefaultSchema)
			mustExec(t, app.DB, `CREATE TABLE observed_uuid (id TEXT, reference TEXT, submitted TEXT)`)
			app.Validators = &ValidatorConfig{Rules: map[string][]ValidatorRule{"items": {{Rule: "reference != ''"}}}}
			app.Hooks = &HookConfig{BeforeInsert: map[string][]Hook{"items": {{SQL: "INSERT INTO observed_uuid(id,reference,submitted) VALUES ('{{id}}','{{reference}}','{{_submitted}}')"}}}}
			w := inventorySchemaRequest(mux, sid, mode, map[string]any{"name": "once"})
			if w.Code != 200 {
				t.Fatalf("create with hooks: %d %s", w.Code, w.Body.String())
			}
			if got := gateScalar(t, app, `SELECT count(*) FROM items JOIN observed_uuid USING(id,reference) WHERE items.name='once' AND observed_uuid.submitted=',name,'`); got != "1" {
				t.Fatal("UUID defaults changed after validation/hooks or became submitted fields")
			}
		})
	}
}
