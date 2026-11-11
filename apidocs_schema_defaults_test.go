//go:build !cli

package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

// sduiEventsSchema is the round 2026-11-05 events app (front findings 2 and
// 3): string defaults of "", a DateTime with a time of day, Booleans and an
// optional relation.
const sduiEventsSchema = `model Venue {
  id       Int     @id @default(autoincrement())
  name     String
  city     String  @default("")
  capacity Int     @default(100)
  userId   Int?    @map("user_id")
  events   Event[]
  @@map("venues")
}

model Event {
  id        Int      @id @default(autoincrement())
  title     String
  summary   String   @default("")
  body      String   @default("")
  startsAt  DateTime @map("starts_at")
  published Boolean  @default(false)
  featured  Boolean  @default(true)
  venueId   Int?     @map("venue_id")
  venue     Venue?   @relation(fields: [venueId], references: [id])
  remindAt  DateTime @default(now()) @map("remind_at")
  userId    Int?     @map("user_id")
  @@map("events")
}
`

func sduiEventsApp(t *testing.T) *App {
	t.Helper()
	dir := writeApp(t, map[string]string{
		"app.yaml":      "site_name: Events\naccess:\n  venues: self\n  events: self\n",
		"schema.prisma": sduiEventsSchema,
	})
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	return app
}

// richSchemaFields returns table → field name → descriptor field, as a
// component reads it from GET /api/_schema (through JSON).
func richSchemaFields(t *testing.T, app *App, s *Session) map[string]map[string]map[string]any {
	t.Helper()
	raw, err := json.Marshal(generateRichSchema(app, s))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Tables map[string]struct {
			Fields []map[string]any `json:"fields"`
		} `json:"tables"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]map[string]any{}
	for table, td := range doc.Tables {
		out[table] = map[string]map[string]any{}
		for _, f := range td.Fields {
			out[table][f["name"].(string)] = f
		}
	}
	return out
}

// /api/_schema handed RecordForm the SQL default literal: `@default("")`
// came back as "”", so a create form was prefilled with two apostrophes and
// saved them. DateTime columns got the date control (a saved edit cut the time
// of day), and Booleans the text box. The descriptor now carries the parsed
// value and a control that can hold the column's value.
func TestRichSchemaDefaultsAndControlsMatchColumnValues(t *testing.T) {
	app := sduiEventsApp(t)
	fields := richSchemaFields(t, app, &Session{UserID: 1, Role: "admin"})

	type want struct {
		control    string
		def        any
		required   bool
		hasDefault bool
	}
	cases := map[string]map[string]want{
		"venues": {
			"name":     {control: "text", required: true},
			"city":     {control: "text", def: "", hasDefault: true},
			"capacity": {control: "number", def: float64(100), hasDefault: true},
		},
		"events": {
			"title":     {control: "text", required: true},
			"summary":   {control: "text", def: "", hasDefault: true},
			"body":      {control: "textarea", def: "", hasDefault: true},
			"starts_at": {control: "datetime", required: true},
			"published": {control: "checkbox", def: false, hasDefault: true},
			"featured":  {control: "checkbox", def: true, hasDefault: true},
			"venue_id":  {control: "number"},
			// now() is computed at insert: there is no value to prefill.
			"remind_at": {control: "datetime"},
		},
	}
	for table, cols := range cases {
		for name, w := range cols {
			f, ok := fields[table][name]
			if !ok {
				t.Errorf("%s.%s missing from the descriptor", table, name)
				continue
			}
			if f["control"] != w.control {
				t.Errorf("%s.%s control = %v, want %s", table, name, f["control"], w.control)
			}
			if got, _ := f["required"].(bool); got != w.required {
				t.Errorf("%s.%s required = %v, want %v", table, name, f["required"], w.required)
			}
			def, has := f["default"]
			if has != w.hasDefault || (has && !reflect.DeepEqual(def, w.def)) {
				t.Errorf("%s.%s default = %#v (present %v), want %#v (present %v)", table, name, def, has, w.def, w.hasDefault)
			}
		}
	}
	if rel, _ := fields["events"]["venue_id"]["relation"].(map[string]any); rel["table"] != "venues" {
		t.Errorf("events.venue_id relation = %v, want venues", fields["events"]["venue_id"]["relation"])
	}
}

// SQLite reports a default as the SQL text it was declared with (PRAGMA
// table_info dflt_value, parentheses removed). Only a literal has a value a
// form can show; anything SQLite computes at insert time has none.
func TestSchemaDefaultValueParsesSQLLiterals(t *testing.T) {
	cases := []struct {
		typ, def string
		want     any
		ok       bool
	}{
		{"TEXT", "''", "", true},
		{"TEXT", "'draft'", "draft", true},
		{"TEXT", "'O''Brien'", "O'Brien", true},
		{"TEXT", `"dq"`, "dq", true},
		{"TEXT", "'a' || 'b'", nil, false},
		{"TEXT", "NULL", nil, false},
		{"TEXT", "lower(hex(randomblob(4)))", nil, false},
		{"TEXT", SQLiteUUID4Default, nil, false},
		{"TEXT", "X'41'", nil, false},
		{"TEXT", "7", "7", true},
		{"INTEGER", "-1", int64(-1), true},
		{"INTEGER", "+7", int64(7), true},
		{"INTEGER", "0x10", int64(16), true},
		{"INTEGER", "'5'", int64(5), true},
		{"REAL", "4.5", 4.5, true},
		{"REAL", "1e3", float64(1000), true},
		{"BOOLEAN", "0", false, true},
		{"BOOLEAN", "1", true, true},
		{"BOOLEAN", "TRUE", true, true},
		{"BOOLEAN", "false", false, true},
		{"DATETIME", "CURRENT_TIMESTAMP", nil, false},
		{"DATE", "CURRENT_DATE", nil, false},
		{"DATETIME", "'2026-01-01T09:00:00Z'", "2026-01-01T09:00:00Z", true},
		{"TEXT", "", nil, false},
	}
	for _, c := range cases {
		got, ok := schemaDefaultValue(Column{Name: "c", Type: c.typ, Default: c.def})
		if ok != c.ok || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s DEFAULT %s = %#v (%v), want %#v (%v)", c.typ, c.def, got, ok, c.want, c.ok)
		}
	}
}

// The declared type picks the control before the column name does, for the
// types a text box would corrupt: a DATE is a date, a DATETIME an instant
// (datetime-local), a BOOLEAN a checkbox even when it is called has_file.
func TestSchemaControlForDeclaredTypes(t *testing.T) {
	cases := []struct{ name, typ, want string }{
		{"starts_at", "DATETIME", "datetime"},
		{"logged", "TIMESTAMP", "datetime"},
		{"due_date", "DATETIME", "date"},
		{"birthday", "DATETIME", "date"},
		{"due", "DATE", "date"},
		{"opens", "TIME", "time"},
		{"published", "BOOLEAN", "checkbox"},
		{"has_file", "BOOLEAN", "checkbox"},
		{"is_active", "INTEGER", "checkbox"},
		{"count", "INTEGER", "number"},
		{"price", "REAL", "number"},
		{"email", "TEXT", "email"},
		{"title", "TEXT", "text"},
		{"created_at", "DATETIME", "hidden"},
	}
	for _, c := range cases {
		if got := schemaControlFor(Column{Name: c.name, Type: c.typ}); got != c.want {
			t.Errorf("%s %s: control %q, want %q", c.name, c.typ, got, c.want)
		}
	}
}
