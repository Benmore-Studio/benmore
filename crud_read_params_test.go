//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// readParamsSchema declares relations whose field names differ from the
// related table names, so only the Prisma relation field can resolve them:
// `notes CaseNote[]` (table case_notes), a second, named relation between
// the same two models (`referrals` / `referredBy`), and a named self-relation
// (`supervisees` / `supervisor`).
const readParamsSchema = `
model Patient {
  id         Int        @id @default(autoincrement())
  userId     Int
  fullName   String
  diagnosis  String?
  apiToken   String?
  notes      CaseNote[]
  referrals  CaseNote[] @relation("Referrals")
  createdAt  DateTime   @default(now())
  updatedAt  DateTime   @updatedAt
}

model CaseNote {
  id           Int      @id @default(autoincrement())
  userId       Int
  patientId    Int
  patient      Patient  @relation(fields: [patientId], references: [id])
  referredById Int?
  referredBy   Patient? @relation("Referrals", fields: [referredById], references: [id])
  body         String
  shareToken   String?
}

model Clinician {
  id           Int         @id @default(autoincrement())
  name         String
  supervisorId Int?
  supervisor   Clinician?  @relation("Supervision", fields: [supervisorId], references: [id])
  supervisees  Clinician[] @relation("Supervision")
}
`

type readParamsFixture struct {
	app   *App
	mux   *http.ServeMux
	alice string
	bob   string
}

func newReadParamsFixture(t *testing.T) *readParamsFixture {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.prisma", readParamsSchema)
	writeTestFile(t, dir, "app.yaml", "versioned:\n  - patients\naccess:\n  clinicians:\n    read: everyone\n")
	app, err := loadApp(dir)
	if err != nil {
		t.Fatalf("load app: %v", err)
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "http://localhost")
	f := &readParamsFixture{app: app, mux: mux}
	f.alice = createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	f.bob = createCrudScopeSession(t, app, "bob@example.com", "user", "", "")
	var aliceID, bobID int64
	if err := app.DB.QueryRow(`SELECT id FROM _benmore_users WHERE email='alice@example.com'`).Scan(&aliceID); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow(`SELECT id FROM _benmore_users WHERE email='bob@example.com'`).Scan(&bobID); err != nil {
		t.Fatal(err)
	}
	mustExecArgs(t, app.DB, `INSERT INTO patients (id, user_id, full_name, diagnosis, api_token, created_at, updated_at) VALUES
		(1, ?, 'Alpha One', 'flu', 'tok-1', '2026-01-01 00:00:00', '2026-01-01 00:00:00'),
		(2, ?, 'Charlie Two', 'cold', 'tok-2', '2026-01-01 00:00:00', '2026-01-01 00:00:00'),
		(3, ?, 'Bravo Three', 'cough', 'tok-3', '2026-01-01 00:00:00', '2026-01-01 00:00:00')`, aliceID, aliceID, aliceID)
	mustExecArgs(t, app.DB, `INSERT INTO case_notes (id, user_id, patient_id, referred_by_id, body, share_token) VALUES
		(1, ?, 1, NULL, 'alice note on one', 'secret-share-1'),
		(2, ?, 1, NULL, 'bob note on one', 'secret-share-2'),
		(3, ?, 2, 1, 'referral from one', 'secret-share-3')`, aliceID, bobID, aliceID)
	mustExec(t, app.DB, `INSERT INTO clinicians (id, name, supervisor_id) VALUES (1, 'Lead', NULL), (2, 'Junior A', 1), (3, 'Junior B', 1)`)
	// Version patient 1: the 2026-01-01 state becomes history.
	mustExec(t, app.DB, `UPDATE patients SET full_name = 'Alpha Renamed', diagnosis = 'measles' WHERE id = 1`)
	return f
}

func (f *readParamsFixture) get(t *testing.T, sid, path string) (*http.Response, []byte) {
	t.Helper()
	w := crudScopeRequest(t, f.mux, http.MethodGet, path, sid, nil)
	return w.Result(), w.Body.Bytes()
}

func decodeRows(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	var rows []map[string]any
	if err := json.Unmarshal(body, &rows); err != nil {
		t.Fatalf("decode rows: %v: %s", err, body)
	}
	return rows
}

func decodeRow(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var row map[string]any
	if err := json.Unmarshal(body, &row); err != nil {
		t.Fatalf("decode row: %v: %s", err, body)
	}
	return row
}

func rowField(rows []map[string]any, key string) []any {
	out := make([]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, row[key])
	}
	return out
}

// ?include=<Prisma relation field> expands the relation (it was silently
// ignored: only table names resolved), through the same row scope and hidden
// column stripping as a table-name include; an include that resolves to
// nothing is named in X-Ignored-Params.
func TestIncludeResolvesPrismaRelationFieldNames(t *testing.T) {
	f := newReadParamsFixture(t)

	// Back-relation list field: notes CaseNote[] (table case_notes).
	resp, body := f.get(t, f.alice, "/api/patients/1?include=notes")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("include=notes: %d %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get(ignoredParamsHeader); got != "" {
		t.Fatalf("include=notes reported ignored: %q", got)
	}
	row := decodeRow(t, body)
	notes, ok := row["notes"].([]any)
	if !ok {
		t.Fatalf("include=notes returned no notes key: %s", body)
	}
	// Bob's note on Alice's patient is outside Alice's row scope.
	if len(notes) != 1 || notes[0].(map[string]any)["body"] != "alice note on one" {
		t.Fatalf("include=notes = %v, want only Alice's own note", notes)
	}
	if strings.Contains(string(body), "secret-share") || strings.Contains(string(body), "tok-1") {
		t.Fatalf("include exposed a hidden column: %s", body)
	}

	// The table name keeps working and returns the same rows under its own
	// key: of case_notes' two FKs to patients it takes the conventional
	// patient_id (map order used to pick one per request).
	_, body = f.get(t, f.alice, "/api/patients/1?include=case_notes")
	byTable := decodeRow(t, body)
	if !reflect.DeepEqual(byTable["case_notes"], row["notes"]) {
		t.Fatalf("include=case_notes %v != include=notes %v", byTable["case_notes"], row["notes"])
	}

	// A second, named relation between the same models uses its own FK.
	_, body = f.get(t, f.alice, "/api/patients?include=referrals&sort=id")
	rows := decodeRows(t, body)
	if len(rows) != 3 {
		t.Fatalf("list: %s", body)
	}
	refs := rows[0]["referrals"].([]any)
	if len(refs) != 1 || refs[0].(map[string]any)["body"] != "referral from one" {
		t.Fatalf("patient 1 referrals = %v", refs)
	}
	if refs := rows[1]["referrals"].([]any); len(refs) != 0 {
		t.Fatalf("patient 2 referrals = %v, want none", refs)
	}

	// Pointer field whose FK column is not <name>_id: referredBy → referred_by_id.
	_, body = f.get(t, f.alice, "/api/case_notes/3?include=referredBy,patient")
	note := decodeRow(t, body)
	if p, _ := note["referredBy"].(map[string]any); p == nil || p["id"] != float64(1) {
		t.Fatalf("include=referredBy = %v", note["referredBy"])
	}
	if p, _ := note["patient"].(map[string]any); p == nil || p["id"] != float64(2) {
		t.Fatalf("include=patient = %v", note["patient"])
	}

	// Named self-relation: supervisees → clinicians.supervisor_id.
	_, body = f.get(t, f.alice, "/api/clinicians/1?include=supervisees")
	lead := decodeRow(t, body)
	subs, _ := lead["supervisees"].([]any)
	if len(subs) != 2 {
		t.Fatalf("include=supervisees = %v", lead["supervisees"])
	}

	// Nested relation-field include.
	_, body = f.get(t, f.alice, "/api/case_notes/1?include=patient.referrals")
	nested := decodeRow(t, body)
	parent, _ := nested["patient"].(map[string]any)
	if parent == nil {
		t.Fatalf("nested include missing parent: %s", body)
	}
	if refs, _ := parent["referrals"].([]any); len(refs) != 1 {
		t.Fatalf("nested include=patient.referrals = %v", parent["referrals"])
	}

	// Includes that resolve to nothing are reported, list and single read.
	for path, want := range map[string]string{
		"/api/patients?include=nope":                                "include=nope",
		"/api/patients?include=notes,nope&titel=x":                  "include=nope,titel",
		"/api/patients/1?include=notes.nope":                        "include=notes.nope",
		"/api/patients/1?include=notes.patient.notes.patient.notes": "include=notes.patient.notes.patient.notes",
		"/api/patients?cursor=0&include=nope":                       "include=nope",
		"/api/patients/1?include=notes.patient.notes.patient":       "",
	} {
		resp, body := f.get(t, f.alice, path)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, resp.StatusCode, body)
		}
		if got := resp.Header.Get(ignoredParamsHeader); got != want {
			t.Errorf("GET %s: X-Ignored-Params = %q, want %q", path, got, want)
		}
	}
}

// Sort parameters the list did not apply are named in X-Ignored-Params, like
// unknown filters; the sorts it does apply, and the refusals for hidden and
// encrypted columns, are unchanged.
func TestListNamesIgnoredSortParams(t *testing.T) {
	f := newReadParamsFixture(t)
	f.app.Encrypted = &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{
		"patients": {{Column: "diagnosis", Roles: []string{"reviewer"}}},
	}}
	defaultOrder := []any{float64(3), float64(2), float64(1)}
	byNameAsc := []any{"Alpha Renamed", "Bravo Three", "Charlie Two"}
	byNameDesc := []any{"Charlie Two", "Bravo Three", "Alpha Renamed"}
	cases := []struct {
		query   string
		ignored string
		key     string
		want    []any
	}{
		{"sort=full_name", "", "full_name", byNameAsc},
		{"sort=full_name&order=desc", "", "full_name", byNameDesc},
		{"sort=full_name&order=DESC", "", "full_name", byNameDesc},
		{"orderBy=full_name:desc", "", "full_name", byNameDesc},
		{"orderBy=full_name&order=desc", "", "full_name", byNameDesc},
		{"sort=nonexistent", "sort", "id", defaultOrder},
		{"sort=-full_name", "sort", "id", defaultOrder},
		{"orderBy=nope:desc", "orderBy", "id", defaultOrder},
		{"sort=full_name&order=sideways", "order", "full_name", byNameAsc},
		{"orderBy=full_name:sideways", "orderBy", "full_name", byNameAsc},
		{"sort=full_name&orderBy=id:desc", "orderBy", "full_name", byNameAsc},
		{"orderBy=full_name:desc&order=asc", "order", "full_name", byNameDesc},
		{"order=asc", "order", "id", defaultOrder},
		{"order_by=full_name", "order_by", "id", defaultOrder},
		{"sort=nope&titel=x", "sort,titel", "id", defaultOrder},
		{"sort=nope&page=1", "sort", "id", defaultOrder},
	}
	for _, tc := range cases {
		resp, body := f.get(t, f.alice, "/api/patients?"+tc.query)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d %s", tc.query, resp.StatusCode, body)
		}
		if got := resp.Header.Get(ignoredParamsHeader); got != tc.ignored {
			t.Errorf("%s: X-Ignored-Params = %q, want %q", tc.query, got, tc.ignored)
		}
		var rows []map[string]any
		if strings.Contains(tc.query, "page=") {
			var env struct {
				Data []map[string]any `json:"data"`
			}
			if err := json.Unmarshal(body, &env); err != nil {
				t.Fatal(err)
			}
			rows = env.Data
		} else {
			rows = decodeRows(t, body)
		}
		if got := rowField(rows, tc.key); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %s order = %v, want %v", tc.query, tc.key, got, tc.want)
		}
	}

	// Cursor pages are always ordered by id; a sort there is not applied.
	resp, body := f.get(t, f.alice, "/api/patients?cursor=0&sort=full_name&order=desc")
	if got := resp.Header.Get(ignoredParamsHeader); got != "order,sort" {
		t.Errorf("cursor sort: X-Ignored-Params = %q", got)
	}
	var page struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}
	if got := rowField(page.Data, "id"); !reflect.DeepEqual(got, []any{float64(1), float64(2), float64(3)}) {
		t.Errorf("cursor order = %v", got)
	}
	// A count applies no sort and reports none.
	resp, _ = f.get(t, f.alice, "/api/patients?count=true&sort=nope")
	if got := resp.Header.Get(ignoredParamsHeader); got != "" {
		t.Errorf("count: X-Ignored-Params = %q", got)
	}

	// Refusals are unchanged: hidden and encrypted sort columns still 400.
	for _, q := range []string{"sort=api_token", "orderBy=api_token:desc", "sort=diagnosis"} {
		if resp, body := f.get(t, f.alice, "/api/patients?"+q); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", q, resp.StatusCode, body)
		}
	}
}

// ?fields= projects a point-in-time read (?as_of=) and a version snapshot
// (/versions/{v}) exactly as it projects the live single-row read, with
// masking applied before the projection.
func TestPointInTimeAndVersionReadsHonorFields(t *testing.T) {
	f := newReadParamsFixture(t)
	f.app.Encrypted = &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{
		"patients": {{Column: "diagnosis", Roles: []string{"reviewer"}}},
	}}
	asOf := url.QueryEscape("2026-02-01T00:00:00Z")
	check := func(path string, want map[string]any) {
		t.Helper()
		resp, body := f.get(t, f.alice, path)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: %d %s", path, resp.StatusCode, body)
		}
		if got := decodeRow(t, body); !reflect.DeepEqual(got, want) {
			t.Errorf("GET %s = %v, want %v", path, got, want)
		}
		if got := resp.Header.Get(ignoredParamsHeader); got != "" {
			t.Errorf("GET %s: X-Ignored-Params = %q", path, got)
		}
	}
	// History snapshot (patient 1 was renamed after 2026-02-01).
	check("/api/patients/1?as_of="+asOf+"&fields=id,full_name", map[string]any{"id": float64(1), "full_name": "Alpha One"})
	// Masked column in the projection stays masked; unknown and hidden names drop.
	check("/api/patients/1?as_of="+asOf+"&fields=diagnosis,nope,api_token", map[string]any{"diagnosis": encryptedFieldMask})
	// No-history fallback (patient 2 was never updated).
	check("/api/patients/2?as_of="+asOf+"&fields=full_name", map[string]any{"full_name": "Charlie Two"})
	// The live read with the same projection answers the same keys.
	check("/api/patients/1?fields=id,full_name", map[string]any{"id": float64(1), "full_name": "Alpha Renamed"})
	// Version snapshot.
	check("/api/patients/1/versions/1?fields=full_name,diagnosis", map[string]any{"full_name": "Alpha One", "diagnosis": encryptedFieldMask})

	// Nothing projectable falls back to the whole (sanitized) row.
	resp, body := f.get(t, f.alice, "/api/patients/1?as_of="+asOf+"&fields=api_token")
	full := decodeRow(t, body)
	if resp.StatusCode != http.StatusOK || full["full_name"] != "Alpha One" || full["user_id"] == nil {
		t.Fatalf("unprojectable as_of fields did not fall back to the full row: %d %v", resp.StatusCode, full)
	}
	if _, leaked := full["api_token"]; leaked {
		t.Fatalf("as_of exposed a hidden column: %v", full)
	}
	resp, body = f.get(t, f.alice, "/api/patients/1/versions/1?fields=nope")
	if v := decodeRow(t, body); resp.StatusCode != http.StatusOK || v["full_name"] != "Alpha One" || v["_version"] == nil {
		t.Fatalf("unprojectable version fields did not fall back to the full snapshot: %d %v", resp.StatusCode, v)
	}

	// A point-in-time read applies no include; it says so.
	resp, body = f.get(t, f.alice, "/api/patients/1?as_of="+asOf+"&include=notes")
	if _, has := decodeRow(t, body)["notes"]; has || resp.Header.Get(ignoredParamsHeader) != "include=notes" {
		t.Fatalf("as_of include: X-Ignored-Params %q body %s", resp.Header.Get(ignoredParamsHeader), body)
	}
}

// The parser keeps each model's relation fields (they emit no column):
// pointers with their FK column, back-relations with their label, and only
// targets that are models of the file.
func TestPrismaParseKeepsRelationFields(t *testing.T) {
	models, err := ParsePrismaSchema(readParamsSchema + `
enum Status {
  OPEN
}
model Ticket {
  id      Int     @id @default(autoincrement())
  userId  Int
  status  Status
  ownerId Int?
  owner   User?   @relation(fields: [ownerId], references: [id])
}
`)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]PrismaRelation{}
	for _, m := range models {
		got[m.Table] = m.Relations
	}
	want := map[string][]PrismaRelation{
		"patients": {
			{Name: "notes", Model: "CaseNote", Table: "case_notes", List: true},
			{Name: "referrals", Model: "CaseNote", Table: "case_notes", List: true, Label: "Referrals"},
		},
		"case_notes": {
			{Name: "patient", Model: "Patient", Table: "patients", Column: "patient_id", References: "id"},
			{Name: "referredBy", Model: "Patient", Table: "patients", Column: "referred_by_id", References: "id", Label: "Referrals"},
		},
		"clinicians": {
			{Name: "supervisor", Model: "Clinician", Table: "clinicians", Column: "supervisor_id", References: "id", Label: "Supervision"},
			{Name: "supervisees", Model: "Clinician", Table: "clinicians", List: true, Label: "Supervision"},
		},
		// An enum-typed field and a pointer to the reserved User model are no relations.
		// (tickets is checked to exist below.)
		"tickets": nil,
	}
	if _, ok := got["tickets"]; !ok {
		t.Fatalf("model Ticket not parsed: %v", got)
	}
	for table, rels := range want {
		if len(rels) == 0 && len(got[table]) == 0 {
			continue
		}
		if !reflect.DeepEqual(got[table], rels) {
			t.Errorf("%s relations = %+v, want %+v", table, got[table], rels)
		}
	}
}
