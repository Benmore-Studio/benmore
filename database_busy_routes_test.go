//go:build !cli

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A write that cannot get SQLite's single write lock within the busy timeout
// is load, not a fault and not a bad request. The write routes disagreed
// about it: 500 "Transaction start failed", 400 "Delete failed", 503 with a
// sentence in `error`, a flow's 500 flow_no_response. Every one of them now
// answers 503 with Retry-After and the `database_busy` code, and the journal
// gets one DATABASE BUSY line instead of a SERVER ERROR or FLOW ERROR.

const busyRouteSchema = `model Item {
  id        Int       @id @default(autoincrement())
  title     String    @default("")
  status    String    @default("draft")
  userId    Int       @map("user_id")
  deletedAt DateTime? @map("deleted_at")
  createdAt DateTime  @default(now()) @map("created_at")
  updatedAt DateTime  @default(now()) @updatedAt @map("updated_at")

  @@map("items")
}

model Pref {
  id     Int    @id @default(autoincrement())
  theme  String @default("")
  userId Int    @unique @map("user_id")

  @@map("prefs")
}
`

const busyRouteWorkflows = `item_state:
  table: items
  field: status
  initial: draft
  states: [draft, done]
  transitions:
    draft:
      done: {}
`

func busyRouteFlow(path string, transaction bool) string {
	return fmt.Sprintf(`on:
  request:
    method: POST
    path: %s
    auth: required
    transaction: %t
jobs:
  write:
    steps:
      - id: added
        run: sql
        with:
          query: "INSERT INTO items (title, user_id) VALUES ('from a flow', :user_id) RETURNING id"
      - run: respond
        with:
          status: 200
          body:
            id: ${{ steps.added.outputs.id }}
`, path, transaction)
}

// busyRoutePartialFlow writes, spends a few hundred milliseconds reading, then
// writes again, with no transaction: its first write is committed when the
// second one runs.
const busyRoutePartialFlow = `on:
  request:
    method: POST
    path: /api/busy/partial
    auth: required
jobs:
  write:
    steps:
      - id: first
        run: sql
        with:
          query: "INSERT INTO items (title, user_id) VALUES ('partial first', :user_id)"
      - id: pause
        run: sql
        with:
          query: "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 4000000) SELECT count(*) AS n FROM c"
      - id: second
        run: sql
        with:
          query: "UPDATE items SET title = 'partial second' WHERE title = 'partial first'"
      - run: respond
        with:
          status: 200
          body:
            ok: true
`

// busyRouteFixture is a loaded, served app whose pool is the product's
// driver and DSN with one change: a 150 ms busy timeout instead of 10 s, so
// a held write lock fails a write quickly. The product's timeout is untouched.
type busyRouteFixture struct {
	t       *testing.T
	app     *App
	mux     http.Handler
	admin   string // Bearer session of an app admin
	adminID int64
	otherID int64
	item    int64 // a live row the admin owns
	deleted int64 // a soft-deleted row the admin owns
}

func newBusyRouteFixture(t *testing.T) *busyRouteFixture {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "busy")
	for name, content := range map[string]string{
		"app.yaml":                 "site_name: \"busy\"\nauth:\n  identifier: email\nfeatures:\n  sharing: true\nversioned:\n  - items\n",
		"schema.prisma":            busyRouteSchema,
		"workflows.yaml":           busyRouteWorkflows,
		"flows/busy-write.yaml":    busyRouteFlow("/api/busy/write", false),
		"flows/busy-write-tx.yaml": busyRouteFlow("/api/busy/write-tx", true),
		"flows/busy-hook.yaml":     busyRouteFlow("/hooks/busy", false),
		"flows/busy-partial.yaml":  busyRoutePartialFlow,
	} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dsn := sqliteAppDSN(filepath.Join(dir, "data.db"), dir)
	short := strings.Replace(dsn, "_busy_timeout=10000", "_busy_timeout=150", 1)
	if short == dsn {
		t.Fatal("the product DSN no longer spells its busy timeout as _busy_timeout=10000")
	}
	t.Setenv("DATABASE_URL", short)
	app, err := loadAppForServerTests(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	f := &busyRouteFixture{t: t, app: app, mux: buildAppMux(app, false, "http://busy.example.test")}
	f.adminID = f.user("root@example.com", "admin")
	f.otherID = f.user("other@example.com", "user")
	if f.admin = CreateSession(app.DB, f.adminID, "root@example.com", "", time.Hour); f.admin == "" {
		t.Fatal("no admin session")
	}
	f.item = f.insert("INSERT INTO items (title, user_id) VALUES ('kept', ?)", f.adminID)
	f.deleted = f.insert("INSERT INTO items (title, user_id, deleted_at) VALUES ('gone', ?, datetime('now'))", f.adminID)
	return f
}

func (f *busyRouteFixture) user(email, role string) int64 {
	f.t.Helper()
	return f.insert("INSERT INTO _benmore_users (username, email, role, verified) VALUES (?, ?, ?, 1)", email, email, role)
}

func (f *busyRouteFixture) insert(query string, args ...any) int64 {
	f.t.Helper()
	res, err := f.app.DB.Exec(query, args...)
	if err != nil {
		f.t.Fatalf("%s: %v", query, err)
	}
	id, _ := res.LastInsertId()
	return id
}

// holdWriteLock takes the database's write lock on a second connection, the
// way another process (or a long transaction) holds it, until release runs.
func (f *busyRouteFixture) holdWriteLock() (release func()) {
	f.t.Helper()
	conn, err := f.app.DB.Conn(context.Background())
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		f.t.Fatal(err)
	}
	return func() {
		_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		_ = conn.Close()
	}
}

func (f *busyRouteFixture) call(method, path, contentType, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://busy.example.test"+path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", contentType)
	}
	r.Header.Set("Authorization", "Bearer "+f.admin)
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return w
}

type busyRoute struct {
	name, method, path, contentType, body string
}

func (f *busyRouteFixture) routes() []busyRoute {
	const js = "application/json"
	item, deleted := strconv.FormatInt(f.item, 10), strconv.FormatInt(f.deleted, 10)
	return []busyRoute{
		{"create", "POST", "/api/items", js, `{"title":"new"}`},
		{"update", "PATCH", "/api/items/" + item, js, `{"title":"changed"}`},
		{"delete", "DELETE", "/api/items/" + item, "", ""},
		{"singleton upsert", "PATCH", "/api/prefs", js, `{"theme":"dark"}`},
		{"restore", "POST", "/api/items/" + deleted + "/restore", "", ""},
		{"batch create", "POST", "/api/items/batch", js, `[{"title":"a"},{"title":"b"}]`},
		{"batch update", "PATCH", "/api/items/batch", js, `{"ids":[` + item + `],"fields":{"title":"batched"}}`},
		{"batch delete", "DELETE", "/api/items/batch", js, `{"ids":[` + item + `]}`},
		{"ingest", "POST", "/api/items/ingest", "application/x-ndjson", "{\"title\":\"n1\"}\n{\"title\":\"n2\"}\n"},
		{"transaction insert", "POST", "/api/_transaction", js, `{"operations":[{"action":"insert","table":"items","data":{"title":"tx"}}]}`},
		{"transaction update", "POST", "/api/_transaction", js, `{"operations":[{"action":"update","table":"items","id":` + item + `,"data":{"title":"tx"}}]}`},
		{"workflow transition", "POST", "/api/items/" + item + "/transition", js, `{"to":"done"}`},
		{"lock acquire", "POST", "/api/items/" + item + "/lock", "", ""},
		{"share", "POST", "/api/items/" + item + "/share", js, `{"email":"other@example.com","permission":"view"}`},
		{"role grant", "POST", "/api/_auth/users/" + strconv.FormatInt(f.otherID, 10) + "/roles", js, `{"role":"admin"}`},
		{"flow sql step", "POST", "/api/busy/write", js, `{}`},
		{"flow transaction", "POST", "/api/busy/write-tx", js, `{}`},
		{"flow outside /api/", "POST", "/hooks/busy", js, `{}`},
	}
}

func (f *busyRouteFixture) count(query string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.app.DB.QueryRow(query, args...).Scan(&n); err != nil {
		f.t.Fatalf("%s: %v", query, err)
	}
	return n
}

func TestBusyDatabaseAnswers503OnEveryWriteRoute(t *testing.T) {
	f := newBusyRouteFixture(t)
	for _, route := range f.routes() {
		t.Run(route.name, func(t *testing.T) {
			release := f.holdWriteLock()
			var w *httptest.ResponseRecorder
			logged := captureLog(t, func() { w = f.call(route.method, route.path, route.contentType, route.body) })
			release()

			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("%s %s with the write lock held: %d %s, want 503", route.method, route.path, w.Code, strings.TrimSpace(w.Body.String()))
			}
			if got := w.Header().Get("Retry-After"); got != "1" {
				t.Errorf("Retry-After %q, want 1", got)
			}
			body := decodeJSONAnswer(t, w)
			if body["error"] != "database_busy" || body["message"] != "the database is busy, retry shortly" || body["docs"] != "recovery.write_lock" {
				t.Errorf("body %v", body)
			}
			id, _ := body["request_id"].(string)
			if !requestIDPattern.MatchString(id) || w.Header().Get(requestIDHeader) != id {
				t.Errorf("request_id %q, X-Request-Id %q", id, w.Header().Get(requestIDHeader))
			}
			if strings.Contains(w.Body.String(), "locked") {
				t.Errorf("the answer carries SQLite's own text: %s", w.Body.String())
			}
			// One DATABASE BUSY line names the request; no error line does.
			if n := strings.Count(logged, "DATABASE BUSY ["); n != 1 || !strings.Contains(logged, "(request "+id+")") {
				t.Errorf("journal has %d DATABASE BUSY lines for request %s:\n%s", n, id, logged)
			}
			for _, level := range []string{"SERVER ERROR", "FLOW ERROR"} {
				if strings.Contains(logged, level) {
					t.Errorf("a busy database was logged as %s:\n%s", level, logged)
				}
			}
		})
	}

	// Nothing a refused request tried to write was kept.
	var titles string
	if err := f.app.DB.QueryRow("SELECT group_concat(title, ',') FROM (SELECT title FROM items ORDER BY id)").Scan(&titles); err != nil {
		t.Fatal(err)
	}
	if titles != "kept,gone" {
		t.Fatalf("rows after the refused writes: %s, want kept,gone", titles)
	}
	if n := f.count("SELECT (SELECT COUNT(*) FROM prefs) + (SELECT COUNT(*) FROM _benmore_locks) + (SELECT COUNT(*) FROM _benmore_permissions) + (SELECT COUNT(*) FROM _benmore_user_roles)"); n != 0 {
		t.Fatalf("%d rows were written by requests answered 503", n)
	}
	// With the lock free the very same requests go through: the 503 was the
	// lock's doing, and sending the request again is the right advice.
	for _, route := range f.routes() {
		if route.name == "delete" || route.name == "batch delete" {
			continue // the routes after them still need the row
		}
		// Sent the way the answer asks a client to: again while it is 503
		// (one of the app's own background writers may hold the lock for a
		// moment, and this fixture waits only 150 ms for it).
		w := f.call(route.method, route.path, route.contentType, route.body)
		for try := 0; try < 20 && w.Code == http.StatusServiceUnavailable; try++ {
			time.Sleep(50 * time.Millisecond)
			w = f.call(route.method, route.path, route.contentType, route.body)
		}
		if w.Code != http.StatusOK && w.Code != http.StatusCreated {
			t.Errorf("%s with the lock free: %d %s", route.name, w.Code, strings.TrimSpace(w.Body.String()))
		}
	}
}

// Reads neither take nor wait for the write lock: they keep answering while
// writes are refused.
func TestBusyDatabaseStillAnswersReads(t *testing.T) {
	f := newBusyRouteFixture(t)
	release := f.holdWriteLock()
	defer release()
	for _, path := range []string{"/api/items", "/api/items/" + strconv.FormatInt(f.item, 10)} {
		if w := f.call("GET", path, "", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "kept") {
			t.Errorf("GET %s with the write lock held: %d %s", path, w.Code, strings.TrimSpace(w.Body.String()))
		}
	}
}

// The busy answer tells the caller to send the request again, so a flow gets
// it only when nothing it wrote was kept. A flow without a transaction whose
// first statement is already committed keeps its flow_no_response answer:
// sending it again would write the first statement twice.
func TestBusyFlowThatAlreadyWroteKeepsItsFailureAnswer(t *testing.T) {
	f := newBusyRouteFixture(t)
	// Take the write lock the moment the flow's first write is visible,
	// while its second step is still reading.
	locked := make(chan func(), 1)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				locked <- nil
				return
			case <-time.After(time.Millisecond):
			}
			var n int
			if f.app.DB.QueryRow("SELECT COUNT(*) FROM items WHERE title = 'partial first'").Scan(&n) == nil && n == 1 {
				conn, err := f.app.DB.Conn(context.Background())
				if err != nil {
					locked <- nil
					return
				}
				if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
					conn.Close()
					locked <- nil
					return
				}
				locked <- func() {
					_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
					_ = conn.Close()
				}
				return
			}
		}
	}()
	var w *httptest.ResponseRecorder
	logged := captureLog(t, func() { w = f.call("POST", "/api/busy/partial", "application/json", `{}`) })
	close(stop)
	release := <-locked
	if release == nil {
		t.Fatalf("fixture: the write lock was not taken between the flow's two writes (answer %d %s)", w.Code, w.Body.String())
	}
	release()

	body := decodeJSONAnswer(t, w)
	if w.Code != http.StatusInternalServerError || body["error"] != "flow_no_response" || body["failed_step"] != "second" || body["reason"] != "the database was busy" {
		t.Fatalf("a flow that had already written: %d %v", w.Code, body)
	}
	if got := w.Header().Get("Retry-After"); got != "" {
		t.Errorf("Retry-After %q on a flow whose first write is committed", got)
	}
	if n := f.count("SELECT COUNT(*) FROM items WHERE title = 'partial first'"); n != 1 {
		t.Errorf("%d rows hold the flow's first write, want 1 (committed, never undone)", n)
	}
	if !strings.Contains(logged, "FLOW ERROR [busy-partial]") || strings.Contains(logged, "DATABASE BUSY [") {
		t.Errorf("journal for the partly written flow:\n%s", logged)
	}
}
