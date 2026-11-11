//go:build !cli

package main

import (
	"database/sql"
	"path/filepath"
	"slices"
	"testing"
)

// includeBudgetFixture: 300 public posts with 50 comments each (15,000).
func includeBudgetFixture(t *testing.T) *App {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	crudScopeMustExec(t, db, `CREATE TABLE posts(id INTEGER PRIMARY KEY, title TEXT)`)
	crudScopeMustExec(t, db, `CREATE TABLE comments(id INTEGER PRIMARY KEY, post_id INTEGER REFERENCES posts(id), body TEXT)`)
	crudScopeMustExec(t, db, `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 3000) INSERT INTO posts SELECT i, 'p' || i FROM n`)
	crudScopeMustExec(t, db, `WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i < 14999) INSERT INTO comments SELECT i+1, (i / 50) + 1, 'c' FROM n`)
	app := &App{DB: db, Access: &AccessConfig{rules: map[string]map[AccessOp]string{
		"posts": {OpRead: "anon"}, "comments": {OpRead: "anon"},
	}}, JoinMap: BuildJoinMap(db)}
	for _, table := range []string{"posts", "comments"} {
		cols, err := GetTableColumns(db, table)
		if err != nil {
			t.Fatal(err)
		}
		app.Tables = append(app.Tables, Table{Name: table, Columns: cols})
	}
	return app
}

func includeBudgetRows(t *testing.T, app *App, query string) []map[string]any {
	t.Helper()
	rows, err := QueryRows(app.DB, query)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// A has-many include over many parents stays within the request's row
// budget; parents it does not reach are flagged, never answered as empty.
func TestIncludeChildRowsBoundedPerRequest(t *testing.T) {
	app := includeBudgetFixture(t)
	posts := includeBudgetRows(t, app, `SELECT * FROM posts WHERE id <= 300 ORDER BY id`)
	if err := ResolveIncludes(app, nil, "posts", posts, "comments", nil); err != nil {
		t.Fatal(err)
	}
	total, cut := 0, 0
	for _, p := range posts {
		flags, _ := p[includeTruncatedKey].([]string)
		children, has := p["comments"].([]map[string]any)
		switch {
		case has:
			if len(children) != 50 {
				t.Fatalf("post %v expanded %d comments, want all 50", p["id"], len(children))
			}
			total += len(children)
		case slices.Contains(flags, "comments"):
			cut++
		default:
			t.Fatalf("post %v has neither comments nor a truncation flag: %v", p["id"], p)
		}
	}
	if total > maxIncludeRowsPerRequest || cut == 0 {
		t.Fatalf("expanded %d comments with %d posts flagged; want at most %d and some flagged", total, cut, maxIncludeRowsPerRequest)
	}
	// The first posts of the answer are the ones expanded.
	if _, ok := posts[0]["comments"]; !ok {
		t.Fatal("first post not expanded")
	}
}

// Parent ids beyond one IN (...) chunk are fetched in further chunks.
func TestIncludeParentsFetchedInChunks(t *testing.T) {
	app := includeBudgetFixture(t)
	// One comment for each of 2,500 posts: more ids than one fetch binds.
	crudScopeMustExec(t, app.DB, `DELETE FROM comments`)
	crudScopeMustExec(t, app.DB, `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 2500) INSERT INTO comments SELECT i, i, 'c' FROM n`)
	comments := includeBudgetRows(t, app, `SELECT * FROM comments ORDER BY id`)
	if len(comments) <= maxIncludeParentsPerFetch {
		t.Fatalf("fixture has %d comments, want more than %d", len(comments), maxIncludeParentsPerFetch)
	}
	if err := ResolveIncludes(app, nil, "comments", comments, "post", nil); err != nil {
		t.Fatal(err)
	}
	for _, c := range comments {
		if _, ok := c["post"].(map[string]any); !ok {
			t.Fatalf("comment %v has no parent post: %v", c["id"], c)
		}
	}
}

// Entries sharing a first segment resolve it once: "comments" and
// "comments.post" expand comments a single time, with post nested on them.
func TestIncludeSharedPrefixResolvedOnce(t *testing.T) {
	app := includeBudgetFixture(t)
	posts := includeBudgetRows(t, app, `SELECT * FROM posts WHERE id <= 2 ORDER BY id`)
	ia := &includeAudit{}
	resolveIncludesDepth(app, "posts", posts, "comments,comments.post", nil, ia, 0)
	if ia.used != 2*50+2 {
		t.Fatalf("include fetched %d rows, want 102 (comments once, their 2 posts once)", ia.used)
	}
	children, _ := posts[0]["comments"].([]map[string]any)
	if len(children) != 50 || children[0]["post"] == nil {
		t.Fatalf("comments.post not nested on the single comments expansion: %d children", len(children))
	}
}
