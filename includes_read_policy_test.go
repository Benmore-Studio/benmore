//go:build !cli

package main

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func includeReadPolicyFixture(t *testing.T) *App {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	crudScopeMustExec(t, db, `CREATE TABLE posts(id INTEGER PRIMARY KEY,user_id INTEGER,org_id TEXT,title TEXT,published INTEGER,deleted_at TEXT)`)
	crudScopeMustExec(t, db, `CREATE TABLE comments(id INTEGER PRIMARY KEY,user_id INTEGER,org_id TEXT,post_id INTEGER REFERENCES posts(id),body TEXT,published INTEGER,deleted_at TEXT)`)
	crudScopeMustExec(t, db, `INSERT INTO posts VALUES(1,2,'org-a','public',1,NULL),(2,2,'org-a','private',0,NULL),(3,1,'org-b','other tenant',0,NULL),(4,2,'org-a','deleted',1,'2026-01-01')`)
	crudScopeMustExec(t, db, `INSERT INTO comments VALUES(1,2,'org-a',1,'public',1,NULL),(2,2,'org-a',1,'private',0,NULL),(3,1,'org-b',1,'other tenant',0,NULL),(4,2,'org-a',1,'deleted',1,'2026-01-01')`)
	EnsurePermissionsTable(db)
	app := &App{DB: db, Group: &GroupConfig{Key: "org_id"}, Access: &AccessConfig{rules: map[string]map[AccessOp]string{}}, JoinMap: BuildJoinMap(db)}
	for _, table := range []string{"posts", "comments"} {
		cols, err := GetTableColumns(db, table)
		if err != nil {
			t.Fatal(err)
		}
		app.Tables = append(app.Tables, Table{Name: table, Columns: cols})
	}
	return app
}

func TestIncludesFollowPublicReadPolicyForParentsAndChildren(t *testing.T) {
	for _, mode := range []string{"anon", "everyone", "self"} {
		t.Run(mode, func(t *testing.T) {
			app := includeReadPolicyFixture(t)
			for _, table := range []string{"posts", "comments"} {
				app.Access.rules[table] = map[AccessOp]string{OpRead: mode}
			}
			if mode == "self" {
				app.Scopes = map[string]ScopeConfig{"posts": {PublicReadWhen: "published=1"}, "comments": {PublicReadWhen: "published=1"}}
			}
			sessions := []*Session{{UserID: 1, Role: "user", GroupID: "org-a", Email: "reader@example.com"}}
			if mode == "anon" {
				sessions = append(sessions, nil)
			}
			for _, session := range sessions {
				parentRows := []map[string]any{{"id": int64(1), "post_id": int64(1)}}
				ResolveIncludes(app, "comments", parentRows, "post", session)
				parent, ok := parentRows[0]["post"].(map[string]any)
				if !ok || parent["title"] != "public" {
					t.Fatalf("public parent omitted for session %#v: %v", session, parentRows)
				}
				childRows := []map[string]any{{"id": int64(1)}}
				ResolveIncludes(app, "posts", childRows, "comments", session)
				children, _ := childRows[0]["comments"].([]map[string]any)
				want := 3
				if mode == "self" {
					want = 1
				}
				if len(children) != want {
					t.Fatalf("children for %s session=%#v: %v", mode, session, children)
				}
				if children[0]["body"] != "public" {
					t.Fatalf("public child missing: %v", children)
				}
			}
		})
	}
}

func TestIncludesRetainTableTokenTenantAndSoftDeleteGuards(t *testing.T) {
	app := includeReadPolicyFixture(t)
	user := &Session{UserID: 1, Role: "user", GroupID: "org-a", Email: "reader@example.com"}
	for _, table := range []string{"posts", "comments"} {
		app.Access.rules[table] = map[AccessOp]string{OpRead: "self"}
	}
	for _, table := range []string{"posts", "comments"} {
		if got := batchFetchByIDs(app, table, map[string]bool{"3": true}, user); len(got) != 0 {
			t.Fatalf("cross-tenant own row visible: %v", got)
		}
	}
	if got := batchFetchByFK(app, "comments", "post_id", map[string]bool{"1": true}, user); len(got) != 0 {
		t.Fatalf("private children visible: %v", got)
	}
	for _, mode := range []string{"admin", "off", "anon"} {
		for _, table := range []string{"posts", "comments"} {
			app.Access.rules[table][OpRead] = mode
		}
		session := user
		if mode == "anon" {
			copy := *user
			copy.Scopes = "unrelated:read"
			session = &copy
		}
		if got := batchFetchByIDs(app, "posts", map[string]bool{"1": true}, session); len(got) != 0 {
			t.Fatalf("mode/scope %s bypassed: %v", mode, got)
		}
		if got := batchFetchByFK(app, "comments", "post_id", map[string]bool{"1": true}, session); len(got) != 0 {
			t.Fatalf("child mode/scope %s bypassed: %v", mode, got)
		}
	}
	if got := batchFetchByIDs(app, "posts", map[string]bool{"4": true}, nil); len(got) != 0 {
		t.Fatalf("soft-deleted public parent visible: %v", got)
	}
}
