package main

import (
	"strings"
	"testing"
)

// A reverify on the same transaction may skip the database half only while
// the schema is unchanged: DDL inside the transaction must still be caught.
func TestAppMCPRevisionReverifyCatchesDDLInsideTheTransaction(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	generation := snapshotAppMCPGeneration(f.app)
	err := withTestRevisionCapability(t, f.app, generation, func(verified *appMCPVerifiedRevisionEnrollment) error {
		if verified.stateDigest == "" {
			t.Fatal("full verification recorded no state digest")
		}
		if _, err := reverifyAppMCPRevisionCapability(verified); err != nil {
			t.Fatalf("unchanged reverify: %v", err)
		}
		var name, original string
		if err := verified.tx.QueryRow(`SELECT name,sql FROM main.sqlite_schema WHERE type='trigger' AND tbl_name='notes' AND substr(name,1,17)='_benmore_mcp_rev_' LIMIT 1`).Scan(&name, &original); err != nil {
			t.Fatal(err)
		}
		mutated := strings.Replace(original, "'notes'", "'NOTES'", 1)
		if mutated == original {
			t.Fatalf("mutation did not change trigger: %s", original)
		}
		if _, err := verified.tx.Exec("DROP TRIGGER main." + quoteIdent(name)); err != nil {
			t.Fatal(err)
		}
		if _, err := verified.tx.Exec(mutated); err != nil {
			t.Fatal(err)
		}
		if _, err := reverifyAppMCPRevisionCapability(verified); err == nil {
			t.Fatal("reverify accepted a trigger replaced inside the transaction")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The orphan check probes the primary key but keeps the exact key match: a
// live ledger row keyed '05' does not name row 5.
func TestAppMCPRevisionRowsOrphanCheckIsExact(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	if _, err := f.app.DB.Exec(`INSERT INTO notes(id,user_id,title) VALUES(5,?,'five')`, f.uid); err != nil {
		t.Fatal(err)
	}
	tx, err := f.app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := appMCPVerifyRevisionRows(tx, "notes"); err != nil {
		t.Fatalf("consistent ledger: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO main._benmore_mcp_row_revisions(table_name,incarnation,key_type,row_key,revision,deleted)
		SELECT table_name,incarnation,key_type,'05',1,0 FROM main._benmore_mcp_row_revisions WHERE table_name='notes' AND row_key='5'`); err != nil {
		t.Fatal(err)
	}
	if err := appMCPVerifyRevisionRows(tx, "notes"); err == nil || !strings.Contains(err.Error(), "absent row live") {
		t.Fatalf("ledger key '05' was taken for row 5: %v", err)
	}
}
