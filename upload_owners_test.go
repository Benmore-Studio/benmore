//go:build !cli

package main

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// A caller who learns another user's private path and writes it into a
// record of their own must not get it signed: the record must vouch for
// the file's uploader. Files with no ownership row keep the reference rule.
func TestSignedURLRequiresRecordToVouchForUploader(t *testing.T) {
	app, mux, cleanup := signedURLApp(t)
	defer cleanup()
	ownerTok := createCrudScopeSession(t, app, "owner-a@example.com", "user", "", "") // id 1, uploaded secret.pdf
	otherTok := createCrudScopeSession(t, app, "other-b@example.com", "user", "", "") // id 2
	EnsureUploadOwnersTable(app.DB)
	mustExec(t, app.DB, `INSERT INTO _benmore_upload_owners (path, user_id) VALUES ('private/secret.pdf', 1)`)
	// User 2's own doc, pointing at user 1's private file.
	mustExec(t, app.DB, `INSERT INTO docs (id, user_id, file_url) VALUES (2, 2, '/uploads/private/secret.pdf')`)

	if code, _ := mintSignedURL(t, mux, otherTok, "path=private/secret.pdf&record_table=docs&record_id=2"); code != http.StatusForbidden {
		t.Fatalf("another user's private file signed through the caller's own record: status=%d", code)
	}
	if code, _ := mintSignedURL(t, mux, ownerTok, "path=private/secret.pdf&record_table=docs&record_id=1"); code != http.StatusOK {
		t.Fatalf("uploader's own record could not sign: status=%d", code)
	}
	// An admin-uploaded file may be attached to anyone's record.
	mustExec(t, app.DB, `UPDATE _benmore_upload_owners SET user_id = 99, uploader_admin = 1 WHERE path = 'private/secret.pdf'`)
	if code, _ := mintSignedURL(t, mux, otherTok, "path=private/secret.pdf&record_table=docs&record_id=2"); code != http.StatusOK {
		t.Fatalf("admin-uploaded file attached to a user's record could not be signed: status=%d", code)
	}
	// No ownership row (uploaded before this change): reference rule only.
	mustExec(t, app.DB, `DELETE FROM _benmore_upload_owners`)
	if code, _ := mintSignedURL(t, mux, otherTok, "path=private/secret.pdf&record_table=docs&record_id=2"); code != http.StatusOK {
		t.Fatalf("legacy private file lost signing: status=%d", code)
	}
}

func TestPrivateUploadRefusesOwnershipWriteFailure(t *testing.T) {
	for _, failure := range []string{"insert", "schema"} {
		t.Run(failure, func(t *testing.T) {
			app, mux, cleanup := signedURLApp(t)
			defer cleanup()
			tok := createCrudScopeSession(t, app, "owner-fixture@example.com", "user", "", "")
			EnsureUploadOwnersTable(app.DB)
			if failure == "insert" {
				mustExec(t, app.DB, `CREATE TRIGGER fixture_refuse_owner BEFORE INSERT ON _benmore_upload_owners BEGIN SELECT RAISE(ABORT, 'fixture ownership write failure'); END`)
			} else {
				mustExec(t, app.DB, `DROP TABLE _benmore_upload_owners`)
				mustExec(t, app.DB, `CREATE VIEW _benmore_upload_owners AS SELECT 'private/fixture.pdf' AS path`)
			}
			var body bytes.Buffer
			mw := multipart.NewWriter(&body)
			if err := mw.WriteField("kind", "private"); err != nil {
				t.Fatal(err)
			}
			fw, err := mw.CreateFormFile("file", "fixture.pdf")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fw.Write([]byte("%PDF-1.4 fixture")); err != nil {
				t.Fatal(err)
			}
			if err := mw.Close(); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("POST", "/api/_upload", &body)
			req.Header.Set("Content-Type", mw.FormDataContentType())
			req.Header.Set("Authorization", "Bearer "+tok)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code >= 200 && rec.Code < 300 {
				t.Errorf("private upload succeeded without ownership: %d %s", rec.Code, rec.Body.String())
			}
			entries, err := os.ReadDir(filepath.Join(app.Dir, "uploads", "private"))
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name() != "secret.pdf" {
				t.Errorf("ownership failure left new file bytes: %v", entries)
			}
			before, err := os.ReadFile(filepath.Join(app.Dir, "uploads", "private", "secret.pdf"))
			if err != nil || string(before) != "PRIVATE-BYTES" {
				t.Errorf("pre-existing upload was changed: %q, %v", before, err)
			}
		})
	}
}

// A private upload through /api/_upload records its uploader.
func TestPrivateUploadRecordsOwner(t *testing.T) {
	app, mux, cleanup := signedURLApp(t)
	defer cleanup()
	tok := createCrudScopeSession(t, app, "owner-a@example.com", "user", "", "")
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	mw.WriteField("kind", "private")
	fw, _ := mw.CreateFormFile("file", "report.pdf")
	fw.Write([]byte("%PDF-1.4 test"))
	mw.Close()
	req := httptest.NewRequest("POST", "/api/_upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body.String())
	}
	var n int
	app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_upload_owners WHERE user_id = 1 AND path LIKE 'private/%'`).Scan(&n)
	if n != 1 {
		t.Fatalf("private upload did not record its owner (rows=%d, response %s)", n, rec.Body.String())
	}
}
