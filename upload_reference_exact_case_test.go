//go:build !cli

package main

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// diskFoldsCase reports whether dir opens a name under another letter case
// (the default macOS and Windows disks do; Linux does not).
func diskFoldsCase(t *testing.T, dir string) bool {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "case-probe.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(filepath.Join(dir, "case-probe.txt"))
	_, err := os.Stat(filepath.Join(dir, "CASE-PROBE.TXT"))
	return err == nil
}

// A private upload is reached only by the spelling under which it is stored.
// On a disk that folds letter case another spelling opens the same file,
// while the uploader record is keyed by the stored spelling and so is not
// found: the file then looked like one with no uploader, and a reference
// respelled in another user's row deleted it, served it and got it signed.
// On a case-sensitive disk the other spelling names no file, so the same
// assertions hold there.
func TestPrivateUploadIsReachedOnlyByItsStoredSpelling(t *testing.T) {
	app, mux, cleanup := signedURLApp(t)
	defer cleanup()
	mustExec(t, app.DB, `DELETE FROM docs`)
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	bob := createCrudScopeSession(t, app, "bob@example.com", "user", "", "")
	folds := diskFoldsCase(t, app.Dir)
	if !folds {
		t.Log("this disk is case-sensitive: another spelling names no file here, so the refusals below are the file system's; the comparison itself is covered by TestStoredEntryNameIsComparedByteForByte")
	}

	bobBytes := []byte("%PDF-1.4 bob's private statement")
	ref := uploadedPath(t, uploadAs(t, mux, bob, "private", "statement.pdf", bobBytes))
	if !strings.HasPrefix(ref, "/uploads/private/") || !strings.HasSuffix(ref, ".pdf") {
		t.Fatalf("private upload stored at %q", ref)
	}
	onDisk := filepath.Join(app.Dir, filepath.FromSlash(strings.TrimPrefix(ref, "/")))
	stillThere := func(what string) {
		t.Helper()
		if got, err := os.ReadFile(onDisk); err != nil || !bytes.Equal(got, bobBytes) {
			t.Fatalf("%s: bob's private file is gone or changed: %v", what, err)
		}
	}

	name := filepath.Base(ref)
	respellings := []string{
		strings.TrimSuffix(ref, ".pdf") + ".PDF",
		"/uploads/private/" + strings.ToUpper(name),
		"/uploads/PRIVATE/" + name,
		"/uploads/Private/" + strings.ToUpper(name),
	}
	for _, respelled := range respellings {
		aliceDoc := createDocAs(t, mux, alice, respelled)

		// run: serve_file, with and without `record:`.
		for _, flow := range []string{ownerServeFlowRecord, ownerServeFlow} {
			rec := runOwnerFlow(t, app, flow, http.MethodGet, "/api/docs/"+aliceDoc+"/file", aliceDoc, alice)
			if rec.Code == http.StatusOK || bytes.Contains(rec.Body.Bytes(), bobBytes) {
				t.Errorf("serve_file served bob's file to alice through the spelling %q: %d", respelled, rec.Code)
			}
		}

		// GET /api/_signed_url: nothing usable is minted for the spelling.
		rel := uploadRelPath(respelled)
		q := url.Values{"path": {rel}, "record_table": {"docs"}, "record_id": {aliceDoc}}.Encode()
		if code, signed := mintSignedURL(t, mux, alice, q); code == http.StatusOK {
			rec := crudScopeRequest(t, mux, http.MethodGet, signed, "", nil)
			if rec.Code == http.StatusOK || bytes.Contains(rec.Body.Bytes(), bobBytes) {
				t.Errorf("a signed URL for the spelling %q served bob's file: %d", respelled, rec.Code)
			}
			if folds {
				t.Errorf("a signed URL was minted for the spelling %q of a stored private file", respelled)
			}
		}

		// GET /uploads/...: a correctly signed link for the spelling, and the
		// bare path, serve nothing (a folder spelled PRIVATE is not gated as
		// private by name, so the bare path must not open the private file).
		for _, target := range []string{GenerateSignedURL("example.com", rel, time.Minute), respelled} {
			rec := crudScopeRequest(t, mux, http.MethodGet, target, "", nil)
			if rec.Code == http.StatusOK || bytes.Contains(rec.Body.Bytes(), bobBytes) {
				t.Errorf("GET %s served bob's private file: %d", target, rec.Code)
			}
		}

		// The connector's file tools and extract_text read through the same
		// resolver.
		logical := strings.TrimPrefix(respelled, "/")
		if data, _, err := appMCPReadPrivateUpload(context.Background(), app, logical, 1<<20); err == nil || bytes.Contains(data, bobBytes) {
			t.Errorf("the connector read bob's file through the spelling %q", respelled)
		}
		if data, _, err := readAppPrivateStorageContext(&FlowContext{App: app}, context.Background(), logical, 1<<20); err == nil || bytes.Contains(data, bobBytes) {
			t.Errorf("extract_text read bob's file through the spelling %q", respelled)
		}

		// run: delete_upload, with and without `record:`.
		for _, flow := range []string{ownerDeleteFlowRecord, ownerDeleteFlow} {
			rec := runOwnerFlow(t, app, flow, http.MethodPost, "/api/docs/"+aliceDoc+"/remove", aliceDoc, alice)
			stillThere("delete_upload through the spelling " + respelled)
			if folds && rec.Code < 400 {
				t.Errorf("delete_upload of the spelling %q of a stored file reported success: %d %s", respelled, rec.Code, rec.Body.String())
			}
		}
	}

	// The stored spelling still works for its uploader, and a reference to a
	// file that does not exist is still a delete that succeeds with nothing
	// to do.
	bobDoc := createDocAs(t, mux, bob, ref)
	rec := runOwnerFlow(t, app, ownerServeFlowRecord, http.MethodGet, "/api/docs/"+bobDoc+"/file", bobDoc, bob)
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), bobBytes) {
		t.Fatalf("bob could not read his own file by its stored reference: %d %q", rec.Code, rec.Body.String())
	}
	code, signed := mintSignedURL(t, mux, bob, url.Values{"path": {uploadRelPath(ref)}, "record_table": {"docs"}, "record_id": {bobDoc}}.Encode())
	if code != http.StatusOK {
		t.Fatalf("bob could not sign his own file by its stored reference: %d", code)
	}
	if rec = crudScopeRequest(t, mux, http.MethodGet, signed, "", nil); rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), bobBytes) {
		t.Fatalf("bob's signed URL did not serve his file: %d", rec.Code)
	}
	missing := createDocAs(t, mux, bob, "/uploads/private/00000000-missing.pdf")
	if rec = runOwnerFlow(t, app, ownerDeleteFlowRecord, http.MethodPost, "/api/docs/"+missing+"/remove", missing, bob); rec.Code != http.StatusOK {
		t.Fatalf("delete of a missing private file: %d %s", rec.Code, rec.Body.String())
	}

	// A case-sensitive disk can hold a second file whose name differs only in
	// letter case. It is a file of its own: its reference reaches it and
	// never the other one.
	if !folds {
		other := strings.TrimSuffix(onDisk, ".pdf") + ".PDF"
		if err := os.WriteFile(other, []byte("%PDF-1.4 another file"), 0o600); err != nil {
			t.Fatal(err)
		}
		otherDoc := createDocAs(t, mux, alice, strings.TrimSuffix(ref, ".pdf")+".PDF")
		rec = runOwnerFlow(t, app, ownerServeFlowRecord, http.MethodGet, "/api/docs/"+otherDoc+"/file", otherDoc, alice)
		if rec.Code != http.StatusOK || rec.Body.String() != "%PDF-1.4 another file" {
			t.Fatalf("the differently spelled file was not served by its own name: %d %q", rec.Code, rec.Body.String())
		}
		if rec = runOwnerFlow(t, app, ownerDeleteFlowRecord, http.MethodPost, "/api/docs/"+otherDoc+"/remove", otherDoc, alice); rec.Code != http.StatusOK {
			t.Fatalf("delete of the differently spelled file: %d %s", rec.Code, rec.Body.String())
		}
		if _, err := os.Stat(other); !os.IsNotExist(err) {
			t.Fatalf("the differently spelled file was not deleted: %v", err)
		}
	}
	stillThere("after every respelled reference")

	rec = runOwnerFlow(t, app, ownerDeleteFlowRecord, http.MethodPost, "/api/docs/"+bobDoc+"/remove", bobDoc, bob)
	if rec.Code != http.StatusOK {
		t.Fatalf("bob could not delete his own file by its stored reference: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(onDisk); !os.IsNotExist(err) {
		t.Fatalf("bob's delete left the file: %v", err)
	}
}

// The comparison itself, on any disk: a name is stored only under the bytes
// the directory returns for it. Another letter case and another Unicode
// normalization are other names, whether or not the disk opens them as the
// same entry, and nothing is lower-cased: an entry stored in upper case is
// matched in upper case only.
func TestStoredEntryNameIsComparedByteForByte(t *testing.T) {
	root := filepath.Join(t.TempDir(), "uploads")
	folder := filepath.Join(root, "private")
	if err := os.MkdirAll(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	const composed, decomposed = "café.txt", "café.txt"
	for _, name := range []string{"a1b2.pdf", "REPORT.PDF", composed} {
		if err := os.WriteFile(filepath.Join(folder, name), []byte("bytes of "+name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(folder)
	if err != nil {
		t.Fatal(err)
	}
	// Some disks store a name in another normalization than the one written;
	// the stored one is whatever the directory lists.
	accented, otherForm := composed, decomposed
	for _, e := range entries {
		if e.Name() == decomposed {
			accented, otherForm = decomposed, composed
		}
	}

	dir, err := openTreeDir(folder)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	for name, want := range map[string]bool{
		"a1b2.pdf":    true,
		"A1B2.pdf":    false,
		"a1b2.PDF":    false,
		"REPORT.PDF":  true,
		"report.pdf":  false,
		"Report.PDF":  false,
		accented:      true,
		otherForm:     false,
		"missing.pdf": false,
		"":            false,
	} {
		got, err := dir.storedAs(name)
		if err != nil || got != want {
			t.Errorf("storedAs(%q) = %v, %v; want %v", name, got, err, want)
		}
	}

	// A directory larger than one read of its entries is searched to the end.
	big := filepath.Join(root, "many")
	if err := os.MkdirAll(big, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1300; i++ {
		if err := os.WriteFile(filepath.Join(big, "f"+strconv.Itoa(i)+".txt"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bigDir, err := openTreeDir(big)
	if err != nil {
		t.Fatal(err)
	}
	defer bigDir.Close()
	for name, want := range map[string]bool{"f0.txt": true, "f1299.txt": true, "F1299.TXT": false, "f1300.txt": false} {
		if got, err := bigDir.storedAs(name); err != nil || got != want {
			t.Errorf("storedAs(%q) in a large directory = %v, %v; want %v", name, got, err, want)
		}
	}

	// The upload resolver applies it to every component under the root.
	for rel, want := range map[string]bool{
		"private/a1b2.pdf":     true,
		"private/A1B2.PDF":     false,
		"PRIVATE/a1b2.pdf":     false,
		"Private/A1B2.pdf":     false,
		"private/REPORT.PDF":   true,
		"private/report.pdf":   false,
		"private/" + accented:  true,
		"private/" + otherForm: false,
	} {
		f, ok := openStoredUpload(root, filepath.Join(root, filepath.FromSlash(rel)))
		if ok {
			f.Close()
		}
		if ok != want {
			t.Errorf("openStoredUpload(%q) opened = %v, want %v", rel, ok, want)
		}
		// The delete and signing side reports the stored spelling, or a name
		// that reaches nothing (deleting a missing file is a no-op): on a
		// case-sensitive disk another spelling is such a name.
		wantDelete := want
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel))); os.IsNotExist(err) {
			wantDelete = true
		}
		if got := localUploadStoredAs(filepath.Dir(root), "uploads/"+rel); got != wantDelete {
			t.Errorf("localUploadStoredAs(%q) = %v, want %v", rel, got, wantDelete)
		}
	}
	// A link inside uploads/ still resolves, by the link's own stored name.
	if err := os.Symlink(filepath.Join("private", "a1b2.pdf"), filepath.Join(root, "alias.pdf")); err != nil {
		t.Fatal(err)
	}
	if f, ok := openStoredUpload(root, filepath.Join(root, "alias.pdf")); !ok {
		t.Error("a link to a stored file no longer opens by its own name")
	} else {
		f.Close()
	}
}

// The stored-name check lists a directory only when two lstats cannot settle
// the answer. Each branch is shown against a directory whose matching rule is
// fixed by the test (so it runs the same on any disk), with the listing
// counted: a plain ASCII name in a case-sensitive directory is decided
// without one.
func TestStoredEntryNameListsOnlyWhenLstatCannotDecide(t *testing.T) {
	tmp := t.TempDir()
	info := func(file string) os.FileInfo {
		t.Helper()
		path := filepath.Join(tmp, file)
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		st, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	one, two := info("one"), info("two")
	// exact matches names byte for byte; folding matches them in any letter
	// case, as one entry.
	exact := func(entries map[string]os.FileInfo) func(string) (os.FileInfo, error) {
		return func(name string) (os.FileInfo, error) {
			if st, ok := entries[name]; ok {
				return st, nil
			}
			return nil, os.ErrNotExist
		}
	}
	folding := func(entries map[string]os.FileInfo) func(string) (os.FileInfo, error) {
		return func(name string) (os.FileInfo, error) {
			for stored, st := range entries {
				if strings.EqualFold(stored, name) {
					return st, nil
				}
			}
			return nil, os.ErrNotExist
		}
	}
	denied := func(string) (os.FileInfo, error) { return nil, os.ErrPermission }

	for _, tc := range []struct {
		what       string
		lstat      func(string) (os.FileInfo, error)
		name       string
		listing    bool // what the listing would answer
		want       bool
		wantListed int
	}{
		{"missing name", exact(map[string]os.FileInfo{"a1b2.pdf": one}), "zz.pdf", true, false, 0},
		{"case-sensitive directory, stored name", exact(map[string]os.FileInfo{"a1b2.pdf": one}), "a1b2.pdf", false, true, 0},
		{"case-sensitive directory, upper-case stored name", exact(map[string]os.FileInfo{"REPORT.PDF": one}), "REPORT.PDF", false, true, 0},
		{"case-sensitive directory, other spelling", exact(map[string]os.FileInfo{"a1b2.pdf": one}), "A1B2.PDF", true, false, 0},
		{"case-sensitive directory holding both spellings", exact(map[string]os.FileInfo{"a1b2.pdf": one, "A1B2.PDF": two}), "A1B2.PDF", false, true, 0},
		{"hard link under the other spelling", exact(map[string]os.FileInfo{"a1b2.pdf": one, "A1B2.PDF": one}), "a1b2.pdf", true, true, 1},
		{"folding directory, stored name", folding(map[string]os.FileInfo{"a1b2.pdf": one}), "a1b2.pdf", true, true, 1},
		{"folding directory, other spelling", folding(map[string]os.FileInfo{"a1b2.pdf": one}), "A1B2.PDF", false, false, 1},
		{"name outside ASCII", exact(map[string]os.FileInfo{"café.txt": one}), "café.txt", true, true, 1},
		{"name outside ASCII, other normalization", folding(map[string]os.FileInfo{"café.txt": one}), "café.txt", false, false, 1},
		{"name with no letter", exact(map[string]os.FileInfo{"2024": one}), "2024", true, true, 1},
		{"name another code point normalizes onto (K)", exact(map[string]os.FileInfo{"K9.pdf": one}), "K9.pdf", false, false, 1},
		{"name another code point normalizes onto (;)", exact(map[string]os.FileInfo{"a;b.pdf": one}), "a;b.pdf", false, false, 1},
		{"name another code point normalizes onto (`)", exact(map[string]os.FileInfo{"a`b.pdf": one}), "a`b.pdf", false, false, 1},
		{"lstat fails otherwise", denied, "a1b2.pdf", true, true, 1},
	} {
		listed := 0
		got, err := entryStoredAs(tc.name, tc.lstat, func() (bool, error) { listed++; return tc.listing, nil })
		if err != nil || got != tc.want || listed != tc.wantListed {
			t.Errorf("%s: entryStoredAs(%q) = %v, %v with %d listings; want %v with %d", tc.what, tc.name, got, err, listed, tc.want, tc.wantListed)
		}
	}

	for name, want := range map[string]string{
		"a1b2.pdf":       "A1B2.PDF",
		"Report-2.PDF":   "rEPORT-2.pdf",
		"2024":           "",
		"":               "",
		"café.txt":       "",
		"K9.pdf":         "",
		"a;b.pdf":        "",
		"a`b.pdf":        "",
		"k9.pdf":         "K9.PDF",
		"K9.pdf":         "",
		"_-.~ (1)+x.txt": "_-.~ (1)+X.TXT",
	} {
		if got, ok := caseSwappedASCII(name); got != want || ok != (want != "") {
			t.Errorf("caseSwappedASCII(%q) = %q, %v; want %q", name, got, ok, want)
		}
	}

	// On the real disk: the answers are the listing's, and a case-sensitive
	// directory gives them without one.
	folder := filepath.Join(tmp, "uploads")
	if err := os.MkdirAll(folder, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(folder, "a1b2.pdf"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	folds := diskFoldsCase(t, folder)
	dir, err := openTreeDir(folder)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	count := func(name string) (bool, int) {
		t.Helper()
		listed := 0
		got, err := entryStoredAs(name, dir.root.Lstat, func() (bool, error) { listed++; return dir.lists(name) })
		if err != nil {
			t.Fatalf("entryStoredAs(%q): %v", name, err)
		}
		return got, listed
	}
	wantListed := 0
	if folds {
		wantListed = 1 // the disk opens the swapped spelling as the same file
	}
	if got, listed := count("a1b2.pdf"); !got || listed != wantListed {
		t.Errorf("stored name on this disk (folds case: %v): stored = %v with %d listings, want true with %d", folds, got, listed, wantListed)
	}
	if got, listed := count("A1B2.PDF"); got || listed != wantListed {
		t.Errorf("other spelling on this disk (folds case: %v): stored = %v with %d listings, want false with %d", folds, got, listed, wantListed)
	}
	if got, listed := count("missing.pdf"); got || listed != 0 {
		t.Errorf("missing name: stored = %v with %d listings, want false with 0", got, listed)
	}
	if folds {
		t.Log("this disk folds case, so it cannot hold a hard link under the other spelling; that fallback is shown above against a fixed directory")
		return
	}
	// A hard link under the swapped spelling is the same file as on a folding
	// disk: only the listing tells that both names are stored.
	if err := os.Link(filepath.Join(folder, "a1b2.pdf"), filepath.Join(folder, "A1B2.PDF")); err != nil {
		t.Skipf("this disk makes no hard links (%v); the fallback is shown above against a fixed directory", err)
	}
	for _, name := range []string{"a1b2.pdf", "A1B2.PDF"} {
		if got, listed := count(name); !got || listed != 1 {
			t.Errorf("hard-linked %q: stored = %v with %d listings, want true with 1", name, got, listed)
		}
	}
	if got, listed := count("A1b2.pdf"); got || listed != 0 {
		t.Errorf("a spelling neither link has: stored = %v with %d listings, want false with 0", got, listed)
	}
}
