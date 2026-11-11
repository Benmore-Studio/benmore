package main

import "testing"

// One rule names a restore stage for every "this is not source" list: a stage
// in .benmore, and the restore and PITR stages older releases made at the top
// of the instance directory.
func TestRestoreStagePathNamesBothPlaces(t *testing.T) {
	stages := []struct{ rel, stage, kind string }{
		{".restore-3354974491", ".restore-3354974491", "restore"},
		{".restore-3354974491/source.db", ".restore-3354974491", "restore"},
		{"./.restore-3354974491/candidate.db", ".restore-3354974491", "restore"},
		{".restore-3354974491/", ".restore-3354974491", "restore"},
		{".pitr-17/data.db-wal", ".pitr-17", "pitr"},
		{".benmore/.restore-0a1b2c3d", ".benmore/.restore-0a1b2c3d", "restore"},
		{".benmore/.restore-0a1b2c3d/candidate.db", ".benmore/.restore-0a1b2c3d", "restore"},
		{".benmore/.pitr-0a1b2c3d/data.db", ".benmore/.pitr-0a1b2c3d", "pitr"},
		{".benmore/.refresh-0a1b2c3d/candidate.db", ".benmore/.refresh-0a1b2c3d", "refresh"},
	}
	for _, tc := range stages {
		if stage, kind := restoreStageRel(tc.rel); stage != tc.stage || kind != tc.kind {
			t.Errorf("restoreStageRel(%q) = %q, %q; want %q, %q", tc.rel, stage, kind, tc.stage, tc.kind)
		}
		if !sourceManifestExcluded(tc.rel, false) || !sourceManifestExcluded(tc.rel, true) {
			t.Errorf("the source manifest lists %q", tc.rel)
		}
		if !appPathProtected(tc.rel) {
			t.Errorf("the file tools may touch %q", tc.rel)
		}
	}
	// The app's own files: only the names a release actually made count, and
	// only where it made them.
	for _, rel := range []string{
		"", ".", ".benmore", ".restore-", ".restore-notes/readme.md", ".restore-12ab/source.db", ".pitr-x/data.db",
		".refresh-12/notes.md", "restore-12/source.db", "static/.restore-12/app.js", "static/.benmore/.restore-ab/app.js",
		".benmore/backups/.restore-12/x", "../.restore-12/source.db", "/.restore-12/source.db", ".restore-12x/source.db",
	} {
		if stage, kind := restoreStageRel(rel); stage != "" || kind != "" {
			t.Errorf("restoreStageRel(%q) = %q, %q; it is not a stage", rel, stage, kind)
		}
	}
	for _, rel := range []string{".restore-notes/readme.md", ".refresh-12/notes.md", "static/.restore-12/app.js", "restore-12/app.js"} {
		if sourceManifestExcluded(rel, false) {
			t.Errorf("the source manifest drops the app's own %q", rel)
		}
		if appPathProtected(rel) {
			t.Errorf("the file tools refuse the app's own %q", rel)
		}
	}
	for _, name := range []string{"source.db", "source.db-wal", "candidate.db", "candidate.db-journal", "data.db", "data.db-shm"} {
		if !restoreStageMember(name) {
			t.Errorf("%q is a stage's database copy", name)
		}
	}
	for _, name := range []string{"notes.md", "source.db.bak", "data.dbx", "app.js", ""} {
		if restoreStageMember(name) {
			t.Errorf("%q is not a stage's database copy", name)
		}
	}
}
