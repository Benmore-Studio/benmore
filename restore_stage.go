package main

import (
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// A restore works on private copies of a database: restore-prepare's copy of
// the selected backup and the candidate made from it (.restore-<id>), a PITR
// replay (.pitr-<id>) and refresh-dev's copy of production (.refresh-<id>).
// Each lives in a stage directory inside the instance's .benmore, which no
// source path covers: it is never committed to the app's history, copied by
// promote, seed_dev or refresh_dev, or listed in a source manifest.
//
// Older releases made the restore and PITR stages at the top of the instance
// directory (os.MkdirTemp: the prefix and decimal digits), where every one of
// those treated them as app source: a history commit during a restore stored
// the whole backup in the app's git history, the GitHub push audit passed it,
// and a code copy carried it to the other instance. A stage one of those
// releases, or a restore that never finished, left there is still a stage:
// restoreStagePath names both places, and every "this is not source" rule
// asks it instead of keeping its own list.

// restoreStageParent holds the stage directories.
const restoreStageParent = ".benmore"

var (
	// restoreStageName is a stage directory's own name inside .benmore.
	restoreStageName = regexp.MustCompile(`^\.(restore|pitr|refresh)-[0-9A-Za-z]+$`)
	// legacyRestoreStageName is a stage an older release made at the top of
	// the instance directory. Refresh stages were never made there.
	legacyRestoreStageName = regexp.MustCompile(`^\.(restore|pitr)-[0-9]+$`)
)

// restoreStageRel returns the stage directory that rel, a path relative to an
// instance directory, names or lies inside (slash form: ".benmore/.restore-<id>",
// or ".restore-<digits>" for an older release's), and its kind: "restore",
// "pitr" or "refresh". Both are "" when rel is in no stage.
func restoreStageRel(rel string) (stage, kind string) {
	parts := strings.Split(path.Clean(filepath.ToSlash(rel)), "/")
	if m := legacyRestoreStageName.FindStringSubmatch(parts[0]); m != nil {
		return parts[0], m[1]
	}
	if len(parts) > 1 && parts[0] == restoreStageParent {
		if m := restoreStageName.FindStringSubmatch(parts[1]); m != nil {
			return parts[0] + "/" + parts[1], m[1]
		}
	}
	return "", ""
}

// restoreStagePath reports whether rel (relative to an instance directory) is
// a restore stage or lies inside one.
func restoreStagePath(rel string) bool {
	stage, _ := restoreStageRel(rel)
	return stage != ""
}

// restoreStageMember reports whether name is a file a restore or PITR stage
// holds: a database copy or one of its SQLite sidecars.
func restoreStageMember(name string) bool {
	for _, db := range []string{"source.db", "candidate.db", "data.db"} {
		if rest, ok := strings.CutPrefix(name, db); ok {
			switch rest {
			case "", "-wal", "-shm", "-journal":
				return true
			}
		}
	}
	return false
}
