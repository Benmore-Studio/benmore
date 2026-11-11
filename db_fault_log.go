//go:build !cli

package main

// SQLite's error log, read for one thing: whether this process has seen the
// database report corruption or an I/O error while serving.
//
// A clean shutdown vouches for the file (db_clean_shutdown.go), which lets the
// next start skip quick_check. Corruption found by a query during the run is
// the case it must not vouch for. SQLite reports corruption through its error
// log (sqlite3_log) wherever it is detected - a request, a job, a checkpoint -
// with SQLITE_CORRUPT as the primary code, so a log callback sees it without
// wrapping the driver. I/O errors are logged less completely: SQLite logs the
// ones from fsync, truncate, shared-memory and similar calls, and any that
// aborts a statement ("statement aborts at"), but some read, write and
// commit-failure paths return SQLITE_IOERR without logging it. Such an error
// still fails the request that met it, and a page it damaged is logged as
// corruption when it is next read; one never read again before a clean stop is
// left to the marker's periodic re-check (7-10 days). The callback records
// the first SQLITE_CORRUPT, SQLITE_IOERR or SQLITE_NOTADB code; it never calls
// back into Go.
//
// The log is process-wide, so a serving process (one app database) blocks its
// marker on a fault in any database it opened. The bundled SQLite (3.53)
// accepts SQLITE_CONFIG_LOG at any time, also after initialization; if
// sqlite3_config still refuses it (an older system library), no marker is
// written.

/*
int sqlite3_config(int, ...);

#define BENMORE_SQLITE_CONFIG_LOG 16
#define BENMORE_SQLITE_IOERR 10
#define BENMORE_SQLITE_CORRUPT 11
#define BENMORE_SQLITE_NOTADB 26

static int benmore_sqlite_fault_code = 0;

static void benmore_sqlite_log(void *arg, int code, const char *msg) {
	int primary = code & 0xff;
	(void)arg;
	(void)msg;
	if (primary == BENMORE_SQLITE_IOERR || primary == BENMORE_SQLITE_CORRUPT || primary == BENMORE_SQLITE_NOTADB) {
		int none = 0;
		__atomic_compare_exchange_n(&benmore_sqlite_fault_code, &none, code, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
	}
}

static int benmore_install_sqlite_fault_log(void) {
	return sqlite3_config(BENMORE_SQLITE_CONFIG_LOG, benmore_sqlite_log, (void *)0);
}

static int benmore_sqlite_fault(void) {
	return __atomic_load_n(&benmore_sqlite_fault_code, __ATOMIC_SEQ_CST);
}

static void benmore_reset_sqlite_fault(void) {
	__atomic_store_n(&benmore_sqlite_fault_code, 0, __ATOMIC_SEQ_CST);
}
*/
import "C"

import "log"

// sqliteFaultLogInstalled says the callback is in place.
var sqliteFaultLogInstalled bool

func init() {
	// Installed at package initialization, before the first open. SQLite
	// 3.53 would also accept it later; older libraries only before
	// sqlite3_initialize.
	if rc := C.benmore_install_sqlite_fault_log(); rc != 0 {
		log.Printf("database: SQLite error log unavailable (sqlite3_config returned %d); clean-shutdown markers are disabled", int(rc))
		return
	}
	sqliteFaultLogInstalled = true
}

// sqliteFaultSeen returns the first corruption or I/O error code SQLite
// reported in this process (0 for none); ok is false when the log could not
// be installed, so nothing can be said.
func sqliteFaultSeen() (code int, ok bool) {
	if !sqliteFaultLogInstalled {
		return 0, false
	}
	return int(C.benmore_sqlite_fault()), true
}

// resetSQLiteFaultSeen forgets recorded faults. Tests only: one test's
// deliberate corruption must not decide another test's marker.
func resetSQLiteFaultSeen() {
	C.benmore_reset_sqlite_fault()
}
