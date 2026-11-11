//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func BenchmarkErrorAuditLargeIntake(b *testing.B) {
	dir := b.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db")+"?_busy_timeout=5000&_journal_mode=WAL&_txlock=immediate")
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	app := &App{Dir: dir, DB: db, Stop: make(chan struct{})}
	defer stopReportingTest(app)
	mux := http.NewServeMux()
	RegisterErrorCaptureRoute(mux, app)
	body := `{"Message":"` + strings.Repeat("m", 40000) + `","Stack":"` + strings.Repeat("s", 15000) + `"}`
	b.ResetTimer()
	client := 0
	for b.Loop() {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/_errors", strings.NewReader(body))
		// Each request from its own address: the beacon limits each client.
		client++
		req.RemoteAddr = fmt.Sprintf("10.%d.%d.%d:1234", client>>16&255, client>>8&255, client&255)
		mux.ServeHTTP(w, req)
		if w.Code != 204 {
			b.Fatal(w.Code)
		}
	}
	b.StopTimer()
}
