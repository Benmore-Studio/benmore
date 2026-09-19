//go:build !cli

package main

import (
	"bytes"
	"database/sql"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a mutex-guarded log sink so a worker goroutine's recover-handler
// write and the test's assertion read don't race on the same bytes.Buffer.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestSafeGoLogsWorkerPanicAndKeepsProcess(t *testing.T) {
	buf := &syncBuffer{}
	prev := log.Writer()
	log.SetOutput(buf)
	defer log.SetOutput(prev)

	safeGo("panic-worker-test", func() {
		panic("boom")
	})

	// safeGo's recover handler logs AFTER fn unwinds, so poll the (mutex-guarded)
	// buffer until the panic line appears instead of racing on fn's return.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s := buf.String()
		if strings.Contains(s, `PANIC in goroutine "panic-worker-test"`) && strings.Contains(s, "boom") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("panic log missing worker name and panic value: %s", buf.String())
}

func TestFireFlowsForEventFallsBackInlineWhenPoolFull(t *testing.T) {
	if cap(flowsEventSem) != flowsEventFanoutLimit || flowsEventFanoutLimit != 32 {
		t.Fatalf("flows event semaphore cap = %d, want 32", cap(flowsEventSem))
	}
	for {
		select {
		case <-flowsEventSem:
		default:
			goto drained
		}
	}
drained:
	for i := 0; i < cap(flowsEventSem); i++ {
		flowsEventSem <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(flowsEventSem); i++ {
			<-flowsEventSem
		}
	}()

	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "flows.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec("CREATE TABLE hits (id INTEGER PRIMARY KEY AUTOINCREMENT, marker TEXT)"); err != nil {
		t.Fatal(err)
	}
	app := &App{
		DB:   db,
		Stop: make(chan struct{}),
		Flows: []Flow{{
			Name:    "bounded_event",
			Trigger: FlowTrigger{Type: "on_insert", Table: "notes"},
			Steps:   []FlowStep{{Type: "sql", SQL: "INSERT INTO hits (marker) VALUES ('inline')"}},
		}},
	}

	FireFlowsForEvent(app, "on_insert", "notes", map[string]any{"id": 1})

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM hits WHERE marker = 'inline'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("full flow event pool should run inline before return; inserted %d rows", count)
	}
}
