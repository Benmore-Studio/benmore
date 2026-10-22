//go:build !cli

package main

import (
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// uploadFairnessApp is an app without auth, so its uploads are keyed by the
// client address.
func uploadFairnessApp(t *testing.T) *http.ServeMux {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{})}
	t.Cleanup(app.Shutdown)
	mux := http.NewServeMux()
	RegisterUploadRoute(mux, app)
	return mux
}

// heldUpload is an upload whose body stalls mid-part, holding its slot.
type heldUpload struct {
	body *io.PipeWriter
	code chan int
}

func startHeldUpload(mux *http.ServeMux, remote string) heldUpload {
	pr, pw := io.Pipe()
	req := httptest.NewRequest(http.MethodPost, "/api/_upload", pr)
	req.RemoteAddr = remote
	req.Header.Set("Content-Type", "multipart/form-data; boundary=held")
	h := heldUpload{body: pw, code: make(chan int, 1)}
	go func() {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		h.code <- rec.Code
	}()
	go pw.Write([]byte("--held\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\nslow"))
	return h
}

func waitUploadSlotsHeld(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(uploadSlots) != n {
		if time.Now().After(deadline) {
			t.Fatalf("%d upload slots held, want %d", len(uploadSlots), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func completeUpload(mux *http.ServeMux, remote string) int {
	body, contentType := uploadTestBody(16)
	req := httptest.NewRequest(http.MethodPost, "/api/_upload", body)
	req.RemoteAddr = remote
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Code
}

// One client could hold all of the process's upload slots with slow bodies,
// turning every other client's upload away with 503. A client now holds at
// most maxConcurrentUploadsPerClient (3) slots; its further uploads queue
// behind its own and get a slot as one finishes, and other clients are
// unaffected.
func TestUploadSlotsArePerClient(t *testing.T) {
	prev := uploadSlotWait
	uploadSlotWait = 300 * time.Millisecond
	defer func() { uploadSlotWait = prev }()
	mux := uploadFairnessApp(t)
	const greedy = "198.51.100.7:4000"

	var held []heldUpload
	defer func() {
		for _, h := range held {
			h.body.CloseWithError(io.ErrUnexpectedEOF)
			<-h.code
		}
	}()
	for i := 0; i < 3; i++ {
		held = append(held, startHeldUpload(mux, greedy))
		waitUploadSlotsHeld(t, i+1)
	}
	if code := completeUpload(mux, greedy); code != http.StatusServiceUnavailable {
		t.Fatalf("a client holding 3 upload slots got a 4th (%d) with %d of %d free", code, maxConcurrentUploads-3, maxConcurrentUploads)
	}
	if code := completeUpload(mux, "203.0.113.9:4000"); code == http.StatusServiceUnavailable {
		t.Fatal("another client's upload was turned away")
	}

	// Promise.all: the client's next upload queues and proceeds once one of
	// its own finishes.
	uploadSlotWait = 5 * time.Second
	queued := make(chan int, 1)
	go func() { queued <- completeUpload(mux, greedy) }()
	time.Sleep(100 * time.Millisecond)
	held[0].body.CloseWithError(io.ErrUnexpectedEOF)
	<-held[0].code
	held = held[1:]
	select {
	case code := <-queued:
		if code == http.StatusServiceUnavailable {
			t.Fatal("a queued upload failed although the client's own upload finished")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("a queued upload did not proceed after the client's own upload finished")
	}
}

// A signed-in user is one client whatever session, token or address an upload
// comes from; anonymous uploads are keyed by address (an IPv6 client by its
// /64, so rotating addresses inside it gains nothing).
func TestUploadClientKey(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{})}
	t.Cleanup(app.Shutdown)
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	if _, err := db.Exec(`INSERT INTO _benmore_users (id, username, email, role, verified) VALUES
		(1, 'alice', 'alice@example.com', 'user', 1), (2, 'bob', 'bob@example.com', 'user', 1)`); err != nil {
		t.Fatal(err)
	}
	req := func(remote, token string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/_upload", nil)
		r.RemoteAddr = remote
		if token != "" {
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		}
		return r
	}
	alice1 := CreateSession(db, 1, "alice@example.com", "", time.Hour)
	alice2 := CreateSession(db, 1, "alice@example.com", "", time.Hour)
	bob := CreateSession(db, 2, "bob@example.com", "", time.Hour)
	a1 := uploadClientKey(app, req("198.51.100.1:1000", alice1))
	if a1 != uploadClientKey(app, req("203.0.113.5:2000", alice2)) {
		t.Fatal("one user's sessions are different upload clients")
	}
	if a1 == uploadClientKey(app, req("198.51.100.1:1000", bob)) {
		t.Fatal("two users at one address share an upload client")
	}
	if a1 == uploadClientKey(app, req("198.51.100.1:1000", "")) {
		t.Fatal("an anonymous upload is charged to a signed-in user")
	}
	if uploadClientKey(app, req("[2001:db8:1:2::1]:1000", "")) != uploadClientKey(app, req("[2001:db8:1:2::ffff]:1000", "")) {
		t.Fatal("addresses inside one IPv6 /64 are different upload clients")
	}
	if uploadClientKey(app, req("198.51.100.1:1000", "")) == uploadClientKey(app, req("198.51.100.2:1000", "")) {
		t.Fatal("two IPv4 clients share an upload client")
	}
}
