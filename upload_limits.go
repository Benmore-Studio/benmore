//go:build !cli

package main

// Upload memory bounds. ParseMultipartForm keeps file parts in RAM up to its
// threshold and spills the rest to temporary files; with the old 32-50 MB
// thresholds a burst of ~16 concurrent uploads could hold more than a hosted
// app's whole memory budget (MemoryHigh=512M). Parts above
// uploadMemoryThreshold now go to disk, and a process-wide slot pool bounds
// how many multipart bodies are parsed at once.

import (
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// uploadMemoryThreshold is the in-memory part of a parsed multipart body;
// larger file parts spill to temporary files. (net/http adds up to 10 MB for
// non-file form values on top of this.)
const uploadMemoryThreshold = 4 << 20

// maxConcurrentUploads bounds concurrent multipart parses per process.
const maxConcurrentUploads = 8

// uploadSlotWait is how long a request queues for a slot before 503 (a var
// only so tests need not wait it out). A queued request has not read its
// body, so waiting costs no memory; apps that upload several files with
// Promise.all and bm.upload (which does not retry) queue instead of failing.
var uploadSlotWait = 30 * time.Second

var uploadSlots = make(chan struct{}, maxConcurrentUploads)

// maxConcurrentUploadsPerClient bounds how many of the process's upload slots
// one client holds at once. Without it one signed-in user sending slow bodies
// could hold every slot and turn all other uploads away; a client's further
// uploads (e.g. a Promise.all batch) queue behind its own instead.
const maxConcurrentUploadsPerClient = 3

// uploadClientSlots holds one semaphore per client with an upload in progress
// or queued; an entry is dropped when its last request leaves.
var uploadClientSlots = struct {
	sync.Mutex
	m map[string]*uploadClientSem
}{m: map[string]*uploadClientSem{}}

type uploadClientSem struct {
	slots chan struct{}
	refs  int
}

func uploadClientSemFor(client string) *uploadClientSem {
	uploadClientSlots.Lock()
	defer uploadClientSlots.Unlock()
	sem := uploadClientSlots.m[client]
	if sem == nil {
		sem = &uploadClientSem{slots: make(chan struct{}, maxConcurrentUploadsPerClient)}
		uploadClientSlots.m[client] = sem
	}
	sem.refs++
	return sem
}

func (sem *uploadClientSem) leave(client string) {
	uploadClientSlots.Lock()
	defer uploadClientSlots.Unlock()
	if sem.refs--; sem.refs == 0 {
		delete(uploadClientSlots.m, client)
	}
}

// uploadClientKey names the client an upload slot is charged to: the
// signed-in user (any session or token of theirs), else the client address,
// with an IPv6 client keyed by its /64 as for rate limits.
func uploadClientKey(app *App, r *http.Request) string {
	if s := getSession(app, r); s != nil && s.UserID != 0 {
		return app.Dir + "\x00user:" + strconv.FormatInt(s.UserID, 10)
	}
	return "ip:" + clientRateBucket(clientIP(r))
}

// acquireUploadSlot reserves one upload slot for the rest of the request,
// first one of client's maxConcurrentUploadsPerClient (uploadClientKey), then
// one of the process's. When none frees up within uploadSlotWait (one wait
// for both) it writes 503 with Retry-After and returns ok=false. The caller
// must call release.
func acquireUploadSlot(w http.ResponseWriter, r *http.Request, client string) (release func(), ok bool) {
	timer := time.NewTimer(uploadSlotWait)
	defer timer.Stop()
	sem := uploadClientSemFor(client)
	select {
	case sem.slots <- struct{}{}:
		select {
		case uploadSlots <- struct{}{}:
			return func() {
				<-uploadSlots
				<-sem.slots
				sem.leave(client)
			}, true
		case <-timer.C:
		case <-r.Context().Done():
		}
		<-sem.slots
	case <-timer.C:
	case <-r.Context().Done():
	}
	sem.leave(client)
	w.Header().Set("Retry-After", "5")
	httpJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "too many uploads in progress, retry shortly"})
	return nil, false
}

// removeMultipartTemp deletes the temporary files a parsed multipart body
// spilled to disk. net/http's server does this after the handler returns,
// but handlers served through other paths (router proxying, tests, the MCP
// probe) don't get that, so upload handlers clean up themselves.
func removeMultipartTemp(r *http.Request) {
	if r != nil && r.MultipartForm != nil {
		_ = r.MultipartForm.RemoveAll()
	}
}

// uploadExtRe is the stored-extension allowlist. The extension comes from the
// client's filename and becomes part of the storage key and the served URL,
// so anything beyond short lowercase alphanumerics is refused.
var uploadExtRe = regexp.MustCompile(`^[a-z0-9]{1,10}$`)

// safeUploadExt reports whether a (lowercased, dot-less) extension from a
// client filename may be stored. No extension is allowed, as before; the
// content type then comes from sniffing.
func safeUploadExt(ext string) bool {
	return ext == "" || uploadExtRe.MatchString(ext)
}
