//go:build !cli

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The backup worker already compresses to a file. Uploading that file must
// not allocate another object-sized buffer in the router process. The sink
// hashes and discards the request so its allocations do not scale either.
func TestS3FileUploadBoundedMemory(t *testing.T) {
	const size = 32 << 20
	f, err := os.Create(filepath.Join(t.TempDir(), "synthetic-backup.db.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	var received atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := sha256.New()
		n, err := io.Copy(h, r.Body)
		if err != nil || r.ContentLength != size || r.Header.Get("X-Amz-Content-Sha256") != fmt.Sprintf("%x", h.Sum(nil)) {
			t.Errorf("upload length/hash mismatch: read=%d length=%d error=%v", n, r.ContentLength, err)
		}
		verifyS3StreamSignature(t, r)
		received.Store(n)
	}))
	defer server.Close()
	store := &S3Storage{Bucket: "fixture", Endpoint: server.URL + "/amazonaws.com", Key: "fixture", Secret: "fixture-secret", Region: "us-east-1"}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	url, err := store.Save("owned/synthetic.db.gz", f)
	runtime.ReadMemStats(&after)
	if err != nil || url != store.objectURL("owned/synthetic.db.gz") || received.Load() != size {
		t.Fatalf("upload result url=%q bytes=%d error=%v", url, received.Load(), err)
	}
	if pos, err := f.Seek(0, io.SeekCurrent); err != nil || pos != size {
		t.Fatalf("caller file offset=%d error=%v, want EOF", pos, err)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > size/2 {
		t.Fatalf("uploading %d MiB allocated %d MiB; backup file must remain streamed", size>>20, alloc>>20)
	}
}

// Verify the actual HTTP request against the SigV4 canonical-request contract,
// including the transmitted payload digest and any temporary credential token.
func verifyS3StreamSignature(t *testing.T, r *http.Request) {
	t.Helper()
	stamp := r.Header.Get("X-Amz-Date")
	if len(stamp) != 16 {
		t.Fatalf("invalid signing timestamp %q", stamp)
	}
	signed := "host;x-amz-content-sha256;x-amz-date"
	canonical := "host:" + r.Host + "\nx-amz-content-sha256:" + r.Header.Get("X-Amz-Content-Sha256") + "\nx-amz-date:" + stamp + "\n"
	if token := r.Header.Get("X-Amz-Security-Token"); token != "" {
		signed += ";x-amz-security-token"
		canonical += "x-amz-security-token:" + token + "\n"
	}
	request := strings.Join([]string{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, canonical, signed, r.Header.Get("X-Amz-Content-Sha256")}, "\n")
	scope := stamp[:8] + "/us-east-1/s3/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + fmt.Sprintf("%x", sha256.Sum256([]byte(request)))
	mac := func(key []byte, value string) []byte {
		h := hmac.New(sha256.New, key)
		_, _ = io.WriteString(h, value)
		return h.Sum(nil)
	}
	key := []byte("AWS4fixture-secret")
	for _, part := range []string{stamp[:8], "us-east-1", "s3", "aws4_request"} {
		key = mac(key, part)
	}
	want := "AWS4-HMAC-SHA256 Credential=fixture/" + scope + ", SignedHeaders=" + signed + ", Signature=" + fmt.Sprintf("%x", mac(key, toSign))
	if r.Header.Get("Authorization") != want {
		t.Error("request does not match payload/token SigV4 signature")
	}
}

func TestS3FileUploadSignerNilAndTokenCompatibility(t *testing.T) {
	for _, body := range [][]byte{nil, {}, []byte("payload")} {
		r, err := http.NewRequest(http.MethodPut, "https://fixture.example/bucket/object", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("X-Amz-Security-Token", "fixture-session-token")
		signAWSv4(r, body, "fixture", "fixture-secret", "us-east-1", "s3")
		if r.Header.Get("X-Amz-Content-Sha256") != fmt.Sprintf("%x", sha256.Sum256(body)) {
			t.Fatal("byte/nil signing wrapper changed payload digest")
		}
		verifyS3StreamSignature(t, r)
	}
}

type s3StreamFailingFile struct {
	*os.File
	seekCalls, failSeek int
	readErr             error
	failReadAtAfter     int64
}

func (f *s3StreamFailingFile) ReadAt(p []byte, offset int64) (int, error) {
	if f.failReadAtAfter > 0 && offset >= f.failReadAtAfter {
		return 0, errors.New("fixture transmission read failure")
	}
	return f.File.ReadAt(p, offset)
}

func (f *s3StreamFailingFile) Seek(offset int64, whence int) (int64, error) {
	f.seekCalls++
	if f.seekCalls == f.failSeek {
		return 0, errors.New("fixture seek failure")
	}
	return f.File.Seek(offset, whence)
}

func (f *s3StreamFailingFile) Read(p []byte) (int, error) {
	if f.readErr != nil {
		return 0, f.readErr
	}
	return f.File.Read(p)
}

func TestS3FileUploadInputErrorsRefuseBeforeHTTP(t *testing.T) {
	for _, tc := range []struct {
		name     string
		failSeek int
		readErr  error
	}{
		{"seek-current", 1, nil},
		{"seek-end", 2, nil},
		{"seek-restore", 3, nil},
		{"read-error", 0, errors.New("fixture read failure")},
		{"short-read", 0, io.EOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file, err := os.Create(filepath.Join(t.TempDir(), "upload"))
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			_, _ = io.WriteString(file, "payload")
			_, _ = file.Seek(0, io.SeekStart)
			f := &s3StreamFailingFile{File: file, failSeek: tc.failSeek, readErr: tc.readErr}
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
			defer server.Close()
			store := &S3Storage{Bucket: "fixture", Endpoint: server.URL, Key: "fixture", Secret: "fixture-secret"}
			url, err := store.Save("owned/object", f)
			if err == nil || url != "" || calls.Load() != 0 {
				t.Fatalf("input error permitted upload: url=%q calls=%d error=%v", url, calls.Load(), err)
			}
		})
	}
}

func TestS3FileUploadNonseekableCompatibility(t *testing.T) {
	for _, payload := range []string{"", "payload"} {
		reader := struct{ io.Reader }{strings.NewReader(payload)}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, err := io.ReadAll(r.Body)
			if err != nil || string(body) != payload || r.ContentLength != int64(len(payload)) {
				t.Errorf("nonseekable body=%q length=%d error=%v", body, r.ContentLength, err)
			}
		}))
		store := &S3Storage{Bucket: "fixture", Endpoint: server.URL, Key: "fixture", Secret: "fixture-secret"}
		_, err := store.Save("owned/object", reader)
		server.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestS3FileUploadTransmissionReadError(t *testing.T) {
	const size = 128 << 10
	file, err := os.Create(filepath.Join(t.TempDir(), "upload"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := file.Truncate(size); err != nil {
		t.Fatal(err)
	}
	// Hashing succeeds through Read. The wire reader sends its first chunk,
	// then ReadAt fails while the HTTP body is in flight.
	f := &s3StreamFailingFile{File: file, failReadAtAfter: 32 << 10}
	type observed struct {
		n   int64
		err error
	}
	wire := make(chan observed, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		wire <- observed{n, err}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()
	store := &S3Storage{Bucket: "fixture", Endpoint: server.URL, Key: "fixture", Secret: "fixture-secret"}
	url, err := store.Save("owned/object", f)
	if err == nil || url != "" {
		t.Fatalf("partial transmission reported success: url=%q error=%v", url, err)
	}
	select {
	case got := <-wire:
		if got.n <= 0 || got.n >= size || got.err == nil {
			t.Fatalf("expected an interrupted wire body: bytes=%d error=%v", got.n, got.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("partial transmission did not reach the test endpoint")
	}
	if pos, err := f.Seek(0, io.SeekCurrent); err != nil || pos != size {
		t.Fatalf("transmission error changed/closed caller file: pos=%d error=%v", pos, err)
	}
}

func TestS3FileUploadRemainingBytesAndMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, path, contentType, disposition string
		start                                int64
		status                               int
	}{
		{"remaining", "owned/backup.db.gz", "application/gzip", "attachment; filename=backup.db.gz", 7, 200},
		{"empty", "owned/empty.db.gz", "", "", 14, 200},
		{"past-eof", "owned/past.db.gz", "", "", 21, 200},
		{"http-error", "owned/rejected.db.gz", "", "", 7, 403},
		{"public", "public/fixture/a.bin", "text/plain", "", 0, 200},
		{"private", "private/fixture/a.bin", "", "inline", 0, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const payload = "prefix:payload"
			f, err := os.Create(filepath.Join(t.TempDir(), "upload"))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err := io.WriteString(f, payload); err != nil {
				t.Fatal(err)
			}
			if _, err := f.Seek(tc.start, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			want := ""
			if tc.start < int64(len(payload)) {
				want = payload[tc.start:]
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got, err := io.ReadAll(r.Body)
				user, password, ok := r.BasicAuth()
				if err != nil || string(got) != want || r.ContentLength != int64(len(want)) || !ok || user != "fixture" || password != "fixture-secret" {
					t.Errorf("payload/auth mismatch: body=%q length=%d error=%v", got, r.ContentLength, err)
				}
				ct := tc.contentType
				if ct == "" {
					ct = "application/octet-stream"
				}
				cache := ""
				if strings.HasPrefix(tc.path, "public/") {
					cache = "public, max-age=31536000, immutable"
				} else if strings.HasPrefix(tc.path, "private/") {
					cache = "no-store"
				}
				if r.Header.Get("Content-Type") != ct || r.Header.Get("Content-Disposition") != tc.disposition || r.Header.Get("Cache-Control") != cache {
					t.Error("object metadata changed")
				}
				w.WriteHeader(tc.status)
				if tc.status >= 400 {
					_, _ = io.WriteString(w, "fixture refusal")
				}
			}))
			defer server.Close()
			store := &S3Storage{Bucket: "fixture", Endpoint: server.URL, Key: "fixture", Secret: "fixture-secret"}
			url, err := store.SaveWithMeta(tc.path, f, tc.contentType, tc.disposition)
			if tc.status >= 400 {
				if err == nil || err.Error() != "S3 upload failed: 403: fixture refusal" || url != "" {
					t.Fatalf("rejected upload returned url=%q error=%v", url, err)
				}
			} else if err != nil || url != store.objectURL(tc.path) {
				t.Fatalf("upload result url=%q error=%v", url, err)
			}
			wantPos := max(tc.start, int64(len(payload)))
			if pos, err := f.Seek(0, io.SeekCurrent); err != nil || pos != wantPos {
				t.Fatalf("caller file offset=%d error=%v, want %d", pos, err, wantPos)
			}
		})
	}
}

func TestS3FileUploadReplaysRedirect(t *testing.T) {
	for _, code := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			f, err := os.Create(filepath.Join(t.TempDir(), "upload"))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			_, _ = io.WriteString(f, "skip:retained")
			_, _ = f.Seek(5, io.SeekStart)
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != "retained" || r.ContentLength != 8 {
					t.Errorf("redirect body=%q length=%d error=%v", body, r.ContentLength, err)
				}
				if r.URL.Path != "/final" {
					http.Redirect(w, r, "/final", code)
				}
			}))
			defer server.Close()
			store := &S3Storage{Bucket: "fixture", Endpoint: server.URL, Key: "fixture", Secret: "fixture-secret"}
			url, err := store.Save("object", f)
			if err != nil || url != store.objectURL("object") || calls.Load() != 2 {
				t.Fatalf("redirect result calls=%d url=%q error=%v", calls.Load(), url, err)
			}
			if pos, err := f.Seek(0, io.SeekCurrent); err != nil || pos != 13 {
				t.Fatalf("redirect consumed/closed caller file incorrectly: pos=%d error=%v", pos, err)
			}
		})
	}
}
