//go:build !cli

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
)

// A hosted app uploads through the presign broker. The upload body used to
// be read whole into memory and then copied into a string, so a 50 MB file
// held over 100 MB of heap until the PUT finished; eight concurrent uploads
// (the process's slot limit) could exceed a hosted app's 768 MB memory limit.
// The body must be streamed from the spooled multipart file instead.
func TestCDNBrokerUploadStreamsBody(t *testing.T) {
	const size = 32 << 20
	var got atomic.Int64
	var gotLen atomic.Int64
	put := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		got.Store(n)
		gotLen.Store(r.ContentLength)
	}))
	t.Cleanup(put.Close)
	startFakeMediaBroker(t, map[string]any{"url": put.URL + "/media/public/app/uploads/files/a.bin", "key": "public/app/uploads/files/a.bin", "headers": map[string]string{"Content-Type": "application/octet-stream"}})

	f, err := os.Create(filepath.Join(t.TempDir(), "upload"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	c := &CDNStorage{s3: &S3Storage{Bucket: "media", Region: "us-east-1"}, Prefix: "app", CDNDomain: "cdn.example.test"}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	url, err := c.saveViaBroker(presignBrokerSocketPath(), "uploads/files/a.bin", f, "application/octet-stream", "")
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if url != "https://cdn.example.test/public/app/uploads/files/a.bin" {
		t.Fatalf("url = %q", url)
	}
	if got.Load() != size || gotLen.Load() != size {
		t.Fatalf("PUT carried %d bytes with Content-Length %d, want %d", got.Load(), gotLen.Load(), size)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > size/2 {
		t.Fatalf("uploading %d MiB allocated %d MiB; the body must be streamed", size>>20, alloc>>20)
	}
}

// A 307 from storage is still followed with the full body, as it was when
// the body was an in-memory reader.
func TestCDNBrokerUploadReplaysBodyOnRedirect(t *testing.T) {
	var final atomic.Int64
	put := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/first" {
			io.Copy(io.Discard, r.Body)
			http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
			return
		}
		n, _ := io.Copy(io.Discard, r.Body)
		final.Store(n)
	}))
	t.Cleanup(put.Close)
	startFakeMediaBroker(t, map[string]any{"url": put.URL + "/first", "key": "public/app/uploads/files/b.bin"})
	f, err := os.Create(filepath.Join(t.TempDir(), "upload"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	c := &CDNStorage{s3: &S3Storage{Bucket: "media", Region: "us-east-1"}, Prefix: "app", CDNDomain: "cdn.example.test"}
	if _, err := c.saveViaBroker(presignBrokerSocketPath(), "uploads/files/b.bin", f, "application/octet-stream", ""); err != nil {
		t.Fatal(err)
	}
	if final.Load() != 4096 {
		t.Fatalf("redirected PUT carried %d bytes, want 4096", final.Load())
	}
}
