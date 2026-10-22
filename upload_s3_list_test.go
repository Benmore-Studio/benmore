//go:build !cli

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestS3ListSignsEveryPageWithCanonicalToken(t *testing.T) {
	var firstSignature string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=fixture/") || r.Header.Get("X-Amz-Date") == "" {
			t.Error("page was not signed")
		}
		if r.URL.Query().Get("continuation-token") == "opaque +/=" {
			if strings.Contains(r.URL.RawQuery, "+") || !strings.Contains(r.URL.RawQuery, "opaque%20%2B%2F%3D") || auth == firstSignature {
				t.Error("continuation token lost canonical encoding or request reused prior signature")
			}
			_, _ = io.WriteString(w, `<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>`)
			return
		}
		firstSignature = auth
		_, _ = io.WriteString(w, `<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>opaque +/=</NextContinuationToken></ListBucketResult>`)
	}))
	defer server.Close()
	// Exercise the existing AWS-compatible endpoint selection without calling AWS.
	store := &S3Storage{Bucket: "bucket", Endpoint: server.URL + "/amazonaws.com", Key: "fixture", Secret: "secret", Region: "us-east-1"}
	if _, err := store.List("demo/"); err != nil {
		t.Fatal(err)
	}
}

func TestS3ListCancellationDiscardsPriorPage(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("continuation-token") != "" {
			cancel()
			<-r.Context().Done()
			return
		}
		_, _ = io.WriteString(w, `<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>next</NextContinuationToken><Contents><Key>demo/old</Key></Contents></ListBucketResult>`)
	}))
	defer server.Close()
	store := &S3Storage{Bucket: "bucket", Endpoint: server.URL}
	objects, err := store.ListContext(ctx, "demo/")
	if !errors.Is(err, context.Canceled) || len(objects) != 0 {
		t.Fatalf("canceled listing returned objects=%v err=%v", objects, err)
	}
}

func TestS3ListBoundsPageAndChecksReadErrors(t *testing.T) {
	for _, kind := range []string{"oversized", "short-body"} {
		t.Run(kind, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if kind == "short-body" {
					w.Header().Set("Content-Length", "1024")
					_, _ = io.WriteString(w, `<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>`)
					return
				}
				_, _ = io.WriteString(w, strings.Repeat(" ", (8<<20)+1))
			}))
			defer server.Close()
			store := &S3Storage{Bucket: "bucket", Endpoint: server.URL}
			if objects, err := store.List("demo/"); err == nil || len(objects) != 0 {
				t.Fatalf("invalid page returned success: objects=%v err=%v", objects, err)
			}
		})
	}
}

func TestS3ListCompletePages(t *testing.T) {
	const next = "opaque+/= space&value"
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		user, password, ok := r.BasicAuth()
		if !ok || user != "fixture" || password != "secret" || r.URL.Query().Get("prefix") != "demo/" || r.URL.Query().Get("max-keys") != "1000" {
			t.Errorf("list lost prefix/auth/page size")
		}
		if r.URL.Query().Get("continuation-token") == next {
			_, _ = io.WriteString(w, `<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>demo/last</Key><Size>7</Size></Contents></ListBucketResult>`)
			return
		}
		_, _ = io.WriteString(w, `<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>opaque+/= space&amp;value</NextContinuationToken>`)
		for i := 0; i < 1000; i++ {
			_, _ = fmt.Fprintf(w, `<Contents><Key>demo/%04d</Key><Size>1</Size></Contents>`, i)
		}
		_, _ = io.WriteString(w, `</ListBucketResult>`)
	}))
	defer server.Close()
	store := &S3Storage{Bucket: "bucket", Endpoint: server.URL, Key: "fixture", Secret: "secret"}
	objects, err := store.List("demo/")
	if err != nil || len(objects) != 1001 || calls.Load() != 2 {
		t.Fatalf("objects=%d calls=%d err=%v", len(objects), calls.Load(), err)
	}
	if objects[1000].Key != "demo/last" || objects[1000].Size != 7 {
		t.Fatalf("last page missing: %+v", objects[1000])
	}
}

func TestS3ListRefusesIncompleteInventory(t *testing.T) {
	for _, kind := range []string{"missing-token", "repeated-token", "later-http", "later-xml", "wrong-root", "missing-truncation", "foreign-prefix", "redirect"} {
		t.Run(kind, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := calls.Add(1)
				if n > 3 {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if kind == "missing-token" {
					_, _ = io.WriteString(w, `<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>`)
					return
				}
				if n == 1 || kind == "repeated-token" {
					_, _ = io.WriteString(w, `<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>next</NextContinuationToken><Contents><Key>demo/old</Key></Contents></ListBucketResult>`)
					return
				}
				switch kind {
				case "later-http":
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = io.WriteString(w, strings.Repeat("x", 64<<10))
				case "later-xml":
					_, _ = io.WriteString(w, `<ListBucketResult><Contents>`)
				case "wrong-root":
					_, _ = io.WriteString(w, `<Error><Code>Denied</Code></Error>`)
				case "missing-truncation":
					_, _ = io.WriteString(w, `<ListBucketResult/>`)
				case "foreign-prefix":
					_, _ = io.WriteString(w, `<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>other/secret</Key></Contents></ListBucketResult>`)
				case "redirect":
					http.Redirect(w, r, "/unexpected", http.StatusFound)
				}
			}))
			defer server.Close()
			store := &S3Storage{Bucket: "bucket", Endpoint: server.URL, Key: "fixture", Secret: "secret"}
			objects, err := store.List("demo/")
			if err == nil || len(objects) != 0 {
				t.Fatalf("incomplete inventory returned objects=%v err=%v", objects, err)
			}
			if calls.Load() > 2 || len(err.Error()) > 4200 {
				t.Fatalf("unbounded failure: calls=%d errorBytes=%d", calls.Load(), len(err.Error()))
			}
		})
	}
}

func TestS3ListFailurePreventsRetentionDeletes(t *testing.T) {
	var deletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletes.Add(1)
			return
		}
		if r.URL.Query().Get("continuation-token") != "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, `<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>next</NextContinuationToken><Contents><Key>removed/2000-01-01-00.db.gz</Key></Contents></ListBucketResult>`)
	}))
	defer server.Close()
	store := &S3Storage{Bucket: "bucket", Endpoint: server.URL, Key: "fixture", Secret: "secret"}
	t.Setenv("BENMORE_RETENTION_DRYRUN", "0")
	_, err := runRetentionSweep(store, func() (map[string]bool, error) { return map[string]bool{"active": true}, nil })
	if err == nil || deletes.Load() != 0 {
		t.Fatalf("failed listing: deleted=%d err=%v", deletes.Load(), err)
	}
}

func BenchmarkS3CompleteInventory(b *testing.B) {
	for _, total := range []int{1000, 10000} {
		b.Run(fmt.Sprint(total), func(b *testing.B) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				start := 0
				if token := r.URL.Query().Get("continuation-token"); token != "" {
					if _, err := fmt.Sscan(token, &start); err != nil {
						b.Error(err)
						return
					}
				}
				end := start + 1000
				_, _ = fmt.Fprintf(w, `<ListBucketResult><IsTruncated>%t</IsTruncated><NextContinuationToken>%d</NextContinuationToken>`, end < total, end)
				for i := start; i < end; i++ {
					_, _ = fmt.Fprintf(w, `<Contents><Key>demo/%08d</Key><Size>1</Size></Contents>`, i)
				}
				_, _ = io.WriteString(w, `</ListBucketResult>`)
			}))
			defer server.Close()
			store := &S3Storage{Bucket: "bucket", Endpoint: server.URL}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				objects, err := store.List("demo/")
				if err != nil || len(objects) != total {
					b.Fatalf("objects=%d err=%v", len(objects), err)
				}
			}
		})
	}
}
