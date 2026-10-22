//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestS3FetchContextBoundsErrorBodyAndRefusesRedirects(t *testing.T) {
	var redirected bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bucket/large-error":
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(strings.Repeat("x", 64<<10)))
		case "/bucket/redirect":
			http.Redirect(w, r, "/bucket/elsewhere", http.StatusFound)
		case "/bucket/elsewhere":
			redirected = true
			_, _ = w.Write([]byte("unexpected redirect target"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	store := &S3Storage{Bucket: "bucket", Endpoint: server.URL}

	if _, err := store.FetchContext(t.Context(), "large-error"); err == nil || len(err.Error()) > 4200 {
		t.Fatalf("S3 error response was not bounded: errLen=%d err=%v", len(err.Error()), err)
	}
	response, err := store.FetchContext(t.Context(), "redirect")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound || redirected {
		t.Fatalf("S3 fetch followed a redirect: status=%d followed=%v", response.StatusCode, redirected)
	}
}
