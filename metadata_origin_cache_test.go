//go:build !cli

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

func TestPublicSDKOriginHeadersAndRevalidation(t *testing.T) {
	mux := http.NewServeMux()
	RegisterLibRoutes(mux)
	requestURIs := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestURIs <- r.RequestURI
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, sdk := range []struct {
		path, etag string
		body       []byte
	}{
		{"/_internal/bm.js", bmJSETag(), bmSDKJS},
		{"/_internal/sdui.js", sduiJSETag(), sduiJS},
		{"/_internal/bm%2ejs", bmJSETag(), bmSDKJS},
		{"/_internal/sdui%2ejs", sduiJSETag(), sduiJS},
	} {
		for name, match := range map[string]string{"fresh": "", "strong": sdk.etag, "weak": "W/" + sdk.etag, "list": `"other", W/` + sdk.etag, "mismatch": `"other"`} {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				t.Run(method+sdk.path+"/"+name, func(t *testing.T) {
					req, err := http.NewRequest(method, server.URL+sdk.path, nil)
					if err != nil {
						t.Fatal(err)
					}
					if req.URL.EscapedPath() != sdk.path {
						t.Fatal("SDK path changed before transport")
					}
					req.Header.Set("If-None-Match", match)
					resp, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					defer resp.Body.Close()
					body, err := io.ReadAll(resp.Body)
					if err != nil {
						t.Fatal(err)
					}
					if got := <-requestURIs; got != sdk.path {
						t.Fatalf("SDK request URI changed: %q", got)
					}
					for key, want := range map[string]string{"Cache-Control": "private, no-cache, no-store, must-revalidate", "Vary": "*", "CDN-Cache-Control": "no-store", "Cloudflare-CDN-Cache-Control": "no-store", "ETag": sdk.etag} {
						if got := resp.Header.Get(key); got != want {
							t.Errorf("%s = %q, want %q", key, got, want)
						}
					}
					wantStatus := http.StatusNotModified
					if name == "fresh" || name == "mismatch" {
						wantStatus = http.StatusOK
					}
					if resp.StatusCode != wantStatus {
						t.Fatalf("status = %d, want %d", resp.StatusCode, wantStatus)
					}
					if method == http.MethodHead || wantStatus == http.StatusNotModified {
						if len(body) != 0 {
							t.Fatalf("HEAD/304 returned %d body bytes", len(body))
						}
					} else if !bytes.Equal(body, sdk.body) {
						t.Fatal("SDK response differs from embedded source")
					}
				})
			}
		}
	}
	control := typesGet(mux, "/_internal/chart.js", "", "")
	if control.Code != http.StatusOK || control.Header().Get("Cache-Control") != "public, max-age=86400" || control.Header().Get("Vary") != "" {
		t.Fatal("unrelated pinned library cache policy changed")
	}
}

// Use real HTTP for HEAD body suppression and inspect the received request URI
// so percent-encoded route checks cannot pass after client normalization.
func TestPrivateMetadataOriginHeadersAndRouteVariants(t *testing.T) {
	app, mux := newTypesAccessApp(t)
	user := createCrudScopeSession(t, app, "user@example.com", "user", "", "")
	admin := createCrudScopeSession(t, app, "admin@example.com", "admin", "", "")
	requestURIs := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestURIs <- r.RequestURI
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	paths := []struct {
		path     string
		registry bool
	}{
		{"/_internal/types.d.ts", false},
		{"/_internal/bm.d.ts", false},
		{"/_internal/flows.json", true},
		{"/%5finternal/types.d.ts", false},
		{"/_internal/%74ypes.d.ts", false},
		{"/_internal/bm%2ed%2ets", false},
		{"/%5Finternal/flows.json", true},
		{"/_internal/%66lows.json", true},
	}
	for _, route := range paths {
		for _, role := range []struct{ name, bearer, flows string }{
			{"anonymous", "", "publicPing"},
			{"user", user, "myReport,publicPing"},
			{"admin", admin, "closeBooks,myReport,publicPing,stripeHook"},
		} {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				t.Run(method+route.path+"/"+role.name, func(t *testing.T) {
					req, err := http.NewRequest(method, server.URL+route.path, nil)
					if err != nil {
						t.Fatal(err)
					}
					if req.URL.EscapedPath() != route.path || (strings.Contains(route.path, "%") && req.URL.RawPath == "") {
						t.Fatalf("encoded path changed before transport: %+v", req.URL)
					}
					if role.bearer != "" {
						req.Header.Set("Authorization", "Bearer "+role.bearer)
					}
					resp, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					defer resp.Body.Close()
					body, err := io.ReadAll(resp.Body)
					if err != nil {
						t.Fatal(err)
					}
					if got := <-requestURIs; got != route.path {
						t.Fatalf("transport normalized request URI: got %q, want %q", got, route.path)
					}
					for name, want := range map[string]string{
						"Cache-Control": "private, no-cache, no-store, must-revalidate, max-age=0",
						"Pragma":        "no-cache", "Expires": "0", "Vary": "*",
						"CDN-Cache-Control": "no-store", "Cloudflare-CDN-Cache-Control": "no-store",
					} {
						if got := resp.Header.Get(name); got != want {
							t.Errorf("%s = %q, want %q", name, got, want)
						}
					}
					wantStatus := http.StatusOK
					if !route.registry && role.name != "admin" {
						wantStatus = http.StatusForbidden
					}
					if resp.StatusCode != wantStatus {
						t.Fatalf("status = %d, want %d", resp.StatusCode, wantStatus)
					}
					if method == http.MethodHead {
						if len(body) != 0 {
							t.Fatalf("HEAD returned %d body bytes", len(body))
						}
						return
					}
					if route.registry {
						var entries map[string]any
						if err := json.Unmarshal(body, &entries); err != nil {
							t.Fatal(err)
						}
						var names []string
						for name := range entries {
							names = append(names, name)
						}
						sort.Strings(names)
						if got := strings.Join(names, ","); got != role.flows {
							t.Errorf("registry = %q, want %q", got, role.flows)
						}
					} else if strings.Contains(string(body), "salary_cents") != (role.name == "admin") {
						t.Error("generated schema authorization changed")
					}
				})
			}
		}
	}
}
