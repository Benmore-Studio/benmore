//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// Custom providers' token/userinfo/email URLs come from app.yaml and pass a
// name-only isPrivateURL check. The client that fetches them must still refuse
// a loopback address at dial time (httptest binds 127.0.0.1), which is where a
// re-resolved provider hostname would land.
func TestOAuthProviderClientRefusesLoopbackDial(t *testing.T) {
	var reached atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		w.Write([]byte(`{"email":"loopback@example.com"}`))
	}))
	defer srv.Close()

	resp, err := oauthProviderHTTPClient().Get(srv.URL + "/userinfo")
	if err == nil {
		resp.Body.Close()
	}
	if err == nil || reached.Load() {
		t.Fatal("OAuth provider client connected to a loopback address")
	}
}
