//go:build !cli

package main

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// GET /api/_signed_url reads `expires_in` the way serve_file reads
// `with.expires_in` (whole seconds or a duration). A signed link is a bearer
// credential, so a value the endpoint cannot read, or one under a second, is
// refused: answering with the one-hour default would hand out a link that
// outlives what the caller asked for (`30s` used to live 120 times longer).
func TestSignedURLRequestLifetimeIsAsAskedOrRefused(t *testing.T) {
	app, mux, cleanup := signedURLApp(t)
	defer cleanup()
	tok := createCrudScopeSession(t, app, "owner-a@example.com", "user", "", "")
	hour := int64(time.Hour / time.Second)
	maxSecs := int64(oauthMaxSignedURLTTL / time.Second)

	for _, tc := range []struct {
		name string
		// param is the raw `&expires_in=...` part ("" leaves it out).
		param string
		want  int64 // lifetime in seconds; 0 means a 400
	}{
		{"absent", "", hour},
		{"empty", "&expires_in=", hour},
		{"whole seconds", "&expires_in=5", 5},
		{"seconds duration", "&expires_in=30s", 30},
		{"hours duration", "&expires_in=2h", 2 * hour},
		{"mixed duration", "&expires_in=1h30m", 5400},
		{"padded", "&expires_in=%2090s%20", 90},
		{"sub-second remainder is dropped", "&expires_in=1500ms", 1},
		{"at the cap", "&expires_in=6h", maxSecs},
		{"seconds over the cap", "&expires_in=21601", maxSecs},
		{"far over the cap", "&expires_in=100000", maxSecs},
		{"duration over the cap", "&expires_in=48h", maxSecs},
		{"number too large for an integer", "&expires_in=99999999999999999999", maxSecs},
		{"word", "&expires_in=abc", 0},
		{"zero", "&expires_in=0", 0},
		{"zero duration", "&expires_in=0s", 0},
		{"negative", "&expires_in=-5", 0},
		{"negative duration", "&expires_in=-30s", 0},
		{"negative that would wrap", "&expires_in=-9223372037", 0},
		{"negative too large for an integer", "&expires_in=-99999999999999999999", 0},
		{"under a second", "&expires_in=500ms", 0},
		{"fraction without a unit", "&expires_in=1.5", 0},
		{"unknown unit", "&expires_in=2days", 0},
		{"template", "&expires_in=%7B%7Bttl%7D%7D", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := time.Now().Unix()
			rec := crudScopeRequest(t, mux, http.MethodGet, "/api/_signed_url?path=private/secret.pdf&record_table=docs&record_id=1"+tc.param, tok, nil)
			after := time.Now().Unix()
			var out map[string]any
			mustDecodeBody(t, rec, &out)

			if tc.want == 0 {
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d (%s), want 400", rec.Code, rec.Body.String())
				}
				msg, _ := out["error"].(string)
				// The cap the message names is the cap the runtime applies.
				cap := strings.TrimSuffix(oauthMaxSignedURLTTL.String(), "0m0s")
				for _, part := range []string{"expires_in", "whole seconds", "duration", "1s", cap} {
					if !strings.Contains(msg, part) {
						t.Errorf("error %q does not mention %q", msg, part)
					}
				}
				if out["code"] != "invalid_expires_in" {
					t.Errorf("code = %v, want invalid_expires_in", out["code"])
				}
				// The answer says where the rule is written.
				if out["docs"] != "signed-urls.lifetime" {
					t.Errorf("docs = %v, want signed-urls.lifetime", out["docs"])
				}
				// No link is minted for a refused request.
				if out["url"] != nil || out["path"] != nil || strings.Contains(rec.Body.String(), "sig=") {
					t.Fatalf("refused request still carries a signed link: %s", rec.Body.String())
				}
				return
			}

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d (%s), want 200", rec.Code, rec.Body.String())
			}
			if got, _ := out["expires_in"].(float64); int64(got) != tc.want {
				t.Fatalf("expires_in in the answer = %v, want %d", out["expires_in"], tc.want)
			}
			// The echoed number is not the proof: the signed expiry is.
			signed, _ := out["path"].(string)
			u, err := url.Parse(signed)
			if err != nil {
				t.Fatalf("signed path %q: %v", signed, err)
			}
			expires, err := strconv.ParseInt(u.Query().Get("expires"), 10, 64)
			if err != nil {
				t.Fatalf("signed path %q has no expiry: %v", signed, err)
			}
			if expires < before+tc.want || expires > after+tc.want {
				t.Fatalf("link expires %ds from now, want %ds", expires-before, tc.want)
			}
			// And the link is a working one.
			get := crudScopeRequest(t, mux, http.MethodGet, signed, "", nil)
			if get.Code != http.StatusOK || get.Body.String() != "PRIVATE-BYTES" {
				t.Fatalf("signed link = %d %q, want the file", get.Code, get.Body.String())
			}
		})
	}
}

// The same reading applies to a private file on the media CDN: the signer is
// asked for the lifetime the caller named, and is not asked at all when the
// value cannot be read.
func TestSignedURLRequestLifetimeOnMediaCDN(t *testing.T) {
	t.Setenv("BENMORE_BIND_LOOPBACK", "1")
	app, mux, cleanup := signedURLApp(t)
	defer cleanup()
	cfg := testMediaConfig(t)
	withPlatformMedia(t, cfg)
	tok := createCrudScopeSession(t, app, "owner-a@example.com", "user", "", "")
	file := "https://" + cfg.CDNDomain + "/private/" + appMediaPrefix(app) + "/uploads/private/talk.mp4"
	mustExec(t, app.DB, "UPDATE docs SET file_url = '"+file+"' WHERE id = 1")
	query := "/api/_signed_url?path=" + url.QueryEscape(file) + "&record_table=docs&record_id=1"

	for _, tc := range []struct {
		param string
		want  float64 // seconds the signer is asked for; 0 means a 400
	}{
		{"", mediaPlaybackSignTTL.Seconds()}, // audio/video default
		{"&expires_in=30s", 30},
		{"&expires_in=45", 45},
		{"&expires_in=7h", oauthMaxSignedURLTTL.Seconds()},
		{"&expires_in=soon", 0},
		{"&expires_in=0", 0},
	} {
		t.Run("expires_in"+tc.param, func(t *testing.T) {
			broker := startFakeMediaBroker(t, map[string]any{"url": "https://cdn.example.test/router-signed", "key": "k"})
			rec := crudScopeRequest(t, mux, http.MethodGet, query+tc.param, tok, nil)
			reqs := broker.requests()
			if tc.want == 0 {
				if rec.Code != http.StatusBadRequest || len(reqs) != 0 {
					t.Fatalf("status = %d (%s), signer asked %d times; want 400 and no signature", rec.Code, rec.Body.String(), len(reqs))
				}
				return
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d (%s), want 200", rec.Code, rec.Body.String())
			}
			if len(reqs) != 1 {
				t.Fatalf("signer asked %d times, want 1", len(reqs))
			}
			if got, _ := reqs[0]["expires_in"].(float64); got != tc.want {
				t.Fatalf("signer asked for %vs, want %vs", reqs[0]["expires_in"], tc.want)
			}
			var out map[string]any
			mustDecodeBody(t, rec, &out)
			if got, _ := out["expires_in"].(float64); got != tc.want {
				t.Fatalf("expires_in in the answer = %v, want %v", out["expires_in"], tc.want)
			}
		})
	}
}
