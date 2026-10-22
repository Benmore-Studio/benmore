//go:build !cli && !windows

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// approveResp POSTs an approval and returns the response (status + headers).
func (h *exposureHarness) approveResp(cookie, id, csrf string) *http.Response {
	resp, _ := h.do("POST", appMCPOperationRoute+id+"/approve", cookie, url.Values{"_csrf": {csrf}}, nil)
	return resp
}

// secondActor adds a second editor in the same workspace with its own
// connector grant, and returns its browser cookie and MCP client.
func (h *exposureHarness) secondActor() (string, *sdk.ClientSession) {
	h.t.Helper()
	cookie := createCrudScopeSession(h.t, h.app, "second-actor@example.com", "editor", "17", "")
	actor := GetSessionFromDB(h.app.DB, cookie)
	if _, err := h.app.DB.Exec(`INSERT INTO members(org_id,email,user_id) VALUES('17',?,?)`, actor.Email, actor.UserID); err != nil {
		h.t.Fatal(err)
	}
	pair, err := createAppMCPNativeGrantFor(context.Background(), h.app, actor.UserID, "17", "client-b2", h.resource, "complete_item", time.Now())
	if err != nil {
		h.t.Fatal(err)
	}
	return cookie, appMCPClient(h.t, h.server, pair.AccessToken, nil)
}

// Two people behind one address have separate approval budgets: the first one
// running dry does not stop the second, and the refusal carries Retry-After.
func TestAppMCPOperationRateLimitIsPerUserNotPerIP(t *testing.T) {
	for _, cluster := range []bool{false, true} {
		name := "single"
		if cluster {
			name = "cluster"
		}
		t.Run(name, func(t *testing.T) {
			if cluster {
				t.Setenv("BENMORE_CLUSTER", "true")
			}
			h := newExposureHarness(t)
			h.addTask(2)
			secondCookie, secondClient := h.secondActor()
			id := h.prepare()
			_, _, token := h.review(h.cookie, id)
			var last *http.Response
			for i := 0; i <= appMCPOperationUserRate; i++ {
				last = h.approveResp(h.cookie, id, token)
				if i < appMCPOperationUserRate && last.StatusCode == http.StatusTooManyRequests {
					t.Fatalf("refused early at approval %d", i+1)
				}
			}
			if last.StatusCode != http.StatusTooManyRequests || last.Header.Get("Retry-After") == "" {
				t.Fatalf("exhausted user: status %d Retry-After %q", last.StatusCode, last.Header.Get("Retry-After"))
			}
			out, code := h.call(secondClient, "complete_item", map[string]any{"arguments": map[string]any{"id": 2, "project_id": 7}})
			if code != "" {
				t.Fatalf("second prepare: %s", code)
			}
			id2, _ := out["operation_id"].(string)
			_, _, token2 := h.review(secondCookie, id2)
			if got := h.approveResp(secondCookie, id2, token2).StatusCode; got != http.StatusSeeOther {
				t.Fatalf("a second user from the same IP was refused after the first ran dry: %d", got)
			}
		})
	}
}

// A page that sends the victim's browser to unknown operation URLs, and
// ordinary review pages, must not spend the budget a real approval needs.
func TestAppMCPOperationRateLimitNotBurnedByUnknownIDsOrReviews(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	for i := 0; i < 40; i++ {
		unknown := fmt.Sprintf("%032x", i+1)
		resp, _ := h.do("GET", appMCPOperationRoute+unknown, h.cookie, nil, map[string]string{"Sec-Fetch-Site": "cross-site"})
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("unknown id %d was charged to the user", i+1)
		}
	}
	var token string
	for i := 0; i < 40; i++ {
		status, _, tok := h.review(h.cookie, id)
		if status != http.StatusOK {
			t.Fatalf("review %d: status %d", i+1, status)
		}
		token = tok
	}
	if got := h.approveResp(h.cookie, id, token).StatusCode; got != http.StatusSeeOther {
		t.Fatalf("approval after 40 unknown ids and 40 reviews: %d", got)
	}
}

// The pre-authentication guard still stops a flood from one address.
func TestAppMCPOperationRateLimitPerIPFloodGuard(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	var last *http.Response
	for i := 0; i <= appMCPOperationIPRate; i++ {
		last, _ = h.do("GET", appMCPOperationRoute+id, "", nil, nil)
	}
	if last.StatusCode != http.StatusTooManyRequests || last.Header.Get("Retry-After") == "" {
		t.Fatalf("anonymous flood: status %d Retry-After %q", last.StatusCode, last.Header.Get("Retry-After"))
	}
}
