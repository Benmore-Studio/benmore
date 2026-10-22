//go:build !cli

package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Regression coverage through the YAML loader and real flow executor.
func TestFlowDeliveryWebhookRejectsUpstreamFailure(t *testing.T) {
	for _, status := range []int{200, 201, 204, 301, 400, 401, 429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			app := secretTaintApp(t)
			flow := parseExpectRowsFlow(t, app, stepKeyFlow("      - id: deliver\n        run: webhook\n        with:\n          url: https://8.8.8.8/callback\n          payload: { event: synthetic_audit }\n"))
			calls := 0
			client := &http.Client{Transport: apiStatusRoundTripper(func(r *http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("synthetic failure")), Request: r}, nil
			})}
			rr := httptest.NewRecorder()
			err := executeFlowHTTPAsWithAPIClient(app, &flow, rr, httptest.NewRequest("POST", "/api/probe", strings.NewReader(`{}`)), nil, client)
			if calls != 1 {
				t.Fatalf("calls=%d", calls)
			}
			if status >= 200 && status < 300 {
				if err != nil || rr.Code != 200 {
					t.Fatalf("successful delivery: %v, HTTP %d", err, rr.Code)
				}
				return
			}
			if err == nil || rr.Code == 200 {
				t.Fatalf("upstream=%d, flow error=%v, client status=%d, body=%s", status, err, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestFlowDeliveryAuthenticatedResponseCannotBeSharedCached(t *testing.T) {
	app := secretTaintApp(t)
	token := createCrudScopeSession(t, app, "private-audit@example.com", "user", "", "")
	for _, auth := range []string{"required", "none"} {
		for _, header := range []string{"Cache-Control: max-age=3600", "Cache-Control: 'private=\"email\", max-age=3600'", "Cache-Control: 'private, max-age=3600'", "Cache-Control: 'public, max-age=3600'", "Expires: 'Wed, 21 Oct 2037 07:28:00 GMT'"} {
			t.Run(auth+"/"+header, func(t *testing.T) {
				source := strings.Replace(responseValueFlow("", "      - run: respond\n        with:\n          headers: { "+header+" }\n          json: { email: '${{ user_email }}' }\n"), "    method: POST", "    method: GET\n    auth: "+auth, 1)
				flow := parseExpectRowsFlow(t, app, source)
				rr := httptest.NewRecorder()
				req := httptest.NewRequest("GET", "/api/probe", nil)
				req.AddCookie(sessionCookie(token, false, app.SessionDuration))
				mux := http.NewServeMux()
				RegisterFlows(mux, app, []Flow{flow})
				SetAppEnv(app.Dir, "RATE_LIMIT_PER_MIN", "0")
				wrapMiddleware(mux, app, false).ServeHTTP(rr, req)
				if rr.Code != 200 || !strings.Contains(rr.Body.String(), "private-audit@example.com") {
					t.Fatalf("authenticated fixture failed: %d %s", rr.Code, rr.Body.String())
				}
				if got := rr.Header().Get("Cache-Control"); got != "private, no-store" {
					t.Fatalf("sensitive response cache policy = %q", got)
				}
			})
		}
	}
	source := responseValueFlow("", "      - run: respond\n        with:\n          headers: { Cache-Control: 'public, max-age=3600' }\n          json: { public: true }\n")
	rr, _, err := runStepValueFlow(t, app, source, "", nil)
	if err != nil || rr.Header().Get("Cache-Control") != "public, max-age=3600" {
		t.Fatalf("anonymous cache: %v, %v", err, rr.Header())
	}
}

func TestFlowDeliveryMissingReferencesStopBeforeExternalEffects(t *testing.T) {
	app := secretTaintApp(t)
	for name, step := range map[string]string{
		"api JSON":     "      - run: api\n        with:\n          url: https://8.8.8.8/action\n          method: POST\n          body: { target: '${{ params.missing }}', action: charge }\n",
		"api list":     "      - run: api\n        with:\n          url: https://8.8.8.8/action\n          method: POST\n          body: [{ target: '${{ params.missing }}' }]\n",
		"api header":   "      - run: api\n        with:\n          url: https://8.8.8.8/action\n          headers: { X-Target: '${{ params.missing }}' }\n",
		"api query":    "      - run: api\n        with:\n          url: https://8.8.8.8/action\n          query: { target: '${{ params.missing }}' }\n",
		"api signer":   "      - run: api\n        with:\n          url: https://8.8.8.8/action\n          sign: { recipe: bearer_token, token: '${{ params.missing }}' }\n",
		"webhook JSON": "      - run: webhook\n        with:\n          url: https://8.8.8.8/action\n          payload: { target: '${{ params.missing }}' }\n",
		"webhook text": "      - run: webhook\n        with:\n          url: https://8.8.8.8/action\n          body: '{\"target\": \"${{ params.missing }}\", \"action\": \"charge\"}'\n",
	} {
		t.Run(name, func(t *testing.T) {
			rr, sent, err := runStepValueFlow(t, app, stepKeyFlow(step), "", nil)
			if err == nil || !strings.Contains(err.Error(), "nothing was sent") {
				t.Fatalf("expected unresolved-reference error, got %v", err)
			}
			if len(sent) != 0 {
				t.Fatalf("flow returned %d (%v) AFTER sending %+v", rr.Code, err, sent)
			}
		})
	}
}

func TestFlowDeliveryRespondArrayInterpolatesValues(t *testing.T) {
	app := secretTaintApp(t)
	for _, field := range []string{"body", "json"} {
		t.Run(field, func(t *testing.T) {
			source := responseValueFlow("", "      - run: respond\n        with:\n          "+field+": [{ nested: [{ value: '${{ params.value }}' }] }, 7, true]\n")
			if gate := ValidateOnWrite("flows/probe.yaml", source); gate != "" {
				t.Fatal(gate)
			}
			rr, _, err := runStepValueFlow(t, app, source, "?value=resolved-audit", nil)
			if err != nil {
				t.Fatal(err)
			}
			if !jsonEqual(t, rr.Body.String(), `[{"nested":[{"value":"resolved-audit"}]},7,true]`) {
				t.Fatalf("unresolved response array: %d %s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestFlowDeliveryRespondArrayMissingValueFailsBeforeResponse(t *testing.T) {
	app := secretTaintApp(t)
	for _, field := range []string{"body", "json"} {
		t.Run(field, func(t *testing.T) {
			source := responseValueFlow("", "      - run: respond\n        with:\n          headers: { X-Success: yes }\n          "+field+": [{ nested: ['${{ params.missing }}'] }]\n")
			rr, _, _ := runStepValueFlow(t, app, source, "", nil)
			if rr.Code != 500 || !strings.Contains(rr.Body.String(), "template_unresolved") || rr.Header().Get("X-Success") != "" {
				t.Fatalf("response: %d %v %s", rr.Code, rr.Header(), rr.Body.String())
			}
		})
	}
}

func TestFlowDeliveryCacheValidation(t *testing.T) {
	for _, cc := range []string{"max-age=60", `private="email", max-age=60`} {
		source := strings.Replace(responseValueFlow("", "      - run: respond\n        with:\n          headers: { Cache-Control: '"+cc+"' }\n          body: ok\n"), "    method: POST", "    method: GET\n    auth: required", 1)
		if got := ValidateOnWrite("flows/probe.yaml", source); !strings.Contains(got, "lets a shared cache") {
			t.Errorf("%s: %s", cc, got)
		}
	}
}
