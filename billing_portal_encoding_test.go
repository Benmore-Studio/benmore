//go:build !cli

package main

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type captureRoundTripper struct{ body string }

func (c *captureRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(r.Body)
	c.body = string(b)
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"url":"https://billing.stripe.test/session"}`)),
		Request:    r,
	}, nil
}

// The caller chooses return_url, so it must be sent as one encoded field.
// Concatenated into the form body it could add fields of its own, such as a
// second customer id.
func TestStripePortalSessionEncodesCallerReturnURL(t *testing.T) {
	capture := &captureRoundTripper{}
	old := http.DefaultTransport
	http.DefaultTransport = capture
	t.Cleanup(func() { http.DefaultTransport = old })

	returnURL := "https://app.example/back?x=1&customer=cus_other"
	if _, err := createStripePortalSession("sk_test_x", "cus_mine", returnURL); err != nil {
		t.Fatalf("createStripePortalSession: %v", err)
	}
	form, err := url.ParseQuery(capture.body)
	if err != nil {
		t.Fatalf("parse body %q: %v", capture.body, err)
	}
	if got := form["customer"]; len(got) != 1 || got[0] != "cus_mine" {
		t.Fatalf("customer = %q, want exactly [cus_mine] (body %q)", got, capture.body)
	}
	if got := form.Get("return_url"); got != returnURL {
		t.Fatalf("return_url = %q, want %q", got, returnURL)
	}
}
