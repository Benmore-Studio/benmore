//go:build !cli

package main

import (
	"strings"
	"testing"
)

// The banner used to promise "anonymous analytics ... No third-party
// trackers" on every app. The framework records a signed-in visitor's
// account id, and an app (benmore.ai among them) can add its own trackers,
// so the default text claims neither, and an app names what it adds in
// seo.cookie_notice. Page scripts can wait for the choice and reopen it.
func TestCookieNoticeTextIsAccurateAndConfigurable(t *testing.T) {
	def := AnalyticsCookieNotice(&App{Design: &DesignConfig{SEO: map[string]string{}}})
	for _, banned := range []string{"anonymous", "No third-party"} {
		if strings.Contains(def, banned) {
			t.Errorf("default notice still claims %q", banned)
		}
	}
	for _, want := range []string{analyticsDefaultNotice, "window.bmCookieSettings", "window.bmCookieConsent", "bm:cookie-consent"} {
		if !strings.Contains(def, want) {
			t.Errorf("default notice missing %q", want)
		}
	}
	custom := AnalyticsCookieNotice(&App{Design: &DesignConfig{SEO: map[string]string{
		"cookie_notice": `We use Google Analytics <b>and</b> our own analytics.`,
		"privacy_url":   "/privacy",
	}}})
	if !strings.Contains(custom, "We use Google Analytics &lt;b&gt;and&lt;/b&gt; our own analytics.") {
		t.Error("custom notice text missing or not escaped")
	}
	if !strings.Contains(custom, `<a href="/privacy"`) {
		t.Error("privacy link missing")
	}
	for _, bad := range []string{"javascript:alert(1)", "//evil.example/privacy", "http://example.com/p", "/pri vacy"} {
		out := AnalyticsCookieNotice(&App{Design: &DesignConfig{SEO: map[string]string{"privacy_url": bad}}})
		if strings.Contains(out, "Privacy policy") {
			t.Errorf("privacy_url %q was linked", bad)
		}
	}
	if !strings.Contains(AnalyticsCookieNotice(&App{Design: &DesignConfig{SEO: map[string]string{"privacy_url": "https://example.com/privacy"}}}), `href="https://example.com/privacy"`) {
		t.Error("an https privacy URL was not linked")
	}
	if AnalyticsCookieNotice(nil) == "" {
		t.Error("nil app must still render the default notice")
	}
}
