package main

// Hosted dev instances (<sub>-dev.benmore.ai) are work in progress: an
// unfinished build, its test data and the preview links people share while
// building. They ask search engines not to index them; prod instances and
// custom domains are unchanged.
//
// The signal is the X-Robots-Tag response header, set on every response the
// dev instance serves (pages, static files, API answers). It is deliberately
// not "Disallow: /" in robots.txt: a crawler that may not fetch a page never
// sees its noindex, so pages already in an index would stay there. The
// generated robots.txt keeps "Allow: /" and only leaves out its Sitemap line
// on dev. An app's own static/robots.txt is still served verbatim, and a
// handler that sets its own X-Robots-Tag replaces this default.
//
// This file is untagged: the framework edition never runs as a dev instance
// (BENMORE_APP_NAME is only set by the platform), so the check is simply false
// there.

import (
	"os"
	"strings"
)

// devInstanceRobotsTag is the X-Robots-Tag a hosted dev instance sends.
const devInstanceRobotsTag = "noindex, nofollow"

// hostedDevInstance reports whether this process serves a platform dev
// instance. BENMORE_APP_NAME is platform-owned (a reserved key an app cannot
// set, see platform_env.go): the prod unit's env file carries "<sub>" and the
// dev unit's carries "<sub>-dev" (writeAppEnvFileFor, deploy_env.go), and no
// logical subdomain ends in -dev (env_model.go).
func hostedDevInstance() bool {
	return IsDevSubdomain(strings.TrimSpace(os.Getenv("BENMORE_APP_NAME")))
}

// generateRobotsFor is GenerateRobots for this instance. A dev instance leaves
// out the Sitemap line so it does not advertise its URLs; everything else,
// including "Allow: /", is unchanged so crawlers can still read the noindex.
func generateRobotsFor(baseURL string, devInstance bool) string {
	text := GenerateRobots(baseURL)
	if !devInstance {
		return text
	}
	lines := strings.Split(text, "\n")
	kept := lines[:0]
	for _, line := range lines {
		if !strings.HasPrefix(line, "Sitemap:") {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}
