//go:build !cli

package main

import (
	"strings"
	"testing"
)

// The round-1105 events page: a GET filter form on a gotmpl page, the
// documented `:param_<name>` optional-filter pattern (api(at:"frontend")
// gotmpl_queries). The write gate refused it twice as a dead form.
const gotmplGetFilterPage = "---\nengine: gotmpl\ntitle: \"Upcoming events\"\nqueries:\n  events: \"SELECT e.id, e.title FROM events e WHERE (:param_city IS NULL OR e.city = :param_city) ORDER BY e.starts_at\"\n---\n" +
	`<form method="get" action="/events"><input name="city"><button type="submit">Filter</button></form>` + "\n" +
	`{{range .events}}<h2>{{.title}}</h2>{{end}}` + "\n"

// A plain POST form with no hand-written token: the runtime's InjectCSRF adds
// a valid _csrf to it when the page renders.
const gotmplPostFormPage = "---\nengine: gotmpl\ntitle: RSVP\n---\n" +
	`<form method="POST" action="/api/rsvp"><input name="email"><button>RSVP</button></form>` + "\n"

func TestDeadFormAllowsGetNavigationForms(t *testing.T) {
	pages := map[string]string{
		"gotmpl get":       gotmplGetFilterPage,
		"mustache get":     `<page title="Events"><form method="GET" action="/events"><input name="city"><button>Filter</button></form></page>`,
		"gotmpl hx-get":    "---\nengine: gotmpl\n---\n" + `<form hx-get="/events" hx-target="#list"><input name="city"></form><div id="list"></div>`,
		"mustache hx-del":  `<page><form hx-delete="/api/notes/1"><input name="reason"><button>x</button></form></page>`,
		"unquoted get":     `<page><form method=get action="/events"><select name="city"></select></form></page>`,
		"gotmpl post form": gotmplPostFormPage,
	}
	for name, page := range pages {
		if msg := detectFrameworkAntipatterns("events.html", page); msg != "" {
			t.Errorf("%s: refused: %s", name, msg)
		}
		if msg := ValidateOnWrite("events.html", page); strings.Contains(msg, "dead-form") || strings.Contains(msg, "form-missing-csrf") {
			t.Errorf("%s: write gate refused: %s", name, msg)
		}
	}
}

// A form with inputs and no method or HTMX attribute is still flagged, and
// the message now offers method="get" for a filter form. No suggestion asks
// for a hand-written _csrf field: `{{csrf}}` renders empty in mustache,
// `{{.csrf}}` renders empty in gotmpl, and in static/ HTML a hand-written
// field stops the runtime injecting the real token.
func TestDeadFormMessagesOfferGetAndNoTokenField(t *testing.T) {
	for name, page := range map[string]string{
		"mustache": `<page><form><input name="city"><button>Go</button></form></page>`,
		"gotmpl":   "---\nengine: gotmpl\n---\n<form><input name=\"city\"><button>Go</button></form>",
	} {
		msg := detectFrameworkAntipatterns("events.html", page)
		if !strings.Contains(msg, "dead-form") {
			t.Fatalf("%s: a form with no method should still be flagged, got %q", name, msg)
		}
		if !strings.Contains(msg, `method=\"get\"`) && !strings.Contains(msg, `method="get"`) {
			t.Errorf("%s: message should offer a GET filter form: %s", name, msg)
		}
		if strings.Contains(msg, "csrf}}") {
			t.Errorf("%s: message suggests a token snippet that renders empty: %s", name, msg)
		}
	}
	// The password-form security message had the same snippet.
	msg := validateFormSecurity(`<form action="/signup"><input name="password" type="password"></form>`)
	if !strings.Contains(msg, "security violation") || strings.Contains(msg, "csrf}}") {
		t.Errorf("password-form message: %s", msg)
	}
}

// `benmore check` reads the same dispatcher as the write gate: an app with a
// GET filter page and a token-less POST form has no form findings.
func TestCheckAcceptsGetFilterAndPlainPostForms(t *testing.T) {
	dir := writeApp(t, map[string]string{
		"app.yaml": "seo:\n  site_name: Events\ntheme: zinc\n",
		"schema.prisma": `model Event {
  id        Int    @id @default(autoincrement())
  title     String
  city      String?
  starts_at String?
}`,
		"events.html": gotmplGetFilterPage,
		"rsvp.html":   gotmplPostFormPage,
		"about.html":  `<page title="About"><form method="post" action="/api/events"><input name="title"><button>Add</button></form></page>`,
	})
	rpt := RunSourceCheck(dir, "")
	for _, f := range rpt.Findings {
		if strings.Contains(f.Message, "dead-form") || strings.Contains(f.Message, "form-missing-csrf") {
			t.Errorf("check flagged a working form: %s: %s", f.File, f.Message)
		}
	}
}
