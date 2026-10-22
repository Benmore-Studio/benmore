//go:build !cli

package main

// Bounds on what POST /api/_feedback keeps.
//
// The endpoint is open to visitors with no account (a published app's widget,
// a draft's /login page), and it used to store whatever one request carried:
// only the screenshot was capped, so every other field could run to the
// request-body limit, nothing limited how often a visitor posted, and
// _benmore_feedback was never bounded. A loop of anonymous posts filled the
// app's database up to its storage ceiling, after which every write the app
// itself makes is refused.
//
//   - A request is read up to feedbackMaxRequestBytes. The comment is refused
//     past feedbackMaxBodyBytes; the fields the widget fills in on its own
//     (page, host, element, name, email) are cut to their limits.
//   - A visitor with no session posts at most feedbackAnonRate times per
//     feedbackAnonWindow from one address (an IPv6 client by its /64).
//   - The table holds at most feedbackMaxOpenRows open items; past that a
//     submission is refused until the owner resolves or deletes some. A row
//     the owner has already handled never counts, so a busy app's history
//     does not close its inbox.
//   - Stored screenshots share feedbackScreenshotBudget bytes; past it a
//     submission is kept without its screenshot.
//
// Together these bound the table at roughly budget + rows x text limits.

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	feedbackMaxScreenshotBytes = 2 << 20
	feedbackMaxRequestBytes    = feedbackMaxScreenshotBytes + (1 << 20)
	feedbackMaxBodyBytes       = 10_000
	feedbackMaxNameBytes       = 200
	feedbackMaxEmailBytes      = 254
	feedbackMaxURLBytes        = 2048
	feedbackMaxHostBytes       = 253
	feedbackMaxSelectorBytes   = 1024
	feedbackAnonRate           = 10
	feedbackAnonWindow         = 10 * time.Minute
	feedbackTotalsMaxAge       = time.Minute
)

// Variables so a test can reach the ceilings with a handful of rows.
var (
	feedbackMaxOpenRows      int64 = 5000
	feedbackScreenshotBudget int64 = 128 << 20
)

// feedbackIntake is one app's submission gate: the anonymous limiter and the
// table totals the ceilings are checked against. The totals are read from the
// table at most once per feedbackTotalsMaxAge and advanced locally in between,
// so a flood costs one aggregate a minute, not one per request.
type feedbackIntake struct {
	app  *App
	anon func() *RateLimiter

	mu        sync.Mutex
	readAt    time.Time
	openRows  int64
	shotBytes int64
}

func newFeedbackIntake(app *App) *feedbackIntake {
	stop := app.Stop
	return &feedbackIntake{
		app:  app,
		anon: sync.OnceValue(func() *RateLimiter { return NewRateLimiterStoppable(feedbackAnonRate, feedbackAnonWindow, stop) }),
	}
}

// cutFeedbackField trims s and cuts it to at most n bytes on a rune boundary.
func cutFeedbackField(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// decode reads one submission within the limits above. It writes the refusal
// itself and reports false.
func (fi *feedbackIntake) decode(w http.ResponseWriter, r *http.Request, session *Session) (feedbackSubmission, bool) {
	var body feedbackSubmission
	if session == nil {
		if ok, retry, _ := fi.anon().Check(appLimiterKey(fi.app, "feedback", clientRateBucket(rateLimitClientHost(r)))); !ok {
			setRetryAfter(w, retry)
			httpJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too many feedback submissions, try again later"})
			return body, false
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, feedbackMaxRequestBytes)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			httpJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "feedback is too large"})
			return body, false
		}
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "feedback body is required"})
		return body, false
	}
	body.Body = strings.TrimSpace(body.Body)
	if body.Body == "" {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "feedback body is required"})
		return body, false
	}
	if len(body.Body) > feedbackMaxBodyBytes {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "feedback is too long (10,000 characters max)"})
		return body, false
	}
	if len(body.Screenshot) > feedbackMaxScreenshotBytes {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "screenshot too large (2MB max)"})
		return body, false
	}
	body.Name = cutFeedbackField(body.Name, feedbackMaxNameBytes)
	body.Email = cutFeedbackField(body.Email, feedbackMaxEmailBytes)
	body.PageURL = cutFeedbackField(body.PageURL, feedbackMaxURLBytes)
	body.OriginHost = cutFeedbackField(body.OriginHost, feedbackMaxHostBytes)
	body.ElementSelector = cutFeedbackField(body.ElementSelector, feedbackMaxSelectorBytes)
	return body, true
}

// totalsLocked refreshes the table totals when they are older than
// feedbackTotalsMaxAge. A failed read keeps the previous numbers.
func (fi *feedbackIntake) totalsLocked(now time.Time) {
	if !fi.readAt.IsZero() && now.Sub(fi.readAt) < feedbackTotalsMaxAge {
		return
	}
	var open, shots int64
	if err := fi.app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_feedback WHERE status = 'open'`).Scan(&open); err != nil {
		return
	}
	if err := fi.app.DB.QueryRow(`SELECT COALESCE(SUM(length(screenshot)), 0) FROM _benmore_feedback WHERE screenshot IS NOT NULL`).Scan(&shots); err != nil {
		return
	}
	fi.openRows, fi.shotBytes, fi.readAt = open, shots, now
}

// store inserts one submission. full reports that the open-item ceiling
// refused it; shotDropped that it was kept without its screenshot.
func (fi *feedbackIntake) store(body *feedbackSubmission, host string) (id int64, full, shotDropped bool, err error) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	fi.totalsLocked(time.Now())
	if fi.openRows >= feedbackMaxOpenRows {
		return 0, true, false, nil
	}
	if body.Screenshot != "" && fi.shotBytes+int64(len(body.Screenshot)) > feedbackScreenshotBudget {
		body.Screenshot = ""
		shotDropped = true
	}
	result, err := fi.app.DB.Exec(
		`INSERT INTO _benmore_feedback (visitor_name, visitor_email, page_url, origin_host, body, element_selector, screenshot)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		body.Name, body.Email, body.PageURL, host, body.Body, body.ElementSelector, body.Screenshot)
	if err != nil {
		return 0, false, shotDropped, err
	}
	id, _ = result.LastInsertId()
	fi.openRows++
	fi.shotBytes += int64(len(body.Screenshot))
	return id, false, shotDropped, nil
}

// submit stores a decoded submission and answers the request. It returns the
// new row's id and the host recorded for it; ok is false when nothing was
// stored (the response is already written).
func (fi *feedbackIntake) submit(w http.ResponseWriter, r *http.Request, body *feedbackSubmission) (id int64, host string, ok bool) {
	host = cutFeedbackField(feedbackOriginHost(body.OriginHost, r), feedbackMaxHostBytes)
	id, full, shotDropped, err := fi.store(body, host)
	switch {
	case full:
		log.Printf("feedback refused: %d open items already stored (resolve or delete some to accept more)", feedbackMaxOpenRows)
		httpJSON(w, http.StatusTooManyRequests, map[string]any{"error": "the feedback inbox is full"})
		return 0, host, false
	case err != nil:
		serverErrorJSON(w, r, fi.app, "_feedback", err, "failed to save")
		return 0, host, false
	}
	resp := map[string]any{"id": id, "status": "submitted"}
	if shotDropped {
		resp["screenshot"] = "not stored: the screenshot space for feedback is full"
	}
	httpJSON(w, http.StatusOK, resp)
	return id, host, true
}
