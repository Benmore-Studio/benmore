//go:build !cli

package main

import (
	"log"
	"path/filepath"
	"time"
)

// Log phase boundaries before potentially slow work so a still-starting
// process can be distinguished from one that has stopped making progress.
// Do not log configuration, SQL, credentials, or application records here.
type appLoadTrace struct {
	app     string
	current string
	started time.Time
	phaseAt time.Time
}

func newAppLoadTrace(dir string) *appLoadTrace {
	return &appLoadTrace{app: filepath.Base(dir), started: time.Now()}
}

func (t *appLoadTrace) phase(name string) {
	if t.current != "" {
		log.Printf("app load: app=%q phase=%s status=complete elapsed=%s", t.app, t.current, time.Since(t.phaseAt).Round(time.Millisecond))
	}
	t.current, t.phaseAt = name, time.Now()
	log.Printf("app load: app=%q phase=%s status=started", t.app, name)
}

func (t *appLoadTrace) finish(err error) {
	status := "complete"
	if err != nil {
		status = "failed"
	}
	log.Printf("app load: app=%q phase=%s status=%s elapsed=%s total=%s", t.app, t.current, status,
		time.Since(t.phaseAt).Round(time.Millisecond), time.Since(t.started).Round(time.Millisecond))
}
