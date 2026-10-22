//go:build !cli && !windows

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A failed session read is not a denial: it classifies as unavailable_provider
// (503 on the page), while an absent session stays an honest refusal.
func TestAppMCPCommandSessionAuthoritySeparatesFailureFromDenial(t *testing.T) {
	h := newExposureHarness(t)
	generation := snapshotAppMCPGeneration(h.app)
	tool, _, err := appMCPFindCommandDeclaration(generation, "complete_item")
	if err != nil {
		t.Fatal(err)
	}
	stored := GetSessionFromDB(h.app.DB, h.cookie)
	tx, err := h.app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := appMCPCommandSessionAuthority(context.Background(), generation, tx, stored.ID, tool); err != nil {
		t.Fatalf("live session: %v", err)
	}
	absent := "sha256:" + strings.Repeat("0", 64)
	if _, _, _, err := appMCPCommandSessionAuthority(context.Background(), generation, tx, absent, tool); !errors.Is(err, errAppMCPGrantDenied) {
		t.Fatalf("absent session: %v, want denial", err)
	}
	if err := tx.Rollback(); err != nil { // a finished transaction stands in for a failing store
		t.Fatal(err)
	}
	_, _, _, err = appMCPCommandSessionAuthority(context.Background(), generation, tx, stored.ID, tool)
	if err == nil || errors.Is(err, errAppMCPGrantDenied) || appMCPCommandErrorClass(err) != "unavailable_provider" {
		t.Fatalf("database failure: %v class %q, want a non-denial unavailable_provider", err, appMCPCommandErrorClass(err))
	}
	// The boolean helper keeps its behavior for other callers.
	if loadStoredSessionWith(h.app.DB, false, stored.ID) == nil {
		t.Fatal("boolean loader lost a live session")
	}
	if s, err := loadStoredSessionChecked(tx, false, stored.ID); s != nil || err == nil {
		t.Fatalf("checked loader folded a failure: %v %v", s, err)
	}
}

// The remaining reads in the authority check also separate failure from
// denial: a cancelled context and a failed actor load are not "denied", while
// an actor row that is simply absent still is.
func TestAppMCPCommandSessionAuthorityActorAndContextFailures(t *testing.T) {
	h := newExposureHarness(t)
	generation := snapshotAppMCPGeneration(h.app)
	tool, _, err := appMCPFindCommandDeclaration(generation, "complete_item")
	if err != nil {
		t.Fatal(err)
	}
	stored := GetSessionFromDB(h.app.DB, h.cookie)
	tx, err := h.app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, err = appMCPCommandSessionAuthority(cancelled, generation, tx, stored.ID, tool)
	if err == nil || errors.Is(err, errAppMCPGrantDenied) || appMCPCommandErrorClass(err) != "unavailable_provider" {
		t.Fatalf("cancelled context: %v class %q", err, appMCPCommandErrorClass(err))
	}

	// An absent user is a denial; a failed read of the actor is not.
	if _, err := loadScheduledActorWith(generation.view, tx, 987654, nil, true); err == nil || errors.As(err, new(*scheduledActorReadError)) {
		t.Fatalf("absent actor must stay a plain denial: %v", err)
	}
	_ = tx.Rollback() // the pool holds one connection
	finished, err := h.app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := finished.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := loadScheduledActorWith(generation.view, finished, stored.UserID, nil, true); !errors.As(err, new(*scheduledActorReadError)) {
		t.Fatalf("failed actor read must be a read failure: %v", err)
	}
}
