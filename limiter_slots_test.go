//go:build !cli

package main

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// holdEverySlotWait bounds how long holdEverySlot waits for goroutines left
// running by earlier tests. The longest one known is a compute run abandoned
// inside a backtracking regex match (computeRegexMatchTimeout).
const holdEverySlotWait = time.Minute

// holdEverySlot makes the calling test the only holder of a limiter channel:
// it sends cap(slots) tokens of its own and returns a function that takes
// them back (it also runs at test cleanup).
//
// The process-wide limiters are shared by every test in the package and their
// tokens are anonymous. Topping a channel up until it is full counts tokens
// still held by goroutines that an earlier test, or an earlier call in the
// same test, left running; when one of those finishes it takes a token out, a
// slot is free again and the call under test gets through. Sending exactly
// cap(slots) tokens instead blocks until those holders have released, and
// once the last send lands the channel holds cap(slots) tokens that are all
// the test's own: nothing else can free a slot before release.
func holdEverySlot(t *testing.T, slots chan struct{}) (release func()) {
	t.Helper()
	deadline := time.NewTimer(holdEverySlotWait)
	defer deadline.Stop()
	for held := 0; held < cap(slots); held++ {
		select {
		case slots <- struct{}{}:
		case <-deadline.C:
			for i := 0; i < held; i++ {
				<-slots
			}
			t.Fatalf("%d of %d slots still held by goroutines from earlier tests after %s", cap(slots)-held, cap(slots), holdEverySlotWait)
		}
	}
	var once sync.Once
	release = func() {
		once.Do(func() {
			for i := 0; i < cap(slots); i++ {
				<-slots
			}
		})
	}
	t.Cleanup(release)
	return release
}

// A goroutine that still holds a slot when the test starts must have let go
// before the test counts every slot as held: otherwise its release frees a
// slot in the middle of the test.
func TestHoldEverySlotWaitsForEarlierHolders(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const earlierHolderRuns = 10 * time.Second
		slots := make(chan struct{}, 2)
		slots <- struct{}{}
		go func() {
			select {
			case <-time.After(earlierHolderRuns):
			case <-t.Context().Done():
			}
			<-slots
		}()
		start := time.Now()
		release := holdEverySlot(t, slots)
		if waited := time.Since(start); waited != earlierHolderRuns {
			t.Fatalf("slots counted as held after %s, while an earlier goroutine keeps one for %s", waited, earlierHolderRuns)
		}
		if len(slots) != cap(slots) {
			t.Fatalf("holding %d of %d slots", len(slots), cap(slots))
		}
		select {
		case slots <- struct{}{}:
			t.Fatal("a slot was free while every slot is held")
		default:
		}
		release()
		release()
		if len(slots) != 0 {
			t.Fatalf("%d slots still held after release", len(slots))
		}
	})
}
