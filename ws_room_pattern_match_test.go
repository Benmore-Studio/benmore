//go:build !cli

package main

import (
	"strings"
	"testing"
)

// legacyMatchWSRoomPattern is the matcher as it was: the first ':' starts the
// placeholder.
func legacyMatchWSRoomPattern(pattern, room string) (val string, ok bool) {
	i := strings.IndexByte(pattern, ':')
	if i < 0 {
		return "", pattern == room
	}
	j := i + 1
	for j < len(pattern) && (pattern[j] == '_' ||
		(pattern[j] >= 'a' && pattern[j] <= 'z') ||
		(pattern[j] >= 'A' && pattern[j] <= 'Z') ||
		(pattern[j] >= '0' && pattern[j] <= '9')) {
		j++
	}
	prefix, suffix := pattern[:i], pattern[j:]
	if len(room) <= len(prefix)+len(suffix) ||
		!strings.HasPrefix(room, prefix) || !strings.HasSuffix(room, suffix) {
		return "", false
	}
	return room[len(prefix) : len(room)-len(suffix)], true
}

// Every pattern that was usable before (a literal name, or one ':' and no
// '*') matches exactly the rooms it matched, with the same join value.
func TestExistingWSRoomPatternsMatchUnchanged(t *testing.T) {
	patterns := []string{
		"lobby", "vip", "room-:id", "room-:room_id", "squad-room-:id", "project-:id-chat", "chat/:slug/feed",
		":id", ":id-notes", "room-:", "chat:", "a.b_c-:x.y", "ROOM-:Id", "room-:id-", "x:y",
	}
	rooms := []string{
		"", "lobby", "lobby2", "vip", "room-", "room-42", "room-42-", "room-a1b2", "room-:id", "squad-room-a1b2",
		"project-7-chat", "project--chat", "project-7", "chat/general/feed", "chat/general", "42", "42-notes", "-notes",
		"chat:5", "chat5", "chat:", "a.b_c-9.y", "ROOM-9", "x9", "x:9", "x", "room-:", "chat:42:x",
	}
	for _, pattern := range patterns {
		if _, problem := parseWSRoomPattern(pattern); problem != "" {
			t.Errorf("%q was a usable pattern and is now refused: %s", pattern, problem)
		}
		for _, room := range rooms {
			wantVal, wantOK := legacyMatchWSRoomPattern(pattern, room)
			if val, ok := matchWSRoomPattern(pattern, room); ok != wantOK || val != wantVal {
				t.Errorf("matchWSRoomPattern(%q, %q) = (%q, %v), was (%q, %v)", pattern, room, val, ok, wantVal, wantOK)
			}
		}
	}
	// The one new shape: a literal ':' directly before the placeholder.
	for _, tc := range []struct {
		pattern, room, val string
		ok                 bool
	}{
		{"chat::id", "chat:42", "42", true},
		{"chat::id", "chat:", "", false},
		{"chat::id", "chat42", "", false},
		{"chat::id", "chat5:id", "", false},
		{"org.chat::id-feed", "org.chat:42-feed", "42", true},
		{"::id", ":42", "42", true},
	} {
		if val, ok := matchWSRoomPattern(tc.pattern, tc.room); ok != tc.ok || val != tc.val {
			t.Errorf("matchWSRoomPattern(%q, %q) = (%q, %v), want (%q, %v)", tc.pattern, tc.room, val, ok, tc.val, tc.ok)
		}
	}
	// An unusable pattern matches nothing (its rooms are closed instead).
	for _, pattern := range []string{"chat:*", "room-*", "*", "a-:x-:y", "chat:room-:id", "chat:::id", ""} {
		if _, problem := parseWSRoomPattern(pattern); problem == "" {
			t.Errorf("%q is accepted as a usable pattern", pattern)
		}
		for _, room := range rooms {
			if _, ok := matchWSRoomPattern(pattern, room); ok {
				t.Errorf("unusable pattern %q matched room %q", pattern, room)
			}
		}
	}
}
