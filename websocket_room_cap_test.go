//go:build !cli

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// wsTestTextFrame is a masked client text frame (zero mask key).
func wsTestTextFrame(payload string) []byte {
	return append([]byte{0x80 | wsOpText, 0x80 | byte(len(payload)), 0, 0, 0, 0}, payload...)
}

// A connection could join rooms without limit: every join of a new name
// added an entry to client.rooms for as long as the socket lived, so one
// anonymous or signed-in socket grew the process's memory at the message
// rate (20 joins a second) until the app hit its memory ceiling. A
// connection now holds a bounded number of rooms; a join past it is refused
// with an error frame, and rooms already joined keep working.
func TestWSJoinBoundsRoomsPerConnection(t *testing.T) {
	resetWSHub(t)
	srv, cli := net.Pipe()
	defer cli.Close()
	client := &wsClient{ws: &wsConn{conn: srv, br: bufio.NewReader(srv)}, send: make(chan []byte, 8),
		appID: "roomcap", userID: 1, subscriptions: map[string]bool{}, rooms: map[string]bool{}}
	const held = 5000
	for i := 0; i < held; i++ {
		client.rooms[scopedRoomID(client, fmt.Sprintf("held-%d", i))] = true
	}
	go io.Copy(io.Discard, cli)
	done := make(chan struct{})
	go func() { wsReadLoop(client, &App{}); close(done) }()
	join := func(room string) {
		msg, _ := json.Marshal(wsClientMsg{Type: "join", Room: room})
		if _, err := cli.Write(wsTestTextFrame(string(msg))); err != nil {
			t.Fatal(err)
		}
	}
	nextError := func() string {
		select {
		case b := <-client.send:
			return string(b)
		case <-time.After(2 * time.Second):
			return ""
		}
	}

	join("one-more")
	if got := nextError(); !strings.Contains(got, `"type":"error"`) || !strings.Contains(got, "one-more") {
		t.Errorf("join past the room limit answered %q, want an error frame", got)
	}
	join("held-7") // already joined: not a new room
	cli.Close()
	<-done
	client.subMu.RLock()
	defer client.subMu.RUnlock()
	if client.rooms[scopedRoomID(client, "one-more")] || len(client.rooms) != held {
		t.Fatalf("connection holds %d rooms after a join past the limit, want %d", len(client.rooms), held)
	}
}

// A connection under the limit still joins and receives room messages.
func TestWSJoinUnderRoomLimitStillWorks(t *testing.T) {
	resetWSHub(t)
	srv, cli := net.Pipe()
	defer cli.Close()
	client := &wsClient{ws: &wsConn{conn: srv, br: bufio.NewReader(srv)}, send: make(chan []byte, 8),
		appID: "roomcap", userID: 1, subscriptions: map[string]bool{}, rooms: map[string]bool{}}
	go io.Copy(io.Discard, cli)
	done := make(chan struct{})
	go func() { wsReadLoop(client, &App{}); close(done) }()
	for _, room := range []string{"lobby", "huddle-1", "huddle-2"} {
		msg, _ := json.Marshal(wsClientMsg{Type: "join", Room: room})
		cli.Write(wsTestTextFrame(string(msg)))
	}
	cli.Close()
	<-done
	if len(client.rooms) != 3 {
		t.Fatalf("connection joined %d rooms, want 3", len(client.rooms))
	}
}
