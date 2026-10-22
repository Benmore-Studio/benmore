//go:build !cli

package main

// List-Unsubscribe-Post (RFC 8058 one-click) is sent only when the caller
// asks for it: it makes mail clients POST to the unsubscribe URL with no
// session, which only a URL built for that handles.

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fakeEmailGateway stands in for the platform email broker's socket and
// records each send request as JSON.
func fakeEmailGateway(t *testing.T) func() []map[string]any {
	t.Helper()
	dir, err := os.MkdirTemp("", "bmgw")
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "e.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BENMORE_EMAIL_SOCKET", sock)
	var mu sync.Mutex
	var got []map[string]any
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			data, _ := io.ReadAll(conn)
			var req map[string]any
			_ = json.Unmarshal(data, &req)
			mu.Lock()
			got = append(got, req)
			mu.Unlock()
			_, _ = conn.Write([]byte(`{"message_id":"m-1","from":"app@mail.example"}`))
			conn.Close()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		os.RemoveAll(dir)
	})
	return func() []map[string]any {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(got)
	}
}

// The raw MIME builder (SMTP and attachment sends) writes the one-click
// header only when asked: flow mail never asks.
func TestListUnsubscribePostOnlyWhenAsked(t *testing.T) {
	for _, oneClick := range []bool{false, true} {
		raw, err := buildRawMIMEMessage("from@example.com", "to@example.com", "", "s", "", "https://app.example.com/u", oneClick, "", "<p>x</p>", "",
			[]EmailAttachment{{Filename: "a.txt", Content: "aGVsbG8="}})
		if err != nil {
			t.Fatal(err)
		}
		msg := string(raw)
		if !strings.Contains(msg, "List-Unsubscribe: <https://app.example.com/u>\r\n") {
			t.Errorf("oneClick=%v: no List-Unsubscribe header", oneClick)
		}
		if got := strings.Contains(msg, "List-Unsubscribe-Post: List-Unsubscribe=One-Click"); got != oneClick {
			t.Errorf("oneClick=%v: List-Unsubscribe-Post present = %v", oneClick, got)
		}
	}
}
