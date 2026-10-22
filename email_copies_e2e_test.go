//go:build !cli

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"net/mail"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const copiesFlow = `on:
  request: { method: POST, path: /api/mail }
jobs:
  send:
    steps:
      - run: email
        with:
          to: "${{ params.to }}"
          cc: "${{ params.cc }}"
          bcc: "${{ params.bcc }}"
          subject: "${{ params.subject | default:'Workflow notice' }}"
          text: "Review is ready."
          unsubscribe_url: "${{ params.unsubscribe_url | default:'' }}"
          unsubscribe_one_click: "${{ params.one_click | default:false }}"
      - run: respond
        with: { status: 200, body: { ok: true } }
`

type smtpReceipt struct {
	recipients []string
	message    []byte
	err        error
}

func captureSMTP(t *testing.T, app *App) <-chan smtpReceipt {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	SetAppEnv(app.Dir, "SMTP_HOST", host)
	SetAppEnv(app.Dir, "SMTP_PORT", port)
	SetAppEnv(app.Dir, "SMTP_USER", "sender@fixturemail.net")
	SetAppEnv(app.Dir, "SMTP_PASS", "fixture-only")
	SetAppEnv(app.Dir, "SMTP_FROM", "Workflow <sender@fixturemail.net>")
	t.Setenv("BENMORE_EMAIL_SOCKET", app.Dir+"/absent-socket")
	t.Setenv("BENMORE_APP_NAME", "")
	done := make(chan smtpReceipt, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- smtpReceipt{err: err}
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := textproto.NewReader(bufio.NewReader(conn))
		var receipt smtpReceipt
		fmt.Fprint(conn, "220 fixture SMTP\r\n")
		for {
			line, err := r.ReadLine()
			if err != nil {
				receipt.err = err
				done <- receipt
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO"):
				fmt.Fprint(conn, "250-fixture\r\n250 AUTH PLAIN\r\n")
			case strings.HasPrefix(line, "AUTH"):
				fmt.Fprint(conn, "235 authenticated\r\n")
			case strings.HasPrefix(line, "MAIL"):
				fmt.Fprint(conn, "250 OK\r\n")
			case strings.HasPrefix(line, "RCPT TO:"):
				receipt.recipients = append(receipt.recipients, strings.TrimPrefix(line, "RCPT TO:"))
				fmt.Fprint(conn, "250 OK\r\n")
			case line == "DATA":
				fmt.Fprint(conn, "354 continue\r\n")
				receipt.message, receipt.err = r.ReadDotBytes()
				fmt.Fprint(conn, "250 accepted\r\n")
			case line == "QUIT":
				fmt.Fprint(conn, "221 bye\r\n")
				done <- receipt
				return
			default:
				fmt.Fprint(conn, "500 unsupported\r\n")
			}
		}
	}()
	return done
}

// User story: an operator copies a colleague, privately copies records, and opts
// into one-click unsubscribe; actual SMTP receives all three but exposes only CC.
func TestEmailCopiesSMTPUserStory(t *testing.T) {
	for _, attachment := range []bool{false, true} {
		for _, oneClick := range []bool{false, true} {
			t.Run(fmt.Sprintf("attachment=%v/one_click=%v", attachment, oneClick), func(t *testing.T) {
				app, cleanup := newTestApp(t)
				defer cleanup()
				receipt := captureSMTP(t, app)
				flow := copiesFlow
				if attachment {
					flow = strings.Replace(flow, "          subject:", "          attachments:\n            - filename: notice.txt\n              content: aGVsbG8=\n          subject:", 1)
				}
				if problem := ValidateOnWriteIn(app.Dir, "flows/mail.yaml", flow); problem != "" {
					t.Fatalf("mail source refused: %s", problem)
				}
				unsubscribeURL := "https://app.fixturemail.net/unsubscribe?token=signed"
				cc, bcc := "colleague@fixturemail.net", "private@fixturemail.net"
				wantRecipients := "<reader@fixturemail.net>,<colleague@fixturemail.net>,<private@fixturemail.net>"
				if oneClick {
					cc, bcc = "", ""
					wantRecipients = "<reader@fixturemail.net>"
				}
				if !oneClick {
					unsubscribeURL += "#confirmation"
				}
				input, _ := json.Marshal(map[string]any{"to": "reader@fixturemail.net", "cc": cc, "bcc": bcc, "unsubscribe_url": unsubscribeURL, "one_click": oneClick})
				rr := runProbeGHAFlow(t, app, flow, string(input))
				if rr.Code != 200 {
					t.Fatalf("flow %d: %s", rr.Code, rr.Body.String())
				}
				got := <-receipt
				if got.err != nil {
					t.Fatal(got.err)
				}
				if strings.Join(got.recipients, ",") != wantRecipients {
					t.Fatalf("envelope recipients: %v", got.recipients)
				}
				msg, err := mail.ReadMessage(strings.NewReader(string(got.message)))
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(msg.Header.Get("Cc"), "colleague@fixturemail.net") == oneClick || strings.Contains(string(got.message), "private@fixturemail.net") || msg.Header.Get("Bcc") != "" {
					t.Fatal("CC header or BCC secrecy mismatch")
				}
				if (msg.Header.Get("List-Unsubscribe-Post") == "List-Unsubscribe=One-Click") != oneClick {
					t.Fatalf("wrong one-click header: %v", msg.Header)
				}
			})
		}
	}
}

// User story: request-controlled recipients cannot expand the authored audience.
func TestEmailCopiesRejectedBeforeDeliveryUserStory(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	sent := fakeEmailGateway(t)
	for _, replacement := range []struct{ old, bad string }{
		{`cc: "${{ params.cc }}"`, "cc: [reader@fixturemail.net]"},
		{`bcc: "${{ params.bcc }}"`, "bcc: 42"},
		{`unsubscribe_one_click: "${{ params.one_click | default:false }}"`, "unsubscribe_one_click: yes"},
	} {
		if problem := ValidateOnWriteIn(app.Dir, "flows/mail.yaml", strings.Replace(copiesFlow, replacement.old, replacement.bad, 1)); problem == "" {
			t.Fatalf("unsafe mail source accepted: %s", replacement.bad)
		}
	}
	for _, invalidURL := range []string{"https://app.fixturemail.net/u#token=signed", "https://person:secret@app.fixturemail.net/u"} {
		source := strings.Replace(copiesFlow, `unsubscribe_one_click: "${{ params.one_click | default:false }}"`, "unsubscribe_one_click: true", 1)
		source = strings.Replace(source, `unsubscribe_url: "${{ params.unsubscribe_url | default:'' }}"`, `unsubscribe_url: "`+invalidURL+`"`, 1)
		if problem := ValidateOnWriteIn(app.Dir, "flows/mail.yaml", source); problem == "" {
			t.Fatalf("unsafe one-click source accepted: %s", invalidURL)
		}
	}
	staticMulti := strings.Replace(copiesFlow, `unsubscribe_one_click: "${{ params.one_click | default:false }}"`, "unsubscribe_one_click: true", 1)
	staticMulti = strings.Replace(staticMulti, `to: "${{ params.to }}"`, "to: reader@fixturemail.net", 1)
	staticMulti = strings.Replace(staticMulti, `cc: "${{ params.cc }}"`, "cc: colleague@fixturemail.net", 1)
	staticMulti = strings.Replace(staticMulti, `bcc: "${{ params.bcc }}"`, "bcc: private@fixturemail.net", 1)
	if problem := ValidateOnWriteIn(app.Dir, "flows/mail.yaml", staticMulti); !strings.Contains(problem, "exactly one recipient") {
		t.Fatalf("static multi-recipient one-click source accepted: %s", problem)
	}
	for _, change := range []map[string]any{
		{"cc": "a@fixturemail.net,b@fixturemail.net"}, {"bcc": "a@fixturemail.net,b@fixturemail.net"},
		{"cc": "a@fixturemail.net\r\nBcc: outsider@fixturemail.net"},
		{"subject": "Notice\r\nBcc: outsider@fixturemail.net"},
		{"cc": strings.Repeat("a", 254) + "@fixturemail.net"},
		{"bcc": strings.Repeat("N", 510) + " <private@fixturemail.net>"},
		{"one_click": true, "unsubscribe_url": "http://app.fixturemail.net/u"},
		{"one_click": true, "unsubscribe_url": "https://app.fixturemail.net/u#token=signed"},
		{"one_click": true, "unsubscribe_url": "https://person:secret@app.fixturemail.net/u"},
		{"one_click": true, "unsubscribe_url": "https://:443/u"},
		{"one_click": true, "unsubscribe_url": ""}, {"one_click": "yes"},
	} {
		input := map[string]any{"to": "reader@fixturemail.net", "cc": "colleague@fixturemail.net", "bcc": "private@fixturemail.net", "one_click": false}
		for k, v := range change {
			input[k] = v
		}
		raw, _ := json.Marshal(input)
		rr := runProbeGHAFlow(t, app, copiesFlow, string(raw))
		if rr.Code < 400 {
			t.Fatalf("invalid request sent: %v => %d %s", change, rr.Code, rr.Body.String())
		}
	}
	input, _ := json.Marshal(map[string]any{"to": "reader@fixturemail.net", "cc": strings.TrimSuffix(strings.Repeat("copy@fixturemail.net,", 50), ","), "bcc": "private@fixturemail.net"})
	rr := runProbeGHAFlow(t, app, strings.Replace(copiesFlow, "params.cc }}", "params.cc | recipients }}", 1), string(input))
	if rr.Code < 400 {
		t.Fatal("combined recipient cap bypassed")
	}
	if len(sent()) != 0 {
		t.Fatal("rejected request reached gateway")
	}
}

func TestEmailCopiesLegacyFlowUserStory(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	receipt := captureSMTP(t, app)
	flows := parseFlows(`notice:
  trigger: POST /api/notice
  steps:
    - email:
      to: reader@fixturemail.net
      cc: colleague@fixturemail.net
      bcc: private@fixturemail.net
      subject: Workflow notice
      text: Review is ready.
      unsubscribe_url: https://app.fixturemail.net/u
      unsubscribe_one_click: false
    - respond:
      status: 200
      body: accepted
`)
	if len(flows) != 1 {
		t.Fatalf("legacy flow parse returned %d", len(flows))
	}
	req := httptest.NewRequest("POST", "/api/notice", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	executeFlowHTTP(app, &flows[0], rr, req)
	if rr.Code != 200 {
		t.Fatalf("legacy flow %d: %s", rr.Code, rr.Body.String())
	}
	got := <-receipt
	if got.err != nil {
		t.Fatal(got.err)
	}
	if len(got.recipients) != 3 || strings.Contains(string(got.message), "List-Unsubscribe-Post: List-Unsubscribe=One-Click") || strings.Contains(string(got.message), "private@fixturemail.net") {
		t.Fatalf("legacy transport lost fields: %v", got.recipients)
	}
}

// Existing root flows use the typed compatibility loader, distinct from the old
// line parser. Exercise the file that production loads through actual SMTP.
func TestEmailCopiesLoadedLegacyUserStory(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	receipt := captureSMTP(t, app)
	source := `notice:
  trigger: POST /api/notice
  steps:
    - email:
        to: reader@fixturemail.net
        cc: colleague@fixturemail.net
        bcc: private@fixturemail.net
        subject: Workflow notice
        text: Review is ready.
        unsubscribe_url: https://app.fixturemail.net/u
        unsubscribe_one_click: false
    - respond:
        status: 200
        body: accepted
`
	if err := os.WriteFile(filepath.Join(app.Dir, "flows.yaml"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	flows, err := loadFlowsChecked(app.Dir, true)
	if err != nil || len(flows) != 1 {
		t.Fatalf("legacy file load: %v (%d flows)", err, len(flows))
	}
	req := httptest.NewRequest("POST", "/api/notice", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	executeFlowHTTP(app, &flows[0], rr, req)
	if rr.Code != 200 {
		t.Fatalf("legacy file flow %d: %s", rr.Code, rr.Body.String())
	}
	got := <-receipt
	if got.err != nil {
		t.Fatal(got.err)
	}
	if len(got.recipients) != 3 || !strings.Contains(string(got.message), "Cc: colleague@fixturemail.net") || strings.Contains(string(got.message), "List-Unsubscribe-Post: List-Unsubscribe=One-Click") || strings.Contains(string(got.message), "private@fixturemail.net") {
		t.Fatalf("loaded legacy transport lost fields: %v", got.recipients)
	}
}

func TestEmailOneClickLegacyLoadersUserStory(t *testing.T) {
	for _, loaded := range []bool{false, true} {
		t.Run(fmt.Sprintf("typed_file=%v", loaded), func(t *testing.T) {
			app, cleanup := newTestApp(t)
			defer cleanup()
			receipt := captureSMTP(t, app)
			source := `notice:
  trigger: POST /api/notice
  steps:
    - email:
      to: reader@fixturemail.net
      subject: Workflow notice
      text: Review is ready.
      unsubscribe_url: https://app.fixturemail.net/u?token=reader-token
      unsubscribe_one_click: true
    - respond:
      status: 200
      body: accepted
`
			var flows []Flow
			if loaded {
				source = strings.ReplaceAll(source, "      ", "        ")
				if err := os.WriteFile(filepath.Join(app.Dir, "flows.yaml"), []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
				var err error
				flows, err = loadFlowsChecked(app.Dir, true)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				flows = parseFlows(source)
			}
			if len(flows) != 1 {
				t.Fatalf("flow count %d", len(flows))
			}
			req := httptest.NewRequest("POST", "/api/notice", strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			executeFlowHTTP(app, &flows[0], rr, req)
			if rr.Code != 200 {
				t.Fatalf("flow %d: %s", rr.Code, rr.Body.String())
			}
			got := <-receipt
			if got.err != nil {
				t.Fatal(got.err)
			}
			if len(got.recipients) != 1 || !strings.Contains(string(got.message), "List-Unsubscribe-Post: List-Unsubscribe=One-Click") {
				t.Fatalf("single-recipient one-click lost: %v", got.recipients)
			}
		})
	}
}
