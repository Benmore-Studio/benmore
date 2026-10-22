//go:build !cli

package main

// Naming people in auth log lines.
//
// Server logs are read by operators, shipped to log stores and pasted into
// tickets, so a line about a failed code or a refused sign-in must not carry
// the person's email address or phone number. A line names the account by its
// user id when there is one; when there is none (a refused OAuth sign-in, a
// reset mail) it carries logAddressRef, and a transport error is passed
// through logSendError because mail and SMS providers quote the recipient in
// their error text. The mail and SMS senders themselves (email.go, sms.go)
// and the CLI sign-in paths follow the same rule.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// logAddressRef is a short keyed digest of an address or phone number:
// stable within one deployment, so lines about the same recipient can be
// correlated, and not reversible without the server secret.
func logAddressRef(addr string) string {
	a := strings.ToLower(strings.TrimSpace(addr))
	if a == "" {
		return "addr#none"
	}
	mac := hmac.New(sha256.New, []byte(serverSecret))
	mac.Write([]byte("benmore-log-ref\x00"))
	mac.Write([]byte(a))
	return "addr#" + hex.EncodeToString(mac.Sum(nil))[:12]
}

// logRecipientsRef is logAddressRef for a To: value, which may list several
// recipients separated by commas: one reference each, in order.
func logRecipientsRef(to string) string {
	var refs []string
	for _, a := range strings.Split(to, ",") {
		if a = strings.TrimSpace(a); a != "" {
			refs = append(refs, logAddressRef(a))
		}
	}
	if len(refs) == 0 {
		return logAddressRef("")
	}
	return strings.Join(refs, ",")
}

// logSendErrorRecipients is logSendError for a To: value that may list
// several recipients.
func logSendErrorRecipients(err error, to string) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	for _, a := range strings.Split(to, ",") {
		if a = strings.TrimSpace(a); a != "" {
			msg = logSendError(errors.New(msg), a)
		}
	}
	return msg
}

// logSendError is a delivery error's text with the recipient replaced by its
// logAddressRef.
func logSendError(err error, recipient string) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	recipient = strings.TrimSpace(recipient)
	if recipient == "" {
		return msg
	}
	ref := logAddressRef(recipient)
	lower, needle := strings.ToLower(msg), strings.ToLower(recipient)
	var b strings.Builder
	for {
		i := strings.Index(lower, needle)
		if i < 0 {
			b.WriteString(msg)
			return b.String()
		}
		b.WriteString(msg[:i])
		b.WriteString(ref)
		msg, lower = msg[i+len(needle):], lower[i+len(needle):]
	}
}
