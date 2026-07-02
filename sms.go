//go:build !cli

package main

import (
	"os"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// smsRateLimit tracks per-phone send counts to prevent abuse.
// Max 5 SMS per phone per 10 minutes.
var smsRateLimit = struct {
	mu    sync.Mutex
	sends map[string][]time.Time // phone → timestamps
}{sends: make(map[string][]time.Time)}

func checkSMSRateLimit(phone string) error {
	smsRateLimit.mu.Lock()
	defer smsRateLimit.mu.Unlock()

	window := 10 * time.Minute
	maxSends := 5
	cutoff := time.Now().Add(-window)

	// Prune old entries
	var recent []time.Time
	for _, t := range smsRateLimit.sends[phone] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	smsRateLimit.sends[phone] = recent

	if len(recent) >= maxSends {
		return fmt.Errorf("SMS rate limit exceeded for %s (max %d per %s)", phone, maxSends, window)
	}

	smsRateLimit.sends[phone] = append(recent, time.Now())
	return nil
}

// SendSMS sends a text message using the configured SMS provider.
// Provider is configured via environment variables:
//
//	SMS_PROVIDER=twilio|webhook (default: webhook if SMS_WEBHOOK_URL set, twilio if SMS_ACCOUNT_SID set)
//	SMS_FROM=+1234567890
//
// For Twilio:
//
//	SMS_ACCOUNT_SID=ACxxx
//	SMS_AUTH_TOKEN=xxx
//
// For generic webhook (any provider):
//
//	SMS_WEBHOOK_URL=https://api.provider.com/sms/send
//	SMS_WEBHOOK_AUTH=Bearer xxx (optional auth header)
//
// The webhook mode POSTs JSON: {"to": "+1...", "body": "message", "from": "+1..."}
// This lets developers use Vonage, MessageBird, AWS SNS, or any HTTP-based SMS API.
// smsNormalizePhone strips spaces, dashes, parens and dots, keeping a single
// optional leading '+', so format variants collapse to one canonical key.
func smsNormalizePhone(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for i, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else if r == '+' && i == 0 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// smsValidE164 reports whether s is a plausible E.164 number: optional '+'
// then 8-15 digits, first digit non-zero.
func smsValidE164(s string) bool {
	d := strings.TrimPrefix(s, "+")
	if len(d) < 8 || len(d) > 15 || d[0] == '0' {
		return false
	}
	for _, r := range d {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func SendSMS(appDir, to, body string) error {
	// Normalize + validate to E.164 BEFORE the rate-limit check, so format
	// variants ("+1 555…", "1-555…") collapse to one bucket (each variant was
	// previously a distinct key, bypassing the cap) and garbage / bad-length
	// numbers are rejected before we bill the provider.
	to = smsNormalizePhone(to)
	if !smsValidE164(to) {
		return fmt.Errorf("invalid recipient phone number (expected E.164, e.g. +14155551234)")
	}
	// Rate limit: max 5 SMS per phone per 10 minutes
	if err := checkSMSRateLimit(to); err != nil {
		log.Printf("SMS BLOCKED: %s", err)
		return err
	}

	from := GetEnv(appDir, "SMS_FROM")
	provider := GetEnv(appDir, "SMS_PROVIDER")

	// Auto-detect provider from env vars if not explicitly set
	if provider == "" {
		if GetEnv(appDir, "SMS_ACCOUNT_SID") != "" {
			provider = "twilio"
		} else if GetEnv(appDir, "SMS_WEBHOOK_URL") != "" {
			provider = "webhook"
		}
	}

	switch provider {
	case "twilio":
		return sendSMSTwilio(appDir, to, body, from)
	case "webhook":
		return sendSMSWebhook(appDir, to, body, from)
	default:
		if provider == "" && smsGatewayReachable() {
			// Platform SMS gateway (v2.7.199): on the hosted platform,
			// apps with NO explicit provider send through the router's
			// AWS End User Messaging broker - zero config, from the
			// shared platform toll-free number (or the app's dedicated
			// number once carrier-approved). Explicit providers above
			// always win; self-hosted has no socket and errors as before.
			resp, gerr := requestGatewaySMSSend(smsGatewayReq{
				To:   to,
				Body: body,
				App:  os.Getenv("BENMORE_APP_NAME"),
			})
			if gerr != nil {
				log.Printf("SMS [platform gateway failed] to=%s: %s", to, gerr)
				return gerr
			}
			log.Printf("SMS [sent via platform] to=%s from=%s id=%s", to, resp.From, resp.MessageID)
			return nil
		}
		if provider == "" {
			// Return an explicit error rather than logging + nil.
			// Pre-fix behavior masked phone-OTP failures: the auth
			// handler thought SendSMS succeeded so it'd redirect the
			// user to /verify-otp with no code in their inbox. The
			// hooks/flows path made the same call look like a no-op
			// when in fact nothing went out the door.
			log.Printf("SMS [not sent - no provider configured] to=%s", to)
			return fmt.Errorf("SMS not delivered: no provider configured. " +
				"Set SMS_ACCOUNT_SID + SMS_AUTH_TOKEN (Twilio - buy a number at " +
				"https://www.twilio.com/console; trial accounts can only send to " +
				"manually-verified numbers) or SMS_WEBHOOK_URL (any HTTP-based SMS " +
				"API - Vonage, MessageBird, AWS SNS) in env.yaml or your " +
				"environment. " +
				"For production US traffic you'll also need a custom domain " +
				"registered with carriers for A2P 10DLC compliance - Twilio's " +
				"console walks you through it after the first paid number is bought.")
		}
		return fmt.Errorf("unknown SMS provider: %s", provider)
	}
}

// sendSMSTwilio sends via the Twilio REST API.
func sendSMSTwilio(appDir, to, body, from string) error {
	sid := GetEnv(appDir, "SMS_ACCOUNT_SID")
	token := GetEnv(appDir, "SMS_AUTH_TOKEN")
	if sid == "" || token == "" {
		return fmt.Errorf("SMS_ACCOUNT_SID and SMS_AUTH_TOKEN required for Twilio")
	}

	apiURL := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", sid)
	data := url.Values{}
	data.Set("To", to)
	data.Set("Body", body)
	if from != "" {
		data.Set("From", from)
	}

	req, _ := http.NewRequest("POST", apiURL, strings.NewReader(data.Encode()))
	req.SetBasicAuth(sid, token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("twilio request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("twilio error %d: %s", resp.StatusCode, string(respBody))
	}

	log.Printf("SMS: sent to %s via Twilio", to)
	return nil
}

// sendSMSWebhook sends via a generic webhook - works with any HTTP-based SMS API.
// POSTs JSON: {"to": "+1...", "body": "Your code is 123456", "from": "+1..."}
func sendSMSWebhook(appDir, to, body, from string) error {
	webhookURL := GetEnv(appDir, "SMS_WEBHOOK_URL")
	if webhookURL == "" {
		return fmt.Errorf("SMS_WEBHOOK_URL required for webhook SMS provider")
	}

	payload, _ := json.Marshal(map[string]string{
		"to":   to,
		"body": body,
		"from": from,
	})

	req, _ := http.NewRequest("POST", webhookURL, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	// Optional auth header
	if auth := GetEnv(appDir, "SMS_WEBHOOK_AUTH"); auth != "" {
		req.Header.Set("Authorization", auth)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("SMS webhook failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("SMS webhook error %d: %s", resp.StatusCode, string(respBody))
	}

	log.Printf("SMS: sent to %s via webhook", to)
	return nil
}
