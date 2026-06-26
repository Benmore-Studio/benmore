//go:build !cli

package main

// Centralized detection of which external integrations an app has wired,
// plus structured warnings for app.yaml configurations that depend on
// missing provider env vars.
//
// The framework was previously a patchwork of inline `GetEnv(...) != ""`
// checks scattered across email.go / sms.go / billing.go / oauth.go.
// Each had its own message and error style; some failed silently when
// not configured (sms.go returned nil), some surfaced clear errors
// (email.go), some just logged. The agent's first signal that
// "auth.otp: true won't work until you wire RESEND_API_KEY" came at
// runtime when a real user tried to sign up - too late.
//
// This file gives every caller one place to ask "does this app have X
// wired", plus a `ProviderGapWarnings(app)` that walks the app's auth
// config and returns plain-English warnings for any
// "feature-enabled-but-provider-missing" mismatch. Called from
// app validation (so the agent sees the gap before deploying) and at
// app load time (so operators see it in the systemd journal).
//
// External integrations the framework knows about:
//
//   Email   - Resend, Postmark, or generic SMTP
//   SMS     - Twilio or generic webhook
//   Stripe  - Billing
//   OAuth   - Per-provider <NAME>_CLIENT_ID + <NAME>_CLIENT_SECRET
//
// S3 uploads are detected too but don't get a warning - they're opt-in
// at the platform level, not driven from app.yaml, so there's no
// "you-configured-X-but-didn't-wire-Y" mismatch to detect.

import (
	"fmt"
	"sort"
	"strings"
)

// EmailProviderConfigured returns "resend", "postmark", "smtp", or ""
// when no email provider env vars are set for this app. The order
// matches SendEmail's preference: Resend first, then Postmark, then
// generic SMTP. Used so callers can include the provider name in
// messages - "send via Resend" reads better than a bool.
func EmailProviderConfigured(appDir string) string {
	if GetEnv(appDir, "RESEND_API_KEY") != "" {
		return "resend"
	}
	if GetEnv(appDir, "POSTMARK_SERVER_TOKEN") != "" {
		return "postmark"
	}
	if GetEnv(appDir, "SMTP_HOST") != "" {
		return "smtp"
	}
	return ""
}

// SMSProviderConfigured returns the SMS provider name in use, or ""
// when nothing is wired. Mirrors SendSMS's auto-detection (explicit
// SMS_PROVIDER wins; otherwise SMS_ACCOUNT_SID implies Twilio and
// SMS_WEBHOOK_URL implies the generic webhook path).
func SMSProviderConfigured(appDir string) string {
	if v := GetEnv(appDir, "SMS_PROVIDER"); v != "" {
		return v
	}
	if GetEnv(appDir, "SMS_ACCOUNT_SID") != "" {
		return "twilio"
	}
	if GetEnv(appDir, "SMS_WEBHOOK_URL") != "" {
		return "webhook"
	}
	return ""
}

// StripeConfigured returns true when both the API key and webhook
// secret env vars (the names of which the app may have overridden in
// app.yaml via auth.billing_api_key_env / auth.billing_webhook_secret_env)
// are set. Mirrors the resolution in billing.go's BillingConfig.
func StripeConfigured(appDir string, app *App) bool {
	apiKeyVar := "STRIPE_SECRET_KEY"
	webhookSecretVar := "STRIPE_WEBHOOK_SECRET"
	if app != nil && app.Design != nil {
		if v, ok := app.Design.Auth["billing_api_key_env"]; ok && v != "" {
			apiKeyVar = v
		}
		if v, ok := app.Design.Auth["billing_webhook_secret_env"]; ok && v != "" {
			webhookSecretVar = v
		}
	}
	return GetEnv(appDir, apiKeyVar) != "" && GetEnv(appDir, webhookSecretVar) != ""
}

// ConfiguredOAuthProviders returns the names of OAuth providers whose
// <NAME>_CLIENT_ID + <NAME>_CLIENT_SECRET env vars are BOTH set -
// i.e., the providers whose /auth/<name> routes will actually register
// at app startup (matches the gate at oauth.go:138). Sorted for
// deterministic output.
func ConfiguredOAuthProviders(appDir string) []string {
	out := []string{}
	for name := range oauthProviders {
		upper := strings.ToUpper(name)
		if GetEnv(appDir, upper+"_CLIENT_ID") != "" && GetEnv(appDir, upper+"_CLIENT_SECRET") != "" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// ProviderGapWarnings returns human-readable warnings for every
// app.yaml configuration that depends on a missing external provider.
// Returns nil when everything required is wired. Each message names
// the relevant env var(s), points the agent at the right setup link,
// and (where applicable) flags the custom-domain need for production
// deliverability - many providers will accept a generic sender for
// development but require a verified domain before live traffic
// flows.
//
// Severity: warnings, not errors. The app still loads and runs; the
// hook or flow that actually depends on the missing provider will
// fail loudly at runtime. This surface is the "spot the gap before
// you hit it" preview.
func ProviderGapWarnings(app *App) []string {
	if app == nil || app.Design == nil {
		return nil
	}
	var warns []string
	auth := app.Design.Auth
	identifier := auth["identifier"]

	// Email gap - verify_email or email-mode OTP requires an email provider.
	needsEmail := []string{}
	if auth["verify_email"] == "true" {
		needsEmail = append(needsEmail, "auth.verify_email: true")
	}
	if auth["otp"] == "true" && identifier != "phone" {
		needsEmail = append(needsEmail, "auth.otp: true")
	}
	if len(needsEmail) > 0 && EmailProviderConfigured(app.Dir) == "" {
		warns = append(warns, fmt.Sprintf(
			"%s requires an email provider, but none is configured. "+
				"Set RESEND_API_KEY (free tier: 3k/month at https://resend.com, no card required) "+
				"or POSTMARK_SERVER_TOKEN or SMTP_HOST+SMTP_USER+SMTP_PASS in env.yaml "+
				"or your environment. "+
				"For production you'll also need a custom domain verified with the provider - "+
				"without one, emails go from a generic sender (e.g. onboarding@resend.dev) "+
				"that Gmail and Outlook treat as untrusted, lowering inbox-placement rates.",
			strings.Join(needsEmail, " + "),
		))
	}

	// SMS gap - phone-OTP requires an SMS provider.
	if auth["otp"] == "true" && identifier == "phone" {
		if SMSProviderConfigured(app.Dir) == "" {
			warns = append(warns,
				"auth.otp: true with identifier: phone requires an SMS provider, "+
					"but none is configured. Set SMS_ACCOUNT_SID + SMS_AUTH_TOKEN "+
					"(Twilio - buy a number first at https://www.twilio.com/console) "+
					"or SMS_WEBHOOK_URL (generic HTTP POST to any provider - Vonage, "+
					"MessageBird, AWS SNS, etc.). Twilio trial accounts can only send "+
					"to numbers manually verified in the Twilio dashboard; production "+
					"needs a paid number, which also means a real domain to register "+
					"with carriers for A2P 10DLC compliance in the US.",
			)
		}
	}

	// Stripe gap - billing_provider: stripe requires both keys + a webhook.
	if auth["billing_provider"] == "stripe" {
		if !StripeConfigured(app.Dir, app) {
			warns = append(warns,
				"auth.billing_provider: stripe requires STRIPE_SECRET_KEY and "+
					"STRIPE_WEBHOOK_SECRET to be set. Get the keys at "+
					"https://dashboard.stripe.com/apikeys; register the webhook at "+
					"https://dashboard.stripe.com/webhooks with the endpoint "+
					"https://<your-domain>/api/_billing/webhook and copy the "+
					"signing secret. Test-mode keys work without a custom domain; "+
					"live keys assume a verified business domain on file with Stripe.",
			)
		}
	}

	// OAuth gap detection deliberately omitted - built-in providers
	// (google/github/microsoft) activate purely from <NAME>_CLIENT_ID +
	// _CLIENT_SECRET env vars; the `auth.oauth.<name>` block in app.yaml
	// has no effect for built-ins. There's no "declared but not wired"
	// mismatch to detect. Custom providers DO read from app.yaml's
	// top-level `oauth:` key (oauth.go:91) but route registration there
	// already fails noisily on missing client_id, so a separate warning
	// would be redundant.

	return warns
}
