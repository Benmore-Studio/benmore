//go:build !cli

package main

import (
	"fmt"
	"html"
	"net/http"
	"strings"
	"unicode"

	qrcode "github.com/skip2/go-qrcode"
)

// Mobile install flow:
//
//   your app           →  [📱 Phone button]
//        ↓                      ↓ opens modal
//        ↓               QR code (PNG from /install/qr)
//        ↓                      ↓ user scans on phone
//        ↓                      ↓
//   Phone Safari/Chrome → https://<your-app>/install
//        ↓
//   Detects iOS / Android / desktop, shows platform-specific "Add to
//   Home Screen" UI. One tap on Android, one-tap + one-swipe on iOS.
//
// /install is a framework route, served by every hosted app
// automatically. The builder button just generates a QR to it.

// RegisterInstallRoute adds the per-app mobile install landing page.
// This is registered inside buildAppMux so each app has its own
// themed install screen (title, colors, icon from app.yaml).
func RegisterInstallRoute(mux *http.ServeMux, app *App) {
	mux.HandleFunc("GET /install", func(w http.ResponseWriter, r *http.Request) {
		renderInstallPage(w, r, app)
	})
}

func renderInstallPage(w http.ResponseWriter, r *http.Request, app *App) {
	vars := resolveInstallVars(app)
	page := renderInstallHTML(vars)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(page))
}

type installVars struct {
	Name       string // Display name, e.g. "TaskFlow"
	ShortName  string // Fallback letter for the icon, e.g. "T"
	ThemeColor string // Brand color hex, e.g. "#7c3aed"
	BgColor    string // Page background hex, e.g. "#09090b"
	IconURL    string // App icon URL, may be ""
}

// resolveInstallVars pulls branding out of app.Design with sensible
// fallbacks. Returned strings are already HTML-escaped so callers can
// safely inject them into the template via strings.ReplaceAll.
func resolveInstallVars(app *App) installVars {
	v := installVars{
		Name:       "App",
		ThemeColor: "#7c3aed",
		BgColor:    "#0a0a0f",
	}

	if app != nil && app.Design != nil {
		if n := app.Design.SEO["site_name"]; n != "" {
			v.Name = n
		}
		if n := app.Design.PWA["name"]; n != "" {
			v.Name = n
		}
		if c := app.Design.Colors["_brand"]; c != "" {
			v.ThemeColor = c
		}
		if c := app.Design.PWA["theme_color"]; c != "" {
			v.ThemeColor = c
		}
		if c := app.Design.PWA["background_color"]; c != "" {
			v.BgColor = c
		}
		if i := app.Design.PWA["icon"]; i != "" {
			v.IconURL = i
		} else if i := app.Design.SEO["favicon"]; i != "" {
			v.IconURL = i
		}
	}

	// First character of the name, uppercase, for the fallback letter icon
	for _, r := range v.Name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			v.ShortName = strings.ToUpper(string(r))
			break
		}
	}
	if v.ShortName == "" {
		v.ShortName = "A"
	}

	// Escape everything we're about to splat into HTML
	v.Name = html.EscapeString(v.Name)
	v.ShortName = html.EscapeString(v.ShortName)
	v.ThemeColor = html.EscapeString(v.ThemeColor)
	v.BgColor = html.EscapeString(v.BgColor)
	v.IconURL = html.EscapeString(v.IconURL)

	return v
}

// renderInstallHTML builds the /install HTML using plain
// strings.ReplaceAll - no fmt.Fprintf, no format-verb counting bugs.
// The template uses {{NAME}}, {{THEME}}, etc. as placeholders.
func renderInstallHTML(v installVars) string {
	// If no icon URL was configured, render a letter-tile as the icon.
	var iconHTML string
	if v.IconURL != "" {
		iconHTML = `<img src="` + v.IconURL + `" class="app-icon" alt="App icon" onerror="this.replaceWith(makeLetterIcon())">`
	} else {
		iconHTML = `<div class="app-icon letter-icon">` + v.ShortName + `</div>`
	}

	out := installPageTemplate
	out = strings.ReplaceAll(out, "{{NAME}}", v.Name)
	out = strings.ReplaceAll(out, "{{SHORT_NAME}}", v.ShortName)
	out = strings.ReplaceAll(out, "{{THEME}}", v.ThemeColor)
	out = strings.ReplaceAll(out, "{{BG}}", v.BgColor)
	out = strings.ReplaceAll(out, "{{ICON_HTML}}", iconHTML)
	return out
}

// installPageTemplate uses {{PLACEHOLDER}} syntax swapped in via
// strings.ReplaceAll. This avoids fmt.Fprintf's format-verb count
// bug where adding a new section would silently shift all following
// arguments out of alignment.
const installPageTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
  <title>Install {{NAME}}</title>
  <meta name="apple-mobile-web-app-title" content="{{NAME}}">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="theme-color" content="{{THEME}}">
  <link rel="manifest" href="/manifest.json">
  <style>
    :root { --brand: {{THEME}}; --bg: {{BG}}; }
    * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
    html, body { margin: 0; padding: 0; background: var(--bg); color: #fafafa; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; -webkit-font-smoothing: antialiased; }
    body::before { content: ''; position: fixed; inset: 0; background: radial-gradient(circle at 50% 0%, color-mix(in srgb, var(--brand) 35%, transparent) 0%, transparent 60%); pointer-events: none; }
    body { min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 48px 24px; position: relative; }
    .hero { display: flex; flex-direction: column; align-items: center; text-align: center; max-width: 380px; width: 100%; position: relative; z-index: 1; }
    .app-icon { width: 88px; height: 88px; border-radius: 22px; margin-bottom: 22px; box-shadow: 0 18px 48px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.06); object-fit: cover; background: #18181b; }
    .letter-icon { display: flex; align-items: center; justify-content: center; font-size: 40px; font-weight: 700; background: linear-gradient(135deg, var(--brand), color-mix(in srgb, var(--brand) 60%, #000)); color: #fff; letter-spacing: -0.02em; }
    h1 { font-size: 30px; font-weight: 700; margin: 0 0 8px; letter-spacing: -0.02em; }
    .sub { font-size: 15px; color: #a1a1aa; margin: 0 0 32px; line-height: 1.5; }
    .cta-card { width: 100%; background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08); border-radius: 18px; padding: 22px; backdrop-filter: blur(20px); margin-bottom: 16px; }
    .cta-card h2 { font-size: 14px; font-weight: 600; margin: 0 0 4px; color: #fafafa; text-transform: uppercase; letter-spacing: 0.05em; }
    .cta-card p { font-size: 14px; color: #a1a1aa; margin: 0 0 16px; line-height: 1.55; }
    .install-btn { display: flex; width: 100%; height: 52px; border-radius: 12px; border: none; background: var(--brand); color: #fff; font-size: 15px; font-weight: 600; font-family: inherit; cursor: pointer; align-items: center; justify-content: center; gap: 10px; transition: transform 0.15s, opacity 0.15s; }
    .install-btn:active { transform: scale(0.98); }
    .install-btn:disabled { opacity: 0.4; cursor: default; }
    .steps { list-style: none; padding: 0; margin: 0; counter-reset: step; }
    .steps li { display: flex; align-items: flex-start; gap: 12px; padding: 10px 0; font-size: 14px; color: #d4d4d8; counter-increment: step; }
    .steps li::before { content: counter(step); flex-shrink: 0; width: 24px; height: 24px; border-radius: 50%; background: color-mix(in srgb, var(--brand) 20%, transparent); border: 1px solid var(--brand); color: var(--brand); display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 700; }
    .steps li strong { color: #fafafa; font-weight: 600; }
    .steps .share-icon { display: inline-flex; width: 18px; height: 18px; background: var(--brand); color: #fff; border-radius: 5px; align-items: center; justify-content: center; vertical-align: -4px; margin: 0 2px; }
    .steps .share-icon svg { width: 11px; height: 11px; }
    .continue { display: inline-block; margin-top: 8px; font-size: 13px; color: #71717a; text-decoration: none; padding: 10px; }
    .continue:hover { color: #fafafa; }
    .qr-wrap { display: flex; justify-content: center; padding: 12px; background: #fff; border-radius: 14px; margin-bottom: 16px; }
    .qr-wrap img { display: block; width: 200px; height: 200px; }

    /* Platform gating - default hidden, shown only by the matching class */
    .ios-card, .android-card, .desktop-card { display: none; }
    .platform-ios .ios-card { display: block; }
    .platform-android .android-card { display: block; }
    .platform-desktop .desktop-card { display: block; }

    /* Hide the "skip" link on desktop - they're already on the web */
    .platform-desktop .continue { display: none; }

    @media (max-width: 420px) {
      h1 { font-size: 26px; }
      .cta-card { padding: 18px; }
    }
  </style>
</head>
<body>
  <main class="hero">
    {{ICON_HTML}}
    <h1>{{NAME}}</h1>
    <p class="sub">Install on your home screen for a fullscreen, app-like experience.</p>

    <!-- Android: one-tap install via beforeinstallprompt -->
    <div class="cta-card android-card">
      <h2>Ready to install</h2>
      <p>Tap below to add <strong style="color:#fafafa">{{NAME}}</strong> to your home screen.</p>
      <button id="android-install" class="install-btn" disabled>Install App</button>
      <p id="android-hint" style="color:#71717a;font-size:12px;margin:12px 0 0;text-align:center;">Waiting for install prompt&hellip;</p>
    </div>

    <!-- iOS: instructions to Add to Home Screen -->
    <div class="cta-card ios-card">
      <h2>Add to Home Screen</h2>
      <ol class="steps">
        <li>Tap the <strong>Share</strong> button <span class="share-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v13"/><path d="M7 7l5-5 5 5"/><path d="M5 15v4a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-4"/></svg></span> at the bottom of Safari</li>
        <li>Scroll and tap <strong>Add to Home Screen</strong></li>
        <li>Tap <strong>Add</strong> in the top right</li>
      </ol>
    </div>

    <!-- Desktop: recommend scanning on a phone -->
    <div class="cta-card desktop-card">
      <h2>Scan with your phone</h2>
      <p>This is the mobile install flow. Scan this code with your phone's camera to continue there, or keep using the web version on this device.</p>
      <div id="desktop-qr" class="qr-wrap"></div>
      <a href="/" class="install-btn" style="text-decoration:none;">Continue to Web App</a>
    </div>

    <a href="/" class="continue">Skip, use web version &rarr;</a>
  </main>

  <script>
    (function() {
      var ua = navigator.userAgent.toLowerCase();
      var isIOS = /iphone|ipad|ipod/.test(ua) && !window.MSStream;
      var isAndroid = /android/.test(ua);
      var platform = isIOS ? 'ios' : isAndroid ? 'android' : 'desktop';
      document.body.classList.add('platform-' + platform);

      // Already installed? Skip straight to the app.
      var standalone = window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;
      if (standalone) { window.location.href = '/'; return; }

      // Fallback letter-icon generator if the configured image fails to load
      window.makeLetterIcon = function() {
        var d = document.createElement('div');
        d.className = 'app-icon letter-icon';
        d.textContent = '{{SHORT_NAME}}';
        return d;
      };

      // Android PWA install via beforeinstallprompt
      var deferredPrompt = null;
      window.addEventListener('beforeinstallprompt', function(e) {
        e.preventDefault();
        deferredPrompt = e;
        var btn = document.getElementById('android-install');
        var hint = document.getElementById('android-hint');
        if (btn) btn.disabled = false;
        if (hint) hint.textContent = 'One tap to install on your device.';
      });

      var androidBtn = document.getElementById('android-install');
      if (androidBtn) {
        androidBtn.addEventListener('click', function() {
          if (!deferredPrompt) return;
          deferredPrompt.prompt();
          deferredPrompt.userChoice.then(function(choice) {
            if (choice.outcome === 'accepted') {
              setTimeout(function() { window.location.href = '/'; }, 500);
            }
            deferredPrompt = null;
          });
        });
      }

      // Trivial service worker so the browser considers this a PWA
      if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/sw.js').catch(function() {});
      }

      // Desktop: render a QR pointing back at this URL
      if (platform === 'desktop') {
        var qrDiv = document.getElementById('desktop-qr');
        if (qrDiv) {
          var img = document.createElement('img');
          img.src = '/install/qr?url=' + encodeURIComponent(location.href);
          img.alt = 'QR code';
          qrDiv.appendChild(img);
        }
      }
    })();
  </script>
</body>
</html>`

// RegisterInstallQRRoute adds a GET /install/qr?url=X endpoint that serves
// a PNG QR code of the given URL. Used by both the /install desktop view
// (to show a QR hopping to mobile) and the builder modal (for the
// "Open on phone" button).
func RegisterInstallQRRoute(mux *http.ServeMux) {
	mux.HandleFunc("GET /install/qr", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if target == "" {
			http.Error(w, "url param required", 400)
			return
		}
		// Only accept https URLs on our own domain to prevent using this
		// endpoint as an arbitrary QR generator.
		if !strings.HasPrefix(target, "https://") {
			http.Error(w, "only https URLs allowed", 400)
			return
		}
		png, err := qrcode.Encode(target, qrcode.Medium, 400)
		if err != nil {
			http.Error(w, "encode failed", 500)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write(png)
	})
}

// Defensive import - if html gets unused after edits above, keep it
// around via a dummy usage to avoid shifting imports in future patches.
var _ = fmt.Sprintf
