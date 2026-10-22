//go:build !cli

package main

// One shared layout for every browser page of the app-facing MCP connector
// (#770): the workspace picker, the consent page, the single and batch review
// pages and every error. They all render through appMCPPageBase, so the app's
// name, favicon and theme colour appear everywhere and a refusal is a page a
// person can act on, not the browser's plain "404 page not found".
//
// Security shape, unchanged from the pages this replaces:
//   - CSP stays default-src 'none' + frame-ancestors 'none' + base-uri 'none'
//     and form-action 'self' (the consent page adds only its client's
//     registered redirect origin, which the browser applies to the redirect
//     after the POST). Inline CSS is admitted by sha256 hash, never
//     'unsafe-inline'; there is no script.
//   - The theme is the only per-app CSS. It is never copied from app config:
//     a configured colour is parsed (hex, rgb() or hsl() only), and the page
//     writes the parsed numbers back out as #rrggbb, so config text cannot
//     reach a stylesheet. Anything else falls back to the default.
//   - The favicon is linked only when it is a same-origin path, and only then
//     does the CSP gain img-src 'self'.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// ---- colours ---------------------------------------------------------------

type pageRGB struct{ r, g, b uint8 }

var (
	pageHexRe = regexp.MustCompile(`^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$`)
	pageRGBRe = regexp.MustCompile(`^rgb\(\s*(\d{1,3})\s*[, ]\s*(\d{1,3})\s*[, ]\s*(\d{1,3})\s*\)$`)
	pageHSLRe = regexp.MustCompile(`^hsl\(\s*(-?\d{1,3}(?:\.\d+)?)(?:deg)?\s*[, ]\s*(\d{1,3}(?:\.\d+)?)%\s*[, ]\s*(\d{1,3}(?:\.\d+)?)%\s*\)$`)
	// presetPrimaryRe reads the shadcn "H S% L%" triplets in css.go's
	// primaryVars, which are framework constants, not app input.
	presetPrimaryRe = regexp.MustCompile(`(?m)^\s*--primary:\s*([\d.]+)\s+([\d.]+)%\s+([\d.]+)%;`)
	presetOnRe      = regexp.MustCompile(`(?m)^\s*--primary-foreground:\s*([\d.]+)\s+([\d.]+)%\s+([\d.]+)%;`)
)

// parsePageColor accepts only an opaque #rgb/#rrggbb, rgb(r,g,b) or
// hsl(h,s%,l%) (commas or spaces) and reports false for everything else,
// including every value with a character that could end a declaration.
func parsePageColor(s string) (pageRGB, bool) {
	s = strings.TrimSpace(s)
	if len(s) > 64 {
		return pageRGB{}, false
	}
	if m := pageHexRe.FindStringSubmatch(s); m != nil {
		h := m[1]
		if len(h) == 3 {
			h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
		}
		n, _ := strconv.ParseUint(h, 16, 32)
		return pageRGB{uint8(n >> 16), uint8(n >> 8), uint8(n)}, true
	}
	if m := pageRGBRe.FindStringSubmatch(s); m != nil {
		var c [3]uint8
		for i := range c {
			n, _ := strconv.Atoi(m[i+1])
			if n > 255 {
				return pageRGB{}, false
			}
			c[i] = uint8(n)
		}
		return pageRGB{c[0], c[1], c[2]}, true
	}
	if m := pageHSLRe.FindStringSubmatch(s); m != nil {
		h, _ := strconv.ParseFloat(m[1], 64)
		sat, _ := strconv.ParseFloat(m[2], 64)
		l, _ := strconv.ParseFloat(m[3], 64)
		if sat > 100 || l > 100 {
			return pageRGB{}, false
		}
		return hslToPageRGB(h, sat, l), true
	}
	return pageRGB{}, false
}

func hslToPageRGB(h, s, l float64) pageRGB {
	h = math.Mod(math.Mod(h, 360)+360, 360) / 360
	s, l = s/100, l/100
	q := l * (1 + s)
	if l >= 0.5 {
		q = l + s - l*s
	}
	p := 2*l - q
	hue := func(t float64) float64 {
		t = math.Mod(t+1, 1)
		switch {
		case t < 1.0/6:
			return p + (q-p)*6*t
		case t < 0.5:
			return q
		case t < 2.0/3:
			return p + (q-p)*(2.0/3-t)*6
		}
		return p
	}
	to8 := func(v float64) uint8 { return uint8(math.Round(math.Max(0, math.Min(1, v)) * 255)) }
	if s == 0 {
		return pageRGB{to8(l), to8(l), to8(l)}
	}
	return pageRGB{to8(hue(h + 1.0/3)), to8(hue(h)), to8(hue(h - 1.0/3))}
}

func (c pageRGB) hex() string { return fmt.Sprintf("#%02x%02x%02x", c.r, c.g, c.b) }

// luminance is the WCAG relative luminance.
func (c pageRGB) luminance() float64 {
	lin := func(v uint8) float64 {
		f := float64(v) / 255
		if f <= 0.03928 {
			return f / 12.92
		}
		return math.Pow((f+0.055)/1.055, 2.4)
	}
	return 0.2126*lin(c.r) + 0.7152*lin(c.g) + 0.0722*lin(c.b)
}

// on is the text colour that reads best on c.
func (c pageRGB) on() pageRGB {
	if c.luminance() > 0.35 {
		return pageRGB{17, 19, 24}
	}
	return pageRGB{255, 255, 255}
}

func (c pageRGB) towardWhite(f float64) pageRGB {
	m := func(v uint8) uint8 { return uint8(math.Round(float64(v) + (255-float64(v))*f)) }
	return pageRGB{m(c.r), m(c.g), m(c.b)}
}

func (c pageRGB) ring() string {
	return fmt.Sprintf("rgba(%d,%d,%d,.45)", c.r, c.g, c.b)
}

// pagePresetColors returns the app's shadcn preset primary and its text colour
// for one scheme, from the framework's own tables.
func pagePresetColors(theme, scheme string) (primary, on pageRGB, ok bool) {
	vars := primaryVars[theme+"-"+scheme]
	pm, om := presetPrimaryRe.FindStringSubmatch(vars), presetOnRe.FindStringSubmatch(vars)
	if pm == nil || om == nil {
		return pageRGB{}, pageRGB{}, false
	}
	conv := func(m []string) pageRGB {
		h, _ := strconv.ParseFloat(m[1], 64)
		s, _ := strconv.ParseFloat(m[2], 64)
		l, _ := strconv.ParseFloat(m[3], 64)
		return hslToPageRGB(h, s, l)
	}
	return conv(pm), conv(om), true
}

// appMCPPageThemeCSS is the per-app custom-property block: the primary colour
// for buttons and accents in the light and dark scheme. Defaults to the zinc
// preset (near-black on light, near-white on dark), the framework's own default.
func appMCPPageThemeCSS(app *App) template.CSS {
	theme, brand := "zinc", ""
	if app != nil && app.Design != nil {
		if t := app.Design.Nav["theme"]; t != "" {
			theme = t
		}
		if t, ok := app.Design.Colors["_theme"]; ok && t != "" {
			theme = t
		}
		brand = app.Design.Colors["_brand"]
	}
	var light, dark [2]pageRGB // primary, text on primary
	for i, scheme := range []string{"light", "dark"} {
		p, on, ok := pagePresetColors(theme, scheme)
		if !ok {
			p, on, _ = pagePresetColors("zinc", scheme)
		}
		if i == 0 {
			light = [2]pageRGB{p, on}
		} else {
			dark = [2]pageRGB{p, on}
		}
	}
	if c, ok := parsePageColor(brand); ok {
		light = [2]pageRGB{c, c.on()}
		d := c
		if c.luminance() < 0.1 { // a very dark brand would vanish on the dark card
			d = c.towardWhite(0.45)
		}
		dark = [2]pageRGB{d, d.on()}
	}
	block := func(v [2]pageRGB) string {
		return "--primary:" + v[0].hex() + ";--on-primary:" + v[1].hex() + ";--ring:" + v[0].ring() + ";"
	}
	return template.CSS(":root{" + block(light) + "}@media (prefers-color-scheme:dark){:root{" + block(dark) + "}}")
}

// ---- styles ----------------------------------------------------------------

const appMCPPageBaseCSS = `*{box-sizing:border-box}
:root{color-scheme:light dark;--bg:#f3f4f7;--card:#fff;--text:#14161b;--muted:#5a6270;--border:#e2e5ea;--border-strong:#c7ccd4;--soft:#f6f7f9;--hl:#fff6dd;--hl-text:#6b4a00;--ok-bg:#e8f6ee;--ok-text:#0b5d33;--bad-bg:#fdecea;--bad-text:#9b1c12;--warn-bg:#fff6e0;--warn-text:#7a4b00;--shadow:0 1px 2px rgba(16,24,40,.05),0 12px 32px rgba(16,24,40,.07)}
@media (prefers-color-scheme:dark){:root{--bg:#0d0f12;--card:#16191e;--text:#eceef2;--muted:#9aa3b1;--border:#262b33;--border-strong:#3a414c;--soft:#1b1f25;--hl:#2a2410;--hl-text:#f3d98b;--ok-bg:#10281b;--ok-text:#7fdba4;--bad-bg:#2d1512;--bad-text:#ff9d93;--warn-bg:#2a2210;--warn-text:#f0cf7a;--shadow:0 1px 2px rgba(0,0,0,.4),0 12px 32px rgba(0,0,0,.35)}}
html{-webkit-text-size-adjust:100%}
body{margin:0;min-height:100vh;display:flex;flex-direction:column;align-items:center;background:var(--bg);color:var(--text);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;-webkit-font-smoothing:antialiased}
header,main,footer{width:100%;max-width:560px;padding-left:20px;padding-right:20px}
body.wide header,body.wide main,body.wide footer{max-width:780px}
header{display:flex;align-items:center;gap:12px;padding-top:36px;padding-bottom:20px}
.mark{flex:none;display:grid;place-items:center;width:38px;height:38px;border-radius:11px;overflow:hidden;background:var(--primary);color:var(--on-primary);font-weight:700;font-size:18px}
.mark img{width:100%;height:100%;object-fit:cover;display:block}
.appname{font-weight:650;font-size:18px;letter-spacing:-.01em;overflow-wrap:anywhere}
main{flex:1}
footer{padding-top:20px;padding-bottom:36px;color:var(--muted);font-size:14px}
a{color:inherit;text-underline-offset:3px}
.card{background:var(--card);border:1px solid var(--border);border-radius:18px;padding:32px;box-shadow:var(--shadow)}
.eyebrow{margin:0 0 6px;font-size:13px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
h1{margin:0 0 10px;font-size:24px;line-height:1.3;letter-spacing:-.02em;font-weight:650;overflow-wrap:anywhere}
h2{margin:28px 0 10px;font-size:13px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
p{margin:0 0 14px;overflow-wrap:anywhere}
.lead{font-size:17px;color:var(--muted)}
.muted{color:var(--muted)}
.small{font-size:14px}
code,pre{font:13px/1.55 ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace}
code{background:var(--soft);border:1px solid var(--border);border-radius:6px;padding:1px 6px;overflow-wrap:anywhere}
.meta{display:flex;flex-wrap:wrap;gap:6px 14px;margin:0 0 14px;font-size:14px;color:var(--muted)}
.meta span{overflow-wrap:anywhere}
pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:0 0 14px;padding:14px 16px;background:var(--soft);border:1px solid var(--border);border-radius:12px}
.pill{display:inline-block;margin:0 0 14px;padding:3px 12px;border-radius:999px;font-size:13px;font-weight:600;background:var(--soft);border:1px solid var(--border);color:var(--muted)}
.note{margin:0 0 14px;padding:12px 16px;border-radius:12px;font-size:15px;background:var(--soft);border:1px solid var(--border)}
.note.ok{background:var(--ok-bg);border-color:transparent;color:var(--ok-text)}
.note.bad{background:var(--bad-bg);border-color:transparent;color:var(--bad-text)}
.note.warn{background:var(--warn-bg);border-color:transparent;color:var(--warn-text)}
.facts{margin:20px 0 0;padding:0;border:1px solid var(--border);border-radius:12px;overflow:hidden}
.facts div{display:grid;grid-template-columns:150px 1fr;gap:12px;padding:12px 16px;border-top:1px solid var(--border)}
.facts div:first-child{border-top:0}
.facts+.note{margin-top:20px}
.facts dt{color:var(--muted);font-size:14px}
.facts dd{margin:0;overflow-wrap:anywhere}
.host{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px}
label{font-weight:600}
select{display:block;width:100%;min-height:46px;margin:8px 0 0;padding:0 12px;border-radius:10px;border:1px solid var(--border-strong);background:var(--card);color:var(--text);font:inherit}
.opt{display:flex;gap:12px;align-items:flex-start;margin:20px 0 0;padding:14px 16px;border:1px solid var(--border);border-radius:12px;background:var(--soft);font-weight:400}
.opt input,.pick input{flex:none;width:20px;height:20px;margin:2px 0 0;accent-color:var(--primary)}
.actions{display:flex;justify-content:flex-end;gap:12px;margin-top:26px}
.btn{display:inline-flex;align-items:center;justify-content:center;min-height:46px;padding:0 22px;border-radius:10px;border:1px solid transparent;font:inherit;font-weight:600;text-decoration:none;cursor:pointer;transition:background-color .12s,filter .12s}
.btn-primary{background:var(--primary);color:var(--on-primary)}
.btn-primary:hover{filter:brightness(1.1)}
.btn-secondary{background:transparent;color:var(--text);border-color:var(--border-strong)}
.btn-secondary:hover{background:var(--soft)}
.btn:focus-visible,a:focus-visible,select:focus-visible,input:focus-visible,summary:focus-visible{outline:3px solid var(--ring);outline-offset:2px}
.changes{width:100%;margin:0 0 14px;border-collapse:separate;border-spacing:0;border:1px solid var(--border);border-radius:12px;overflow:hidden;font-size:15px}
.changes th,.changes td{padding:10px 14px;text-align:left;vertical-align:top;border-top:1px solid var(--border);overflow-wrap:anywhere}
.changes thead th{border-top:0;background:var(--soft);font-size:12px;font-weight:600;letter-spacing:.05em;text-transform:uppercase;color:var(--muted)}
.changes tbody th{font-weight:600;width:28%}
.changes tr.changed td,.changes tr.changed th{background:var(--hl)}
.changes tr.changed td:last-child{font-weight:600}
.tag{display:block;width:max-content;margin-top:4px;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;background:var(--hl-text);color:var(--card)}
.none{color:var(--muted)}
details{margin:0 0 14px}
summary{cursor:pointer;color:var(--muted);font-size:14px}
ul{margin:0 0 14px;padding-left:20px}
li{margin:0 0 4px}
.item{margin:0 0 16px;padding:20px;border:1px solid var(--border);border-radius:14px}
.item-title{display:block;margin:0 0 4px;font-size:18px;line-height:1.35;font-weight:650;overflow-wrap:anywhere}
.pick{display:flex;gap:12px;align-items:flex-start;margin:0 0 10px;font-weight:400;cursor:pointer}
.pick input{margin-top:4px}
.errmark{display:grid;place-items:center;width:44px;height:44px;margin:0 0 16px;border-radius:12px;background:var(--soft);border:1px solid var(--border);color:var(--muted)}
.errmark svg{width:22px;height:22px}
.ref{margin-top:18px;font-size:13px;color:var(--muted)}
@media (max-width:520px){
header{padding-top:24px}
.card{padding:22px 18px;border-radius:16px}
h1{font-size:22px}
.facts div{grid-template-columns:1fr;gap:2px}
.actions{flex-direction:column-reverse}
.btn{width:100%}
.changes thead{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
.changes,.changes tbody,.changes tr,.changes th,.changes td{display:block;width:auto}
.changes tbody th{width:auto;border-top:1px solid var(--border);padding-bottom:2px}
.changes tbody tr:first-child th{border-top:0}
.tag{display:inline-block;margin:0 0 0 8px}
.changes td{border-top:0;padding-top:4px}
.changes td[data-label]::before{content:attr(data-label);display:block;font-size:11px;font-weight:600;letter-spacing:.05em;text-transform:uppercase;color:var(--muted)}
}
@media (prefers-reduced-motion:reduce){.btn{transition:none}}`

func appMCPStyleHash(css string) string {
	sum := sha256.Sum256([]byte(css))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

// ---- templates -------------------------------------------------------------

const appMCPPageBaseHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light dark"><meta name="robots" content="noindex"><title>{{.Title}} - {{.App}}</title>{{if .Favicon}}<link rel="icon" href="{{.Favicon}}">{{end}}<style>{{.BaseCSS}}</style><style>{{.ThemeCSS}}</style></head>
<body class="{{if .Wide}}wide{{end}}">
<header><span class="mark" aria-hidden="true">{{if .Favicon}}<img src="{{.Favicon}}" alt="">{{else}}{{.Initial}}{{end}}</span><span class="appname">{{.App}}</span></header>
<main>{{template "content" .}}</main>
<footer>{{if not .Bare}}<a href="{{.Home}}">Back to {{.App}}</a>{{end}}</footer>
</body></html>
`

// Shared fragments for the review pages (single and batch).
const appMCPPageFragments = `
{{define "changes"}}{{if .Changes}}<table class="changes"><thead><tr><th scope="col">Field</th>{{if .ShowBefore}}<th scope="col">Before</th><th scope="col">After</th>{{else}}<th scope="col">Value</th>{{end}}</tr></thead><tbody>{{range .Changes}}<tr class="{{if .Changed}}changed{{end}}"><th scope="row">{{.Label}}{{if .Changed}}<span class="tag">Changed</span>{{end}}</th>{{if $.ShowBefore}}<td data-label="Before">{{if .Before}}{{.Before}}{{else}}<span class="none">(empty)</span>{{end}}</td>{{end}}<td data-label="{{if $.ShowBefore}}After{{else}}Value{{end}}">{{if .After}}{{.After}}{{else}}<span class="none">(empty)</span>{{end}}</td></tr>{{end}}</tbody></table><details class="raw"><summary>Exact data</summary><pre>{{.Preview}}</pre></details>{{else}}<pre>{{.Preview}}</pre>{{end}}{{end}}
{{define "told"}}{{if and .Description (not .HasText)}}<details><summary>What the assistant was told</summary><p class="small muted">{{.Description}}</p></details>{{end}}{{end}}
{{define "effects"}}{{if .Effects}}<p class="small muted">Side effects, queued with the change and delivered after it is applied, only while the assistant's connection stays authorized:</p><ul>{{range .Effects}}<li>{{.}}</li>{{end}}</ul>{{else}}<p class="small muted">No downstream effects: this change sends no email, notification, webhook or background job.</p>{{end}}{{end}}
{{define "why"}}{{if .AutoApprove}}<p class="note">Why this needs your approval: {{.AutoApprove}}</p>{{end}}{{end}}
{{define "expiry"}}<p class="meta"><span>{{.ExpiresText}}</span><span><time datetime="{{.Expires}}">{{.ExpiresClock}}</time></span></p>{{end}}
`

var appMCPPageBase = template.Must(template.Must(template.New("page").Parse(appMCPPageBaseHTML)).Parse(appMCPPageFragments))

func appMCPPageSet(content string) *template.Template {
	return template.Must(template.Must(appMCPPageBase.Clone()).Parse(`{{define "content"}}` + content + `{{end}}`))
}

var appMCPErrorPage = appMCPPageSet(`<div class="card"><div class="errmark" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7.5v5.5M12 16.5h.01"/></svg></div>
<h1>{{.Data.Title}}</h1><p class="lead">{{.Data.Message}}</p>{{if .Data.Ref}}<p class="ref">Reference <code>{{.Data.Ref}}</code></p>{{end}}
<div class="actions"><a class="btn btn-primary" href="{{.Home}}">Go to {{.App}}</a></div></div>`)

var appMCPPickerPage = appMCPPageSet(`<div class="card"><p class="eyebrow">Connect an assistant</p><h1>Choose a workspace</h1>
<p class="lead">{{if .Data.Client}}<strong>{{.Data.Client}}</strong> will{{else}}This connection will{{end}} be able to access only the workspace you select.</p>
<form method="get" action="/oauth/authorize">{{range .Data.Fields}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">{{end}}
<label for="workspace">Workspace</label><select id="workspace" name="workspace" required><option value="">Choose a workspace</option>{{range .Data.Workspaces}}<option value="{{.ID}}">{{.Name}}</option>{{end}}</select>
<div class="actions"><button class="btn btn-primary" type="submit">Continue</button></div></form></div>`)

var appMCPConsentPage = appMCPPageSet(`<div class="card"><p class="eyebrow">Connect an assistant</p><h1>Allow {{.Data.Client}} to access your {{.App}} account?</h1>
<p class="lead">Signed in as {{.Data.EmailOpen}}<strong>{{.Data.Subject}}</strong>{{.Data.EmailClose}}</p>
<dl class="facts"><div><dt>Access</dt><dd>{{.Data.Scope}}</dd></div><div><dt>Lasts</dt><dd>Up to 30 days, until you revoke it</dd></div><div><dt>Access key goes to</dt><dd class="host">{{.Data.Host}}</dd></div></dl>
<p class="note warn">Only approve if you started this connection yourself from a tool you trust.</p>
<form method="post" action="/oauth/authorize">{{range .Data.Fields}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">{{end}}
{{if .Data.AutoApprove}}<label class="opt"><input type="checkbox" name="auto_approve" value="1"><span>Let this assistant apply these changes without asking me each time: <strong>{{.Data.AutoApprove}}</strong>. Every change is still recorded in the audit log, and revoking this connection stops it.</span></label>{{end}}
<div class="actions"><button class="btn btn-secondary" name="decision" value="deny">Deny</button><button class="btn btn-primary" name="decision" value="approve">Approve</button></div></form></div>`)

var appMCPReviewPage = appMCPPageSet(`{{with .Data}}<div class="card"><p class="eyebrow">Review requested change</p><h1>{{.Heading}}</h1>
{{if .Summary}}<p class="lead">{{.Summary}}</p>{{end}}
<p class="meta"><span>Tool <code>{{.Tool}}</code></span></p>
{{template "told" .}}
{{if .StateText}}<p class="note {{.StateKind}}">{{.StateText}}</p>{{else}}<p class="pill">{{if eq .State "prepared"}}Waiting for your approval{{else}}Status: {{.State}}{{end}}</p>{{end}}
<h2>Exact change</h2>
{{template "changes" .}}
{{template "why" .}}
<h2>Side effects</h2>
{{template "effects" .}}
{{template "expiry" .}}
{{if .Approvable}}<form method="post" action="{{.Action}}"><input type="hidden" name="_csrf" value="{{.CSRF}}"><div class="actions"><button class="btn btn-primary" type="submit">Approve this exact change</button></div></form>
<p class="small muted">Approving lets that assistant apply exactly this change once. It grants no other access.</p>{{end}}</div>{{end}}`)

var appMCPBatchReviewPage = appMCPPageSet(`<div class="card"><p class="eyebrow">Connected assistant</p><h1>Review requested changes</h1>
{{with .Data}}{{if eq .Approved 0}}<p class="note warn" role="status">None of the selected changes could be approved. They may have expired or been handled already.</p>{{else if gt .Approved 0}}<p class="note" role="status">Approved {{.Approved}} {{if eq .Approved 1}}change{{else}}changes{{end}}. The assistant can now apply {{if eq .Approved 1}}it{{else}}them{{end}}.</p>{{end}}{{if .NoneTicked}}<p class="note warn" role="status">Tick at least one change to approve.</p>{{end}}{{if .Items}}<p class="lead">A connected assistant asked to make these changes. Tick the ones you want to approve (none is ticked for you); each applies exactly once, when the assistant commits it.</p>
<form method="post" action="{{.Action}}"><input type="hidden" name="_csrf" value="{{.CSRF}}"><input type="hidden" name="grant" value="{{.Grant}}">
{{range .Items}}<section class="item"><label class="pick"><input type="checkbox" name="op" value="{{.ID}}"><span><span class="item-title">{{.Heading}}</span>{{if .Summary}}<span class="muted">{{.Summary}}</span>{{end}}</span></label>
<p class="meta"><span>Tool <code>{{.Tool}}</code></span></p>
{{template "told" .}}
{{template "changes" .}}
{{template "why" .}}
{{template "effects" .}}
{{template "expiry" .}}</section>{{end}}
<div class="actions"><button class="btn btn-primary" type="submit">Approve selected changes</button></div></form>
<p class="small muted">Approving grants no other access.</p>{{else}}<p class="lead">Nothing from this connection is waiting for your approval.</p>{{end}}{{end}}</div>`)

// ---- rendering -------------------------------------------------------------

type appMCPPageOpts struct {
	Title string
	Wide  bool
	// Bare drops the footer link (an error page already offers one).
	Bare bool
	// FormAction extends form-action beyond 'self' (the consent page's client).
	FormAction string
	// Referrer is the Referrer-Policy; "" omits the header. A page that posts a
	// form must use "same-origin", never "no-referrer": on 2026-10-14
	// (benmore-go#464) the single and batch review pages sent
	// no-referrer, a real browser posted the approve form with `Origin: null`,
	// and appMCPBoundCSRF refused it, so no person could approve any connector
	// change on any app, while every Go test passed (net/http never derives
	// Origin from a referrer policy). Guarded by
	// TestNoReferrerPageDoesNotPostASameOriginForm and
	// TestReferrerPolicyBrowserPostsAreNotRefusedForOrigin_* (security.md 5b).
	Referrer string
}

type appMCPPageView struct {
	App, Initial, Title, Home, Favicon string
	Wide, Bare                         bool
	BaseCSS, ThemeCSS                  template.CSS
	Data                               any
}

// appMCPPageFavicon is the app's configured icon when it is a plain
// same-origin path; an absolute or protocol-relative URL is never linked.
func appMCPPageFavicon(app *App) string {
	if app == nil || app.Design == nil {
		return ""
	}
	f := strings.TrimSpace(app.Design.SEO["favicon"])
	if f == "" || len(f) > 512 || !strings.HasPrefix(f, "/") || strings.HasPrefix(f, "//") || strings.ContainsAny(f, "\\\"'<>\r\n\t ") {
		return ""
	}
	return f
}

func appMCPPageInitial(name string) string {
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return string(unicode.ToUpper(r))
		}
	}
	return "B"
}

// writeAppMCPPage renders into a buffer first so a template failure is a clean
// 500, then sets the strict headers and writes the page.
func writeAppMCPPage(w http.ResponseWriter, app *App, status int, t *template.Template, o appMCPPageOpts, data any) {
	view := appMCPPageView{App: appSiteName(app), Title: o.Title, Home: "/", Favicon: appMCPPageFavicon(app), Wide: o.Wide, Bare: o.Bare,
		BaseCSS: template.CSS(appMCPPageBaseCSS), ThemeCSS: appMCPPageThemeCSS(app), Data: data}
	view.Initial = appMCPPageInitial(view.App)
	var buf bytes.Buffer
	if err := t.Execute(&buf, view); err != nil {
		log.Printf("mcp-pages: title=%q class=render err=%v", o.Title, err)
		http.Error(w, "page unavailable", http.StatusInternalServerError)
		return
	}
	csp := "default-src 'none'; style-src " + appMCPStyleHash(appMCPPageBaseCSS) + " " + appMCPStyleHash(string(view.ThemeCSS))
	if view.Favicon != "" {
		csp += "; img-src 'self'"
	}
	form := "'self'"
	if o.FormAction != "" {
		form = o.FormAction
	}
	csp += "; form-action " + form + "; frame-ancestors 'none'; base-uri 'none'"
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	if o.Referrer != "" { // same-origin on form pages: see appMCPPageOpts.Referrer (2026-10-14 incident)
		h.Set("Referrer-Policy", o.Referrer)
	}
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// ---- errors ----------------------------------------------------------------

type appMCPErrorView struct{ Title, Message, Ref string }

// writeAppMCPError answers with the styled error page. The caller keeps the
// status code it always used; only the body is new.
func writeAppMCPError(w http.ResponseWriter, app *App, status int, title, message string) {
	writeAppMCPPage(w, app, status, appMCPErrorPage, appMCPPageOpts{Title: title, Bare: true}, appMCPErrorView{Title: title, Message: message, Ref: w.Header().Get(requestIDHeader)})
}

// writeAppMCPCannotShow is the ONE answer for an operation or grant that is
// unknown, belongs to someone else, or was refused. Those must be
// indistinguishable to the viewer (same status, same bytes), or the page would
// tell a prober which operation ids exist. Nothing request-specific goes in.
func writeAppMCPCannotShow(w http.ResponseWriter, app *App) {
	writeAppMCPError(w, app, http.StatusNotFound, "This request can't be shown",
		"It may have expired, already been handled, or belong to another account. Ask the assistant to prepare it again.")
}

// writeAppMCPApprovalsOff is for a connector whose approved writes are not
// live. It is not secret: the connector's tool list already shows it. The
// status stays 404, as before: no review page exists while writes are off.
func writeAppMCPApprovalsOff(w http.ResponseWriter, app *App) {
	writeAppMCPError(w, app, http.StatusNotFound, "Approvals are turned off",
		"Approving assistant changes is currently turned off for "+appSiteName(app)+". Ask the app owner to turn it on.")
}

// writeAppMCPConnectorOff is for a connector whose mcp.yaml review no longer matches the served source
// (app.mcpWithheld): no tool runs and no operation can be approved until the owner re-reviews and pushes
// it. The status stays 404, as for writes off. Without this page an approval link prepared before the
// connector went off answered the framework's generic "no API route matches this path".
func writeAppMCPConnectorOff(w http.ResponseWriter, app *App) {
	writeAppMCPError(w, app, http.StatusNotFound, "The assistant connector is off",
		"Changes an assistant prepares for "+appSiteName(app)+" can't be reviewed while its connector is off. Ask the app owner to turn it back on, then ask the assistant to prepare the change again.")
}

func writeAppMCPCannotApprove(w http.ResponseWriter, app *App) {
	writeAppMCPError(w, app, http.StatusForbidden, "This can't be approved from here",
		"Open the review link in the browser where you are signed in to "+appSiteName(app)+" yourself (not through a support or admin session), then try again.")
}

func writeAppMCPUnavailable(w http.ResponseWriter, app *App) {
	writeAppMCPError(w, app, http.StatusServiceUnavailable, "Review is temporarily unavailable",
		"Something went wrong on our side. Try again in a moment.")
}

func writeAppMCPTooManyRequests(w http.ResponseWriter, app *App) {
	writeAppMCPError(w, app, http.StatusTooManyRequests, "Too many requests",
		"You've made a lot of requests in a short time. Wait a moment and try again.")
}

// ---- review display --------------------------------------------------------

// appMCPReviewView is what the review pages show of one appMCPReview.
type appMCPReviewView struct {
	ID, Tool, Heading, Summary, Description, Preview, State, AutoApprove string
	HasText, ShowBefore                                                  bool
	Changes                                                              []appMCPReviewChange
	Effects                                                              []string
	Expires, ExpiresText, ExpiresClock                                   string
	StateKind, StateText                                                 string
	Approvable                                                           bool
	Action, CSRF                                                         string
}

// appMCPBatchItem is one entry of the batch page.
type appMCPBatchItem = appMCPReviewView

func appMCPExpiryText(expiresAt int64, now time.Time) string {
	d := time.Unix(expiresAt, 0).Sub(now)
	switch m := int(d / time.Minute); {
	case d <= 0:
		return "Expired"
	case m < 1:
		return "Expires in less than a minute"
	case m == 1:
		return "Expires in 1 minute"
	case m < 120:
		return fmt.Sprintf("Expires in %d minutes", m)
	default:
		return fmt.Sprintf("Expires in %d hours", m/60)
	}
}

// appMCPReviewStateNote is the plain sentence for a state past "prepared".
func appMCPReviewStateNote(state string) (kind, text string) {
	switch state {
	case "approved":
		return "ok", "Approved. Your assistant can now apply this change."
	case "running":
		return "", "This change is being applied now."
	case "succeeded":
		return "ok", "Applied. This change has been made."
	case "failed":
		return "bad", "This change could not be applied."
	case "conflict":
		return "bad", "The data changed after this was prepared, so it was not applied. Ask the assistant to prepare it again."
	case "unknown":
		return "warn", "The result of this change is unclear. Check the app before trying it again."
	case "expired":
		return "warn", "This request expired and can no longer be approved. Ask the assistant to prepare it again."
	}
	return "", ""
}

// newAppMCPReviewView copies the display fields of a review. It only renders
// what the review carries; Description is model-facing text and is shown only
// as a collapsed fallback when no human title or summary exists.
func newAppMCPReviewView(review *appMCPReview, id string, now time.Time) appMCPReviewView {
	v := appMCPReviewView{ID: id, Tool: review.Tool, Heading: review.Title, Summary: review.Summary, Description: review.Description,
		Preview: review.Preview, State: review.State, AutoApprove: review.AutoApprove, Changes: review.Changes, Effects: review.Effects,
		HasText: review.Title != "" || review.Summary != ""}
	if v.Heading == "" {
		v.Heading = review.Tool
	}
	for _, c := range review.Changes {
		if c.Before != "" {
			v.ShowBefore = true
		}
	}
	exp := time.Unix(review.ExpiresAt, 0).UTC()
	v.Expires, v.ExpiresText, v.ExpiresClock = exp.Format(time.RFC3339), appMCPExpiryText(review.ExpiresAt, now), exp.Format("2006-01-02 15:04 UTC")
	return v
}

// clampLabel makes a looked-up workspace name safe to show on one line.
func clampLabel(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > 120 {
		s = string([]rune(s)[:120]) + "..."
	}
	return s
}
