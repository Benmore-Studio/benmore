//go:build !cli

package main

import (
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// formatColName converts a column name to a human-readable label.
func formatColName(name string) string {
	name = strings.ReplaceAll(name, "_", " ")
	if len(name) > 0 {
		return strings.ToUpper(name[:1]) + name[1:]
	}
	return name
}

// RegisterAdminRoutes sets up the auto-generated admin panel at /_admin/*.
func RegisterAdminRoutes(mux *http.ServeMux, app *App) {
	// Admin requires auth + admin role
	adminAuth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			session := getSession(app, r)
			if session == nil {
				http.Redirect(w, r, app.Paths.Login+"?redirect="+r.URL.Path, http.StatusSeeOther)
				return
			}
			role := getUserRole(app.DB, session.UserID)
			if role != "admin" {
				http.Error(w, "Forbidden — admin access required", http.StatusForbidden)
				return
			}
			next(w, r)
		}
	}

	// Admin dashboard
	mux.HandleFunc("GET /_admin", adminAuth(func(w http.ResponseWriter, r *http.Request) {
		serveAdminDashboard(w, r, app)
	}))

	// Feedback admin page
	if app.FeatureEnabled("testing") {
		mux.HandleFunc("GET /_admin/feedback", adminAuth(func(w http.ResponseWriter, r *http.Request) {
			ServeFeedbackAdmin(w, r, app)
		}))
	}

	// Admin tools page (flow triggers)
	mux.HandleFunc("GET /_admin/tools", adminAuth(func(w http.ResponseWriter, r *http.Request) {
		serveAdminTools(w, r, app)
	}))

	// Admin tools flow proxy — executes flow and redirects back to tools with result
	mux.HandleFunc("POST /_admin/tools/run", adminAuth(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if !validateCSRF(r) {
			http.Redirect(w, r, "/_admin/tools?error=Invalid+CSRF+token", http.StatusSeeOther)
			return
		}
		flowPath := r.FormValue("_flow_path")
		if flowPath == "" {
			http.Redirect(w, r, "/_admin/tools?error=No+flow+specified", http.StatusSeeOther)
			return
		}
		// Validate the flow path exists, is admin-only, and has no path params
		var targetFlow *Flow
		for i := range app.Flows {
			f := &app.Flows[i]
			if f.Trigger.Path == flowPath && f.Role == "admin" && f.Trigger.Method == "POST" && !strings.Contains(f.Trigger.Path, ":") {
				targetFlow = f
				break
			}
		}
		if targetFlow == nil {
			http.Redirect(w, r, "/_admin/tools?error=Flow+not+found+or+not+admin", http.StatusSeeOther)
			return
		}
		// Execute the flow by forwarding the request internally
		session := getSession(app, r)
		ctx := &FlowContext{
			App:     app,
			Writer:  nil, // suppress redirects/responses
			Request: r,
			Data:    make(map[string]any),
			Params:  make(map[string]string),
		}
		// Populate context with form values
		for k, v := range r.Form {
			if k != "_csrf" && k != "_flow_path" && len(v) > 0 {
				ctx.Data[k] = v[0]
				ctx.Params[k] = v[0]
			}
		}
		// Inject session context
		if session != nil {
			ctx.Data["user_id"] = session.UserID
			ctx.Data["user_email"] = session.Email
			ctx.Data["user_role"] = getUserRole(app.DB, session.UserID)
		}
		// Execute steps
		if targetFlow.Transaction {
			tx, err := app.DB.Begin()
			if err == nil {
				ctx.Tx = tx
				executeSteps(ctx, targetFlow.Steps)
				if ctx.Error != nil {
					tx.Rollback()
				} else {
					tx.Commit()
				}
			}
		} else {
			executeSteps(ctx, targetFlow.Steps)
		}
		if ctx.Error != nil {
			http.Redirect(w, r, "/_admin/tools?error="+url.QueryEscape(ctx.Error.Error()), http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/_admin/tools?msg="+url.QueryEscape(targetFlow.Name+" executed successfully"), http.StatusSeeOther)
		}
	}))

	// Admin table list
	mux.HandleFunc("GET /_admin/", adminAuth(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/_admin/")
		parts := strings.SplitN(path, "/", 2)
		table := parts[0]

		if table == "" {
			serveAdminDashboard(w, r, app)
			return
		}

		// Check if it's a specific record: /_admin/contacts/5
		if len(parts) == 2 && parts[1] != "" {
			serveAdminDetail(w, r, app, table, parts[1])
			return
		}

		serveAdminTable(w, r, app, table)
	}))

	// Admin API for inline editing
	mux.HandleFunc("POST /_admin/api/", adminAuth(func(w http.ResponseWriter, r *http.Request) {
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpError(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/_admin/api/")
		parts := strings.SplitN(path, "/", 2)
		if len(parts) < 2 {
			httpError(w, "Bad request", http.StatusBadRequest)
			return
		}
		table := parts[0]
		action := parts[1]

		switch {
		case action == "create":
			handleCreate(w, r, app, table)
		case strings.HasPrefix(action, "delete/"):
			id := strings.TrimPrefix(action, "delete/")
			r.URL.Path = fmt.Sprintf("/api/%s/%s", table, id)
			handleDelete(w, r, app, table)
		case strings.HasPrefix(action, "update/"):
			id := strings.TrimPrefix(action, "update/")
			r.URL.Path = fmt.Sprintf("/api/%s/%s", table, id)
			handleUpdate(w, r, app, table)
		}
	}))

	// Set user role
	mux.HandleFunc("POST /_admin/set-role", adminAuth(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if !validateCSRF(r) {
			httpError(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		userID := r.FormValue("user_id")
		role := r.FormValue("role")
		var uid int64
		fmt.Sscanf(userID, "%d", &uid)
		if err := SetUserRole(app.DB, uid, role); err != nil {
			httpError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if isHTMX(r) {
			w.Header().Set("HX-Refresh", "true")
			return
		}
		http.Redirect(w, r, "/_admin/_benmore_users", http.StatusSeeOther)
	}))

	log.Printf("  admin: /_admin (requires admin role; legacy /admin redirects unless user page exists)")
}

// adminShell wraps admin content in a self-contained admin layout with sidebar.
func adminShell(content, title, activeTable string, app *App, session *Session) string {
	tables, _ := GetTableNames(app.DB)

	// Gather stats
	var userCount, sessionCount, auditCount int64
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_users").Scan(&userCount)
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_sessions WHERE expires_at > datetime('now')").Scan(&sessionCount)
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_audit_log").Scan(&auditCount)

	var sb strings.Builder

	// --- Sidebar nav ---
	sb.WriteString(`<div style="display:flex;height:100vh;overflow:hidden;font-family:system-ui,-apple-system,sans-serif;">`)

	// Sidebar
	sb.WriteString(`<aside style="width:240px;flex-shrink:0;background:hsl(var(--card));border-right:1px solid hsl(var(--border));display:flex;flex-direction:column;overflow:hidden;">`)

	// Brand header: app name + Admin
	appName := "Admin"
	if app.Design != nil {
		if sn, ok := app.Design.SEO["site_name"]; ok && sn != "" {
			appName = sn
		}
	}
	sb.WriteString(fmt.Sprintf(`<div style="height:56px;display:flex;align-items:center;padding:0 20px;border-bottom:1px solid hsl(var(--border));">
		<a href="/_admin" style="text-decoration:none;">
			<div style="font-size:15px;font-weight:700;color:#111;">%s</div>
			<div style="font-size:11px;color:#888;margin-top:1px;">Admin</div>
		</a>
	</div>`, html.EscapeString(appName)))

	// Dashboard link
	dashActive := ""
	if activeTable == "" {
		dashActive = "background:hsl(var(--accent));color:hsl(var(--foreground));font-weight:600;"
	}
	sb.WriteString(fmt.Sprintf(`<div style="padding:8px 12px;">
		<a href="/_admin" style="display:flex;align-items:center;gap:8px;padding:8px 12px;font-size:13px;text-decoration:none;color:hsl(var(--foreground));border-radius:6px;transition:background 0.1s;%s">
			<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
			Dashboard
		</a>
	</div>`, dashActive))

	// Tables list
	sb.WriteString(`<div style="padding:4px 12px 0;"><div style="font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.08em;color:hsl(var(--muted-foreground));padding:4px 12px 4px;">Tables</div></div>`)
	sb.WriteString(`<nav id="admin-table-list" style="flex:1;overflow-y:auto;padding:0 12px 12px;scrollbar-width:none;">`)

	for _, t := range tables {
		// admin.yaml: skip tables explicitly hidden by the developer.
		// This keeps internal/operational tables out of the admin UI
		// without pulling them out of the schema.
		if app.Admin.IsTableHidden(t) {
			continue
		}
		var count int64
		app.DB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", t)).Scan(&count)
		active := ""
		if t == activeTable {
			active = "background:hsl(var(--accent));color:hsl(var(--foreground));font-weight:600;"
		}
		// Display name precedence: explicit admin.yaml label → strip
		// _benmore_ prefix → replace underscores. Lets devs rename
		// "contacts" to "Customers" without changing the schema.
		displayName := app.Admin.TableLabel(t)
		if displayName == "" {
			displayName = strings.ReplaceAll(t, "_", " ")
			if strings.HasPrefix(t, "_benmore_") {
				displayName = strings.TrimPrefix(t, "_benmore_")
				displayName = strings.ReplaceAll(displayName, "_", " ")
			}
		}
		sb.WriteString(fmt.Sprintf(`<a href="/_admin/%s" style="display:flex;align-items:center;justify-content:space-between;padding:6px 12px;font-size:12px;text-decoration:none;color:hsl(var(--muted-foreground));border-radius:6px;transition:background 0.1s;%s" onmouseover="this.style.background='hsl(var(--accent))'" onmouseout="this.style.background='%s'">
			<span style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">%s</span>
			<span style="font-size:10px;background:hsl(var(--muted));padding:1px 6px;border-radius:10px;flex-shrink:0;">%d</span>
		</a>`, t, active, func() string {
			if t == activeTable {
				return "hsl(var(--accent))"
			}
			return ""
		}(), displayName, count))
	}
	sb.WriteString(`</nav>`)

	// Tools link (if app has admin flows)
	hasAdminFlows := false
	for _, f := range app.Flows {
		if f.Role == "admin" && f.Trigger.Method == "POST" {
			hasAdminFlows = true
			break
		}
	}
	if hasAdminFlows {
		toolsActive := ""
		if activeTable == "_tools" {
			toolsActive = "background:hsl(var(--accent));color:hsl(var(--foreground));font-weight:600;"
		}
		sb.WriteString(fmt.Sprintf(`<div style="padding:4px 12px 0;"><div style="font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.08em;color:hsl(var(--muted-foreground));padding:4px 12px 4px;">Operations</div></div>
		<div style="padding:0 12px 8px;">
			<a href="/_admin/tools" style="display:flex;align-items:center;gap:8px;padding:6px 12px;font-size:12px;text-decoration:none;color:hsl(var(--muted-foreground));border-radius:6px;transition:background 0.1s;%s" onmouseover="this.style.background='hsl(var(--accent))'" onmouseout="if('%s'==='')this.style.background=''">
				<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>
				Tools
			</a>
		</div>`, toolsActive, toolsActive))
	}

	// Footer: back to app
	// Feedback link (if enabled)
	if app.FeatureEnabled("testing") {
		fbActive := ""
		if activeTable == "_feedback" {
			fbActive = "background:hsl(var(--accent));color:hsl(var(--foreground));font-weight:600;"
		}
		var fbCount int64
		app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_feedback WHERE status = 'open'").Scan(&fbCount)
		countBadge := ""
		if fbCount > 0 {
			countBadge = fmt.Sprintf(`<span style="font-size:10px;background:#dc2626;color:#fff;padding:1px 6px;border-radius:10px;flex-shrink:0;">%d</span>`, fbCount)
		}
		sb.WriteString(fmt.Sprintf(`<div style="padding:4px 12px;">
			<a href="/_admin/feedback" style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;font-size:13px;text-decoration:none;color:hsl(var(--foreground));border-radius:6px;transition:background 0.1s;%s">
				<span style="display:flex;align-items:center;gap:8px;">
					<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
					Feedback
				</span>
				%s
			</a>
		</div>`, fbActive, countBadge))
	}

	backLink := "/"
	if app.Design != nil && app.Design.Auth != nil {
		if r := app.Design.Auth["redirect"]; r != "" {
			backLink = r
		}
	}
	sb.WriteString(fmt.Sprintf(`<div style="padding:12px;border-top:1px solid hsl(var(--border));">
		<a href="%s" style="display:flex;align-items:center;gap:8px;padding:8px 12px;font-size:12px;text-decoration:none;color:hsl(var(--muted-foreground));border-radius:6px;transition:background 0.1s;" onmouseover="this.style.background='hsl(var(--accent))'" onmouseout="this.style.background=''">
			<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 12H5"/><path d="M12 19l-7-7 7-7"/></svg>
			Back to App
		</a>
	</div>`, backLink))

	sb.WriteString(`</aside>`)

	// --- Main content ---
	sb.WriteString(`<main style="flex:1;overflow-y:auto;background:hsl(var(--background));">`)

	// Top bar with search
	sb.WriteString(fmt.Sprintf(`<header style="height:48px;border-bottom:1px solid hsl(var(--border));display:flex;align-items:center;justify-content:space-between;padding:0 24px;background:hsl(var(--card));">
		<div style="font-size:14px;font-weight:600;color:hsl(var(--foreground));">%s</div>
		<div style="display:flex;align-items:center;gap:12px;">
			<button onclick="openAdminSearch()" style="display:flex;align-items:center;gap:8px;height:32px;padding:0 12px;border:1px solid hsl(var(--border));border-radius:6px;background:hsl(var(--background));color:hsl(var(--muted-foreground));font-size:12px;cursor:pointer;">
				<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
				Search everything...
				<kbd style="font-size:10px;background:hsl(var(--muted));padding:2px 6px;border-radius:4px;">&#8984;K</kbd>
			</button>
			<span style="font-size:11px;color:hsl(var(--muted-foreground));">%d users</span>
			<span style="font-size:11px;color:hsl(var(--muted-foreground));">%d sessions</span>
		</div>
	</header>`, html.EscapeString(title), userCount, sessionCount))

	// Fuzzy search modal
	sb.WriteString(`<div id="admin-search-overlay" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:9998;backdrop-filter:blur(2px);" onclick="closeAdminSearch()"></div>
	<div id="admin-search-modal" style="display:none;position:fixed;top:15%%;left:50%%;transform:translateX(-50%%);width:560px;max-width:90vw;z-index:9999;background:hsl(var(--card));border:1px solid hsl(var(--border));box-shadow:0 20px 60px rgba(0,0,0,0.2);border-radius:12px;overflow:hidden;">
		<div style="display:flex;align-items:center;padding:0 16px;border-bottom:1px solid hsl(var(--border));">
			<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="hsl(var(--muted-foreground))" stroke-width="2" style="flex-shrink:0;"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
			<input id="admin-search-input" type="text" autocomplete="off" spellcheck="false" placeholder="Search tables, users, records..." style="flex:1;border:none;outline:none;background:transparent;padding:14px 12px;font-size:15px;color:hsl(var(--foreground));"/>
			<kbd style="font-size:11px;color:hsl(var(--muted-foreground));background:hsl(var(--muted));padding:3px 8px;border-radius:4px;">ESC</kbd>
		</div>
		<div id="admin-search-results" style="max-height:400px;overflow-y:auto;"></div>
	</div>`)

	// Build search index from tables
	sb.WriteString(`<script>
(function(){
	var searchItems=[];
	var tables=document.querySelectorAll('#admin-table-list a');
	tables.forEach(function(a){
		var name=a.querySelector('span').textContent;
		var count=a.querySelectorAll('span')[1]?a.querySelectorAll('span')[1].textContent:'';
		searchItems.push({title:name,sub:count+' records',url:a.href,cat:'Tables'});
	});`)
	// Add users to search index
	userRows, _ := QueryRows(app.DB, "SELECT id, email, role FROM _benmore_users ORDER BY id LIMIT 100")
	sb.WriteString(`var users=[`)
	for i, u := range userRows {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(fmt.Sprintf(`{id:%v,email:"%s",role:"%s"}`,
			u["id"], html.EscapeString(fmt.Sprintf("%v", u["email"])), html.EscapeString(fmt.Sprintf("%v", u["role"]))))
	}
	sb.WriteString(`];
	users.forEach(function(u){searchItems.push({title:u.email,sub:u.role,url:'/_admin/_benmore_users/'+u.id,cat:'Users'});});

	function fuzzy(q,t){q=q.toLowerCase();t=t.toLowerCase();if(!q)return 1;if(t.indexOf(q)>=0)return 100+(q.length/t.length*50);var qi=0,s=0;for(var i=0;i<t.length&&qi<q.length;i++){if(t[i]===q[qi]){qi++;s+=10;}}return qi===q.length?s:0;}

	function render(q){
		var el=document.getElementById('admin-search-results');
		if(!q){el.innerHTML='<div style="padding:24px;text-align:center;color:hsl(var(--muted-foreground));font-size:13px;">Type to search tables, users, and records</div>';return;}
		var scored=[];
		searchItems.forEach(function(item){var s=Math.max(fuzzy(q,item.title),fuzzy(q,item.sub||'')*0.7);if(s>0)scored.push({item:item,score:s});});
		scored.sort(function(a,b){return b.score-a.score;});
		scored=scored.slice(0,12);
		if(!scored.length){el.innerHTML='<div style="padding:24px;text-align:center;color:hsl(var(--muted-foreground));font-size:13px;">No results for "'+q.replace(/</g,'&lt;')+'"</div>';return;}
		var groups={};var order=['Tables','Users'];
		scored.forEach(function(r){var c=r.item.cat;if(!groups[c])groups[c]=[];groups[c].push(r.item);});
		var html='';
		order.forEach(function(cat){if(!groups[cat])return;
			html+='<div style="padding:8px 16px 4px;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:hsl(var(--muted-foreground));">'+cat+'</div>';
			groups[cat].forEach(function(item){
				html+='<a href="'+item.url+'" style="display:flex;align-items:center;gap:12px;padding:10px 16px;text-decoration:none;color:inherit;transition:background 0.1s;" onmouseover="this.style.background=\'hsl(var(--accent))\'" onmouseout="this.style.background=\'\'">'
					+'<span style="flex:1;"><span style="display:block;font-size:14px;font-weight:500;color:hsl(var(--foreground));">'+item.title+'</span>'
					+'<span style="display:block;font-size:12px;color:hsl(var(--muted-foreground));">'+item.sub+'</span></span></a>';
			});
		});
		el.innerHTML=html;
	}

	var input=document.getElementById('admin-search-input');
	var debounce;
	if(input){input.addEventListener('input',function(){clearTimeout(debounce);debounce=setTimeout(function(){render(input.value);},80);});}
	input&&input.addEventListener('keydown',function(e){if(e.key==='Escape')closeAdminSearch();if(e.key==='Enter'){var first=document.querySelector('#admin-search-results a');if(first)window.location.href=first.href;}});

	window.openAdminSearch=function(){document.getElementById('admin-search-modal').style.display='block';document.getElementById('admin-search-overlay').style.display='block';var inp=document.getElementById('admin-search-input');inp.value='';render('');setTimeout(function(){inp.focus();},50);};
	window.closeAdminSearch=function(){document.getElementById('admin-search-modal').style.display='none';document.getElementById('admin-search-overlay').style.display='none';};
	document.addEventListener('keydown',function(e){if((e.metaKey||e.ctrlKey)&&e.key==='k'){e.preventDefault();openAdminSearch();}if(e.key==='Escape'&&document.getElementById('admin-search-modal').style.display==='block')closeAdminSearch();});
})();
</script>`)

	// Page content
	sb.WriteString(`<div style="padding:24px;max-width:1200px;">`)
	sb.WriteString(content)
	sb.WriteString(`</div></main></div>`)

	return wrapHTMLShell(sb.String(), title+" — Admin", app, session, nil,
		func() string {
			if app.Design != nil {
				if t, ok := app.Design.Colors["_theme"]; ok {
					return t
				}
				if t := app.Design.Nav["theme"]; t != "" {
					return t
				}
			}
			return "zinc"
		}(),
		"light", // admin panel always light mode
		func() string {
			if app.Design != nil {
				return app.Design.Nav["brand"]
			}
			return ""
		}(),
		func() string {
			if app.Design != nil {
				return app.Design.Nav["font"]
			}
			return ""
		}(),
		loadThemeCSS(app),
	)
}

func serveAdminTools(w http.ResponseWriter, r *http.Request, app *App) {
	session := getSession(app, r)
	csrfToken := generateCSRFToken()

	var sb strings.Builder
	sb.WriteString(`<div style="max-width:800px;">`)
	sb.WriteString(`<h1 style="font-size:24px;font-weight:700;margin-bottom:4px;">Tools</h1>`)
	sb.WriteString(`<p style="font-size:13px;color:hsl(var(--muted-foreground));margin-bottom:24px;">Run admin operations and trigger flows.</p>`)

	// Show result message if redirected back with one
	if msg := r.URL.Query().Get("msg"); msg != "" {
		sb.WriteString(fmt.Sprintf(`<div style="padding:12px 16px;background:hsl(var(--accent));border:1px solid hsl(var(--border));margin-bottom:16px;font-size:13px;color:hsl(var(--foreground));">%s</div>`, html.EscapeString(msg)))
	}
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		sb.WriteString(fmt.Sprintf(`<div style="padding:12px 16px;background:hsl(0 80%% 95%%);border:1px solid hsl(0 60%% 85%%);margin-bottom:16px;font-size:13px;color:hsl(0 70%% 40%%);">%s</div>`, html.EscapeString(errMsg)))
	}

	// Render a card for each admin POST flow
	for _, f := range app.Flows {
		if f.Role != "admin" || f.Trigger.Method != "POST" {
			continue
		}
		path := f.Trigger.Path

		// Skip flows that need path params (like :claim_id) — those are record-level actions
		if strings.Contains(path, ":") {
			continue
		}

		// Flow name
		displayName := strings.ReplaceAll(f.Name, "_", " ")
		displayName = strings.Title(displayName)

		sb.WriteString(fmt.Sprintf(`<div style="background:hsl(var(--card));border:1px solid hsl(var(--border));padding:20px;margin-bottom:16px;border-radius:8px;">
			<div style="margin-bottom:14px;"><h3 style="font-size:14px;font-weight:600;margin-bottom:2px;">%s</h3>
			<code style="font-size:10px;padding:2px 6px;background:hsl(var(--muted));border-radius:4px;color:hsl(var(--muted-foreground));">%s</code></div>
			<form method="POST" action="/_admin/tools/run" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px;align-items:end;">
				<input type="hidden" name="_csrf" value="%s">
				<input type="hidden" name="_flow_path" value="%s">`,
			html.EscapeString(displayName),
			html.EscapeString(f.Trigger.Method+" "+f.Trigger.Path),
			csrfToken,
			html.EscapeString(path)))

		// Detect form fields from flow steps — look for {{var}} references that aren't system vars
		seen := make(map[string]bool)
		systemVars := map[string]bool{"user_id": true, "user_email": true, "user_role": true, "user_name": true, "user_group_id": true, "csrf_token": true}
		for _, step := range f.Steps {
			sql := step.SQL
			// Extract {{var}} patterns from SQL
			for {
				idx := strings.Index(sql, "{{")
				if idx < 0 {
					break
				}
				end := strings.Index(sql[idx:], "}}")
				if end < 0 {
					break
				}
				varName := strings.TrimSpace(sql[idx+2 : idx+end])
				sql = sql[idx+end+2:]
				// Skip system vars, step references (contain .), and env vars
				if systemVars[varName] || strings.Contains(varName, ".") || strings.HasPrefix(varName, "env.") {
					continue
				}
				if !seen[varName] {
					seen[varName] = true
					label := strings.ReplaceAll(varName, "_", " ")
					label = strings.Title(label)
					sb.WriteString(fmt.Sprintf(`<div>
						<label style="display:block;font-size:11px;font-weight:600;color:hsl(var(--muted-foreground));margin-bottom:4px;text-transform:uppercase;letter-spacing:0.04em;">%s</label>
						<input type="text" name="%s" placeholder="%s" style="width:100%%;padding:8px 12px;border:2px solid hsl(var(--border));border-radius:6px;font-size:13px;background:hsl(var(--background));color:hsl(var(--foreground));outline:none;transition:border-color 0.15s;" onfocus="this.style.borderColor='hsl(var(--primary))'" onblur="this.style.borderColor='hsl(var(--border))'">
					</div>`, html.EscapeString(label), html.EscapeString(varName), html.EscapeString(varName)))
				}
			}
		}

		sb.WriteString(`<div><label style="display:block;font-size:11px;color:transparent;margin-bottom:4px;">&nbsp;</label><button type="submit" style="width:100%;padding:8px 20px;background:hsl(var(--primary));color:hsl(var(--primary-foreground));border:none;border-radius:6px;font-size:13px;font-weight:600;cursor:pointer;transition:opacity 0.15s;" onmouseover="this.style.opacity='0.9'" onmouseout="this.style.opacity='1'">Run</button></div>`)
		sb.WriteString(`</form></div>`)
	}

	sb.WriteString(`</div>`)

	html_out := adminShell(sb.String(), "Tools", "_tools", app, session)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html_out))
}

func serveAdminDashboard(w http.ResponseWriter, r *http.Request, app *App) {
	tables, _ := GetTableNames(app.DB)
	session := getSession(app, r)
	currentPeriod := time.Now().UTC().Format("2006-01")

	var sb strings.Builder

	// --- Row 1: 4 stat cards ---
	var userCount, sessionCount, pageViews, apiRequests int64
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_users").Scan(&userCount)
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_sessions WHERE expires_at > datetime('now')").Scan(&sessionCount)
	app.DB.QueryRow("SELECT COALESCE(SUM(count), 0) FROM _benmore_usage WHERE metric = 'page_views' AND period = ?", currentPeriod).Scan(&pageViews)
	app.DB.QueryRow("SELECT COALESCE(SUM(count), 0) FROM _benmore_usage WHERE metric = 'api_requests' AND period = ?", currentPeriod).Scan(&apiRequests)

	sb.WriteString(`<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:20px;">`)
	statCards := []struct {
		label string
		value int64
		icon  string
	}{
		{"Users", userCount, `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`},
		{"Active Sessions", sessionCount, `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`},
		{"Page Views", pageViews, `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`},
		{"API Requests", apiRequests, `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`},
	}
	for _, sc := range statCards {
		sb.WriteString(fmt.Sprintf(`<div style="background:hsl(var(--card));border:1px solid hsl(var(--border));border-radius:8px;padding:20px;">
			<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
				<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:hsl(var(--muted-foreground));">%s</div>
				<div style="color:hsl(var(--muted-foreground));">%s</div>
			</div>
			<div style="font-size:2rem;font-weight:700;color:hsl(var(--foreground));">%d</div>
		</div>`, sc.label, sc.icon, sc.value))
	}
	sb.WriteString(`</div>`)

	// --- Row 2: 3 cards (Storage, Total Records, Audit Trail) ---
	// Storage (DB file size)
	storageLabel := "0 KB"
	if fi, err := os.Stat(app.Dir + "/data.db"); err == nil {
		sizeBytes := fi.Size()
		switch {
		case sizeBytes >= 1024*1024*1024:
			storageLabel = fmt.Sprintf("%.1f GB", float64(sizeBytes)/float64(1024*1024*1024))
		case sizeBytes >= 1024*1024:
			storageLabel = fmt.Sprintf("%.1f MB", float64(sizeBytes)/float64(1024*1024))
		default:
			storageLabel = fmt.Sprintf("%.1f KB", float64(sizeBytes)/float64(1024))
		}
	}

	// Total records across non-internal tables
	var totalRecords int64
	for _, t := range tables {
		if strings.HasPrefix(t, "_benmore_") {
			continue
		}
		var c int64
		app.DB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", t)).Scan(&c)
		totalRecords += c
	}

	// Audit trail entries
	var auditCount int64
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_audit_log").Scan(&auditCount)

	sb.WriteString(`<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:32px;">`)
	row2Cards := []struct {
		label string
		value string
		sub   string
	}{
		{"Storage", storageLabel, "data.db file size"},
		{"Total Records", fmt.Sprintf("%d", totalRecords), "across all app tables"},
		{"Audit Trail", fmt.Sprintf("%d", auditCount), "total logged mutations"},
	}
	for _, c := range row2Cards {
		sb.WriteString(fmt.Sprintf(`<div style="background:hsl(var(--card));border:1px solid hsl(var(--border));border-radius:8px;padding:20px;">
			<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:hsl(var(--muted-foreground));">%s</div>
			<div style="font-size:2rem;font-weight:700;color:hsl(var(--foreground));margin-top:4px;">%s</div>
			<div style="font-size:11px;color:hsl(var(--muted-foreground));margin-top:2px;">%s</div>
		</div>`, c.label, c.value, c.sub))
	}
	sb.WriteString(`</div>`)

	// --- Test Reset (testing mode only) ---
	if app.FeatureEnabled("testing") {
		sb.WriteString(`<div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:16px;margin-bottom:24px;display:flex;align-items:center;justify-content:space-between;">
			<div>
				<div style="font-size:13px;font-weight:600;color:#dc2626;">Reset Test Data</div>
				<div style="font-size:12px;color:#64748b;margin-top:2px;">Wipe all app tables and re-run seeds.sql</div>
			</div>
			<button onclick="if(confirm('This will DELETE all data and re-seed. Continue?')){fetch('/api/_testing/reset',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':document.querySelector('meta[name=csrf-token]').content}}).then(function(r){return r.json()}).then(function(d){alert('Reset complete: '+d.tables_cleared+' tables cleared');location.reload();})}" style="padding:8px 20px;font-size:12px;font-weight:600;background:#dc2626;color:#fff;border:none;border-radius:6px;cursor:pointer;">Reset &amp; Reseed</button>
		</div>`)
	}

	// --- Recent Users ---
	sb.WriteString(`<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:hsl(var(--muted-foreground));margin-bottom:12px;">Recent Users</div>`)
	sb.WriteString(`<div style="background:hsl(var(--card));border:1px solid hsl(var(--border));border-radius:8px;overflow:hidden;margin-bottom:32px;">`)
	sb.WriteString(`<table style="width:100%;border-collapse:collapse;font-size:13px;">
		<thead><tr style="border-bottom:1px solid hsl(var(--border));">
			<th style="text-align:left;padding:10px 16px;font-weight:600;color:hsl(var(--muted-foreground));font-size:11px;text-transform:uppercase;letter-spacing:0.04em;">Email</th>
			<th style="text-align:left;padding:10px 16px;font-weight:600;color:hsl(var(--muted-foreground));font-size:11px;text-transform:uppercase;letter-spacing:0.04em;">Role</th>
			<th style="text-align:left;padding:10px 16px;font-weight:600;color:hsl(var(--muted-foreground));font-size:11px;text-transform:uppercase;letter-spacing:0.04em;">Last Login</th>
			<th style="text-align:left;padding:10px 16px;font-weight:600;color:hsl(var(--muted-foreground));font-size:11px;text-transform:uppercase;letter-spacing:0.04em;">Joined</th>
			<th style="text-align:right;padding:10px 16px;font-weight:600;color:hsl(var(--muted-foreground));font-size:11px;text-transform:uppercase;letter-spacing:0.04em;"></th>
		</tr></thead><tbody>`)

	userRows, _ := QueryRows(app.DB, "SELECT id, COALESCE(email, phone, username, 'User #' || id) as email, role, last_login_at, created_at FROM _benmore_users ORDER BY created_at DESC LIMIT 10")
	for _, row := range userRows {
		uid := fmt.Sprintf("%v", row["id"])
		email := fmt.Sprintf("%v", row["email"])
		if email == "<nil>" || email == "" {
			email = fmt.Sprintf("User #%v", row["id"])
		}
		role := fmt.Sprintf("%v", row["role"])
		lastLogin := fmt.Sprintf("%v", row["last_login_at"])
		joined := fmt.Sprintf("%v", row["created_at"])
		if lastLogin == "<nil>" || lastLogin == "" {
			lastLogin = "Never"
		}

		roleBg := "hsl(var(--muted))"
		roleColor := "hsl(var(--muted-foreground))"
		if role == "admin" {
			roleBg = "hsl(var(--primary) / 0.15)"
			roleColor = "hsl(var(--primary))"
		}

		sb.WriteString(fmt.Sprintf(`<tr style="border-bottom:1px solid hsl(var(--border)/0.5);">
			<td style="padding:8px 16px;color:hsl(var(--foreground));font-weight:500;">%s</td>
			<td style="padding:8px 16px;"><span style="font-size:11px;font-weight:600;padding:2px 8px;border-radius:10px;background:%s;color:%s;">%s</span></td>
			<td style="padding:8px 16px;color:hsl(var(--muted-foreground));font-size:12px;">%s</td>
			<td style="padding:8px 16px;color:hsl(var(--muted-foreground));font-size:12px;">%s</td>
			<td style="padding:8px 16px;text-align:right;"><a href="/_admin/_benmore_users/%s" style="font-size:11px;color:hsl(var(--primary));text-decoration:none;font-weight:600;">Step In</a></td>
		</tr>`, html.EscapeString(email), roleBg, roleColor, html.EscapeString(role), html.EscapeString(lastLogin), html.EscapeString(joined), html.EscapeString(uid)))
	}
	if len(userRows) == 0 {
		sb.WriteString(`<tr><td colspan="5" style="padding:24px;text-align:center;color:hsl(var(--muted-foreground));">No users yet.</td></tr>`)
	}
	sb.WriteString(`</tbody></table></div>`)

	// --- Recent Activity ---
	sb.WriteString(`<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:hsl(var(--muted-foreground));margin-bottom:12px;">Recent Activity</div>`)
	sb.WriteString(`<div style="background:hsl(var(--card));border:1px solid hsl(var(--border));border-radius:8px;overflow:hidden;">`)
	sb.WriteString(`<table style="width:100%;border-collapse:collapse;font-size:13px;">
		<thead><tr style="border-bottom:1px solid hsl(var(--border));">
			<th style="text-align:left;padding:10px 16px;font-weight:600;color:hsl(var(--muted-foreground));font-size:11px;text-transform:uppercase;letter-spacing:0.04em;">Action</th>
			<th style="text-align:left;padding:10px 16px;font-weight:600;color:hsl(var(--muted-foreground));font-size:11px;text-transform:uppercase;letter-spacing:0.04em;">Table</th>
			<th style="text-align:left;padding:10px 16px;font-weight:600;color:hsl(var(--muted-foreground));font-size:11px;text-transform:uppercase;letter-spacing:0.04em;">User</th>
			<th style="text-align:right;padding:10px 16px;font-weight:600;color:hsl(var(--muted-foreground));font-size:11px;text-transform:uppercase;letter-spacing:0.04em;">When</th>
		</tr></thead><tbody>`)

	auditRows, _ := QueryRows(app.DB, "SELECT action, table_name, row_id, user_email, created_at FROM _benmore_audit_log ORDER BY created_at DESC LIMIT 15")
	for _, row := range auditRows {
		action := fmt.Sprintf("%v", row["action"])
		tableName := fmt.Sprintf("%v", row["table_name"])
		email := fmt.Sprintf("%v", row["user_email"])
		created := fmt.Sprintf("%v", row["created_at"])
		rowID := fmt.Sprintf("%v", row["row_id"])

		actionColor := "hsl(var(--muted-foreground))"
		switch action {
		case "insert":
			actionColor = "#059669"
		case "delete":
			actionColor = "#dc2626"
		case "update":
			actionColor = "#d97706"
		}

		sb.WriteString(fmt.Sprintf(`<tr style="border-bottom:1px solid hsl(var(--border)/0.5);">
			<td style="padding:8px 16px;"><span style="font-size:11px;font-weight:600;color:%s;text-transform:uppercase;">%s</span></td>
			<td style="padding:8px 16px;"><a href="/_admin/%s/%s" style="color:hsl(var(--foreground));text-decoration:none;">%s #%s</a></td>
			<td style="padding:8px 16px;color:hsl(var(--muted-foreground));">%s</td>
			<td style="padding:8px 16px;text-align:right;color:hsl(var(--muted-foreground));font-size:12px;">%s</td>
		</tr>`, actionColor, html.EscapeString(action), html.EscapeString(tableName), html.EscapeString(rowID), html.EscapeString(tableName), html.EscapeString(rowID), html.EscapeString(email), html.EscapeString(created)))
	}
	if len(auditRows) == 0 {
		sb.WriteString(`<tr><td colspan="4" style="padding:24px;text-align:center;color:hsl(var(--muted-foreground));">No activity recorded yet.</td></tr>`)
	}
	sb.WriteString(`</tbody></table></div>`)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, adminShell(sb.String(), "Dashboard", "", app, session))
}

func serveAdminTable(w http.ResponseWriter, r *http.Request, app *App, table string) {
	if !isValidColumnName(table) {
		notFoundHandler(app)(w, r)
		return
	}
	// admin.yaml: hidden tables are not reachable by URL either, even
	// if an admin guesses the path. Keeps the hide directive honest.
	if app.Admin.IsTableHidden(table) {
		notFoundHandler(app)(w, r)
		return
	}
	cols, err := GetTableColumns(app.DB, table)
	if err != nil {
		notFoundHandler(app)(w, r)
		return
	}

	page := queryParamInt(r, "page", 1)
	perPage := 50
	offset := (page - 1) * perPage
	search := r.URL.Query().Get("q")

	// Build query
	query := fmt.Sprintf("SELECT * FROM %s", table)
	var args []any
	if search != "" {
		var conditions []string
		for _, col := range cols {
			conditions = append(conditions, fmt.Sprintf("%s LIKE ?", col.Name))
			args = append(args, "%"+search+"%")
		}
		query += " WHERE " + strings.Join(conditions, " OR ")
	}
	query += fmt.Sprintf(" ORDER BY id DESC LIMIT %d OFFSET %d", perPage, offset)

	rows, _ := QueryRows(app.DB, query, args...)
	var total int64
	app.DB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", table)).Scan(&total)

	csrf := generateCSRFToken()

	var sb strings.Builder

	// Header with create button
	sb.WriteString(fmt.Sprintf(`<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
		<div>
			<div style="font-size:1.25rem;font-weight:700;color:hsl(var(--foreground));">%s</div>
			<div style="font-size:12px;color:hsl(var(--muted-foreground));margin-top:2px;">%d records &middot; %d columns</div>
		</div>
		<button onclick="document.getElementById('admin-create').showModal()" style="padding:8px 16px;font-size:13px;font-weight:500;background:hsl(var(--primary));color:hsl(var(--primary-foreground));border:none;border-radius:6px;cursor:pointer;">+ Create</button>
	</div>`, html.EscapeString(strings.Title(table)), total, len(cols)))

	// Search
	sb.WriteString(fmt.Sprintf(`<form method="GET" action="/_admin/%s" style="margin-bottom:16px;">
		<input name="q" value="%s" placeholder="Search %s..." style="height:36px;padding:0 12px;border:1px solid hsl(var(--border));border-radius:6px;background:hsl(var(--card));color:hsl(var(--foreground));font-size:13px;width:280px;">
	</form>`, table, html.EscapeString(search), table))

	// Table
	sb.WriteString(`<div style="background:hsl(var(--card));border:1px solid hsl(var(--border));border-radius:8px;overflow:hidden;overflow-x:auto;">`)
	sb.WriteString(`<table style="width:100%;border-collapse:collapse;font-size:13px;"><thead><tr style="border-bottom:1px solid hsl(var(--border));">`)
	for _, col := range cols {
		sb.WriteString(fmt.Sprintf(`<th style="text-align:left;padding:10px 12px;font-weight:600;color:hsl(var(--muted-foreground));font-size:11px;text-transform:uppercase;letter-spacing:0.04em;white-space:nowrap;">%s</th>`, formatColName(col.Name)))
	}
	sb.WriteString(`<th style="text-align:right;padding:10px 12px;font-weight:600;color:hsl(var(--muted-foreground));font-size:11px;text-transform:uppercase;letter-spacing:0.04em;">Actions</th></tr></thead><tbody>`)

	for _, row := range rows {
		id := fmt.Sprintf("%v", row["id"])
		sb.WriteString(`<tr style="border-bottom:1px solid hsl(var(--border)/0.5);">`)
		for _, col := range cols {
			val := fmt.Sprintf("%v", row[col.Name])
			if val == "<nil>" {
				val = ""
			}
			if len(val) > 60 {
				val = val[:60] + "..."
			}
			sb.WriteString(fmt.Sprintf(`<td style="padding:8px 12px;color:hsl(var(--foreground));white-space:nowrap;max-width:200px;overflow:hidden;text-overflow:ellipsis;">%s</td>`, html.EscapeString(val)))
		}
		sb.WriteString(fmt.Sprintf(`<td style="padding:8px 12px;text-align:right;white-space:nowrap;">
			<a href="/_admin/%s/%s" style="font-size:12px;color:hsl(var(--primary));text-decoration:none;margin-right:12px;">Edit</a>
			<button style="font-size:12px;color:hsl(var(--destructive));background:none;border:none;cursor:pointer;" hx-post="/_admin/api/%s/delete/%s" hx-target="closest tr" hx-swap="outerHTML swap:0.2s" hx-confirm="Delete this record?" hx-vals='{"_csrf":"%s"}'>Delete</button>
		</td>`, table, id, table, id, csrf))
		sb.WriteString(`</tr>`)
	}

	if len(rows) == 0 {
		sb.WriteString(fmt.Sprintf(`<tr><td colspan="%d" style="padding:32px;text-align:center;color:hsl(var(--muted-foreground));">No records found.</td></tr>`, len(cols)+1))
	}

	sb.WriteString(`</tbody></table></div>`)

	// Pagination
	totalPages := (int(total) + perPage - 1) / perPage
	if totalPages > 1 {
		sb.WriteString(`<div style="display:flex;gap:8px;margin-top:16px;align-items:center;">`)
		if page > 1 {
			sb.WriteString(fmt.Sprintf(`<a href="/_admin/%s?page=%d&q=%s" style="padding:6px 12px;font-size:12px;border:1px solid hsl(var(--border));border-radius:6px;text-decoration:none;color:hsl(var(--foreground));background:hsl(var(--card));">Prev</a>`, table, page-1, search))
		}
		sb.WriteString(fmt.Sprintf(`<span style="font-size:12px;color:hsl(var(--muted-foreground));">Page %d of %d (%d total)</span>`, page, totalPages, total))
		if page < totalPages {
			sb.WriteString(fmt.Sprintf(`<a href="/_admin/%s?page=%d&q=%s" style="padding:6px 12px;font-size:12px;border:1px solid hsl(var(--border));border-radius:6px;text-decoration:none;color:hsl(var(--foreground));background:hsl(var(--card));">Next</a>`, table, page+1, search))
		}
		sb.WriteString(`</div>`)
	}

	// Create modal
	sb.WriteString(fmt.Sprintf(`<dialog id="admin-create" style="border:1px solid hsl(var(--border));border-radius:12px;background:hsl(var(--card));color:hsl(var(--foreground));box-shadow:0 20px 60px rgba(0,0,0,0.3);max-width:480px;width:100%%;padding:0;">
		<div style="padding:20px 24px;border-bottom:1px solid hsl(var(--border));display:flex;align-items:center;justify-content:space-between;">
			<span style="font-size:15px;font-weight:600;">Create %s</span>
			<button onclick="this.closest('dialog').close()" style="background:none;border:none;cursor:pointer;font-size:18px;color:hsl(var(--muted-foreground));">&times;</button>
		</div>
		<div style="padding:20px 24px;"><form method="POST" action="/_admin/api/%s/create">
		<input type="hidden" name="_csrf" value="%s">`, strings.Title(table), table, csrf))

	for _, col := range cols {
		if col.PK || col.Name == "created_at" || col.Name == "updated_at" || col.Name == "user_id" {
			continue
		}
		if col.Name == "password" || col.Name == "password_hash" {
			continue
		}
		inputType := "text"
		if strings.Contains(strings.ToUpper(col.Type), "INT") || strings.Contains(strings.ToUpper(col.Type), "REAL") {
			inputType = "number"
		}
		if strings.Contains(col.Name, "date") {
			inputType = "date"
		}
		if strings.Contains(col.Name, "email") {
			inputType = "email"
		}
		sb.WriteString(fmt.Sprintf(`<div style="margin-bottom:12px;">
			<label style="display:block;font-size:12px;font-weight:500;color:hsl(var(--muted-foreground));margin-bottom:4px;">%s</label>
			<input type="%s" name="%s" placeholder="%s" style="width:100%%;height:36px;padding:0 12px;border:1px solid hsl(var(--border));border-radius:6px;background:hsl(var(--background));color:hsl(var(--foreground));font-size:13px;">
		</div>`, formatColName(col.Name), inputType, col.Name, col.Name))
	}

	sb.WriteString(`<button type="submit" style="width:100%;padding:10px;font-size:13px;font-weight:500;background:hsl(var(--primary));color:hsl(var(--primary-foreground));border:none;border-radius:6px;cursor:pointer;margin-top:8px;">Create</button></form></div></dialog>`)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	session := getSession(app, r)
	fmt.Fprint(w, adminShell(sb.String(), strings.Title(table), table, app, session))
}

func serveAdminDetail(w http.ResponseWriter, r *http.Request, app *App, table, id string) {
	if !isValidColumnName(table) {
		notFoundHandler(app)(w, r)
		return
	}
	if app.Admin.IsTableHidden(table) {
		notFoundHandler(app)(w, r)
		return
	}
	rows, err := QueryRows(app.DB, fmt.Sprintf("SELECT * FROM %s WHERE id = ?", table), id)
	if err != nil || len(rows) == 0 {
		notFoundHandler(app)(w, r)
		return
	}
	row := rows[0]
	cols, _ := GetTableColumns(app.DB, table)
	csrf := generateCSRFToken()

	var sb strings.Builder

	// Header
	sb.WriteString(fmt.Sprintf(`<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
		<div style="font-size:1.25rem;font-weight:700;color:hsl(var(--foreground));">%s #%s</div>
		<a href="/_admin/%s" style="padding:8px 16px;font-size:13px;border:1px solid hsl(var(--border));border-radius:6px;text-decoration:none;color:hsl(var(--foreground));background:hsl(var(--card));">Back to list</a>
	</div>`, strings.Title(table), id, table))

	// Edit form
	sb.WriteString(fmt.Sprintf(`<div style="background:hsl(var(--card));border:1px solid hsl(var(--border));border-radius:8px;padding:24px;">
		<form method="POST" action="/_admin/api/%s/update/%s">
		<input type="hidden" name="_csrf" value="%s">`, table, id, csrf))

	for _, col := range cols {
		val := fmt.Sprintf("%v", row[col.Name])
		if val == "<nil>" {
			val = ""
		}

		if col.PK {
			sb.WriteString(fmt.Sprintf(`<div style="margin-bottom:16px;">
				<label style="display:block;font-size:12px;font-weight:500;color:hsl(var(--muted-foreground));margin-bottom:4px;">%s</label>
				<input value="%v" disabled style="width:100%%;height:36px;padding:0 12px;border:1px solid hsl(var(--border));border-radius:6px;background:hsl(var(--muted));color:hsl(var(--muted-foreground));font-size:13px;">
			</div>`, formatColName(col.Name), row[col.Name]))
			continue
		}
		if col.Name == "password_hash" {
			continue
		}

		inputType := "text"
		if strings.Contains(strings.ToUpper(col.Type), "INT") || strings.Contains(strings.ToUpper(col.Type), "REAL") {
			inputType = "number"
		}
		if strings.Contains(col.Name, "date") {
			inputType = "date"
		}
		if strings.Contains(col.Name, "email") {
			inputType = "email"
		}
		if col.Name == "role" && table == "_benmore_users" {
			// Show all roles defined in app config, plus defaults
			sb.WriteString(fmt.Sprintf(`<div style="margin-bottom:16px;">
				<label style="display:block;font-size:12px;font-weight:500;color:hsl(var(--muted-foreground));margin-bottom:4px;">%s</label>
				<select name="%s" style="width:100%%;height:36px;padding:0 12px;border:1px solid hsl(var(--border));border-radius:6px;background:hsl(var(--background));color:hsl(var(--foreground));font-size:13px;">
					<option value="user" %s>user</option>
					<option value="admin" %s>admin</option>`,
				formatColName(col.Name), col.Name, sel(val, "user"), sel(val, "admin")))
			if app.Roles != nil {
				for roleName := range app.Roles.Roles {
					if roleName != "admin" && roleName != "user" {
						sb.WriteString(fmt.Sprintf(`<option value="%s" %s>%s</option>`, roleName, sel(val, roleName), roleName))
					}
				}
			}
			sb.WriteString(`</select></div>`)
			continue
		}

		sb.WriteString(fmt.Sprintf(`<div style="margin-bottom:16px;">
			<label style="display:block;font-size:12px;font-weight:500;color:hsl(var(--muted-foreground));margin-bottom:4px;">%s</label>
			<input type="%s" name="%s" value="%s" style="width:100%%;height:36px;padding:0 12px;border:1px solid hsl(var(--border));border-radius:6px;background:hsl(var(--background));color:hsl(var(--foreground));font-size:13px;">
		</div>`, formatColName(col.Name), inputType, col.Name, html.EscapeString(val)))
	}

	sb.WriteString(`<button type="submit" style="padding:10px 24px;font-size:13px;font-weight:500;background:hsl(var(--primary));color:hsl(var(--primary-foreground));border:none;border-radius:6px;cursor:pointer;">Save Changes</button></form></div>`)

	// Related records
	allTables, _ := GetTableNames(app.DB)
	for _, otherTable := range allTables {
		if otherTable == table {
			continue
		}
		fkCol := strings.TrimSuffix(table, "s") + "_id"
		if !hasColumn(app, otherTable, fkCol) {
			continue
		}
		related, _ := QueryRows(app.DB, fmt.Sprintf("SELECT * FROM %s WHERE %s = ? LIMIT 20", otherTable, fkCol), id)
		if len(related) == 0 {
			continue
		}
		relCols, _ := GetTableColumns(app.DB, otherTable)

		sb.WriteString(fmt.Sprintf(`<div style="margin-top:24px;">
			<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:hsl(var(--muted-foreground));margin-bottom:8px;">Related %s (%d)</div>
			<div style="background:hsl(var(--card));border:1px solid hsl(var(--border));border-radius:8px;overflow:hidden;">
			<table style="width:100%%;border-collapse:collapse;font-size:12px;"><thead><tr style="border-bottom:1px solid hsl(var(--border));">`, strings.Title(otherTable), len(related)))

		for _, rc := range relCols {
			if rc.Name == "password_hash" {
				continue
			}
			sb.WriteString(fmt.Sprintf(`<th style="text-align:left;padding:8px 12px;font-weight:600;color:hsl(var(--muted-foreground));font-size:10px;text-transform:uppercase;">%s</th>`, formatColName(rc.Name)))
		}
		sb.WriteString(`</tr></thead><tbody>`)
		for _, rr := range related {
			sb.WriteString(`<tr style="border-bottom:1px solid hsl(var(--border)/0.5);">`)
			for _, rc := range relCols {
				if rc.Name == "password_hash" {
					continue
				}
				v := fmt.Sprintf("%v", rr[rc.Name])
				if v == "<nil>" {
					v = ""
				}
				if len(v) > 50 {
					v = v[:50] + "..."
				}
				sb.WriteString(fmt.Sprintf(`<td style="padding:6px 12px;color:hsl(var(--foreground));">%s</td>`, html.EscapeString(v)))
			}
			sb.WriteString(`</tr>`)
		}
		sb.WriteString(`</tbody></table></div></div>`)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	session := getSession(app, r)
	fmt.Fprint(w, adminShell(sb.String(), fmt.Sprintf("%s #%s", strings.Title(table), id), table, app, session))
}

func sel(val, option string) string {
	if val == option {
		return "selected"
	}
	return ""
}
