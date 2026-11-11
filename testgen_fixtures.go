//go:build !cli

package main

// What the framework test generator knows about the identity its tests sign
// in as, and how it builds a row that identity can create.
//
// A generated test must assert what the app declares. Expecting a route to
// work for a table an access rule closes, or for a role whose scopes do not
// name the table, reports a correct app as broken; so does a create that is
// missing a required parent row or that repeats another test's unique value.
// The helpers here predict the refusals from the same gates the handlers run
// (access mode, then role scopes) and plan a valid row: required parents are
// created through the API first, each saving its new id for the child, and
// unique columns get values no other generated row shares. When no valid row
// can be built the plan says why, and the test is reported as skipped with
// that reason instead of failing.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"
)

// generatedTestSession mirrors the session the test runner's loginTestUser
// yields for a fresh identity: the given primary role, a verified address, no
// tenant and no extra role grants, with the app's roles: scopes applied the way
// the session loader applies them.
func generatedTestSession(app *App, email, role string) *Session {
	if role == "" {
		role = "user"
	}
	s := &Session{UserID: 1, Email: email, Role: role, Roles: []string{role}, Verified: true, GlobalAdmin: role == "admin"}
	if app == nil {
		return s
	}
	return applySessionRoleScopes(app, s)
}

// plainGeneratedSession is the session of frameworkTestUser.
func plainGeneratedSession(app *App) *Session {
	return generatedTestSession(app, frameworkTestUser, "user")
}

// generatedDenial is how an auto-CRUD route refuses a request outright.
type generatedDenial struct {
	status   int
	contains string
}

func (d generatedDenial) denied() bool { return d.status != 0 }

func (d generatedDenial) expect() AppTestExpect {
	return AppTestExpect{Status: d.status, Contains: []string{d.contains}}
}

var generatedRouteDenial = generatedDenial{http.StatusNotFound, "no API route matches this path"}

// generatedOpDenial is EnforceCRUDAccess refusing a create, update or delete
// on a table the caller may read (writeCRUDOpDenied).
var generatedOpDenial = generatedDenial{http.StatusForbidden, "access rules do not let you"}

// generatedCRUDDenial predicts the table-level refusal of op for session, in
// the order the handlers check: the access mode (EnforceCRUDAccess answers it
// like an unmatched route, or 403 for a write on a table the caller may read)
// and then the role scopes (checkScope, 403). The zero value means neither
// refuses; row scope, hooks and validation still run.
func generatedCRUDDenial(app *App, table string, op AccessOp, session *Session) generatedDenial {
	if app == nil {
		return generatedRouteDenial
	}
	hasUID := hasColumn(app, table, "user_id")
	hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
	mode := app.Access.ModeFor(table, op, hasUID, hasGroupKey)
	if mode == "off" {
		return generatedRouteDenial
	}
	if !tableModeAllowed(app, table, op, mode, session, 0) {
		// A group-mode read with no tenant yet is an empty list, not a refusal.
		if !(op == OpRead && mode == "group" && session != nil && !session.EffectiveHasGroup() && !session.IsAdminBypass() && (hasUID || hasGroupKey)) {
			if op != OpRead && crudReadGatePasses(app, table, session, hasUID, hasGroupKey) {
				return generatedOpDenial
			}
			return generatedRouteDenial
		}
	}
	action := "write"
	switch op {
	case OpRead:
		action = "read"
	case OpDelete:
		action = "delete"
	}
	if session != nil && checkScope(session, table, action) != nil {
		return generatedDenial{http.StatusForbidden, "scope denied"}
	}
	return generatedDenial{}
}

// generatedWriteGuaranteed reports whether session can DEFINITELY create a row
// in table: an owner or public write mode its gates admit, no tenant key (the
// generated identities have no tenant) and no before_insert hook that could
// abort it for reasons the generator can't see.
func generatedWriteGuaranteed(app *App, table string, session *Session) bool {
	if app == nil {
		return false
	}
	hasUID := hasColumn(app, table, "user_id")
	hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
	switch app.Access.ModeFor(table, OpWrite, hasUID, hasGroupKey) {
	case "self", "everyone", "anon", "public":
	default:
		// off, admin, group, role:*, perm:*, member-of:*, owner_or_role:*
		return false
	}
	if hasGroupKey {
		return false
	}
	if app.Hooks != nil {
		if h, ok := app.Hooks.BeforeInsert[table]; ok && len(h) > 0 {
			return false
		}
	}
	return !generatedCRUDDenial(app, table, OpWrite, session).denied()
}

// generatedOwnUser is the identity of a test that needs one to itself: a
// unique index lets one account hold a single row of the table it creates.
func generatedOwnUser(key, role string) string {
	sum := sha256.Sum256([]byte(role + "\x00" + key))
	return "_test_user_" + hex.EncodeToString(sum[:6]) + "@benmore.test"
}

// generatedRow is a row a generated test can create as its identity.
type generatedRow struct {
	// Steps create the parent rows the row references, in order; each saves
	// the new row's key for Data to use.
	Steps []AppTestStep
	Data  map[string]any
	// Skip says why no valid row can be built; the test is then skipped.
	Skip string
	// OwnUser: a unique index allows one row per account, so the test signs
	// in as an identity of its own (generatedOwnUser).
	OwnUser bool
	// Batchable: every unique index has a column re-valued per row, so two
	// rows can go in one batch (Variant).
	Batchable bool
	perRow    []Column
}

// Variant returns Data with every per-row unique column re-valued for token,
// so several rows of one test do not collide.
func (r generatedRow) Variant(token string) map[string]any {
	out := make(map[string]any, len(r.Data))
	for k, v := range r.Data {
		out[k] = v
	}
	for _, col := range r.perRow {
		if v, ok := generatedUniqueValue(col, token); ok {
			out[col.Name] = v
		}
	}
	return out
}

// varies reports whether column gets a unique value per row.
func (r generatedRow) varies(column string) bool {
	for _, col := range r.perRow {
		if identIs(col.Name, column) {
			return true
		}
	}
	return false
}

// generatedParentDepth bounds how many levels of required parents a plan
// creates before it gives up and skips the journey.
const generatedParentDepth = 4

type generatedRowPlanner struct {
	app     *App
	session *Session
	vars    int
}

// planGeneratedRow plans a row of table that session can create. key names
// the test; it seeds the unique values, so every test writes its own.
func planGeneratedRow(app *App, table, key string, session *Session) generatedRow {
	p := &generatedRowPlanner{app: app, session: session}
	return p.plan(table, key, map[string]bool{}, 0)
}

func (p *generatedRowPlanner) plan(table, token string, visiting map[string]bool, depth int) generatedRow {
	app := p.app
	row := generatedRow{Data: map[string]any{}, Batchable: true}
	if app == nil || app.DB == nil {
		row.Skip = "the app's database is not open"
		return row
	}
	folded := sqliteIdentifierFold(table)
	visiting[folded] = true
	defer delete(visiting, folded)

	if app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key) && !p.session.EffectiveHasGroup() {
		row.Skip = fmt.Sprintf("%s is keyed by the tenant column %s, and the generated test identity belongs to no tenant", table, app.Group.Key)
		return row
	}
	cols := tableColumns(app, table)
	if len(cols) == 0 {
		row.Skip = fmt.Sprintf("the columns of %s could not be read", table)
		return row
	}
	declared, err := GetForeignKeys(app.DB, table)
	if err != nil {
		row.Skip = fmt.Sprintf("the foreign keys of %s could not be read", table)
		return row
	}
	refs := foreignKeyRefs(app, table)
	for name, ref := range declared {
		refs[name] = ref
	}
	refFor := func(col string) (ForeignKey, bool) {
		for name, ref := range refs {
			if identIs(name, col) {
				return ref, true
			}
		}
		return ForeignKey{}, false
	}

	data := smartFormData(app, table, cols)
	protected := protectedCreateFields(app, table)
	owned := commandOwnedColumns(app, table)
	for name := range data {
		if protected.has(name) || owned[sqliteIdentifierFold(name)] != "" {
			delete(data, name)
		}
	}
	// The API never accepts a primary key from a client: the database must
	// supply a fresh one for every row.
	pkCount := 0
	for _, c := range cols {
		if c.PK {
			pkCount++
		}
	}
	for _, c := range cols {
		if !c.PK || (pkCount == 1 && strings.Contains(strings.ToUpper(c.Type), "INT")) {
			continue
		}
		if generatedConstantDefault(c.Default) {
			row.Skip = fmt.Sprintf("the primary key %s.%s defaults to the constant %s, so the API can create only one row", table, c.Name, c.Default)
			return row
		}
		if c.Default == "" && c.NotNull {
			row.Skip = fmt.Sprintf("the primary key %s.%s has no default, and the API never accepts one from a client", table, c.Name)
			return row
		}
	}
	for _, c := range cols {
		if c.PK || !c.NotNull || c.Default != "" || identIs(c.Name, "user_id") {
			continue
		}
		if protected.has(c.Name) {
			row.Skip = fmt.Sprintf("required column %s.%s has no default, and the API never accepts it from a client", table, c.Name)
			return row
		}
		if flow := owned[sqliteIdentifierFold(c.Name)]; flow != "" {
			row.Skip = fmt.Sprintf("required column %s.%s has no default and is owned by command %s", table, c.Name, flow)
			return row
		}
	}

	// A membership-scoped write needs a parent row the identity is a member
	// of: create it, and its create founds the membership.
	if rule := memberOfFor(app, table, OpWrite); rule != nil && !p.session.IsAdminBypass() {
		local, ok := rule.joinTarget(app, table)
		if !ok {
			row.Skip = fmt.Sprintf("access.%s write is member-of:%s, but %s has no %s column", table, rule.Table, table, rule.JoinCol)
			return row
		}
		if local != "id" {
			parent := p.memberOfParent(table, local, rule, refFor)
			if parent == "" {
				row.Skip = fmt.Sprintf("writes to %s need a %s membership, and no parent the generated test identity can create founds one", table, rule.Table)
				return row
			}
			ref, why := p.createParent(&row, parent, "id", token, visiting, depth)
			if why != "" {
				row.Skip = fmt.Sprintf("writes to %s need a %s membership in a %s row: %s", table, rule.Table, parent, why)
				return row
			}
			data[local] = ref
		}
	}

	// Required foreign keys reference a parent created first.
	for _, c := range cols {
		ref, isFK := refFor(c.Name)
		if !isFK || c.PK || identIs(c.Name, "user_id") || !c.NotNull || c.Default != "" {
			continue
		}
		if _, planned := data[c.Name]; planned {
			continue
		}
		parentCol := ref.Column
		if parentCol == "" {
			parentCol = "id"
		}
		if strings.HasPrefix(sqliteIdentifierFold(ref.Table), "_benmore_") {
			if identIs(ref.Table, "_benmore_users") && identIs(parentCol, "id") {
				data[c.Name] = "{{user_id}}"
				continue
			}
			row.Skip = fmt.Sprintf("required column %s.%s references the framework table %s", table, c.Name, ref.Table)
			return row
		}
		value, why := p.createParent(&row, ref.Table, parentCol, token, visiting, depth)
		if why != "" {
			row.Skip = fmt.Sprintf("required column %s.%s references %s: %s", table, c.Name, ref.Table, why)
			return row
		}
		data[c.Name] = value
	}

	p.applyUniqueValues(&row, table, cols, data, token, refFor, protected, owned)
	row.Data = data
	return row
}

// createParent plans a parent row, appends the steps that create it and
// returns the reference the child uses, or why it can't.
func (p *generatedRowPlanner) createParent(row *generatedRow, parent, parentCol, token string, visiting map[string]bool, depth int) (string, string) {
	app := p.app
	switch {
	case visiting[sqliteIdentifierFold(parent)]:
		return "", "the row would have to exist before itself"
	case depth+1 >= generatedParentDepth:
		return "", "the chain of required parent rows is too long to build"
	case !appHasTable(app, parent):
		return "", fmt.Sprintf("%s is not an auto-CRUD table", parent)
	case !generatedWriteGuaranteed(app, parent, p.session):
		return "", fmt.Sprintf("the generated test identity cannot create %s rows through the API", parent)
	}
	sub := p.plan(parent, token+">"+parent, visiting, depth+1)
	if sub.Skip != "" {
		return "", sub.Skip
	}
	row.Steps = append(row.Steps, sub.Steps...)
	row.OwnUser = row.OwnUser || sub.OwnUser
	p.vars++
	name := fmt.Sprintf("fw_parent_%d", p.vars)
	row.Steps = append(row.Steps, AppTestStep{
		API:    "POST /api/" + parent,
		Data:   sub.Data,
		Save:   map[string]string{name: parentCol},
		Expect: AppTestExpect{Status: http.StatusOK},
	})
	return "{{" + name + "}}", ""
}

// memberOfParent returns the table whose new rows found the membership a
// child's member-of write needs, or "": the child's join column must point at
// it, and its own read rule must be the same membership with the table as
// the parent (so creating a row adds the creator as a member).
func (p *generatedRowPlanner) memberOfParent(table, local string, rule *memberOfRule, refFor func(string) (ForeignKey, bool)) string {
	app := p.app
	candidates := []string{}
	if ref, ok := refFor(local); ok {
		candidates = append(candidates, ref.Table)
	}
	for mt, fks := range app.joinMapSnapshot() {
		if !identIs(mt, rule.Table) {
			continue
		}
		for col, fk := range fks {
			if identIs(col, rule.JoinCol) {
				candidates = append(candidates, fk.Table)
			}
		}
	}
	for _, t := range userTables(app) {
		if memberOfJoinNamesTable(local, t) {
			candidates = append(candidates, t)
		}
	}
	for _, parent := range candidates {
		pr := memberOfFor(app, parent, OpRead)
		if pr == nil || !identIs(pr.Table, rule.Table) || !identIs(pr.JoinCol, rule.JoinCol) || !identIs(pr.UserCol, rule.UserCol) || !memberOfAutoJoins(app, parent, pr) {
			continue
		}
		if !generatedMembershipInsertable(app, rule) {
			return ""
		}
		return parent
	}
	return ""
}

// generatedMembershipInsertable reports whether the founding membership row
// (memberOfAutoJoin: join, member and user_id columns) satisfies every
// required column of the membership table.
func generatedMembershipInsertable(app *App, rule *memberOfRule) bool {
	for _, c := range tableColumns(app, rule.Table) {
		if c.PK || !c.NotNull || c.Default != "" {
			continue
		}
		if identIs(c.Name, rule.JoinCol) || identIs(c.Name, rule.UserCol) || identIs(c.Name, "user_id") {
			continue
		}
		return false
	}
	return true
}

// applyUniqueValues gives each unique index of table a value no other
// generated row shares. A column the row sets gets a value derived from token
// (re-derived per row in a batch); an index made only of the owner column and
// columns that can't vary needs an identity per test (OwnUser).
func (p *generatedRowPlanner) applyUniqueValues(row *generatedRow, table string, cols []Column, data map[string]any, token string, refFor func(string) (ForeignKey, bool), protected protectedFields, owned map[string]string) {
	byName := map[string]Column{}
	for _, c := range cols {
		byName[sqliteIdentifierFold(c.Name)] = c
	}
	varied := map[string]bool{}
	for _, index := range generatedUniqueIndexes(p.app.DB, table) {
		perRow, perTest, owner := false, false, false
		for _, name := range index {
			key := sqliteIdentifierFold(name)
			col, known := byName[key]
			if identIs(name, "user_id") {
				owner = true
				continue
			}
			if !known || col.PK {
				perRow = perRow || (known && col.PK)
				continue
			}
			value, inData := data[col.Name]
			if s, ok := value.(string); ok && strings.HasPrefix(s, "{{") {
				if s == "{{user_id}}" {
					owner = true
				} else {
					perTest = true // a parent created by this test
				}
				continue
			}
			if !inData {
				// Omitted: NULL never collides, but a column default does.
				if _, isFK := refFor(col.Name); isFK || col.Default == "" || protected.has(col.Name) || owned[key] != "" {
					continue
				}
			}
			if varied[key] {
				perRow = true
				continue
			}
			if v, ok := generatedUniqueValue(col, token); ok {
				data[col.Name] = v
				varied[key] = true
				row.perRow = append(row.perRow, col)
				perRow = true
			}
		}
		if !perRow {
			row.Batchable = false
			if !perTest && owner {
				row.OwnUser = true
			}
		}
	}
}

// generatedUniqueIndexes lists the columns of table's UNIQUE indexes,
// constraints and partial indexes alike (a partial index still refuses the
// duplicate rows it covers). The primary key's index and expression terms
// are left out.
func generatedUniqueIndexes(db *sql.DB, table string) [][]string {
	rows, err := db.Query(`SELECT name FROM pragma_index_list(?) WHERE "unique" = 1 AND origin <> 'pk'`, table)
	if err != nil {
		return nil
	}
	var names []string
	for rows.Next() {
		var name string
		if rows.Scan(&name) == nil {
			names = append(names, name)
		}
	}
	rows.Close()
	var out [][]string
	for _, name := range names {
		colRows, err := db.Query(`SELECT name FROM pragma_index_info(?) ORDER BY seqno`, name)
		if err != nil {
			continue
		}
		var cols []string
		for colRows.Next() {
			var col sql.NullString
			if colRows.Scan(&col) == nil && col.Valid {
				cols = append(cols, col.String)
			}
		}
		colRows.Close()
		if len(cols) > 0 {
			out = append(out, cols)
		}
	}
	return out
}

// generatedUniqueValue returns col's usual generated value made distinct by
// token, keeping the shape a validator expects (an email stays an email).
// ok=false for a boolean, which has no room for a distinct value.
func generatedUniqueValue(col Column, token string) (string, bool) {
	sum := sha256.Sum256([]byte(token))
	n := binary.BigEndian.Uint32(sum[:4])
	tag := hex.EncodeToString(sum[:5])
	upper := strings.ToUpper(col.Type)
	name := strings.ToLower(col.Name)
	switch {
	case strings.Contains(upper, "BOOL"):
		return "", false
	case strings.Contains(upper, "REAL") || strings.Contains(upper, "FLOAT") || strings.Contains(upper, "DOUBLE") || strings.Contains(upper, "DECIMAL") || strings.Contains(upper, "NUMERIC"):
		return fmt.Sprintf("%d.%02d", 1000+n%1000000, n%100), true
	case strings.Contains(upper, "DATE") || strings.Contains(upper, "TIME"):
		return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, int(n%36500)).Format("2006-01-02"), true
	case strings.Contains(upper, "INT"):
		return fmt.Sprint(100000 + n%900000000), true
	}
	switch {
	case name == "email" || strings.HasSuffix(name, "_email"):
		return "fw-" + tag + "@example.com", true
	case name == "url" || name == "website" || strings.HasSuffix(name, "_url"):
		return "https://example.com/fw-" + tag, true
	case name == "phone" || strings.HasSuffix(name, "_phone"):
		return fmt.Sprintf("555-%07d", n%10000000), true
	case strings.Contains(name, "date") || strings.Contains(name, "time"):
		return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, int(n%36500)).Format("2006-01-02"), true
	}
	return smartTestValue(col) + "-" + tag, true
}

// generatedConstantDefault reports a column default that is the same value
// for every row (a literal), as opposed to an expression such as a generated
// UUID or the current time.
func generatedConstantDefault(def string) bool {
	d := strings.TrimSpace(def)
	for strings.HasPrefix(d, "(") && strings.HasSuffix(d, ")") {
		d = strings.TrimSpace(d[1 : len(d)-1])
	}
	if d == "" {
		return false
	}
	if len(d) >= 2 && strings.HasPrefix(d, "'") && strings.HasSuffix(d, "'") && !strings.Contains(d[1:len(d)-1], "'") {
		return true
	}
	if _, err := strconv.ParseFloat(d, 64); err == nil {
		return true
	}
	switch strings.ToUpper(d) {
	case "NULL", "TRUE", "FALSE":
		return true
	}
	return false
}

// generatedEnumLikeColumn names columns whose generated value is likely one
// of a fixed set (a CHECK constraint or validator), so a lifecycle journey
// should not identify its row by a varied value there.
func generatedEnumLikeColumn(name string) bool {
	switch strings.ToLower(name) {
	case "status", "state", "type", "kind", "category", "stage", "priority", "role", "color", "hex",
		"currency", "country", "zip", "postal_code", "region", "locale", "language", "lang", "timezone",
		"gender", "plan", "tier", "visibility", "mode", "level", "unit", "format", "provider", "channel",
		"source", "method", "frequency", "interval", "period", "size", "phone":
		return true
	}
	return false
}

// generatedAnonCreateExpect is how a create without a session or CSRF token
// is refused on table: by the API auth gate (401), by an access rule that
// removes the route (404) or, on an anonymous-write table, by the CSRF check.
func generatedAnonCreateExpect(app *App, table string) AppTestExpect {
	hasUID := hasColumn(app, table, "user_id")
	hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
	mode := app.Access.ModeFor(table, OpWrite, hasUID, hasGroupKey)
	anon := app.Access.AllowsAnon(mode)
	authGate := app.Design != nil && len(app.Design.Auth) > 0 && !anon
	if authGate {
		if publicTables, ok := app.Design.Auth["public_api"]; ok {
			for _, t := range strings.Split(fmt.Sprintf("%v", publicTables), ",") {
				if strings.TrimSpace(t) == table {
					authGate = false
				}
			}
		}
	}
	switch {
	case authGate:
		return AppTestExpect{Status: http.StatusUnauthorized}
	case mode == "off":
		return generatedRouteDenial.expect()
	case !anon:
		return AppTestExpect{Status: http.StatusUnauthorized}
	}
	return AppTestExpect{Status: http.StatusForbidden, Contains: []string{"Invalid CSRF token"}}
}

// appOwnedPageExpect reports how the app's own pages answer a GET of path
// when no framework route claims it (a feature switched off): a
// server-rendered page route, then an HTML page under static/ including the
// index fallback. signedIn is whether the request carries the plain test
// user's session. owned=false means nothing answers and the router's 404
// stands; skip is set when a role- or field-gated page answers, whose answer
// the generator can't predict.
func appOwnedPageExpect(app *App, path string, signedIn bool) (expect AppTestExpect, skip string, owned bool) {
	if app == nil {
		return AppTestExpect{}, "", false
	}
	if len(app.Pages) > 0 {
		mux := http.NewServeMux()
		for route := range app.Pages {
			func() {
				defer func() { _ = recover() }() // a colliding page never registers either
				mux.HandleFunc(pageMuxPattern(route), func(http.ResponseWriter, *http.Request) {})
			}()
		}
		if _, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, path, nil)); pattern != "" {
			for route, source := range app.Pages {
				if pageMuxPattern(route) != pattern {
					continue
				}
				page := pageRouteSnapshot(source)
				if role := pageRole(&page); page.Require != "" || (role != "" && role != "public") {
					return AppTestExpect{}, fmt.Sprintf("the app's gated page %s answers %s", route, path), true
				}
				if page.Auth == "required" && !signedIn {
					return AppTestExpect{Status: http.StatusSeeOther, Redirect: app.Paths.Login}, "", true
				}
				return AppTestExpect{Status: http.StatusOK}, "", true
			}
		}
	}
	rec := httptest.NewRecorder()
	if serveStaticHTML(rec, httptest.NewRequest(http.MethodGet, path, nil), app) {
		return AppTestExpect{Status: rec.Code}, "", true
	}
	return AppTestExpect{}, "", false
}
