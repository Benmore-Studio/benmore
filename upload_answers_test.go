//go:build !cli

package main

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// uploadPart is one file part of a test multipart body.
type uploadPart struct{ field, name, content string }

const pngBytes = "\x89PNG\r\n\x1a\nnot really an image"

// uploadRequest builds a multipart request carrying text fields and file
// parts, authenticated by a Bearer session.
func uploadRequest(t *testing.T, method, path, sid string, fields map[string]string, parts ...uploadPart) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range parts {
		fw, err := mw.CreateFormFile(p.field, p.name)
		if err != nil {
			t.Fatal(err)
		}
		fw.Write([]byte(p.content))
	}
	mw.Close()
	r := httptest.NewRequest(method, "https://app.example.com"+path, &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	if sid != "" {
		r.Header.Set("Authorization", "Bearer "+sid)
	}
	return r
}

// uploadRoutes mounts the two upload routes and the auto-CRUD create of
// `docs` on one mux, the way an app serves them.
func uploadRoutes(app *App) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterUploadRoute(mux, app)
	RegisterFileUploadRoute(mux, app)
	mux.HandleFunc("POST /api/docs", func(w http.ResponseWriter, r *http.Request) { handleCreate(w, r, app, "docs") })
	return mux
}

func answerJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("answer is not JSON: %d %q (%s)", w.Code, w.Body.String(), w.Header().Get("Content-Type"))
	}
	return out
}

const docsTable = "CREATE TABLE docs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, attachment TEXT)"

// On the hosted platform the media store decides an object's served type
// from its extension and refuses a file that has none. The app used to send
// the upload there anyway and pass the store's refusal on, doubled and
// naming an internal component ("save upload: save upload: presign broker:
// file type not allowed"). It is refused before the store is asked, with the
// same 415 on all three upload paths and a message that says what to change;
// nothing is stored and no ownership row is left.
func TestUploadWithoutExtensionOnPlatformMedia(t *testing.T) {
	// What the platform's store answers for such a key (the rule the app
	// applies early is the store's own).
	if _, _, err := brokerObjectMeta("uploads/private/0123456789abcdef."); err == nil {
		t.Fatal("the media store accepts a key with no extension: the early refusal no longer mirrors it")
	}
	app := newGateApp(t, docsTable)
	if err := EnsureUploadOwnersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	_, sid := gateUser(t, app, "owner@example.com")
	withPlatformMedia(t, &PlatformMediaConfig{Bucket: "media", Region: "us-east-1", CDNDomain: "cdn.example.test"})
	broker := startFakeMediaBroker(t, map[string]any{"error": "file type not allowed"})
	mux := uploadRoutes(app)

	for name, r := range map[string]*http.Request{
		"_upload private": uploadRequest(t, "POST", "/api/_upload", sid, map[string]string{"kind": "private"}, uploadPart{"file", "README", "plain text"}),
		"_upload public":  uploadRequest(t, "POST", "/api/_upload", sid, nil, uploadPart{"file", "README", "plain text"}),
		"_files":          uploadRequest(t, "POST", "/api/_files", sid, nil, uploadPart{"file", "README", "plain text"}),
		"create":          uploadRequest(t, "POST", "/api/docs", sid, map[string]string{"title": "no extension"}, uploadPart{"attachment", "README", "plain text"}),
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			body := answerJSON(t, w)
			msg, _ := body["error"].(string)
			if w.Code != http.StatusUnsupportedMediaType {
				t.Errorf("status = %d %s, want 415", w.Code, w.Body.String())
			}
			if !strings.Contains(msg, "extension") {
				t.Errorf("message %q does not say the file needs an extension", msg)
			}
			for _, internal := range []string{"presign", "broker", "save upload"} {
				if strings.Contains(msg, internal) {
					t.Errorf("message %q names %q", msg, internal)
				}
			}
		})
	}
	// The store's other extension refusal the app's own list does not hold.
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, uploadRequest(t, "POST", "/api/_upload", sid, nil, uploadPart{"file", "page.shtml", "plain text"}))
	if msg, _ := answerJSON(t, w)["error"].(string); w.Code != http.StatusUnsupportedMediaType || msg != "file type not allowed: .shtml" {
		t.Errorf(".shtml: %d %s, want 415 file type not allowed: .shtml", w.Code, w.Body.String())
	}
	if asked := broker.requests(); len(asked) != 0 {
		t.Errorf("the media store was asked %d times for files it refuses: %v", len(asked), asked)
	}
	if got := gateScalar(t, app, "SELECT COUNT(*) FROM _benmore_upload_owners"); got != "0" {
		t.Errorf("refused uploads left %s ownership rows", got)
	}
	if got := gateScalar(t, app, "SELECT COUNT(*) FROM docs WHERE title = 'no extension'"); got != "0" {
		t.Errorf("the refused create stored %s rows", got)
	}
}

// Any other refusal of the platform's media store reaches the client
// without the doubled prefix and without naming the component; the reason
// stays in the app log.
func TestPlatformMediaStoreFaultIsNotPassedOnVerbatim(t *testing.T) {
	app := newGateApp(t)
	_, sid := gateUser(t, app, "owner@example.com")
	withPlatformMedia(t, &PlatformMediaConfig{Bucket: "media", Region: "us-east-1", CDNDomain: "cdn.example.test"})
	startFakeMediaBroker(t, map[string]any{"error": "presign failed"})
	w := httptest.NewRecorder()
	uploadRoutes(app).ServeHTTP(w, uploadRequest(t, "POST", "/api/_upload", sid, nil, uploadPart{"file", "scan.png", pngBytes}))
	msg, _ := answerJSON(t, w)["error"].(string)
	if w.Code < 400 {
		t.Fatalf("a store fault answered %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(msg, "presign") || strings.Contains(msg, "broker") || strings.Count(msg, "save upload") > 1 {
		t.Errorf("message %q passes the store's internal text on", msg)
	}
}

// Self-hosted local storage has no such rule: a file with no extension is
// stored as `<id>.` (uploads.size_limits).
func TestUploadWithoutExtensionOnLocalStorage(t *testing.T) {
	app := newGateApp(t)
	_, sid := gateUser(t, app, "owner@example.com")
	w := httptest.NewRecorder()
	uploadRoutes(app).ServeHTTP(w, uploadRequest(t, "POST", "/api/_upload", sid, nil, uploadPart{"file", "README", "plain text"}))
	body := answerJSON(t, w)
	if path, _ := body["path"].(string); w.Code != http.StatusOK || !regexp.MustCompile(`^/uploads/files/[0-9a-f]{16}\.$`).MatchString(path) {
		t.Fatalf("local upload with no extension: %d %s, want 200 and /uploads/files/<id>.", w.Code, w.Body.String())
	}
}

// A zero-byte file is an upload like any other (uploads.size_limits).
func TestZeroByteUploadIsStored(t *testing.T) {
	app := newGateApp(t)
	_, sid := gateUser(t, app, "owner@example.com")
	w := httptest.NewRecorder()
	uploadRoutes(app).ServeHTTP(w, uploadRequest(t, "POST", "/api/_upload", sid, nil, uploadPart{"file", "empty.pdf", ""}))
	body := answerJSON(t, w)
	if w.Code != http.StatusOK || body["size"] != float64(0) || len(everyStoredUpload(t, app)) != 1 {
		t.Fatalf("zero-byte upload: %d %s, stored %v", w.Code, w.Body.String(), everyStoredUpload(t, app))
	}
}

// uploads.gotchas says an active file type is refused at upload with 415.
// POST /api/_upload answered 415; the multipart create and POST /api/_files
// answered 400 for the same file. Nothing is stored either way.
func TestRefusedFileTypeIs415OnEveryUploadPath(t *testing.T) {
	app := newGateApp(t, docsTable)
	_, sid := gateUser(t, app, "owner@example.com")
	mux := uploadRoutes(app)
	html := "<!DOCTYPE html><html><body><script>alert(1)</script></body></html>"
	for _, file := range []uploadPart{
		{"", "page.html", html},     // refused by content
		{"", "notes.txt", html},     // refused by content under a harmless name
		{"", "drawing.svg", "<svg"}, // refused by extension
	} {
		for path, field := range map[string]string{"/api/_upload": "file", "/api/_files": "file", "/api/docs": "attachment"} {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, uploadRequest(t, "POST", path, sid, map[string]string{"title": "refused type"}, uploadPart{field, file.name, file.content}))
			msg, _ := answerJSON(t, w)["error"].(string)
			if w.Code != http.StatusUnsupportedMediaType || !strings.Contains(msg, "file type not allowed") {
				t.Errorf("%s with %s: %d %s, want 415 file type not allowed", path, file.name, w.Code, w.Body.String())
			}
		}
	}
	if left := everyStoredUpload(t, app); len(left) != 0 {
		t.Errorf("refused files were stored: %v", left)
	}
	if got := gateScalar(t, app, "SELECT COUNT(*) FROM docs WHERE title = 'refused type'"); got != "0" {
		t.Errorf("refused creates stored %s rows", got)
	}
}

// The statuses the upload paths share: over the per-file cap is 413, a
// refused type or extension 415, anything else 400.
func TestUploadRefusalStatus(t *testing.T) {
	app := newGateApp(t)
	request := func(name, content string) *http.Request {
		return uploadRequest(t, "POST", "/api/anything", "", nil, uploadPart{"file", name, content})
	}
	for _, c := range []struct {
		name, content string
		maxSize       int64
		want          int
	}{
		{"big.bin", strings.Repeat("x", 4096), 1024, http.StatusRequestEntityTooLarge},
		{"page.html", "<html>", 0, http.StatusUnsupportedMediaType},
		{"archive.tar.gz!", "x", 0, http.StatusUnsupportedMediaType},
	} {
		_, _, err := handleFileUploadAt(app, request(c.name, c.content), "file", "docs", c.maxSize, nil)
		if err == nil {
			t.Fatalf("%s was accepted", c.name)
		}
		if got := uploadRefusalStatus(err); got != c.want {
			t.Errorf("%s (%v): status %d, want %d", c.name, err, got, c.want)
		}
	}
}

// A multipart create stored every file part, also one whose field is no
// column of the table (a typo in the input's name) or a column the create
// never takes from the request: the bytes stayed in storage, referenced by
// nothing, and the answer was 200. Such a part is not stored, and the answer
// names it the way it names other fields it did not use.
func TestMultipartCreateDoesNotStoreUnusedFileParts(t *testing.T) {
	for _, table := range []string{"docs", "private"} { // "private" is the folder that records an ownership row
		t.Run(table, func(t *testing.T) {
			app := newGateApp(t, "CREATE TABLE "+quoteIdent(table)+" (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, attachment TEXT)")
			if err := EnsureUploadOwnersTable(app.DB); err != nil {
				t.Fatal(err)
			}
			uid, sid := gateUser(t, app, "owner@example.com")
			create := func(title string, parts ...uploadPart) *httptest.ResponseRecorder {
				w := httptest.NewRecorder()
				handleCreate(w, uploadRequest(t, "POST", "/api/"+table, sid, map[string]string{"title": title}, parts...), app, table)
				return w
			}

			w := create("typo", uploadPart{"nosuchcol", "n.png", pngBytes})
			if w.Code != http.StatusOK {
				t.Fatalf("create with an unknown file field: %d %s, want 200 (not a refusal)", w.Code, w.Body.String())
			}
			if got := w.Header().Get(ignoredFieldsHeader); got != "nosuchcol" {
				t.Errorf("%s = %q, want nosuchcol", ignoredFieldsHeader, got)
			}
			if left := everyStoredUpload(t, app); len(left) != 0 {
				t.Errorf("the ignored file part was stored: %v", left)
			}
			if got := gateScalar(t, app, "SELECT COUNT(*) FROM _benmore_upload_owners"); got != "0" {
				t.Errorf("the ignored file part left %s ownership rows", got)
			}
			if got := gateScalar(t, app, "SELECT COALESCE(attachment, '') FROM "+quoteIdent(table)+" WHERE title = 'typo'"); got != "" {
				t.Errorf("attachment = %q, want empty", got)
			}

			// A file sent as the owner column: the create fills user_id from
			// the session, so the file is not stored and the field is named
			// as stripped.
			w = create("owner", uploadPart{"user_id", "u.png", pngBytes})
			if w.Code != http.StatusOK {
				t.Fatalf("create with a file as user_id: %d %s", w.Code, w.Body.String())
			}
			if got := w.Header().Get("X-Stripped-Fields"); got != "user_id" {
				t.Errorf("X-Stripped-Fields = %q, want user_id", got)
			}
			if left := everyStoredUpload(t, app); len(left) != 0 {
				t.Errorf("the stripped file part was stored: %v", left)
			}
			if got := gateScalar(t, app, "SELECT user_id FROM "+quoteIdent(table)+" WHERE title = 'owner'"); got != strings.TrimSpace(jsonNumber(uid)) {
				t.Errorf("user_id = %s, want the session's %d", got, uid)
			}

			// The file part of a real column is stored beside an ignored one.
			w = create("both", uploadPart{"attachment", "a.png", pngBytes}, uploadPart{"attachmnet", "b.png", pngBytes})
			if w.Code != http.StatusOK || w.Header().Get(ignoredFieldsHeader) != "attachmnet" {
				t.Fatalf("create with a used and an unused file: %d %s, %s=%q", w.Code, w.Body.String(), ignoredFieldsHeader, w.Header().Get(ignoredFieldsHeader))
			}
			if kept := everyStoredUpload(t, app); len(kept) != 1 {
				t.Errorf("stored %v, want only the attachment", kept)
			}
			if got := gateScalar(t, app, "SELECT COUNT(*) FROM "+quoteIdent(table)+" WHERE title = 'both' AND attachment LIKE '/uploads/%'"); got != "1" {
				t.Errorf("rows with the stored attachment: %s, want 1", got)
			}
		})
	}
}

func jsonNumber(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// A PATCH never stores a file. A multipart PATCH of file parts only answered
// 400 "No fields to update", which sent the builder to their field names; it
// says what an update does with a multipart body and what to send instead.
// (multipart_fields_test.go covers the text fields, for every credential.)
func TestMultipartPatchSaysWhatToSend(t *testing.T) {
	app := newGateApp(t, docsTable)
	uid, sid := gateUser(t, app, "owner@example.com")
	mustExecArgs(t, app.DB, "INSERT INTO docs (id, user_id, title, attachment) VALUES (1, ?, 'first', '')", uid)

	w := httptest.NewRecorder()
	handleUpdate(w, uploadRequest(t, "PATCH", "/api/docs/1", sid, nil, uploadPart{"attachment", "scan.png", pngBytes}), app, "docs")
	body := answerJSON(t, w)
	if w.Code != http.StatusBadRequest || body["error"] != "No fields to update" {
		t.Fatalf("multipart PATCH: %d %s, want 400 No fields to update", w.Code, w.Body.String())
	}
	hint, _ := body["hint"].(string)
	for _, want := range []string{"multipart", "text field", "/api/_upload"} {
		if !strings.Contains(hint, want) {
			t.Errorf("hint %q does not mention %s", hint, want)
		}
	}
	if body["docs"] != "uploads.multipart_bodies" {
		t.Errorf("docs = %v, want uploads.multipart_bodies", body["docs"])
	}
	if got := gateScalar(t, app, "SELECT title || '|' || COALESCE(attachment, '') FROM docs WHERE id = 1"); got != "first|" {
		t.Errorf("row after the refused PATCH: %q", got)
	}
	if left := everyStoredUpload(t, app); len(left) != 0 {
		t.Errorf("the PATCH stored %v", left)
	}

	// An update that names no field for another reason keeps its answer.
	w = gateCall(app, handleUpdate, "docs", "PATCH", "/api/docs/1", "application/json", `{}`, sid)
	if body := answerJSON(t, w); w.Code != http.StatusBadRequest || body["hint"] != nil {
		t.Errorf("empty JSON PATCH: %d %s, want the plain 400", w.Code, w.Body.String())
	}
}

// With features.uploads: false the two upload routes answered Go's
// plain-text "404 page not found", so bm.upload threw with that text as its
// code and nothing told the page uploads are switched off. They keep the
// 404 and answer JSON carrying the code the multipart create answers.
func TestUploadsOffRoutesAnswerJSONWithTheCode(t *testing.T) {
	app := newGateApp(t)
	setUploadsFeature(app, false)
	mux := uploadRoutes(app)
	for _, path := range []string{"/api/_upload", "/api/_files"} {
		body := &uploadCountingReader{r: strings.NewReader("never read")}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, body))
		got := answerJSON(t, w)
		if w.Code != http.StatusNotFound || body.n != 0 {
			t.Errorf("%s: status %d, %d body bytes read; want 404 before the body is read", path, w.Code, body.n)
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("%s: Content-Type %q, want JSON", path, ct)
		}
		if got["error"] != uploadsDisabledCode || got["docs"] != "uploads.feature_gate" {
			t.Errorf("%s: %s, want error %s and docs uploads.feature_gate", path, w.Body.String(), uploadsDisabledCode)
		}
		if msg, _ := got["message"].(string); !strings.Contains(msg, "features.uploads: false") {
			t.Errorf("%s: message %q does not name the switch", path, msg)
		}
	}
}

// The generated bm.d.ts typed bm.upload's answer as {path, url?, size,
// mime}; POST /api/_upload answers {path, url, filename, size} and no mime.
// The type's members are exactly the keys of the answer.
func TestUploadTypeMatchesTheAnswer(t *testing.T) {
	app := newGateApp(t)
	_, sid := gateUser(t, app, "owner@example.com")
	w := httptest.NewRecorder()
	uploadRoutes(app).ServeHTTP(w, uploadRequest(t, "POST", "/api/_upload", sid, map[string]string{"kind": "private"}, uploadPart{"file", "scan.png", pngBytes}))
	if w.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}
	answer := answerJSON(t, w)
	if answer["filename"] != "scan.png" || answer["size"] != float64(len(pngBytes)) || answer["path"] != answer["url"] {
		t.Errorf("answer = %s", w.Body.String())
	}
	var keys []string
	for k := range answer {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	types := GenerateBMTypes(app)
	decl := regexp.MustCompile(`(?s)export function upload\(.*?\): Promise<\{([^}]*)\}>;`).FindStringSubmatch(types)
	if decl == nil {
		t.Fatal("bm.d.ts declares no upload()")
	}
	var members []string
	for _, m := range regexp.MustCompile(`(\w+)\??:`).FindAllStringSubmatch(decl[1], -1) {
		members = append(members, m[1])
	}
	sort.Strings(members)
	if strings.Join(members, ",") != strings.Join(keys, ",") {
		t.Errorf("bm.d.ts upload() answers {%s}; the endpoint answers {%s}", strings.Join(members, ", "), strings.Join(keys, ", "))
	}
	if strings.Contains(decl[1], "?:") {
		t.Errorf("upload()'s answer marks a member optional that the endpoint always sends: %s", decl[1])
	}
}
