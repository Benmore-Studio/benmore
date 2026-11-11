//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"time"
)

// Page render data (RenderContext.Data) is read by name from author
// templates, and both engines read more than a value's text. html/template
// reaches every exported field and method of what it is handed and prints
// structs with fmt; mustache prints anything it does not know with fmt and
// JSON-encodes it for pipes and scripts. A framework object placed there is
// therefore readable in full: `current_user` was the *Session, so
// `{{current_user}}` wrote the stored session key hash, user id, address and
// roles into the page, `{{current_user | json}}` every exported field, and a
// gotmpl page could read `.current_user.ID` or call the session's methods.
//
// Render data holds template values only: text, numbers, booleans, times,
// rows, maps and lists of them, and pageViewer. sealPageData enforces it for
// every render, so a framework object can't become reachable under any name.

// pageViewer is the page value `current_user` for a signed-in viewer: a
// signed-in test (`{{#current_user}}`, `{{if .current_user}}`) that prints
// nothing. It carries only the three values a page already has by name
// (user_id, user_email, user_role), so a gotmpl page that read them as
// `.current_user.UserID`, `.Email` or `.Role` keeps rendering. An anonymous
// viewer's `current_user` is the empty string: falsy and empty in both
// engines.
type pageViewer struct {
	UserID int64
	Email  string
	Role   string
}

// Format prints nothing for every verb (%v, %+v, %#v, %s, %d ...), so no
// template form, pipe or helper that formats the value writes its fields.
func (pageViewer) Format(fmt.State, rune) {}

// MarshalJSON is `true`: in a script or through a json pipe the value stays
// a truthy signed-in test and carries no field.
func (pageViewer) MarshalJSON() ([]byte, error) { return []byte("true"), nil }

// pageCurrentUser is the page value `current_user` for session.
func pageCurrentUser(session *Session) any {
	if session == nil {
		return ""
	}
	return pageViewer{UserID: session.UserID, Email: session.Email, Role: session.Role}
}

// sealPageData replaces every value in data that is not a template value
// with the empty string, which both engines read as empty and falsy. It
// names the key and the type in the log (never the value): a replaced value
// is a framework bug, and the page stays up without the object on it.
func sealPageData(data map[string]any) {
	for key, v := range data {
		if !templateValue(v) {
			log.Printf("SECURITY page data %q held a %T, which is not a template value; templates read it as empty", key, v)
			data[key] = ""
		}
	}
}

// templateValue reports whether v may sit in page render data.
func templateValue(v any) bool {
	switch v.(type) {
	case nil, string, bool, int, int64, float64, []byte, time.Time, json.Number,
		map[string]any, []map[string]any, []any, layoutPageHTML, pageViewer:
		return true
	}
	return templateValueType(reflect.TypeOf(v), 0)
}

var timeType = reflect.TypeOf(time.Time{})

// templateValueType judges a type the fast path above does not list: basic
// kinds, and lists and maps of template values. An element typed `any`
// passes (rows and decoded JSON). Pointers, structs other than time.Time,
// funcs and channels do not, nor does a type nested deeper than any render
// data is.
func templateValueType(t reflect.Type, depth int) bool {
	if depth > 6 {
		return false
	}
	switch t.Kind() {
	case reflect.Bool, reflect.String,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	case reflect.Interface:
		return depth > 0
	case reflect.Slice, reflect.Array:
		return templateValueType(t.Elem(), depth+1)
	case reflect.Map:
		return templateValueType(t.Key(), depth+1) && templateValueType(t.Elem(), depth+1)
	case reflect.Struct:
		return t == timeType
	}
	return false
}
