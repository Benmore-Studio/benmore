//go:build !cli

package main

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// :create="table" on a <form>
	createDirectiveRe = regexp.MustCompile(`(<form\s[^>]*):create="([^"]+)"([^>]*)>`)

	// :delete="table" :id="expr"  - strict form, table + id together
	deleteDirectiveRe = regexp.MustCompile(`(<\w+\s[^>]*):delete="([^"]+)"\s*:id="([^"]+)"([^>]*)>`)

	// :delete="/api/url/{{id}}" - URL form, mirrors :patch's URL form.
	// Matches when :delete value starts with "/" (path, not table name).
	deleteURLDirectiveRe = regexp.MustCompile(`(<\w+\s[^>]*):delete="(/[^"]+)"([^>]*)>`)

	// :patch="url" :set="field=value" on any element - strict form
	patchDirectiveRe = regexp.MustCompile(`(<\w+\s[^>]*):patch="([^"]+)"\s*:set="([^"]+)"([^>]*)>`)

	// :patch="url" alone (no :set) - bare URL form
	patchURLDirectiveRe = regexp.MustCompile(`(<\w+\s[^>]*):patch="(/[^"]+)"([^>]*)>`)

	// :confirm="message" on any element with hx- attributes
	confirmDirectiveRe = regexp.MustCompile(`:confirm="([^"]+)"`)

	// :target="selector" for HTMX target override
	targetDirectiveRe = regexp.MustCompile(`:target="([^"]+)"`)
)

// CompileDirectives transforms :create, :delete, :patch directives into HTMX attributes.
//
// Order matters: the strict (table+id) form runs first so it consumes
// the :delete="table" :id="..." pattern. The URL-form pass that
// follows then only matches bare :delete="/path/...". Same idea for
// :patch - strict :patch :set form first, then bare :patch URL form.
func CompileDirectives(content string) string {
	content = compileCreateDirectives(content)
	content = compileDeleteDirectives(content)
	content = compileDeleteURLDirectives(content)
	content = compilePatchDirectives(content)
	content = compilePatchURLDirectives(content)
	content = compileValidateDirectives(content)
	return content
}

func compileCreateDirectives(content string) string {
	return createDirectiveRe.ReplaceAllStringFunc(content, func(match string) string {
		m := createDirectiveRe.FindStringSubmatch(match)
		if m == nil {
			return match
		}

		prefix := m[1] // <form ...
		table := m[2]  // table name
		suffix := m[3] // remaining attrs

		// Build HTMX form attributes
		hxAttrs := fmt.Sprintf(
			`hx-post="/api/%s" hx-target="closest form" hx-swap="outerHTML" hx-indicator=".htmx-indicator"`,
			table,
		)

		// Check for :target override
		if targetMatch := targetDirectiveRe.FindStringSubmatch(suffix); targetMatch != nil {
			hxAttrs = strings.Replace(hxAttrs, `hx-target="closest form"`, fmt.Sprintf(`hx-target="%s"`, targetMatch[1]), 1)
			suffix = targetDirectiveRe.ReplaceAllString(suffix, "")
		}

		return fmt.Sprintf(`%s %s%s>`, prefix, hxAttrs, suffix)
	})
}

func compileDeleteDirectives(content string) string {
	return deleteDirectiveRe.ReplaceAllStringFunc(content, func(match string) string {
		m := deleteDirectiveRe.FindStringSubmatch(match)
		if m == nil {
			return match
		}

		prefix := m[1] // <button ...
		table := m[2]  // table name
		id := m[3]     // ID expression (may contain mustache)
		suffix := m[4] // remaining attrs

		// Build HTMX delete attributes
		// hx-target uses a single `closest` keyword with a comma-separated
		// CSS selector list (passed to Element.closest()) so the row to
		// remove is whichever ancestor matches first. Previous syntax was
		// `closest tr, closest .card, closest li` which HTMX parsed as
		// closest("tr, closest .card, closest li") - invalid CSS, delete
		// failed silently. Override with :target="..." if you need
		// something more specific.
		hxAttrs := fmt.Sprintf(
			`hx-delete="/api/%s/%s" hx-target="closest tr, li, [class*='row'], [class*='item'], [class*='card'], [data-row]" hx-swap="outerHTML swap:0.2s" hx-confirm="Are you sure?"`,
			table, id,
		)

		// Check for custom :confirm
		if confirmMatch := confirmDirectiveRe.FindStringSubmatch(suffix); confirmMatch != nil {
			hxAttrs = strings.Replace(hxAttrs, `hx-confirm="Are you sure?"`, fmt.Sprintf(`hx-confirm="%s"`, confirmMatch[1]), 1)
			suffix = confirmDirectiveRe.ReplaceAllString(suffix, "")
		}

		return fmt.Sprintf(`%s %s%s>`, prefix, hxAttrs, suffix)
	})
}

func compileDeleteURLDirectives(content string) string {
	return deleteURLDirectiveRe.ReplaceAllStringFunc(content, func(match string) string {
		m := deleteURLDirectiveRe.FindStringSubmatch(match)
		if m == nil {
			return match
		}
		prefix := m[1]
		url := m[2]
		suffix := m[3]

		hxAttrs := fmt.Sprintf(
			`hx-delete="%s" hx-target="closest tr, li, [class*='row'], [class*='item'], [class*='card'], [data-row]" hx-swap="outerHTML swap:0.2s" hx-confirm="Are you sure?"`,
			url,
		)
		if confirmMatch := confirmDirectiveRe.FindStringSubmatch(suffix); confirmMatch != nil {
			hxAttrs = strings.Replace(hxAttrs, `hx-confirm="Are you sure?"`, fmt.Sprintf(`hx-confirm="%s"`, confirmMatch[1]), 1)
			suffix = confirmDirectiveRe.ReplaceAllString(suffix, "")
		}
		return fmt.Sprintf(`%s %s%s>`, prefix, hxAttrs, suffix)
	})
}

func compilePatchURLDirectives(content string) string {
	return patchURLDirectiveRe.ReplaceAllStringFunc(content, func(match string) string {
		m := patchURLDirectiveRe.FindStringSubmatch(match)
		if m == nil {
			return match
		}
		prefix := m[1]
		url := m[2]
		suffix := m[3]

		hxAttrs := fmt.Sprintf(
			`hx-patch="%s" hx-target="closest tr, li, [class*='row'], [class*='item'], [class*='card'], [data-row]" hx-swap="outerHTML swap:0.2s"`,
			url,
		)
		if confirmMatch := confirmDirectiveRe.FindStringSubmatch(suffix); confirmMatch != nil {
			hxAttrs += fmt.Sprintf(` hx-confirm="%s"`, confirmMatch[1])
			suffix = confirmDirectiveRe.ReplaceAllString(suffix, "")
		}
		return fmt.Sprintf(`%s %s%s>`, prefix, hxAttrs, suffix)
	})
}

func compilePatchDirectives(content string) string {
	return patchDirectiveRe.ReplaceAllStringFunc(content, func(match string) string {
		m := patchDirectiveRe.FindStringSubmatch(match)
		if m == nil {
			return match
		}

		prefix := m[1] // <element ...
		url := m[2]    // /api/table/:id
		set := m[3]    // field=value
		suffix := m[4] // remaining attrs

		// Emit hx-vals as a DOUBLE-quoted attribute with " escaped to &quot;.
		// Single-quoted was fragile: if a user value (or a mustache block that
		// expanded to one) contained a ', the attribute closed early and HTMX
		// tried to JSON.parse a truncated string ("Unterminated string at
		// position N"). Double quotes sidestep that because ' is legal inside
		// a double-quoted attribute, and the " in the JSON structure is safely
		// expressed as the HTML entity.
		vals := buildHxVals(set)
		vals = strings.ReplaceAll(vals, `"`, "&quot;")

		hxAttrs := fmt.Sprintf(
			`hx-patch="%s" hx-vals="%s" hx-swap="outerHTML"`,
			url, vals,
		)

		return fmt.Sprintf(`%s %s%s>`, prefix, hxAttrs, suffix)
	})
}

// buildHxVals converts "field=value" or "field=value,field2=value2" to JSON for hx-vals.
func buildHxVals(set string) string {
	pairs := strings.Split(set, ",")
	var parts []string
	for _, pair := range pairs {
		kv := strings.SplitN(strings.TrimSpace(pair), "=", 2)
		if len(kv) == 2 {
			parts = append(parts, fmt.Sprintf(`"%s":"%s"`, kv[0], kv[1]))
		}
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// compileValidateDirectives processes :validate="rules" on form fields.
// 1. Injects an error <div> after each validated field
// 2. Adds HTML5 required attribute where applicable
// 3. Injects per-form validation JS that runs on submit + blur
// 4. Strips :validate from the output HTML
func compileValidateDirectives(content string) string {
	fieldValRe := regexp.MustCompile(`(<(?:input|select|textarea)\s[^>]*?)(\s*):validate="([^"]+)"([^>]*>)`)
	formIDCounter := 0

	// Track which forms have validated fields (by position)
	// First pass: find all validated fields and their containing forms
	// Replace :validate with HTML5 attrs + error divs
	content = fieldValRe.ReplaceAllStringFunc(content, func(match string) string {
		m := fieldValRe.FindStringSubmatch(match)
		if m == nil {
			return match
		}
		prefix := m[1]
		rules := m[3]
		suffix := m[4]

		// Extract field name
		nameMatch := regexp.MustCompile(`name="([^"]+)"`).FindStringSubmatch(prefix + suffix)
		fieldName := ""
		if nameMatch != nil {
			fieldName = nameMatch[1]
		}

		// Build HTML5 attributes from rules
		var htmlAttrs []string
		for _, rule := range strings.Split(rules, ",") {
			rule = strings.TrimSpace(rule)
			parts := strings.SplitN(rule, ":", 2)
			switch parts[0] {
			case "required":
				// Don't add native required - it breaks on hidden fields.
				// The JS validation from data-validate handles required checks.
			case "email":
				htmlAttrs = append(htmlAttrs, `type="email"`)
			case "minlen":
				if len(parts) == 2 {
					htmlAttrs = append(htmlAttrs, fmt.Sprintf(`minlength="%s"`, parts[1]))
				}
			case "maxlen":
				if len(parts) == 2 {
					htmlAttrs = append(htmlAttrs, fmt.Sprintf(`maxlength="%s"`, parts[1]))
				}
			case "min":
				if len(parts) == 2 {
					htmlAttrs = append(htmlAttrs, fmt.Sprintf(`min="%s"`, parts[1]))
				}
			case "max":
				if len(parts) == 2 {
					htmlAttrs = append(htmlAttrs, fmt.Sprintf(`max="%s"`, parts[1]))
				}
			case "number":
				htmlAttrs = append(htmlAttrs, `type="number"`)
			}
		}

		attrStr := ""
		if len(htmlAttrs) > 0 {
			attrStr = " " + strings.Join(htmlAttrs, " ")
		}

		// Add data-validate attribute for JS validation
		dataAttr := fmt.Sprintf(` data-validate="%s"`, rules)

		// Build: original element (with HTML5 attrs + data-validate) + error div
		errorDiv := ""
		if fieldName != "" {
			errorDiv = fmt.Sprintf(`<div class="benmore-field-error" data-for="%s" style="display:none;color:#dc2626;font-size:12px;margin-top:2px;"></div>`, fieldName)
		}

		// For textarea, skip the error div here - it gets injected after </textarea> in a second pass
		if strings.Contains(strings.ToLower(prefix), "<textarea") {
			return prefix + attrStr + dataAttr + suffix
		}

		return prefix + attrStr + dataAttr + suffix + errorDiv
	})

	// Inject error divs after </textarea> for validated textareas
	textareaErrRe := regexp.MustCompile(`(<textarea\s[^>]*data-validate="[^"]*"[^>]*name="([^"]+)"[^>]*>[\s\S]*?</textarea>)`)
	content = textareaErrRe.ReplaceAllStringFunc(content, func(match string) string {
		m := textareaErrRe.FindStringSubmatch(match)
		if m == nil {
			return match
		}
		fieldName := m[2]
		errorDiv := fmt.Sprintf(`<div class="benmore-field-error" data-for="%s" style="display:none;color:#dc2626;font-size:12px;margin-top:2px;"></div>`, fieldName)
		return m[1] + errorDiv
	})
	// Also handle case where name comes before data-validate
	textareaErrRe2 := regexp.MustCompile(`(<textarea\s[^>]*name="([^"]+)"[^>]*data-validate="[^"]*"[^>]*>[\s\S]*?</textarea>)`)
	content = textareaErrRe2.ReplaceAllStringFunc(content, func(match string) string {
		m := textareaErrRe2.FindStringSubmatch(match)
		if m == nil {
			return match
		}
		fieldName := m[2]
		// Only inject if not already present (avoid duplicates from first regex)
		errorDiv := fmt.Sprintf(`<div class="benmore-field-error" data-for="%s"`, fieldName)
		if strings.Contains(match, errorDiv) {
			return match
		}
		errorDiv = fmt.Sprintf(`<div class="benmore-field-error" data-for="%s" style="display:none;color:#dc2626;font-size:12px;margin-top:2px;"></div>`, fieldName)
		return m[1] + errorDiv
	})

	// Second pass: inject validation JS after each form that has data-validate fields
	formRe := regexp.MustCompile(`</form>`)
	content = formRe.ReplaceAllStringFunc(content, func(match string) string {
		formIDCounter++
		return match + fmt.Sprintf(`<script>(function(){
var f=document.currentScript.previousElementSibling;
if(!f||f.tagName!=='FORM')return;
var fields=f.querySelectorAll('[data-validate]');
if(!fields.length)return;
function validateField(el){
  var rules=(el.getAttribute('data-validate')||'').split(',');
  var val=el.value.trim();
  var name=el.getAttribute('name');
  var errEl=f.querySelector('.benmore-field-error[data-for="'+name+'"]');
  for(var i=0;i<rules.length;i++){
    var r=rules[i].trim(),p=r.split(':'),rn=p[0],rp=p[1]||'';
    var msg='';
    if(rn==='required'&&!val)msg=name.replace(/_/g,' ')+' is required';
    else if(rn==='email'&&val&&!/^[^@]+@[^@]+\.[^@]+$/.test(val))msg='Must be a valid email';
    else if(rn==='minlen'&&val.length<parseInt(rp))msg='Must be at least '+rp+' characters';
    else if(rn==='maxlen'&&val.length>parseInt(rp))msg='Must be at most '+rp+' characters';
    else if(rn==='min'&&parseFloat(val)<parseFloat(rp))msg='Must be at least '+rp;
    else if(rn==='max'&&parseFloat(val)>parseFloat(rp))msg='Must be at most '+rp;
    else if(rn==='number'&&val&&isNaN(parseFloat(val)))msg='Must be a number';
    else if(rn==='phone'&&val&&!/^[\d\s\-\+\(\)]{7,20}$/.test(val))msg='Must be a valid phone number';
    if(msg){
      el.style.borderColor='#dc2626';
      if(errEl){errEl.textContent=msg;errEl.style.display='';}
      return false;
    }
  }
  el.style.borderColor='';
  if(errEl){errEl.textContent='';errEl.style.display='none';}
  return true;
}
fields.forEach(function(el){el.addEventListener('blur',function(){validateField(el)});});
f.addEventListener('submit',function(e){
  var valid=true;
  fields.forEach(function(el){if(el.offsetParent!==null&&!validateField(el))valid=false;});
  if(!valid){e.preventDefault();e.stopPropagation();}
});
})();</script>`)
	})

	return content
}
