//go:build !cli

package main

// Legacy flow YAML parsing; GitHub Actions-style flow YAML is parsed in flows_gha.go.

import (
	"fmt"
	"strings"
	"time"
)

func parseFlows(content string) []Flow {
	var flows []Flow
	var current *Flow
	var stepStack []*[]FlowStep
	var currentStep *FlowStep

	lines := strings.Split(content, "\n")

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " "))

		// Flow name (indent 0)
		if indent == 0 && strings.HasSuffix(trimmed, ":") {
			if current != nil {
				flows = append(flows, *current)
			}
			current = &Flow{
				Name:  strings.TrimSuffix(trimmed, ":"),
				Steps: []FlowStep{},
			}
			stepStack = []*[]FlowStep{&current.Steps}
			currentStep = nil
			continue
		}

		if current == nil {
			continue
		}

		// Flow-level properties (indent 2)
		if indent == 2 {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			val = strings.Trim(val, `"'`)

			switch key {
			case "trigger":
				current.Trigger = parseTrigger(val)
			case "verify":
				current.Verify = val
			case "secret":
				current.Secret = val
			case "auth":
				current.Auth = val
			case "role":
				current.Role = val
			}
			continue
		}

		// Steps (indent 4+)
		if indent >= 4 && len(stepStack) > 0 {
			// Adjust stack depth based on indentation:
			// indent 4 = depth 1 (top-level steps)
			// indent 8 = depth 2 (nested steps inside if/for_each)
			// indent 12 = depth 3 (double-nested)
			targetDepth := (indent - 2) / 2 // 4->1, 6->2, 8->3, 10->4
			if targetDepth < 1 {
				targetDepth = 1
			}
			// Pop stack if we've come back out to a shallower level
			for len(stepStack) > targetDepth {
				stepStack = stepStack[:len(stepStack)-1]
				currentStep = nil
			}

			target := stepStack[len(stepStack)-1]

			// List item
			if strings.HasPrefix(trimmed, "- ") {
				trimmed = strings.TrimPrefix(trimmed, "- ")

				// Parse step
				step := parseFlowStepLine(trimmed)
				if step != nil {
					*target = append(*target, *step)
					currentStep = &(*target)[len(*target)-1]
				}
				continue
			}

			// Sub-property of current step
			if currentStep != nil {
				parts := strings.SplitN(trimmed, ":", 2)
				if len(parts) == 2 {
					key := strings.TrimSpace(parts[0])
					val := strings.TrimSpace(parts[1])
					val = strings.Trim(val, `"'`)

					// Block sub-properties that declare / promote the step's type.
					// Enables the idiomatic:
					//   - name: room
					//     api:
					//       method: POST
					// pattern where `- name: room` creates a placeholder step
					// and `api:` here promotes it to an API step before the
					// nested method/url/json lines get applied.
					if val == "" {
						switch key {
						case "api":
							if currentStep.API == nil {
								currentStep.API = &FlowAPICall{}
							}
							if currentStep.Type == "" {
								currentStep.Type = "api"
							}
							continue
						case "email":
							if currentStep.Email == nil {
								currentStep.Email = &FlowEmail{}
							}
							if currentStep.Type == "" {
								currentStep.Type = "email"
							}
							continue
						case "respond":
							if currentStep.Respond == nil {
								currentStep.Respond = &FlowRespond{}
							}
							if currentStep.Type == "" {
								currentStep.Type = "respond"
							}
							continue
						}
					}

					// Inline sub-properties that declare the step's type +
					// value in a single line (e.g. `sql: "UPDATE ..."` under
					// `- name: updater`). Only applied when the current step
					// doesn't already have a type.
					if currentStep.Type == "" && val != "" {
						switch key {
						case "sql":
							currentStep.Type = "sql"
							currentStep.SQL = val
							continue
						case "webhook":
							currentStep.Type = "webhook"
							currentStep.Webhook = val
							continue
						case "redirect":
							currentStep.Type = "redirect"
							currentStep.Redirect = val
							continue
						case "parse":
							currentStep.Type = "parse"
							currentStep.Parse = val
							continue
						}
					}

					// "steps:" pushes nested step list onto stack
					if key == "steps" && val == "" {
						stepStack = append(stepStack, &currentStep.Steps)
						currentStep = nil
						continue
					}
					// "else:" pushes else branch onto stack
					if key == "else" && val == "" {
						stepStack = append(stepStack, &currentStep.ElseSteps)
						currentStep = nil
						continue
					}
					// "json:" sub-block for respond/api steps - collect indented key-value pairs
					if key == "json" && val == "" {
						// Read subsequent indented lines as JSON key-value pairs
						jsonMap := make(map[string]any)
						for i+1 < len(lines) {
							nextLine := lines[i+1]
							nextTrimmed := strings.TrimSpace(nextLine)
							nextIndent := len(nextLine) - len(strings.TrimLeft(nextLine, " "))
							if nextTrimmed == "" || nextTrimmed[0] == '#' {
								i++
								continue
							}
							if nextIndent <= indent {
								break // back to same or shallower level
							}
							jParts := strings.SplitN(nextTrimmed, ":", 2)
							if len(jParts) == 2 {
								jKey := strings.TrimSpace(jParts[0])
								jVal := strings.TrimSpace(jParts[1])
								jVal = strings.Trim(jVal, `"'`)
								jsonMap[jKey] = jVal
							}
							i++
						}
						if currentStep.Respond != nil {
							currentStep.Respond.JSON = jsonMap
						} else if currentStep.API != nil {
							// Keep the nested map[string]any (it was flattened to
							// map[string]string, dropping arrays/objects). #94.
							currentStep.API.JSON = jsonMap
						}
						continue
					}

					// "form:" sub-block for api steps - collect form key-value pairs
					if key == "form" && val == "" && currentStep.API != nil {
						formMap := make(map[string]string)
						for i+1 < len(lines) {
							nextLine := lines[i+1]
							nextTrimmed := strings.TrimSpace(nextLine)
							nextIndent := len(nextLine) - len(strings.TrimLeft(nextLine, " "))
							if nextTrimmed == "" || nextTrimmed[0] == '#' {
								i++
								continue
							}
							if nextIndent <= indent {
								break
							}
							fParts := strings.SplitN(nextTrimmed, ":", 2)
							if len(fParts) == 2 {
								fKey := strings.TrimSpace(fParts[0])
								fVal := strings.TrimSpace(fParts[1])
								fVal = strings.Trim(fVal, `"'`)
								formMap[fKey] = fVal
							}
							i++
						}
						currentStep.API.Form = formMap
						continue
					}

					// "headers:" sub-block for api steps
					if key == "headers" && val == "" && currentStep.API != nil {
						headerMap := make(map[string]string)
						for i+1 < len(lines) {
							nextLine := lines[i+1]
							nextTrimmed := strings.TrimSpace(nextLine)
							nextIndent := len(nextLine) - len(strings.TrimLeft(nextLine, " "))
							if nextTrimmed == "" || nextTrimmed[0] == '#' {
								i++
								continue
							}
							if nextIndent <= indent {
								break
							}
							hParts := strings.SplitN(nextTrimmed, ":", 2)
							if len(hParts) == 2 {
								hKey := strings.TrimSpace(hParts[0])
								hVal := strings.TrimSpace(hParts[1])
								hVal = strings.Trim(hVal, `"'`)
								headerMap[hKey] = hVal
							}
							i++
						}
						currentStep.API.Headers = headerMap
						continue
					}

					// "sign:" sub-block for api steps - outbound auth recipe.
					// Captures the indented block raw and hands it to
					// parseSignBlock (yaml.v3) so we get proper map-order
					// preservation for compute: and nested before:/request:.
					if key == "sign" && val == "" && currentStep.API != nil {
						var block []string
						minIndent := -1
						for i+1 < len(lines) {
							nextLine := lines[i+1]
							nextTrimmed := strings.TrimSpace(nextLine)
							nextIndent := len(nextLine) - len(strings.TrimLeft(nextLine, " "))
							if nextTrimmed == "" || nextTrimmed[0] == '#' {
								block = append(block, nextLine)
								i++
								continue
							}
							if nextIndent <= indent {
								break
							}
							block = append(block, nextLine)
							if minIndent < 0 || nextIndent < minIndent {
								minIndent = nextIndent
							}
							i++
						}
						// Dedent block to column 0 so yaml.v3 parses it.
						var dedented []string
						for _, l := range block {
							if minIndent > 0 && len(l) >= minIndent && strings.TrimSpace(l) != "" {
								dedented = append(dedented, l[minIndent:])
							} else {
								dedented = append(dedented, strings.TrimLeft(l, " "))
							}
						}
						sign, err := parseSignBlock(strings.Join(dedented, "\n"))
						if err != nil {
							// Parse errors stop here - without a usable sign block,
							// the request would ship unauthenticated. Better to fail
							// at load time than at 403 time. We surface the error via
							// a flag the API step can refuse to run with.
							currentStep.API.Sign = &FlowAPISign{Bindings: map[string]string{"_parse_error": err.Error()}}
						} else {
							currentStep.API.Sign = sign
						}
						continue
					}

					applyStepProperty(currentStep, key, val)
				}
			}
		}
	}

	if current != nil {
		flows = append(flows, *current)
	}

	return flows
}

func parseTrigger(val string) FlowTrigger {
	val = strings.TrimSpace(val)

	if strings.HasPrefix(val, "POST ") || strings.HasPrefix(val, "GET ") {
		parts := strings.SplitN(val, " ", 2)
		return FlowTrigger{Type: "http", Method: parts[0], Path: parts[1]}
	}
	if strings.HasPrefix(val, "cron ") {
		return FlowTrigger{Type: "cron", Cron: strings.TrimPrefix(val, "cron ")}
	}
	if strings.HasPrefix(val, "on_insert ") {
		return FlowTrigger{Type: "on_insert", Table: strings.TrimPrefix(val, "on_insert ")}
	}
	if strings.HasPrefix(val, "on_update ") {
		return FlowTrigger{Type: "on_update", Table: strings.TrimPrefix(val, "on_update ")}
	}
	if strings.HasPrefix(val, "on_delete ") {
		return FlowTrigger{Type: "on_delete", Table: strings.TrimPrefix(val, "on_delete ")}
	}

	return FlowTrigger{}
}

func parseFlowStepLine(line string) *FlowStep {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return nil
	}
	key := strings.TrimSpace(parts[0])
	val := strings.TrimSpace(parts[1])
	val = strings.Trim(val, `"'`)

	switch key {
	case "sql":
		return &FlowStep{Type: "sql", SQL: val}
	case "webhook":
		return &FlowStep{Type: "webhook", Webhook: val}
	case "redirect":
		return &FlowStep{Type: "redirect", Redirect: val}
	case "if":
		return &FlowStep{Type: "if", Condition: val, Steps: []FlowStep{}}
	case "for_each":
		return &FlowStep{Type: "for_each", ForEach: val, Steps: []FlowStep{}}
	case "parse":
		return &FlowStep{Type: "parse", Parse: val}
	case "email":
		return &FlowStep{Type: "email", Email: &FlowEmail{}}
	case "api":
		return &FlowStep{Type: "api", API: &FlowAPICall{}}
	case "respond":
		return &FlowStep{Type: "respond", Respond: &FlowRespond{}}
	}

	// "name: step_name" starts a step whose type is declared via subsequent
	// sub-properties (api:, email:, sql:, etc.). Returning a placeholder here
	// means sub-properties apply to this step instead of leaking onto the
	// previous one or being silently dropped.
	if key == "name" {
		return &FlowStep{Name: val}
	}

	return nil
}

func applyStepProperty(step *FlowStep, key, val string) {
	switch key {
	case "name":
		step.Name = val
	case "body":
		if step.Type == "webhook" {
			step.WebhookBody = val
		} else if step.Email != nil {
			step.Email.Html = val
		} else if step.Respond != nil {
			step.Respond.Body = val
		} else if step.API != nil {
			step.API.Body = val
		}
	case "html":
		if step.Email != nil {
			step.Email.Html = val
		} else if step.Respond != nil && val != "" {
			// Preserve the pre-existing respond-JSON fallthrough for this key.
			if step.Respond.JSON == nil {
				step.Respond.JSON = make(map[string]any)
			}
			step.Respond.JSON[key] = val
		}
	case "text":
		if step.Email != nil {
			step.Email.Text = val
		} else if step.Respond != nil && val != "" {
			if step.Respond.JSON == nil {
				step.Respond.JSON = make(map[string]any)
			}
			step.Respond.JSON[key] = val
		}
	case "method":
		if step.API != nil {
			step.API.Method = val
		}
	case "url":
		if step.API != nil {
			step.API.URL = val
		}
	case "auth":
		if step.API != nil {
			step.API.Auth = val
		}
	case "status":
		if step.Respond != nil {
			fmt.Sscanf(val, "%d", &step.Respond.Status)
		}
	case "to":
		if step.Email != nil {
			step.Email.To = val
		}
	case "subject":
		if step.Email != nil {
			step.Email.Subject = val
		}
	case "template":
		if step.Email != nil {
			step.Email.Template = val
		}
	case "from":
		if step.Email != nil {
			step.Email.From = val
		} else if step.Respond != nil && val != "" {
			// Preserve the respond-JSON fallthrough for this key.
			if step.Respond.JSON == nil {
				step.Respond.JSON = make(map[string]any)
			}
			step.Respond.JSON[key] = val
		}
	case "reply_to":
		if step.Email != nil {
			step.Email.ReplyTo = val
		}
	case "as":
		if step.Type == "for_each" {
			step.ForAs = val
		}
	case "retry":
		fmt.Sscanf(val, "%d", &step.Retry)
	case "retry_delay":
		step.RetryDelay, _ = time.ParseDuration(val)
	case "timeout":
		step.Timeout, _ = time.ParseDuration(val)
	default:
		// Handle respond JSON sub-keys: any unknown key under a respond step becomes a JSON field
		if step.Respond != nil && val != "" {
			if step.Respond.JSON == nil {
				step.Respond.JSON = make(map[string]any)
			}
			step.Respond.JSON[key] = val
		}
	}
}
