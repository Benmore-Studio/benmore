//go:build !cli

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const flowStrictJSONMaxBytes = 32 << 10

var errInvalidStrictJSONRequest = errors.New("invalid strict JSON request")

func flowStrictJSONFlag(value any) (bool, error) {
	node, ok := value.(yaml.Node)
	if !ok || node.Kind == 0 {
		return false, nil
	}
	if node.Kind != yaml.ScalarNode || node.Tag != "!!bool" {
		return false, errors.New("on.request.strict_json must be a YAML boolean (`true` or `false`)")
	}
	flag, err := strconv.ParseBool(node.Value)
	if err != nil {
		return false, errors.New("on.request.strict_json must be a YAML boolean (`true` or `false`)")
	}
	return flag, nil
}

// decodeStrictFlowJSON keeps the decoder's number representation while
// refusing ambiguous object members at every nesting level.
func decodeStrictFlowJSON(raw []byte) (map[string]any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("request is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := decodeStrictFlowJSONValue(decoder)
	if err != nil {
		return nil, err
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, errors.New("request must be a JSON object")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("request must contain exactly one JSON value")
	}
	return value.(map[string]any), nil
}

func decodeStrictFlowJSONValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, compound := token.(json.Delim)
	if !compound {
		return token, nil
	}
	switch delim {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("invalid JSON object key")
			}
			if _, duplicate := object[key]; duplicate {
				return nil, errors.New("duplicate JSON object key")
			}
			value, err := decodeStrictFlowJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
			return nil, errors.New("invalid JSON object")
		}
		return object, nil
	case '[':
		var array []any
		for decoder.More() {
			value, err := decodeStrictFlowJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
			return nil, errors.New("invalid JSON array")
		}
		return array, nil
	default:
		return nil, errors.New("invalid JSON value")
	}
}
