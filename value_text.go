//go:build !cli

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

// valueText renders a data value as text: a request or API JSON value, a
// job payload field, a step output or a row column on its way into SQL, a
// URL, a header, a template or a condition operand.
//
// It is fmt.Sprint except for floating-point numbers, which are written the
// way JSON writes them: whole numbers in full and no exponent below 1e21.
// encoding/json decodes every JSON number as a float64, and fmt.Sprint
// writes one of a million or more as 1.234567e+06. SQLite's CAST(x AS
// INTEGER) reads that text only up to the decimal point, so a flow binding
// a request's 1234567 stored 1 with no error: video durations over about 17
// minutes, Stripe event timestamps, byte sizes over 1 MB.
func valueText(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return floatText(t, 64)
	case float32:
		return floatText(float64(t), 32)
	case json.Number:
		return t.String()
	}
	return fmt.Sprint(v)
}

// floatText formats f like encoding/json: 'f' notation, switching to the
// shortest 'e' form only outside [1e-6, 1e21), with "e-07" cleaned to
// "e-7". NaN and infinities keep fmt's spelling.
func floatText(f float64, bits int) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return fmt.Sprint(f)
	}
	format := byte('f')
	if abs := math.Abs(f); abs != 0 {
		if bits == 64 && (abs < 1e-6 || abs >= 1e21) ||
			bits == 32 && (float32(abs) < 1e-6 || float32(abs) >= 1e21) {
			format = 'e'
		}
	}
	b := strconv.AppendFloat(nil, f, format, -1, bits)
	if format == 'e' {
		if n := len(b); n >= 4 && b[n-4] == 'e' && b[n-3] == '-' && b[n-2] == '0' {
			b[n-2] = b[n-1]
			b = b[:n-1]
		}
	}
	return string(b)
}

// sqlNativeBindValue is the value a resolved `{{ref}}` binds in SQL. A
// whole float64 within the exactly representable integer range binds as an
// INTEGER, as the same number written as text (a `:name` param) does through
// sqlBindValue; other values bind unchanged.
func sqlNativeBindValue(v any) any {
	if f, ok := v.(float64); ok && f == math.Trunc(f) && math.Abs(f) <= 1<<53 {
		return int64(f)
	}
	return v
}

// maxExactFloatInteger is the largest integer magnitude a float64 holds
// exactly (2^53).
const maxExactFloatInteger = 1 << 53

// unmarshalJSONExact is json.Unmarshal except for integers beyond ±2^53,
// which a float64 cannot hold: they decode as int64 with every digit. A
// 64-bit id in a request body or an API response (a Discord or Twitter
// snowflake, 1234567890123456789) used to come out as ...768 and be stored,
// compared and sent on wrong with no error. Every other number decodes as the
// float64 it always was.
func unmarshalJSONExact(data []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("invalid character after top-level value")
	}
	switch target := v.(type) {
	case *map[string]any:
		return exactJSONMap(*target)
	case *any:
		value, err := exactJSONValue(*target)
		*target = value
		return err
	}
	return nil
}

func exactJSONMap(m map[string]any) error {
	for k, x := range m {
		value, err := exactJSONValue(x)
		if err != nil {
			return err
		}
		m[k] = value
	}
	return nil
}

func exactJSONValue(v any) (any, error) {
	switch t := v.(type) {
	case json.Number:
		text := string(t)
		if !strings.ContainsAny(text, ".eE") {
			if i, err := strconv.ParseInt(text, 10, 64); err == nil && (i > maxExactFloatInteger || i < -maxExactFloatInteger) {
				return i, nil
			}
		}
		f, err := t.Float64()
		if err != nil {
			return nil, fmt.Errorf("json: cannot unmarshal number %s into Go value of type float64", text)
		}
		return f, nil
	case map[string]any:
		return t, exactJSONMap(t)
	case []any:
		for i, x := range t {
			value, err := exactJSONValue(x)
			if err != nil {
				return nil, err
			}
			t[i] = value
		}
		return t, nil
	}
	return v, nil
}
