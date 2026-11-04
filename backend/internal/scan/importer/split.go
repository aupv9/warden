package importer

import (
	"bytes"
	"encoding/json"
	"errors"
)

// Lists and maps (runs, results, rules, tags, partial fingerprints, …) are
// json.RawMessage fields, cut into elements here: as subslices, with no
// copy and nothing allocated per element, so the counts are checked before
// anything is decoded (a json.Decoder would buffer and copy every element,
// a slice field allocate them all). The JSON was validated by json.Unmarshal
// (decode) before it gets here; this code is still bounds-checked and
// returns errMalformed on anything unexpected rather than trusting that.

var (
	errNotArray  = errors.New("not an array")
	errTooMany   = errors.New("too many elements")
	errMalformed = errors.New("malformed JSON")
	nullJSON     = []byte("null")
)

func absent(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) == 0 || bytes.Equal(t, nullJSON)
}

// elements calls fn for each element of the JSON array raw (absent or null:
// none), refusing more than max of them (errTooMany, before the first one
// over is read) and a value that isn't an array (errNotArray).
func elements(raw json.RawMessage, max int, fn func(el json.RawMessage) error) error {
	if absent(raw) {
		return nil
	}
	n := 0
	return each(raw, '[', func(_, el []byte) (bool, error) {
		if n == max {
			return false, errTooMany
		}
		n++
		return true, fn(el)
	})
}

// firstElements calls fn for the first n elements of raw, if it is an
// array, and ignores the rest.
func firstElements(raw json.RawMessage, n int, fn func(el json.RawMessage)) {
	if absent(raw) {
		return
	}
	seen := 0
	_ = each(raw, '[', func(_, el []byte) (bool, error) {
		if seen == n {
			return false, nil
		}
		seen++
		fn(el)
		return true, nil
	})
}

// members calls fn for the first max members of the JSON object raw, if it
// is one, and ignores the rest.
func members(raw json.RawMessage, max int, fn func(key string, val json.RawMessage)) {
	if absent(raw) {
		return
	}
	seen := 0
	_ = each(raw, '{', func(k, val []byte) (bool, error) {
		if seen == max {
			return false, nil
		}
		seen++
		var key string
		if err := json.Unmarshal(k, &key); err != nil {
			return false, err
		}
		fn(key, val)
		return true, nil
	})
}

// each walks the array ('[') or object ('{') raw: fn gets each element, or
// each member's key (the quoted JSON string) and value, and returns whether
// to go on. A value that isn't such a container is errNotArray.
func each(raw []byte, open byte, fn func(key, val []byte) (bool, error)) error {
	b := bytes.TrimSpace(raw)
	if len(b) == 0 || b[0] != open {
		return errNotArray
	}
	end := byte(']')
	if open == '{' {
		end = '}'
	}
	i := skipSpace(b, 1)
	if i < len(b) && b[i] == end {
		return nil
	}
	for {
		var key []byte
		if open == '{' {
			if i >= len(b) || b[i] != '"' {
				return errMalformed
			}
			e, err := stringEnd(b, i)
			if err != nil {
				return err
			}
			key = b[i:e]
			if i = skipSpace(b, e); i >= len(b) || b[i] != ':' {
				return errMalformed
			}
			i = skipSpace(b, i+1)
		}
		e, err := valueEnd(b, i)
		if err != nil {
			return err
		}
		more, err := fn(key, b[i:e])
		if err != nil || !more {
			return err
		}
		if i = skipSpace(b, e); i >= len(b) {
			return errMalformed
		}
		switch b[i] {
		case ',':
			i = skipSpace(b, i+1)
		case end:
			return nil
		default:
			return errMalformed
		}
	}
}

func skipSpace(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return i
}

// valueEnd returns the index just past the JSON value that starts at b[i]:
// a string, an object or array (brackets counted outside strings), or a
// number or literal (up to the next delimiter).
func valueEnd(b []byte, i int) (int, error) {
	if i >= len(b) {
		return 0, errMalformed
	}
	switch b[i] {
	case '"':
		return stringEnd(b, i)
	case '{', '[':
		depth := 0
		for j := i; j < len(b); j++ {
			switch b[j] {
			case '"':
				e, err := stringEnd(b, j)
				if err != nil {
					return 0, err
				}
				j = e - 1
			case '{', '[':
				depth++
			case '}', ']':
				if depth--; depth == 0 {
					return j + 1, nil
				}
			}
		}
		return 0, errMalformed
	}
	j := i
	for j < len(b) && !delimiter(b[j]) {
		j++
	}
	if j == i {
		return 0, errMalformed
	}
	return j, nil
}

func delimiter(c byte) bool {
	switch c {
	case ',', ':', '[', ']', '{', '}', '"', ' ', '\t', '\n', '\r':
		return true
	}
	return false
}

// stringEnd returns the index just past the JSON string that starts at b[i].
func stringEnd(b []byte, i int) (int, error) {
	for j := i + 1; j < len(b); j++ {
		switch b[j] {
		case '\\':
			j++
		case '"':
			return j + 1, nil
		}
	}
	return 0, errMalformed
}
