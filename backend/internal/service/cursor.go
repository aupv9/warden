package service

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
)

// Pagination limits.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// PageParams are the raw ?limit= and ?cursor= values.
type PageParams struct {
	Limit  string
	Cursor string
}

func (p PageParams) limit() (int, error) {
	if p.Limit == "" {
		return DefaultLimit, nil
	}
	n, err := strconv.Atoi(p.Limit)
	if err != nil || n < 1 || n > MaxLimit {
		return 0, errField("limit", "must be an integer between 1 and 200")
	}
	return n, nil
}

// Cursors are opaque to clients: base64url-encoded JSON of the last row's sort
// key. They only position a page; access filters are always applied on top, so a
// forged cursor can't reveal anything.
func encodeCursor(v any) *string {
	b, _ := json.Marshal(v)
	s := base64.RawURLEncoding.EncodeToString(b)
	return &s
}

func decodeCursor(s string, v any) error {
	if len(s) > 512 {
		return errField("cursor", "invalid cursor")
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || json.Unmarshal(b, v) != nil {
		return errField("cursor", "invalid cursor")
	}
	return nil
}

// page trims a limit+1 result to limit items and builds the next cursor.
func page[T any](rows []T, limit int, cursor func(T) any) ([]T, *string) {
	if rows == nil {
		rows = []T{}
	}
	if len(rows) <= limit {
		return rows, nil
	}
	rows = rows[:limit]
	return rows, encodeCursor(cursor(rows[limit-1]))
}
