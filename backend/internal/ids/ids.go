// Package ids generates primary keys (UUIDv7: time-ordered, index-friendly).
package ids

import "github.com/google/uuid"

func New() uuid.UUID {
	return uuid.Must(uuid.NewV7())
}
