//go:build !webui

package webui

import "io/fs"

// Embedded returns nil: this binary was built without -tags webui, so the API
// serves no UI (development uses Vite's server on :5173).
func Embedded() fs.FS { return nil }
