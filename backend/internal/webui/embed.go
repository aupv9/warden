//go:build webui

package webui

import (
	"embed"
	"io/fs"
)

// dist is frontend/dist, copied here at build time (Dockerfile, `make
// build-webui`; git ignores it). Without the "all:" prefix, embed leaves out
// files whose names start with "." or "_".
//
//go:embed dist
var dist embed.FS

// Embedded returns the bundled UI.
func Embedded() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err) // "dist" is a valid path, and the directive guarantees it exists
	}
	return sub
}
