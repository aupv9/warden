// warden-sandbox-io runs inside a kubernetes scanner Pod (sandbox/kube): it
// receives the scan's input as a tar stream over the exec API, sends the
// tool's reports back the same way, keeps the Pod alive until the worker has
// them, and is the network canary of the worker's preflight. See
// sandboxio.Main for the commands.
package main

import (
	"os"

	"github.com/aupv9/warden/backend/internal/scan/sandbox/sandboxio"
)

func main() {
	ctx, stop := sandboxio.SignalContext()
	code := sandboxio.Main(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
