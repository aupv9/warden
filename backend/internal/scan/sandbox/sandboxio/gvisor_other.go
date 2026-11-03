//go:build !linux

package sandboxio

// underGVisor: gVisor is Linux only.
func underGVisor() bool { return false }
