package sandboxio

import (
	"bytes"
	"strings"

	"golang.org/x/sys/unix"
)

// underGVisor reports whether this process runs on gVisor's Sentry rather
// than on a host kernel. gVisor answers syslog(2) READ_ALL to unprivileged
// callers with its own boot log ("Starting gVisor..."); a host kernel refuses
// it (no CAP_SYSLOG, dmesg_restrict, RuntimeDefault seccomp) or returns its
// own log. If syslog is blocked (runsc --oci-seccomp), the fixed uname gVisor
// reports is the fallback.
func underGVisor() bool {
	buf := make([]byte, 64<<10)
	if n, err := unix.Klogctl(3 /* SYSLOG_ACTION_READ_ALL */, buf); err == nil && n > 0 &&
		bytes.Contains(buf[:n], []byte("gVisor")) {
		return true
	}
	var u unix.Utsname
	if unix.Uname(&u) != nil {
		return false
	}
	release := strings.TrimRight(string(u.Release[:]), "\x00")
	version := strings.TrimRight(string(u.Version[:]), "\x00")
	return release == "4.4.0" && version == "#1 SMP Sun Jan 10 15:06:54 PST 2016"
}
