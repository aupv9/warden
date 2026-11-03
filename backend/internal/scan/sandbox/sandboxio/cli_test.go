package sandboxio

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// A NetworkPolicy may take effect only after a Pod started: wait -connect
// lets the scanner start only once nothing connects, and probe -within
// retries until the network is cut off.
func TestCLINetworkGate(t *testing.T) {
	open, _, _ := countingListener(t)
	marker := filepath.Join(t.TempDir(), "ready")
	must(t, os.WriteFile(marker, nil, 0o444))

	// Still open after the window: refused, so io-in fails and the scanner never starts.
	code, _, msg := run(t, context.Background(), nil, "wait", "-marker", marker, "-connect", open, "-within", "1s", "-timeout", "500ms")
	if code != ExitError || !strings.Contains(msg, "still reaches "+open) {
		t.Fatalf("open network: exit %d: %s", code, msg)
	}

	// Cut off after the first round (the policy applied late): accepted. A
	// listener of its own: the first one may still hold connections from the
	// run above in its backlog, which would close it before this probe's first
	// round (the flake the v0.6.0-alpha.3 release hit).
	late, accepted, ln := countingListener(t)
	go func() {
		for accepted() == 0 {
			time.Sleep(5 * time.Millisecond)
		}
		ln.Close()
	}()
	open = late
	code, out, _ := run(t, context.Background(), nil, "probe", "-connect", open, "-within", "10s", "-timeout", "500ms")
	var r ProbeReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Reached) != 0 || len(r.Early) != 1 || r.Early[0] != open {
		t.Fatalf("report %+v (exit %d)", r, code)
	}
	if code, _, msg := run(t, context.Background(), nil, "wait", "-marker", marker, "-connect", open, "-within", "5s", "-timeout", "500ms"); code != ExitOK {
		t.Fatalf("closed network: exit %d: %s", code, msg)
	}
}

// countingListener accepts and closes connections on a loopback port and
// counts them; the listener closes when the test ends.
func countingListener(t *testing.T) (addr string, accepted func() int, ln net.Listener) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var mu sync.Mutex
	n := 0
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
			mu.Lock()
			n++
			mu.Unlock()
		}
	}()
	return ln.Addr().String(), func() int { mu.Lock(); defer mu.Unlock(); return n }, ln
}

func run(t *testing.T, ctx context.Context, stdin []byte, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Main(ctx, args, bytes.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestCLIReceiveSeals(t *testing.T) {
	dir, ctl := t.TempDir(), t.TempDir()
	seal := filepath.Join(ctl, "ready")
	data := tarOf(t, entry{name: "src/a", body: "1"})
	args := []string{"receive", "-dir", dir, "-max-bytes", "10", "-max-entries", "5", "-seal", seal}
	if code, _, msg := run(t, context.Background(), data, args...); code != ExitOK {
		t.Fatalf("exit %d: %s", code, msg)
	}
	if _, err := os.Lstat(seal); err != nil {
		t.Fatal("not sealed")
	}
	// Once sealed, no second stream: the scanner may be reading the input.
	if code, _, msg := run(t, context.Background(), tarOf(t, entry{name: "src/b", body: "2"}), args...); code != ExitError || !strings.Contains(msg, "sealed") {
		t.Fatalf("second stream: exit %d: %s", code, msg)
	}
	// A refused stream doesn't seal.
	seal2 := filepath.Join(ctl, "ready2")
	bad := tarOf(t, entry{name: "l", typ: tar.TypeSymlink, linkname: "/"})
	if code, _, _ := run(t, context.Background(), bad, "receive", "-dir", t.TempDir(), "-max-bytes", "10", "-max-entries", "5", "-seal", seal2); code != ExitError {
		t.Fatalf("symlink: exit %d", code)
	}
	if _, err := os.Lstat(seal2); err == nil {
		t.Fatal("sealed after a refused stream")
	}
}

func TestCLISend(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "result.sarif"), []byte("{}"), 0o644))
	code, out, msg := run(t, context.Background(), nil, "send", "-dir", dir, "-file", "result.sarif=100", "-file", "trivy.json=100")
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, msg)
	}
	got := t.TempDir()
	st, err := Receive(strings.NewReader(out), got, Limits{MaxBytes: 200, MaxEntries: 2, Files: map[string]int64{"result.sarif": 100, "trivy.json": 100}})
	if err != nil || st.Files != 1 {
		t.Fatalf("%+v %v", st, err)
	}
	for _, args := range [][]string{
		{"send", "-dir", dir},
		{"send", "-dir", dir, "-file", "x"},
		{"send", "-dir", dir, "-file", "x=-1"},
		{"send", "-dir", dir, "-file", "x=1", "-file", "x=2"},
		{"receive"},
		{"wait"},
		{"probe"},
		{"hold", "extra"},
		{"bogus"},
		{},
	} {
		if code, _, _ := run(t, context.Background(), nil, args...); code != ExitUsage {
			t.Errorf("%v: exit %d, want usage", args, code)
		}
	}
	if code, _, _ := run(t, context.Background(), nil, "send", "-dir", dir, "-file", "../x=1"); code != ExitError {
		t.Errorf("traversal name: exit %d", code)
	}
}

func TestCLIWaitAndHold(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ready")
	done := make(chan int, 1)
	go func() {
		code, _, _ := run(t, context.Background(), nil, "wait", "-marker", marker, "-poll", "5ms")
		done <- code
	}()
	select {
	case <-done:
		t.Fatal("returned before the marker existed")
	case <-time.After(30 * time.Millisecond):
	}
	must(t, os.WriteFile(marker, nil, 0o444))
	if code := <-done; code != ExitOK {
		t.Fatalf("wait: exit %d", code)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()
	if code, _, _ := run(t, ctx, nil, "wait", "-marker", marker+"x", "-poll", "5ms"); code != ExitError {
		t.Fatalf("stopped wait: exit %d", code)
	}
	ctx, cancel = context.WithCancel(context.Background())
	go func() { time.Sleep(10 * time.Millisecond); cancel() }()
	if code, _, _ := run(t, ctx, nil, "hold"); code != ExitOK {
		t.Fatalf("hold: exit %d", code)
	}
}

func TestCLIProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	open := ln.Addr().String()
	// A port nothing listens on: refused, which doesn't count as reached.
	closedLn, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := closedLn.Addr().String()
	closedLn.Close()

	report := filepath.Join(t.TempDir(), "report")
	t.Setenv("WARDEN_TEST_HOST", "127.0.0.1")
	_, port, _ := net.SplitHostPort(open)
	t.Setenv("WARDEN_TEST_PORT", port)
	code, out, _ := run(t, context.Background(), nil, "probe", "-connect", closed, "-connect", "$WARDEN_TEST_HOST:$WARDEN_TEST_PORT",
		"-connect", "$WARDEN_UNSET:1", "-timeout", "1s", "-report", report)
	if code != ExitReached {
		t.Fatalf("exit %d", code)
	}
	var r ProbeReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Tried) != 2 || len(r.Reached) != 1 || r.Reached[0] != "127.0.0.1:"+port {
		t.Fatalf("report %+v", r)
	}
	if b, err := os.ReadFile(report); err != nil || !strings.Contains(string(b), strconv.Quote("127.0.0.1:"+port)) {
		t.Fatalf("report file %q %v", b, err)
	}
	// Nothing reached: isolated only under gVisor.
	want := ExitReached
	if underGVisor() {
		want = ExitOK
	}
	if code, _, _ := run(t, context.Background(), nil, "probe", "-connect", closed, "-timeout", "1s"); code != want {
		t.Fatalf("nothing reached: exit %d, want %d", code, want)
	}
}
