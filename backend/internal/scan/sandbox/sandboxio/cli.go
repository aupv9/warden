package sandboxio

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Exit codes of warden-sandbox-io.
const (
	ExitOK    = 0
	ExitError = 1
	ExitUsage = 2
	// ExitReached: probe connected to at least one target (the namespace is
	// not isolated) or found itself outside gVisor.
	ExitReached = 10
)

// Commands of warden-sandbox-io (the Pod's io containers; see sandbox/kube):
//
//	receive -dir D -max-bytes N -max-entries N [-seal F]   tar on stdin into D; then create F
//	send -dir D -file NAME=CAP ...                          those files of D as tar on stdout
//	wait -marker F                                          return once F exists (the input is complete)
//	hold                                                    block until SIGTERM (keeps the Pod alive)
//	probe -connect HOST:PORT ... [-report F]                the canary: can this Pod reach anything?
//
// Main returns the exit code. Stdout carries only the tar stream (send) or
// the probe's report; messages go to stderr.
func Main(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: warden-sandbox-io receive|send|wait|hold|probe [flags]")
		return ExitUsage
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	var err error
	switch args[0] {
	case "receive":
		dir := fs.String("dir", "", "target directory")
		maxBytes := fs.Int64("max-bytes", 0, "total content bytes")
		maxEntries := fs.Int("max-entries", 0, "files and directories")
		seal := fs.String("seal", "", "file created once the stream was received completely")
		if fs.Parse(args[1:]) != nil || *dir == "" || fs.NArg() != 0 {
			return ExitUsage
		}
		err = receive(stdin, *dir, Limits{MaxBytes: *maxBytes, MaxEntries: *maxEntries}, *seal)
	case "send":
		dir := fs.String("dir", "", "source directory")
		files := fileCaps{}
		fs.Var(files, "file", "NAME=CAP: a top-level file and its largest size (repeatable)")
		if fs.Parse(args[1:]) != nil || *dir == "" || len(files) == 0 || fs.NArg() != 0 {
			return ExitUsage
		}
		_, err = SendFiles(stdout, *dir, files)
	case "wait":
		marker := fs.String("marker", "", "file to wait for")
		poll := fs.Duration("poll", 100*time.Millisecond, "poll interval")
		if fs.Parse(args[1:]) != nil || *marker == "" || fs.NArg() != 0 {
			return ExitUsage
		}
		err = wait(ctx, *marker, *poll)
	case "hold":
		if fs.Parse(args[1:]) != nil || fs.NArg() != 0 {
			return ExitUsage
		}
		<-ctx.Done()
		return ExitOK
	case "probe":
		var targets multi
		fs.Var(&targets, "connect", "HOST:PORT to try (repeatable); $VAR:$VAR reads the environment")
		report := fs.String("report", "", "also write the JSON report here (the termination message)")
		timeout := fs.Duration("timeout", 3*time.Second, "per connection attempt")
		if fs.Parse(args[1:]) != nil || len(targets) == 0 || fs.NArg() != 0 {
			return ExitUsage
		}
		r := Probe(ctx, expand(targets), *timeout)
		b, _ := json.Marshal(r)
		fmt.Fprintln(stdout, string(b))
		if *report != "" {
			_ = os.WriteFile(*report, b, 0o644)
		}
		if len(r.Reached) > 0 || !r.GVisor {
			return ExitReached
		}
		return ExitOK
	default:
		fmt.Fprintf(stderr, "warden-sandbox-io: unknown command %q\n", args[0])
		return ExitUsage
	}
	if err != nil {
		fmt.Fprintln(stderr, "warden-sandbox-io:", err)
		return ExitError
	}
	return ExitOK
}

// SignalContext is cancelled on SIGTERM or SIGINT (the kubelet stopping the
// container, the worker deleting the Pod).
func SignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
}

// receive refuses a second stream once sealed: the scanner may already be
// reading the input.
func receive(r io.Reader, dir string, l Limits, seal string) error {
	if seal != "" {
		if _, err := os.Lstat(seal); err == nil {
			return errors.New("input already sealed")
		}
	}
	// Receive returns at the end-of-archive marker: nothing waits for stdin to
	// close, which not every exec transport passes on.
	if _, err := Receive(r, dir, l); err != nil {
		return err
	}
	if seal == "" {
		return nil
	}
	f, err := os.OpenFile(seal, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o444)
	if err != nil {
		return err
	}
	return f.Close()
}

func wait(ctx context.Context, marker string, poll time.Duration) error {
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		if fi, err := os.Lstat(marker); err == nil && fi.Mode().IsRegular() {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("stopped before the input was complete")
		case <-t.C:
		}
	}
}

// fileCaps parses -file NAME=CAP.
type fileCaps map[string]int64

func (f fileCaps) String() string { return fmt.Sprint(map[string]int64(f)) }

func (f fileCaps) Set(v string) error {
	name, c, ok := strings.Cut(v, "=")
	n, err := strconv.ParseInt(c, 10, 64)
	if !ok || name == "" || err != nil || n < 0 {
		return fmt.Errorf("want NAME=CAP, got %q", v)
	}
	if _, dup := f[name]; dup {
		return fmt.Errorf("file %q given twice", name)
	}
	f[name] = n
	return nil
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// expand resolves $HOST:$PORT targets from the environment (the kubelet sets
// KUBERNETES_SERVICE_HOST/PORT in every Pod, even without service links);
// one whose variables are unset is dropped.
func expand(targets []string) []string {
	var out []string
	for _, t := range targets {
		host, port, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		if strings.HasPrefix(host, "$") {
			host = os.Getenv(host[1:])
		}
		if strings.HasPrefix(port, "$") {
			port = os.Getenv(port[1:])
		}
		if host == "" || port == "" {
			continue
		}
		out = append(out, net.JoinHostPort(host, port))
	}
	return out
}

// ProbeReport is the canary's finding.
type ProbeReport struct {
	// Tried are the targets, Reached those a TCP connection was made to.
	Tried   []string `json:"tried"`
	Reached []string `json:"reached"`
	// GVisor: the canary found itself under gVisor (see underGVisor).
	GVisor bool `json:"gvisor"`
}

// Probe tries a TCP connection to each target. Only a completed handshake
// counts as reached: a timeout, "refused" or "unreachable" means nothing
// answered for the Pod (a NetworkPolicy drops; a refusal can come from the
// Pod's own network stack).
func Probe(ctx context.Context, targets []string, timeout time.Duration) ProbeReport {
	r := ProbeReport{Tried: targets, Reached: []string{}, GVisor: underGVisor()}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Go(func() {
			d := net.Dialer{Timeout: timeout}
			c, err := d.DialContext(ctx, "tcp", t)
			if err != nil {
				return
			}
			c.Close()
			mu.Lock()
			r.Reached = append(r.Reached, t)
			mu.Unlock()
		})
	}
	wg.Wait()
	return r
}
