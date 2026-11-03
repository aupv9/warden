package kube

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	utilexec "k8s.io/client-go/util/exec"
	"k8s.io/streaming/pkg/httpstream"
)

// Execer runs a command in a container of a running Pod (pods/exec) and
// streams its stdin and stdout. It is the only way data enters or leaves a
// scanner Pod. A non-zero exit is an error carrying the code (ExitCode).
type Execer interface {
	Exec(ctx context.Context, namespace, pod, container string, cmd []string, stdin io.Reader, stdout, stderr io.Writer) error
}

// ExitCode returns the exit status of a command Exec ran, or -1 if err is
// not an exit status.
func ExitCode(err error) int {
	var ce utilexec.CodeExitError
	if errors.As(err, &ce) {
		return ce.Code
	}
	var cp *utilexec.CodeExitError
	if errors.As(err, &cp) {
		return cp.Code
	}
	return -1
}

// RemoteExecer is the Execer of a real cluster: WebSocket (RemoteCommand
// v5), falling back to SPDY on servers without it, as kubectl does.
type RemoteExecer struct {
	Config *rest.Config
	Client kubernetes.Interface
}

func (e RemoteExecer) Exec(ctx context.Context, namespace, pod, container string, cmd []string, stdin io.Reader, stdout, stderr io.Writer) error {
	req := e.Client.CoreV1().RESTClient().Post().
		Resource("pods").Namespace(namespace).Name(pod).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container, Command: cmd,
			Stdin: stdin != nil, Stdout: stdout != nil, Stderr: stderr != nil,
		}, scheme.ParameterCodec)
	ws, err := remotecommand.NewWebSocketExecutor(e.Config, "GET", req.URL().String())
	if err != nil {
		return err
	}
	spdy, err := remotecommand.NewSPDYExecutor(e.Config, "POST", req.URL())
	if err != nil {
		return err
	}
	ex, err := remotecommand.NewFallbackExecutor(ws, spdy, func(err error) bool {
		return httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err)
	})
	if err != nil {
		return err
	}
	return ex.StreamWithContext(ctx, remotecommand.StreamOptions{Stdin: stdin, Stdout: stdout, Stderr: stderr})
}

// tail keeps the last n bytes written (a command's stderr).
type tail struct {
	n   int
	buf []byte
}

func (w *tail) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	if len(w.buf) > w.n {
		w.buf = w.buf[len(w.buf)-w.n:]
	}
	return len(p), nil
}

func (w *tail) String() string { return strings.TrimSpace(string(w.buf)) }

// execErr describes a failed exec with the command's last words.
func execErr(what string, err error, stderr *tail) error {
	if msg := stderr.String(); msg != "" {
		return fmt.Errorf("%s: %w: %s", what, err, msg)
	}
	return fmt.Errorf("%s: %w", what, err)
}
