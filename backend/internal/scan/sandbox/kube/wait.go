package kube

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/aupv9/warden/backend/internal/scan/sandbox"
)

// check inspects a Pod: done when it reached the state waited for, an error
// (a *runError) when it never will.
type check func(*corev1.Pod) (done bool, err error)

// resync bounds how long a watch is trusted before the Pod is read again
// (a watch can end or miss an event; a Get can't).
const resync = 10 * time.Second

// waitFor returns the Pod once ok says done, watching it in between. The Pod
// must keep its UID: one recreated under the same name is not this run's.
func (b *Backend) waitFor(ctx context.Context, name string, uid types.UID, ok check) (*corev1.Pod, error) {
	pods := b.Client.CoreV1().Pods(b.Namespace)
	var last *corev1.Pod
	for {
		pod, err := pods.Get(ctx, name, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, failed("the scanner pod was deleted")
		case err != nil:
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			// The API server may be restarting: try again until the deadline.
			if b.Log != nil {
				b.Log.Warn("reading the scanner pod failed; retrying", "pod", name, "err", err)
			}
			if !sleep(ctx, time.Second) {
				return nil, timeoutWith(ctx.Err(), last)
			}
			continue
		}
		if done, p, err := evaluate(pod, uid, ok); done {
			return p, err
		}
		last = pod
		if p, done, err := b.watchOnce(ctx, name, uid, pod.ResourceVersion, ok); done {
			return p, timeoutWith(err, last)
		}
		if ctx.Err() != nil {
			return nil, timeoutWith(ctx.Err(), last)
		}
	}
}

// timeoutWith adds why a Pod never started to a timeout.
func timeoutWith(err error, last *corev1.Pod) error {
	if err == nil || last == nil || !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if why := describePending(last); why != "" {
		return &runError{status: sandbox.Timeout, msg: "timeout (" + why + ")"}
	}
	return err
}

func evaluate(pod *corev1.Pod, uid types.UID, ok check) (bool, *corev1.Pod, error) {
	if pod.UID != uid {
		return true, nil, failed("the scanner pod was replaced")
	}
	done, err := ok(pod)
	if err != nil {
		return true, nil, err
	}
	return done, pod, nil
}

// watchOnce follows the Pod until ok is satisfied, the watch ends or resync
// passes; done is false when the caller should read the Pod again.
func (b *Backend) watchOnce(ctx context.Context, name string, uid types.UID, rv string, ok check) (*corev1.Pod, bool, error) {
	w, err := b.Client.CoreV1().Pods(b.Namespace).Watch(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector("metadata.name", name).String(), ResourceVersion: rv,
	})
	if err != nil {
		sleep(ctx, time.Second)
		return nil, false, nil
	}
	defer w.Stop()
	timer := time.NewTimer(resync)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, true, ctx.Err()
		case <-timer.C:
			return nil, false, nil
		case ev, open := <-w.ResultChan():
			if !open {
				return nil, false, nil
			}
			pod, isPod := ev.Object.(*corev1.Pod)
			if !isPod || pod.Name != name {
				continue // a watch error, or (a fake's) other Pod: read again on resync
			}
			if ev.Type == watch.Deleted {
				if ctx.Err() != nil {
					return nil, true, ctx.Err()
				}
				return nil, true, failed("the scanner pod was deleted")
			}
			if done, p, err := evaluate(pod, uid, ok); done {
				return p, true, err
			}
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func containerStatus(ss []corev1.ContainerStatus, name string) *corev1.ContainerStatus {
	for i := range ss {
		if ss[i].Name == name {
			return &ss[i]
		}
	}
	return &corev1.ContainerStatus{Name: name}
}

// fatalWaiting are the reasons a container waits for that won't resolve on
// their own within a scan's time. ErrImagePull is not one: the kubelet
// retries, and the next failure is ImagePullBackOff.
var fatalWaiting = map[string]bool{
	"ImagePullBackOff":           true,
	"InvalidImageName":           true,
	"ErrImageNeverPull":          true,
	"CreateContainerConfigError": true,
	"CreateContainerError":       true,
	"RunContainerError":          true,
	"CrashLoopBackOff":           true,
}

// maxMessage bounds what of a kubelet message goes into a run's error.
const maxMessage = 512

func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxMessage {
		return s[:maxMessage] + "…"
	}
	return s
}

// podFailure is the reason the Pod can't get further, or nil.
func podFailure(p *corev1.Pod) error {
	if p.DeletionTimestamp != nil {
		return failed("the scanner pod is being deleted")
	}
	switch p.Status.Phase {
	case corev1.PodFailed:
		if p.Status.Reason == "DeadlineExceeded" {
			return &runError{status: sandbox.Timeout, msg: "timeout"}
		}
		if t := containerStatus(p.Status.InitContainerStatuses, containerIn).State.Terminated; t != nil && t.ExitCode != 0 {
			return failed("input container failed: exit %d %s", t.ExitCode, clip(t.Reason+" "+t.Message))
		}
		return failed("the scanner pod failed: %s", clip(p.Status.Reason+" "+p.Status.Message))
	case corev1.PodSucceeded:
		return failed("the scanner pod ended before its results were fetched")
	}
	all := append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...)
	for _, s := range all {
		if w := s.State.Waiting; w != nil && fatalWaiting[w.Reason] {
			return failed("%s: %s: %s", s.Name, w.Reason, clip(w.Message))
		}
	}
	return nil
}

// inputReady: io-in is running, so the worker can exec into it.
func inputReady(p *corev1.Pod) (bool, error) {
	if err := podFailure(p); err != nil {
		return false, err
	}
	s := containerStatus(p.Status.InitContainerStatuses, containerIn)
	if s.State.Terminated != nil {
		return false, failed("input container exited before the input was sent (exit %d)", s.State.Terminated.ExitCode)
	}
	return s.State.Running != nil, nil
}

// scannerDone: the scanner terminated, and io-out runs if the results are to
// be fetched (fetch says which exits have results). The deadline wins over
// the scanner's own exit status: the kubelet killed it.
func scannerDone(fetch func(*corev1.ContainerStateTerminated) bool) check {
	return func(p *corev1.Pod) (bool, error) {
		if p.DeletionTimestamp != nil || p.Status.Reason == "DeadlineExceeded" {
			return false, podFailure(p)
		}
		t := containerStatus(p.Status.ContainerStatuses, containerScanner).State.Terminated
		if t == nil {
			return false, podFailure(p)
		}
		if !fetch(t) {
			return true, nil
		}
		return outReady(p)
	}
}

func outReady(p *corev1.Pod) (bool, error) {
	out := containerStatus(p.Status.ContainerStatuses, containerOut)
	if out.State.Running == nil {
		if out.State.Terminated != nil {
			return false, failed("the results container exited (exit %d)", out.State.Terminated.ExitCode)
		}
		if err := podFailure(p); err != nil {
			return false, err
		}
		return false, nil // io-out not started yet
	}
	return true, nil
}

// describePending explains a Pod still waiting to start, for a timeout's error.
func describePending(p *corev1.Pod) string {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionFalse {
			return fmt.Sprintf("not scheduled: %s", clip(c.Reason+" "+c.Message))
		}
	}
	return ""
}
