package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/worker/dbtest"
)

// fakeDocker answers docker commands by subcommand ("info", "ps", "pull",
// "rm", "image inspect") and records each argv.
type fakeDocker struct {
	out     map[string]string
	err     map[string]error
	present map[string]bool // images "docker image inspect" finds
	calls   [][]string
}

func (f *fakeDocker) Run(_ context.Context, argv ...string) ([]byte, error) {
	f.calls = append(f.calls, argv)
	key := argv[1]
	if key == "image" {
		if f.present[argv[len(argv)-1]] {
			return []byte("sha256:x"), nil
		}
		return nil, errors.New("No such image")
	}
	return []byte(f.out[key]), f.err[key]
}

func (f *fakeDocker) ran(sub string) [][]string {
	var out [][]string
	for _, c := range f.calls {
		if c[1] == sub {
			out = append(out, c)
		}
	}
	return out
}

const runtimesJSON = `{"runc":{"path":"runc"},"runsc":{"path":"/usr/local/bin/runsc"}}`

func preflightEnv(t *testing.T, active []uuid.UUID, scanErr error) (*Env, string) {
	t.Helper()
	org := uuid.New()
	rows := [][]any{}
	for _, id := range active {
		rows = append(rows, []any{id})
	}
	db := dbtest.Loose(t,
		dbtest.Step{Prefix: "SELECT id FROM organization", Rows: [][]any{{org}}},
		dbtest.Step{Prefix: "SELECT id FROM scan WHERE status IN ('queued', 'running')", Rows: rows, Err: scanErr},
	)
	scratch := t.TempDir()
	return &Env{
		Tx:  func(_ context.Context, _ uuid.UUID, fn func(DB) error) error { return fn(db) },
		Log: quietLog(), Now: time.Now,
		Settings: Settings{ScratchDir: scratch, Runtime: "runsc", Images: testImages},
	}, scratch
}

func TestPreflightStrictRefusals(t *testing.T) {
	local := "sha256:" + strings.Repeat("c", 64)
	for _, c := range []struct {
		name   string
		docker *fakeDocker
		images map[string]string
		want   string
	}{
		{"daemon down", &fakeDocker{err: map[string]error{"info": errors.New("Cannot connect to the Docker daemon")}}, nil, "docker daemon unreachable"},
		{"no runsc", &fakeDocker{out: map[string]string{"info": `{"runc":{}}`}}, nil, `no "runsc" runtime`},
		{"pull fails", &fakeDocker{out: map[string]string{"info": runtimesJSON}, err: map[string]error{"pull": errors.New("denied")}}, nil, "scan.images.gitleaks"},
		{"local image missing", &fakeDocker{out: map[string]string{"info": runtimesJSON}}, map[string]string{"trivy": local}, "scan.images.trivy"},
	} {
		t.Run(c.name, func(t *testing.T) {
			env, _ := preflightEnv(t, nil, nil)
			if c.images != nil {
				env.Images = c.images
			}
			err := env.Preflight(context.Background(), c.docker, true)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
			// Outside prod the same problems only warn.
			env2, _ := preflightEnv(t, nil, nil)
			if c.images != nil {
				env2.Images = c.images
			}
			if err := env2.Preflight(context.Background(), c.docker, false); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPreflightPullsMissingPinnedImages(t *testing.T) {
	env, _ := preflightEnv(t, nil, nil)
	d := &fakeDocker{out: map[string]string{"info": runtimesJSON}, present: map[string]bool{testImages["opengrep"]: true}}
	if err := env.Preflight(context.Background(), d, true); err != nil {
		t.Fatal(err)
	}
	pulls := d.ran("pull")
	if len(pulls) != 1 || pulls[0][len(pulls[0])-1] != testImages["gitleaks"] {
		t.Fatalf("pulls %v", pulls)
	}
	for _, c := range d.calls {
		if c[0] != "docker" {
			t.Fatalf("non-docker command %v", c)
		}
	}
}

func TestPreflightRemovesOnlyOrphans(t *testing.T) {
	running, orphan, stale := uuid.New(), uuid.New(), uuid.New()
	env, scratch := preflightEnv(t, []uuid.UUID{running}, nil)
	d := &fakeDocker{out: map[string]string{"info": runtimesJSON, "ps": strings.Join([]string{
		"warden-" + running.String() + "-trivy\t" + running.String(),
		"warden-" + orphan.String() + "-opengrep\t" + orphan.String(),
		"warden-api-1\t",
	}, "\n")}, present: map[string]bool{testImages["opengrep"]: true, testImages["gitleaks"]: true}}

	mk := func(name string) string {
		p := filepath.Join(scratch, name)
		if err := os.MkdirAll(filepath.Join(p, "src"), 0o700); err != nil {
			t.Fatal(err)
		}
		// A read-only extracted tree, as zipcheck leaves it.
		if err := os.Chmod(filepath.Join(p, "src"), 0o500); err != nil {
			t.Fatal(err)
		}
		return p
	}
	keepRunning, removeStale := mk(running.String()), mk(stale.String())
	keepOther := mk("not-a-scan")
	outside := t.TempDir()
	victim := filepath.Join(outside, uuid.NewString())
	if err := os.Mkdir(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(scratch, uuid.NewString())
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, p := range []string{keepRunning, keepOther} {
			_ = os.Chmod(filepath.Join(p, "src"), 0o700)
		}
	})

	if err := env.Preflight(context.Background(), d, true); err != nil {
		t.Fatal(err)
	}
	rms := d.ran("rm")
	if len(rms) != 1 || rms[0][len(rms[0])-1] != "warden-"+orphan.String()+"-opengrep" {
		t.Fatalf("removed %v", rms)
	}
	for p, want := range map[string]bool{keepRunning: true, removeStale: false, keepOther: true, link: true, victim: true} {
		_, err := os.Lstat(p)
		if exists := err == nil; exists != want {
			t.Errorf("%s exists=%v, want %v", p, exists, want)
		}
	}
}

func TestPreflightKeepsEverythingWhenScansCantBeListed(t *testing.T) {
	env, scratch := preflightEnv(t, nil, errors.New("db down"))
	orphan := uuid.New()
	dir := filepath.Join(scratch, orphan.String())
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	d := &fakeDocker{out: map[string]string{"info": runtimesJSON, "ps": "warden-" + orphan.String() + "-trivy\t"},
		present: map[string]bool{testImages["opengrep"]: true, testImages["gitleaks"]: true}}
	if err := env.Preflight(context.Background(), d, true); err != nil {
		t.Fatal(err)
	}
	if len(d.ran("rm")) != 0 || len(d.ran("ps")) != 0 {
		t.Fatalf("cleaned up without knowing the active scans: %v", d.calls)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatal("scratch directory removed")
	}
}

func TestDockerChecker(t *testing.T) {
	now := time.Now()
	d := &fakeDocker{out: map[string]string{"info": runtimesJSON}}
	c := &DockerChecker{Docker: d, Runtime: "runsc", TTL: 15 * time.Second, Now: func() time.Time { return now }, Warn: quietLog().Warn}
	if err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	d.err = map[string]error{"info": errors.New("Cannot connect to unix:///var/run/docker.sock")}
	if err := c.Check(context.Background()); err != nil || len(d.calls) != 1 {
		t.Fatal("not cached", err)
	}
	now = now.Add(time.Minute)
	if err := c.Check(context.Background()); err == nil || err.Error() != "unavailable" {
		t.Fatal(err)
	}
	d.err = nil
	d.out["info"] = `{"runc":{}}`
	now = now.Add(time.Minute)
	if err := c.Check(context.Background()); err == nil {
		t.Fatal("runtime missing but ready")
	}
	if !slices.Contains([]string{"docker"}, c.Name()) {
		t.Fatal(c.Name())
	}
}
