// selfscan scans Warden with Warden: it zips the repo like a developer
// upload, validates it with zipcheck, runs the four scanners with production
// sandbox flags and applies the release gate.
//
//	go -C backend run ./cmd/selfscan -root .. -fail-on high
//	go -C backend run ./cmd/selfscan -root .. -zip sample.zip   # push any archive through
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/aupv9/warden/backend/internal/domain/severity"
	"github.com/aupv9/warden/backend/internal/pack"
	"github.com/aupv9/warden/backend/internal/scan/gate"
	"github.com/aupv9/warden/backend/internal/scan/orchestrator"
	"github.com/aupv9/warden/backend/internal/scan/sandbox"
	"github.com/aupv9/warden/backend/internal/scan/zipcheck"
)

func main() {
	code, err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "selfscan:", err)
		if code == 0 {
			code = 2
		}
	}
	os.Exit(code)
}

type options struct {
	root, runtime, mirror, reports, baseline, zipPath, failOn string
	tools                                                     []string
}

func run() (int, error) {
	var o options
	var tools string
	flag.StringVar(&o.root, "root", "", "repository root (default: git toplevel of the working directory)")
	flag.StringVar(&o.failOn, "fail-on", "critical", "critical|high|medium|low|info")
	flag.StringVar(&o.runtime, "runtime", "", "runsc (default if installed) or runc")
	flag.StringVar(&o.mirror, "mirror", "", "offline mirror (default ROOT/.cache/mirror)")
	flag.StringVar(&o.reports, "reports", "", "report dir (default ROOT/reports/selfscan)")
	flag.StringVar(&o.baseline, "baseline", "", "baseline (default ROOT/.warden/baseline.json)")
	flag.StringVar(&tools, "tools", strings.Join(sandbox.ToolNames, ","), "comma-separated scanners")
	flag.StringVar(&o.zipPath, "zip", "", "scan this archive instead of the Warden repo")
	flag.Parse()

	failOn, err := severity.Parse(o.failOn)
	if err != nil {
		return 2, err
	}
	if o.root == "" {
		if o.root, err = output(exec.Command("git", "rev-parse", "--show-toplevel")); err != nil {
			return 2, err
		}
	}
	if o.root, err = filepath.Abs(o.root); err != nil {
		return 2, err
	}
	def := func(p *string, rel string) {
		if *p == "" {
			*p = filepath.Join(o.root, rel)
		}
	}
	def(&o.mirror, ".cache/mirror")
	def(&o.reports, "reports/selfscan")
	def(&o.baseline, ".warden/baseline.json")
	for _, t := range strings.Split(tools, ",") {
		if t == "" {
			continue
		}
		if _, ok := sandbox.Tools[t]; !ok {
			return 2, fmt.Errorf("unknown tool %q", t)
		}
		o.tools = append(o.tools, t)
	}

	if o.runtime == "" {
		runtimes, err := output(exec.Command("docker", "info", "-f", "{{json .Runtimes}}"))
		if err != nil {
			return 2, err
		}
		o.runtime = "runc"
		if strings.Contains(runtimes, `"runsc"`) {
			o.runtime = "runsc"
		}
	}
	if o.runtime != "runsc" {
		fmt.Println("WARNING: gVisor (runsc) not available; sandbox uses runc. OK for local dev only.")
	}
	if st, err := os.Stat(filepath.Join(o.mirror, "trivy")); err != nil || !st.IsDir() {
		return 2, fmt.Errorf("mirror missing at %s; run `make mirror` first", o.mirror)
	}

	images, err := buildImages(o.root, o.tools)
	if err != nil {
		return 2, err
	}

	scanID := fmt.Sprintf("selfscan-%d", os.Getpid())
	scanDir := filepath.Join(o.root, ".cache/selfscan", scanID)
	if err := os.MkdirAll(filepath.Dir(scanDir), 0o700); err != nil {
		return 2, err
	}
	if err := os.Mkdir(scanDir, 0o700); err != nil {
		return 2, err
	}
	defer zipcheck.RemoveAll(scanDir)
	return scan(o, failOn, images, scanID, scanDir)
}

func scan(o options, failOn severity.Severity, images map[string]string, scanID, scanDir string) (int, error) {
	zipPath := filepath.Join(scanDir, "src.zip")
	var err error
	if o.zipPath != "" {
		err = copyFile(o.zipPath, zipPath)
	} else {
		_, err = pack.Repo(o.root, zipPath, "warden/")
	}
	if err != nil {
		return 2, err
	}
	res, err := zipcheck.Extract(zipPath, filepath.Join(scanDir, "src"), zipcheck.DefaultLimits())
	if err != nil {
		return 1, err
	}
	fmt.Printf("==> extracted %d files (%d bytes); %d warnings\n", res.Files, res.TotalBytes, len(res.Warnings))

	key, err := orchestrator.NewHMACKey()
	if err != nil {
		return 2, err
	}
	if err := os.Mkdir(filepath.Join(scanDir, "secrets"), 0o700); err != nil {
		return 2, err
	}
	if err := os.WriteFile(filepath.Join(scanDir, "secrets/hmac"), key, 0o444); err != nil {
		return 2, err
	}

	runs := make([]sandbox.ToolRun, len(o.tools))
	var wg sync.WaitGroup
	for i, t := range o.tools {
		wg.Go(func() {
			runs[i] = sandbox.Run(context.Background(), sandbox.Tools[t], sandbox.RunConfig{
				ScanID: scanID, ScanDir: scanDir, Image: images[t], Runtime: o.runtime, MirrorDir: o.mirror,
			})
		})
	}
	wg.Wait()

	if err := os.MkdirAll(o.reports, 0o755); err != nil {
		return 2, err
	}
	var inputs []gate.Input
	var failed []string
	for _, r := range runs {
		line := fmt.Sprintf("  %-9s %-9s %6.1fs", r.Tool, r.Status, float64(r.DurationMS)/1000)
		if r.Error != "" {
			e := strings.TrimSpace(r.Error)
			line += "  " + e[max(0, len(e)-300):]
		}
		fmt.Println(line)
		if r.Status != sandbox.Succeeded {
			failed = append(failed, r.Tool)
			continue
		}
		out := filepath.Join(o.reports, r.Tool+".sarif")
		if err := copyFile(r.Sarif, out); err != nil {
			return 2, err
		}
		inputs = append(inputs, gate.Input{Tool: r.Tool, File: out})
	}

	code := 1
	if len(inputs) > 0 {
		if code, err = gate.Run(gate.Options{
			Inputs: inputs, FailOn: failOn, Baseline: o.baseline,
			SourceRoot: filepath.Join(scanDir, "src"), JSONOut: filepath.Join(o.reports, "findings.json"),
		}, os.Stdout); err != nil {
			return 2, err
		}
	}
	if len(failed) > 0 {
		fmt.Printf("FAIL: scanner(s) did not complete: %s\n", strings.Join(failed, ", "))
		return 1, nil
	}
	return code, nil
}

type lockEntry struct {
	Upstream string `json:"upstream"`
}

// buildImages builds the Warden scanner images and pulls the pinned upstream ones.
// Locally built images are referenced by their sha256 image ID.
func buildImages(root string, tools []string) (map[string]string, error) {
	raw, err := os.ReadFile(filepath.Join(root, "scanners/images.lock.json"))
	if err != nil {
		return nil, err
	}
	var lock map[string]json.RawMessage // also holds "_comment"
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}
	images := map[string]string{}
	for _, t := range tools {
		switch t {
		case "gitleaks", "opengrep":
			tag := "warden/" + t + ":selfscan"
			fmt.Println("==> building", tag)
			cmd := exec.Command("docker", "build", "-q", "-f", "scanners/"+t+"/Dockerfile", "-t", tag, ".")
			cmd.Dir, cmd.Stderr = root, os.Stderr
			if err := cmd.Run(); err != nil {
				return nil, fmt.Errorf("build %s: %w", t, err)
			}
			if images[t], err = output(exec.Command("docker", "image", "inspect", "-f", "{{.Id}}", tag)); err != nil {
				return nil, err
			}
		default:
			var e lockEntry
			_ = json.Unmarshal(lock[t], &e)
			ref := e.Upstream
			if ref == "" {
				return nil, fmt.Errorf("no upstream image for %s in images.lock.json", t)
			}
			cmd := exec.Command("docker", "pull", "-q", ref)
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return nil, fmt.Errorf("pull %s: %w", ref, err)
			}
			images[t] = ref
		}
	}
	return images, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func output(cmd *exec.Cmd) (string, error) {
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s: %w", strings.Join(cmd.Args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}
