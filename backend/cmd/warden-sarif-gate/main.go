// warden-sarif-gate fails when SARIF findings at or above a severity aren't baselined:
//
//	warden-sarif-gate -sarif opengrep=out.sarif [-sarif trivy=t.sarif] -fail-on high -baseline .warden/baseline.json
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/aupv9/warden/backend/internal/domain/severity"
	"github.com/aupv9/warden/backend/internal/scan/gate"
)

type inputs []gate.Input

func (i *inputs) String() string { return fmt.Sprint(*i) }

func (i *inputs) Set(v string) error {
	tool, file, ok := strings.Cut(v, "=")
	if !ok || tool == "" || file == "" {
		return fmt.Errorf("want TOOL=FILE, got %q", v)
	}
	*i = append(*i, gate.Input{Tool: tool, File: file})
	return nil
}

func main() {
	var opts gate.Options
	var in inputs
	flag.Var(&in, "sarif", "TOOL=FILE (repeatable)")
	failOn := flag.String("fail-on", "critical", "critical|high|medium|low|info")
	flag.StringVar(&opts.Baseline, "baseline", "", "baseline JSON")
	flag.StringVar(&opts.SourceRoot, "source-root", "", "extracted source, to read flagged lines")
	flag.StringVar(&opts.JSONOut, "json-out", "", "write normalized findings here")
	flag.Parse()
	if len(in) == 0 {
		fmt.Fprintln(os.Stderr, "at least one -sarif TOOL=FILE is required")
		os.Exit(2)
	}
	sev, err := severity.Parse(*failOn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	opts.Inputs, opts.FailOn = in, sev
	code, err := gate.Run(opts, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warden-sarif-gate:", err)
	}
	os.Exit(code)
}
