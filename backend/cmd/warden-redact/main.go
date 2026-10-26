// warden-redact runs inside the Gitleaks sandbox after gitleaks:
//
//	warden-redact [-key-file /run/warden/hmac] raw.sarif result.sarif
//
// It writes the redacted SARIF and deletes the raw one.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aupv9/warden/backend/internal/scan/redact"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "warden-redact:", err)
		os.Exit(2)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("warden-redact", flag.ContinueOnError)
	defKey := os.Getenv("WARDEN_HMAC_KEY_FILE")
	if defKey == "" {
		defKey = "/run/warden/hmac"
	}
	keyFile := fs.String("key-file", defKey, "file holding the per-org HMAC key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage: warden-redact [-key-file F] SRC DST")
	}
	src, dst := fs.Arg(0), fs.Arg(1)

	rawKey, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	key := []byte(strings.TrimSpace(string(rawKey)))

	f, err := os.Open(src)
	if err != nil {
		return err
	}
	v, err := sarif.Decode(io.LimitReader(f, sarif.MaxFileBytes))
	f.Close()
	if err != nil {
		return fmt.Errorf("invalid SARIF JSON: %w", err)
	}
	doc, ok := v.(map[string]any)
	if !ok {
		return errors.New("SARIF is not an object")
	}
	out, err := redact.Doc(doc, key)
	if err != nil {
		return err
	}

	w, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		w.Close()
		os.Remove(dst)
		return err
	}
	if err := w.Close(); err != nil {
		os.Remove(dst)
		return err
	}
	return os.Remove(src)
}
