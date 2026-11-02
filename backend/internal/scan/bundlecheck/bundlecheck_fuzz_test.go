package bundlecheck

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// checkBundle runs Check and, when it accepts, re-derives what it may accept
// from the bytes as an independent oracle: a v2/v3 signature, no
// prerequisite or filter, reference names under refs/ (or HEAD) without
// "..", control characters or spaces, and a pack that ends the file with a
// matching checksum.
func checkBundle(t *testing.T, data []byte) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "repo.bundle")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Check(p, Limits{MaxBytes: 1 << 20})
	if err != nil {
		var r *Rejected
		if !errors.As(err, &r) {
			t.Fatalf("error that isn't a *Rejected: %v", err)
		}
		if r.Code != CodeInvalid && r.Code != CodeIncomplete && r.Code != CodeTooLarge {
			t.Fatalf("unknown code %q", r.Code)
		}
		return
	}
	header, pack, ok := bytes.Cut(data, []byte("\n\n"))
	if !ok {
		t.Fatalf("accepted a bundle without a blank line: %+v", res)
	}
	lines := strings.Split(string(header), "\n")
	switch {
	case lines[0] == "# v2 git bundle" && res.Version == 2, lines[0] == "# v3 git bundle" && res.Version == 3:
	default:
		t.Fatalf("accepted signature %q as v%d", lines[0], res.Version)
	}
	hexLen := map[string]int{"sha1": 40, "sha256": 64}[res.ObjectFormat]
	refs := 0
	for _, l := range lines[1:] {
		if strings.HasPrefix(l, "@") {
			if res.Version != 3 || (l != "@object-format=sha1" && l != "@object-format=sha256") {
				t.Fatalf("accepted capability %q", l)
			}
			continue
		}
		oid, name, ok := strings.Cut(l, " ")
		if !ok || len(oid) != hexLen || strings.Trim(oid, "0123456789abcdef") != "" {
			t.Fatalf("accepted reference line %q", l)
		}
		if name != "HEAD" && (!strings.HasPrefix(name, "refs/") || strings.Contains(name, "..") ||
			strings.ContainsAny(name, " ~^:?*[\\\x7f") || strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 }) ||
			strings.Contains(name, "//") || strings.HasSuffix(name, "/") || strings.HasSuffix(name, ".lock") || strings.Contains(name, "/.")) {
			t.Fatalf("accepted reference name %q", name)
		}
		refs++
	}
	if refs != res.Refs || refs == 0 {
		t.Fatalf("%d reference lines, Refs=%d", refs, res.Refs)
	}
	var sum []byte
	switch res.ObjectFormat {
	case "sha1":
		s := sha1.Sum(pack[:max(0, len(pack)-sha1.Size)])
		sum = s[:]
	case "sha256":
		s := sha256.Sum256(pack[:max(0, len(pack)-sha256.Size)])
		sum = s[:]
	default:
		t.Fatalf("object format %q", res.ObjectFormat)
	}
	if len(pack) < 12+len(sum) || string(pack[:4]) != "PACK" || !bytes.Equal(pack[len(pack)-len(sum):], sum) {
		t.Fatalf("accepted a pack with bad framing or checksum")
	}
	if n := binary.BigEndian.Uint32(pack[8:12]); n == 0 || n != res.Objects || int(n) > (len(pack)-12-len(sum))/minObjectBytes {
		t.Fatalf("accepted %d objects in %d bytes", n, len(pack))
	}
}

// FuzzCheckRaw mutates whole bundles.
func FuzzCheckRaw(f *testing.F) {
	good := pack(2, 3, body, false)
	f.Add(bundle(v2(oid1+" refs/heads/main", oid1+" HEAD", oid2+" refs/tags/v1.0"), good))
	f.Add(bundle("# v3 git bundle\n@object-format=sha256\n"+oid256+" refs/heads/main\n\n", pack(3, 1, body, true)))
	f.Add(bundle(v2("-"+oid2+" the parent", oid1+" refs/heads/main"), good))
	f.Add(bundle("# v3 git bundle\n@filter=blob:none\n"+oid1+" refs/heads/main\n\n", good))
	f.Add(bundle(v2(oid1+" refs/heads/../../config"), good))
	f.Add(bundle(v2(oid1+" refs/heads/main"), pack(2, 0xffffffff, body, false)))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		checkBundle(t, data)
	})
}

// FuzzCheckHeader fuzzes the header text and the pack's header fields, and
// always appends a pack with the right checksum, so the fuzzer gets past the
// checksum and explores the header rules.
func FuzzCheckHeader(f *testing.F) {
	f.Add(v2(oid1+" refs/heads/main", oid1+" HEAD"), uint32(2), uint32(3), body, false)
	f.Add("# v3 git bundle\n@object-format=sha256\n"+oid256+" refs/heads/main\n\n", uint32(3), uint32(1), body, true)
	f.Add("# v3 git bundle\n@object-format=sha1\n"+oid1+" refs/heads/feature/a-b_c.d\n\n", uint32(2), uint32(1), body, false)
	f.Add(v2(oid1+" refs/heads/a@{1}", oid1+" refs/heads/x.lock", oid1+" refs//x"), uint32(2), uint32(1), body, false)
	f.Add(v2("-"+oid2, oid1+" refs/heads/main"), uint32(2), uint32(1), body, false)
	f.Add("# v2 git bundle\n\n"+oid1+" refs/heads/main\n\n", uint32(2), uint32(4), body, false)
	f.Fuzz(func(t *testing.T, header string, version, objects uint32, packBody []byte, sha256Trailer bool) {
		if len(header)+len(packBody) > 64<<10 {
			return
		}
		checkBundle(t, bundle(header, pack(version, objects, packBody, sha256Trailer)))
	})
}
