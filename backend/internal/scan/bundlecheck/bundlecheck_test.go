package bundlecheck

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var (
	oid1   = strings.Repeat("ab", 20)
	oid2   = strings.Repeat("cd", 20)
	oid256 = strings.Repeat("ef", 32)
)

// pack builds a framed pack: header, body and the right trailer (sha1 or
// sha256). The objects aren't real: bundlecheck reads only the framing.
func pack(version, objects uint32, body []byte, sha256Trailer bool) []byte {
	var b bytes.Buffer
	b.WriteString("PACK")
	_ = binary.Write(&b, binary.BigEndian, version)
	_ = binary.Write(&b, binary.BigEndian, objects)
	b.Write(body)
	if sha256Trailer {
		s := sha256.Sum256(b.Bytes())
		b.Write(s[:])
	} else {
		s := sha1.Sum(b.Bytes())
		b.Write(s[:])
	}
	return b.Bytes()
}

var body = bytes.Repeat([]byte{0x78}, 30) // room for 3 objects

func bundle(header string, p []byte) []byte { return append([]byte(header), p...) }

func write(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "repo.bundle")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func check(t *testing.T, b []byte) (*Result, error) {
	t.Helper()
	return Check(write(t, b), Limits{MaxBytes: 64 << 20})
}

func code(err error) string {
	var r *Rejected
	if errors.As(err, &r) {
		return r.Code
	}
	return fmt.Sprint(err)
}

func v2(refs ...string) string {
	return "# v2 git bundle\n" + strings.Join(refs, "\n") + "\n\n"
}

func TestAcceptsWellFormedBundles(t *testing.T) {
	r, err := check(t, bundle(v2(oid1+" refs/heads/main", oid1+" HEAD", oid2+" refs/tags/v1.0"), pack(2, 3, body, false)))
	if err != nil || r.Version != 2 || r.ObjectFormat != "sha1" || r.Refs != 3 || r.Objects != 3 {
		t.Fatal(r, err)
	}
	v3 := "# v3 git bundle\n@object-format=sha256\n" + oid256 + " refs/heads/main\n\n"
	if r, err := check(t, bundle(v3, pack(3, 1, body, true))); err != nil || r.Version != 3 || r.ObjectFormat != "sha256" {
		t.Fatal(r, err)
	}
	v3sha1 := "# v3 git bundle\n@object-format=sha1\n" + oid1 + " refs/heads/feature/a-b_c.d\n\n"
	if _, err := check(t, bundle(v3sha1, pack(2, 1, body, false))); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsHostileBundles(t *testing.T) {
	good := pack(2, 3, body, false)
	ref := oid1 + " refs/heads/main"
	longName := "refs/heads/" + strings.Repeat("a", MaxRefName)
	for name, c := range map[string]struct {
		data []byte
		code string
	}{
		"empty":                    {nil, CodeInvalid},
		"zip":                      {append([]byte("PK\x03\x04"), good...), CodeInvalid},
		"v4 signature":             {bundle("# v4 git bundle\n"+ref+"\n\n", good), CodeInvalid},
		"crlf":                     {bundle("# v2 git bundle\r\n"+ref+"\r\n\r\n", good), CodeInvalid},
		"no newline":               {[]byte("# v2 git bundle"), CodeInvalid},
		"truncated header":         {[]byte("# v2 git bundle\n" + ref + "\n"), CodeInvalid},
		"header without blank":     {[]byte("# v2 git bundle\n" + ref + "\nPACK"), CodeInvalid},
		"huge line":                {bundle("# v2 git bundle\n"+oid1+" refs/heads/"+strings.Repeat("x", 1<<20)+"\n\n", good), CodeInvalid},
		"huge line no newline":     {[]byte("# v2 git bundle\n" + strings.Repeat("x", 1<<20)), CodeInvalid},
		"no refs":                  {bundle("# v2 git bundle\n\n", good), CodeInvalid},
		"short oid":                {bundle(v2(oid1[1:]+" refs/heads/main"), good), CodeInvalid},
		"upper-case oid":           {bundle(v2(strings.ToUpper(oid1)+" refs/heads/main"), good), CodeInvalid},
		"non-hex oid":              {bundle(v2("zz"+oid1[2:]+" refs/heads/main"), good), CodeInvalid},
		"null oid":                 {bundle(v2(strings.Repeat("0", 40)+" refs/heads/main"), good), CodeInvalid},
		"sha256 oid in v2":         {bundle(v2(oid256+" refs/heads/main"), good), CodeInvalid},
		"sha1 oid in sha256":       {bundle("# v3 git bundle\n@object-format=sha256\n"+ref+"\n\n", pack(2, 1, body, true)), CodeInvalid},
		"no refname":               {bundle(v2(oid1), good), CodeInvalid},
		"two spaces":               {bundle(v2(oid1+"  refs/heads/main"), good), CodeInvalid},
		"traversal":                {bundle(v2(oid1+" refs/heads/../../config"), good), CodeInvalid},
		"outside refs":             {bundle(v2(oid1+" ../etc/passwd"), good), CodeInvalid},
		"absolute":                 {bundle(v2(oid1+" /etc/passwd"), good), CodeInvalid},
		"other top level":          {bundle(v2(oid1+" FETCH_HEAD"), good), CodeInvalid},
		"refs/ alone":              {bundle(v2(oid1+" refs/"), good), CodeInvalid},
		"double slash":             {bundle(v2(oid1+" refs//heads/x"), good), CodeInvalid},
		"trailing slash":           {bundle(v2(oid1+" refs/heads/x/"), good), CodeInvalid},
		"trailing dot":             {bundle(v2(oid1+" refs/heads/x."), good), CodeInvalid},
		"dot component":            {bundle(v2(oid1+" refs/heads/.hidden"), good), CodeInvalid},
		"lock":                     {bundle(v2(oid1+" refs/heads/main.lock"), good), CodeInvalid},
		"reflog syntax":            {bundle(v2(oid1+" refs/heads/a@{1}"), good), CodeInvalid},
		"escape":                   {bundle(v2(oid1+" refs/heads/a\x1b[31m"), good), CodeInvalid},
		"nul":                      {bundle(v2(oid1+" refs/heads/a\x00b"), good), CodeInvalid},
		"del":                      {bundle(v2(oid1+" refs/heads/a\x7f"), good), CodeInvalid},
		"tab":                      {bundle(v2(oid1+" refs/heads/a\tb"), good), CodeInvalid},
		"space":                    {bundle(v2(oid1+" refs/heads/a b"), good), CodeInvalid},
		"backslash":                {bundle(v2(oid1+` refs\heads\x`), good), CodeInvalid},
		"glob":                     {bundle(v2(oid1+" refs/heads/*"), good), CodeInvalid},
		"colon":                    {bundle(v2(oid1+" refs/heads/a:b"), good), CodeInvalid},
		"tilde":                    {bundle(v2(oid1+" refs/heads/a~1"), good), CodeInvalid},
		"long refname":             {bundle(v2(oid1+" "+longName), good), CodeInvalid},
		"duplicate ref":            {bundle(v2(ref, oid2+" refs/heads/main"), good), CodeInvalid},
		"capability in v2":         {bundle("# v2 git bundle\n@object-format=sha1\n"+ref+"\n\n", good), CodeInvalid},
		"unknown capability":       {bundle("# v3 git bundle\n@bundle-uri=https://evil.test\n"+ref+"\n\n", good), CodeInvalid},
		"unknown object format":    {bundle("# v3 git bundle\n@object-format=md5\n"+ref+"\n\n", good), CodeInvalid},
		"object format no value":   {bundle("# v3 git bundle\n@object-format\n"+ref+"\n\n", good), CodeInvalid},
		"repeated capability":      {bundle("# v3 git bundle\n@object-format=sha1\n@object-format=sha256\n"+ref+"\n\n", good), CodeInvalid},
		"capability after ref":     {bundle("# v3 git bundle\n"+ref+"\n@filter=blob:none\n\n", good), CodeInvalid},
		"filter":                   {bundle("# v3 git bundle\n@filter=blob:none\n"+ref+"\n\n", good), CodeIncomplete},
		"prerequisite":             {bundle(v2("-"+oid2+" the parent", ref), good), CodeIncomplete},
		"bare prerequisite":        {bundle(v2("-"+oid2, ref), good), CodeIncomplete},
		"bad prerequisite oid":     {bundle(v2("-../../x", ref), good), CodeInvalid},
		"no pack":                  {[]byte(v2(ref)), CodeInvalid},
		"pack magic":               {bundle(v2(ref), append([]byte("KCAP"), good[4:]...)), CodeInvalid},
		"zip instead of pack":      {bundle(v2(ref), append([]byte("PK\x03\x04"), good[4:]...)), CodeInvalid},
		"pack version 1":           {bundle(v2(ref), pack(1, 3, body, false)), CodeInvalid},
		"pack version 4":           {bundle(v2(ref), pack(4, 3, body, false)), CodeInvalid},
		"no objects":               {bundle(v2(ref), pack(2, 0, body, false)), CodeInvalid},
		"more objects than bytes":  {bundle(v2(ref), pack(2, 4, body, false)), CodeInvalid},
		"absurd object count":      {bundle(v2(ref), pack(2, 0xffffffff, body, false)), CodeInvalid},
		"bad checksum":             {bundle(v2(ref), append(good[:len(good)-1:len(good)-1], good[len(good)-1]^1)), CodeInvalid},
		"truncated pack":           {bundle(v2(ref), good[:len(good)-5]), CodeInvalid},
		"pack header only":         {bundle(v2(ref), good[:12]), CodeInvalid},
		"trailing garbage":         {bundle(v2(ref), append(append([]byte{}, good...), "#!/bin/sh\n"...)), CodeInvalid},
		"second pack appended":     {bundle(v2(ref), append(append([]byte{}, good...), good...)), CodeInvalid},
		"sha1 trailer for sha256":  {bundle("# v3 git bundle\n@object-format=sha256\n"+oid256+" refs/heads/main\n\n", pack(2, 1, body, false)), CodeInvalid},
		"sha256 trailer for sha1":  {bundle(v2(ref), pack(2, 1, body, true)), CodeInvalid},
		"blank line before refs":   {bundle("# v2 git bundle\n\n"+ref+"\n\n", good), CodeInvalid},
		"leading space before oid": {bundle(v2(" "+ref), good), CodeInvalid},
	} {
		_, err := check(t, c.data)
		if code(err) != c.code {
			t.Errorf("%s: got %v, want %s", name, err, c.code)
		}
	}
}

func TestRejectsTooLarge(t *testing.T) {
	good := pack(2, 3, body, false)
	p := write(t, bundle(v2(oid1+" refs/heads/main"), good))
	st, _ := os.Stat(p)
	if _, err := Check(p, Limits{MaxBytes: st.Size() - 1}); code(err) != CodeTooLarge {
		t.Fatal(err)
	}
	if _, err := Check(p, Limits{MaxBytes: st.Size()}); err != nil {
		t.Fatal(err)
	}

	refs := make([]string, MaxRefs+1)
	for i := range refs {
		refs[i] = fmt.Sprintf("%s refs/tags/t%d", oid1, i)
	}
	if _, err := check(t, bundle(v2(refs...), good)); code(err) != CodeTooLarge {
		t.Fatal(err)
	}
	if _, err := check(t, bundle(v2(refs[:MaxRefs]...), good)); err != nil {
		t.Fatal(err)
	}

	// Fewer refs than the cap, but long ones: the header cap applies.
	long := make([]string, MaxHeaderBytes/(MaxRefName-100)+1)
	for i := range long {
		long[i] = fmt.Sprintf("%s refs/tags/%0*d", oid1, MaxRefName-100, i)
	}
	if _, err := check(t, bundle(v2(long...), good)); code(err) != CodeTooLarge {
		t.Fatal(err)
	}
}

func TestRejectsNonRegularFile(t *testing.T) {
	if _, err := Check(t.TempDir(), Limits{MaxBytes: 1 << 20}); code(err) != CodeInvalid {
		t.Fatal(err)
	}
}

// git runs git with no user or system configuration.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x.test", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x.test")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func repo(t *testing.T, initArgs ...string) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, append([]string{"init", "-q", "-b", "main"}, initArgs...)...)
	for i := range 3 {
		if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte(fmt.Sprint(i)), 0o600); err != nil {
			t.Fatal(err)
		}
		git(t, dir, "add", "f.txt")
		git(t, dir, "commit", "-q", "-m", fmt.Sprint("c", i))
	}
	git(t, dir, "tag", "v1")
	git(t, dir, "branch", "feature/x")
	return dir
}

// Bundles made by git itself, as `warden scan --history` makes them.
func TestAcceptsRealGitBundles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := repo(t)
	out := filepath.Join(t.TempDir(), "r.bundle")
	git(t, dir, "bundle", "create", "-q", out, "--all")
	r, err := Check(out, Limits{MaxBytes: 64 << 20})
	if err != nil || r.Refs != 4 || r.Objects != 9 {
		t.Fatal(r, err)
	}

	// A bundle of the last commit only has the earlier ones as prerequisites.
	partial := filepath.Join(t.TempDir(), "p.bundle")
	git(t, dir, "bundle", "create", "-q", partial, "main~1..main")
	if _, err := Check(partial, Limits{MaxBytes: 64 << 20}); code(err) != CodeIncomplete {
		t.Fatal(err)
	}

	// A shallow clone's --all bundle has no prerequisites: git writes the
	// boundary commit without its parents, which the header doesn't show.
	// git finds out when it fetches the bundle in the sandbox (warden-gitleaks
	// exits 3, BUNDLE_INCOMPLETE), and the CLI refuses shallow clones first.
	shallow := t.TempDir()
	git(t, shallow, "clone", "-q", "--depth=1", "--no-local", "file://"+dir, ".")
	sb := filepath.Join(t.TempDir(), "s.bundle")
	git(t, shallow, "bundle", "create", "-q", sb, "--all")
	if _, err := Check(sb, Limits{MaxBytes: 64 << 20}); err != nil {
		t.Fatal(err)
	}

	// sha256 repositories write a v3 bundle (git 2.29+ can create them).
	if exec.Command("git", "init", "-q", "--object-format=sha256", t.TempDir()).Run() == nil {
		dir := repo(t, "--object-format=sha256")
		out := filepath.Join(t.TempDir(), "r256.bundle")
		git(t, dir, "bundle", "create", "-q", out, "--all")
		if r, err := Check(out, Limits{MaxBytes: 64 << 20}); err != nil || r.Version != 3 || r.ObjectFormat != "sha256" {
			t.Fatal(r, err)
		}
	}
}
