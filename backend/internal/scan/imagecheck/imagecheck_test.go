package imagecheck

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type ent struct {
	name string
	typ  byte
	body string
	link string
}

func file(name, body string) ent { return ent{name: name, typ: tar.TypeReg, body: body} }
func dir(name string) ent        { return ent{name: name, typ: tar.TypeDir} }

func writeTar(t *testing.T, entries ...ent) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Size: int64(len(e.body)), Mode: 0o644, Linkname: e.link, Format: tar.FormatPAX}
		if e.typ != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			_, _ = tw.Write([]byte(e.body))
		}
	}
	_ = tw.Close()
	p := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func hex64(c byte) string { return strings.Repeat(string(c), 64) }

var (
	cfg   = hex64('c')
	layer = hex64('1')
	mfst  = hex64('a')
	other = hex64('b')
)

// dockerSave has the shape Docker 25+ writes: manifest.json and an OCI layout,
// where index.json points at a manifest list of which one platform is present.
func dockerSave(extra ...ent) []ent {
	return append([]ent{
		dir("blobs/"), dir("blobs/sha256/"),
		file("blobs/sha256/"+mfst, `{"schemaVersion":2,"config":{"digest":"sha256:`+cfg+`"},"layers":[{"digest":"sha256:`+layer+`"}]}`),
		file("blobs/sha256/"+cfg, `{"os":"linux"}`),
		file("blobs/sha256/"+layer, "layer"),
		file("index.json", `{"schemaVersion":2,"manifests":[{"digest":"sha256:`+hex64('f')+`"}]}`),
		file("blobs/sha256/"+hex64('f'), `{"manifests":[{"digest":"sha256:`+mfst+`"},{"digest":"sha256:`+other+`"}]}`),
		file("manifest.json", `[{"Config":"blobs/sha256/`+cfg+`","RepoTags":null,"Layers":["blobs/sha256/`+layer+`"]}]`),
		file("oci-layout", `{"imageLayoutVersion":"1.0.0"}`),
	}, extra...)
}

func check(t *testing.T, p string) (*Result, error) {
	t.Helper()
	return Check(p, Limits{MaxBytes: 64 << 20})
}

func code(err error) string {
	var r *Rejected
	if errors.As(err, &r) {
		return r.Code
	}
	return fmt.Sprint(err)
}

func TestAcceptsDockerSave(t *testing.T) {
	r, err := check(t, writeTar(t, dockerSave()...))
	if err != nil || r.Layout != "docker" || r.Layers != 1 {
		t.Fatal(r, err)
	}
	// Classic docker save: <id>/layer.tar, no OCI layout.
	classic := writeTar(t, dir("abc/"), file("abc/layer.tar", "l"), file("abc/VERSION", "1.0"), file(cfg+".json", "{}"),
		file("manifest.json", `[{"Config":"`+cfg+`.json","RepoTags":["alpine:3.18"],"Layers":["abc/layer.tar"]}]`), file("repositories", "{}"))
	if r, err := check(t, classic); err != nil || r.Layers != 1 {
		t.Fatal(r, err)
	}
}

func TestAcceptsOCILayout(t *testing.T) {
	var entries []ent
	for _, e := range dockerSave() {
		if e.name != "manifest.json" {
			entries = append(entries, e)
		}
	}
	r, err := check(t, writeTar(t, entries...))
	if err != nil || r.Layout != "oci" || r.Layers != 1 {
		t.Fatal(r, err)
	}
	// index.json straight to an image manifest.
	direct := writeTar(t, file("oci-layout", "{}"), file("index.json", `{"manifests":[{"digest":"sha256:`+mfst+`"}]}`),
		file("blobs/sha256/"+mfst, `{"config":{"digest":"sha256:`+cfg+`"},"layers":[{"digest":"sha256:`+layer+`"}]}`),
		file("blobs/sha256/"+cfg, "{}"), file("blobs/sha256/"+layer, "l"))
	if _, err := check(t, direct); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsHostileTarballs(t *testing.T) {
	twoImages := `[{"Config":"blobs/sha256/` + cfg + `","Layers":["blobs/sha256/` + layer + `"]},{"Config":"blobs/sha256/` + cfg + `","Layers":["blobs/sha256/` + layer + `"]}]`
	manyLayers := make([]string, MaxLayers+1)
	for i := range manyLayers {
		manyLayers[i] = `"blobs/sha256/` + layer + `"`
	}
	ociOnly := func(index string, extra ...ent) []ent {
		return append([]ent{file("oci-layout", "{}"), file("index.json", index), file("blobs/sha256/"+cfg, "{}"), file("blobs/sha256/"+layer, "l")}, extra...)
	}
	img := `{"config":{"digest":"sha256:` + cfg + `"},"layers":[{"digest":"sha256:` + layer + `"}]}`
	for name, c := range map[string]struct {
		entries []ent
		code    string
	}{
		"symlink":             {dockerSave(ent{name: "evil", typ: tar.TypeSymlink, link: "/etc/passwd"}), CodeInvalid},
		"symlinked layer":     {[]ent{file("manifest.json", `[{"Config":"c","Layers":["l"]}]`), file("c", "{}"), {name: "l", typ: tar.TypeSymlink, link: "../../etc/shadow"}}, CodeInvalid},
		"hardlink":            {dockerSave(ent{name: "evil", typ: tar.TypeLink, link: "manifest.json"}), CodeInvalid},
		"device":              {dockerSave(ent{name: "dev", typ: tar.TypeChar}), CodeInvalid},
		"fifo":                {dockerSave(ent{name: "fifo", typ: tar.TypeFifo}), CodeInvalid},
		"traversal":           {dockerSave(file("../../etc/cron.d/x", "x")), CodeInvalid},
		"absolute":            {dockerSave(file("/etc/passwd", "x")), CodeInvalid},
		"windows drive":       {dockerSave(file(`C:\x`, "x")), CodeInvalid},
		"deep path":           {dockerSave(file(strings.Repeat("d/", 60)+"x", "x")), CodeInvalid},
		"duplicate":           {dockerSave(file("./manifest.json", "[]")), CodeInvalid},
		"duplicate dir/file":  {dockerSave(dir("x/"), file("x", "x")), CodeInvalid},
		"no manifest":         {[]ent{file("layer.tar", "x")}, CodeInvalid},
		"empty manifest":      {[]ent{file("manifest.json", `[]`)}, CodeInvalid},
		"manifest type":       {[]ent{file("manifest.json", `{"Config":"c"}`)}, CodeInvalid},
		"manifest trailing":   {[]ent{file("manifest.json", `[] []`)}, CodeInvalid},
		"manifest too big":    {[]ent{file("manifest.json", `[`+strings.Repeat(" ", MaxManifestBytes)+`]`)}, CodeInvalid},
		"two images":          {[]ent{file("manifest.json", twoImages), file("blobs/sha256/"+cfg, "{}"), file("blobs/sha256/"+layer, "l")}, CodeMultiple},
		"missing layer":       {[]ent{file("manifest.json", `[{"Config":"c","Layers":["nope/layer.tar"]}]`), file("c", "{}")}, CodeInvalid},
		"missing config":      {[]ent{file("manifest.json", `[{"Config":"c","Layers":["l"]}]`), file("l", "x")}, CodeInvalid},
		"config traversal":    {[]ent{file("manifest.json", `[{"Config":"../c","Layers":["l"]}]`), file("l", "x")}, CodeInvalid},
		"layer is a dir":      {[]ent{file("manifest.json", `[{"Config":"c","Layers":["d"]}]`), file("c", "{}"), dir("d/")}, CodeInvalid},
		"no layers":           {[]ent{file("manifest.json", `[{"Config":"c","Layers":[]}]`), file("c", "{}")}, CodeInvalid},
		"too many layers":     {[]ent{file("manifest.json", `[{"Config":"blobs/sha256/`+cfg+`","Layers":[`+strings.Join(manyLayers, ",")+`]}]`), file("blobs/sha256/"+cfg, "{}"), file("blobs/sha256/"+layer, "l")}, CodeTooLarge},
		"index no oci-layout": {[]ent{file("index.json", `{"manifests":[]}`)}, CodeInvalid},
		"oci two images":      {ociOnly(`{"manifests":[{"digest":"sha256:`+mfst+`"},{"digest":"sha256:`+other+`"}]}`, file("blobs/sha256/"+mfst, img), file("blobs/sha256/"+other, img)), CodeMultiple},
		"oci two platforms":   {ociOnly(`{"manifests":[{"digest":"sha256:`+hex64('f')+`"}]}`, file("blobs/sha256/"+hex64('f'), `{"manifests":[{"digest":"sha256:`+mfst+`"},{"digest":"sha256:`+other+`"}]}`), file("blobs/sha256/"+mfst, img), file("blobs/sha256/"+other, img)), CodeMultiple},
		"oci missing blob":    {ociOnly(`{"manifests":[{"digest":"sha256:` + mfst + `"}]}`), CodeInvalid},
		"oci bad digest":      {ociOnly(`{"manifests":[{"digest":"sha256:../../x"}]}`), CodeInvalid},
		"oci missing layer":   {ociOnly(`{"manifests":[{"digest":"sha256:`+mfst+`"}]}`, file("blobs/sha256/"+mfst, `{"config":{"digest":"sha256:`+cfg+`"},"layers":[{"digest":"sha256:`+hex64('9')+`"}]}`)), CodeInvalid},
		"oci nested too deep": {ociOnly(`{"manifests":[{"digest":"sha256:`+hex64('f')+`"}]}`, file("blobs/sha256/"+hex64('f'), `{"manifests":[{"digest":"sha256:`+mfst+`"}]}`), file("blobs/sha256/"+mfst, `{"manifests":[{"digest":"sha256:`+cfg+`"}]}`)), CodeInvalid},
		"oci manifest type":   {ociOnly(`{"manifests":"x"}`), CodeInvalid},
	} {
		if _, err := check(t, writeTar(t, c.entries...)); code(err) != c.code {
			t.Errorf("%s: got %v, want %s", name, err, c.code)
		}
	}
}

func TestRejectsTooManyEntriesAndTooLarge(t *testing.T) {
	many := dockerSave()
	for i := range MaxEntries {
		many = append(many, file(fmt.Sprintf("pad/%d", i), ""))
	}
	if _, err := check(t, writeTar(t, many...)); code(err) != CodeTooLarge {
		t.Fatal(err)
	}
	p := writeTar(t, dockerSave()...)
	if _, err := Check(p, Limits{MaxBytes: 10}); code(err) != CodeTooLarge {
		t.Fatal(err)
	}
	// Not a tar at all, or truncated.
	junk := filepath.Join(t.TempDir(), "junk.tar")
	_ = os.WriteFile(junk, []byte(strings.Repeat("not a tar ", 100)), 0o600)
	if _, err := check(t, junk); code(err) != CodeInvalid {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	trunc := filepath.Join(t.TempDir(), "trunc.tar")
	_ = os.WriteFile(trunc, raw[:700], 0o600)
	if _, err := check(t, trunc); code(err) != CodeInvalid {
		t.Fatal(err)
	}
	if _, err := check(t, filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
}

// A real `docker save` (Docker 25+, alpine), when the verification run left one.
func TestRealDockerSave(t *testing.T) {
	p := os.Getenv("WARDEN_TEST_IMAGE_TAR")
	if p == "" {
		t.Skip("set WARDEN_TEST_IMAGE_TAR to a docker save tarball")
	}
	if r, err := Check(p, Limits{MaxBytes: 2 << 30}); err != nil || r.Layers == 0 {
		t.Fatal(r, err)
	}
}
