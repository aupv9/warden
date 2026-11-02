package imagecheck

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aupv9/warden/backend/internal/scan/archpath"
)

// tarBytes builds a tarball in memory (the fuzz seeds; writeTar needs a *testing.T).
func tarBytes(entries ...ent) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Size: int64(len(e.body)), Mode: 0o644, Linkname: e.link, Format: tar.FormatPAX}
		if e.typ != tar.TypeReg {
			h.Size = 0
		}
		if tw.WriteHeader(h) != nil {
			return buf.Bytes()
		}
		if e.typ == tar.TypeReg {
			_, _ = tw.Write([]byte(e.body))
		}
	}
	_ = tw.Close()
	return buf.Bytes()
}

// checkTarball runs Check and, when it accepts, re-reads the tarball as an
// independent oracle: only regular files and directories with safe, unique
// names, and every config and layer the manifest names is a regular file.
func checkTarball(t *testing.T, data []byte) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	limits := Limits{MaxBytes: 1 << 20}
	res, err := Check(p, limits)
	res2, err2 := Check(p, limits)
	if (err == nil) != (err2 == nil) || (err == nil && *res != *res2) {
		t.Fatalf("not deterministic: %v / %v", err, err2)
	}
	if err != nil {
		var r *Rejected
		if !errors.As(err, &r) {
			t.Fatalf("error that isn't a *Rejected: %v", err)
		}
		if r.Code != CodeInvalid && r.Code != CodeTooLarge && r.Code != CodeMultiple {
			t.Fatalf("unknown code %q", r.Code)
		}
		return
	}
	if res.Layers < 1 || res.Layers > MaxLayers || (res.Layout != "docker" && res.Layout != "oci") {
		t.Fatalf("accepted %+v", res)
	}
	tr := tar.NewReader(bytes.NewReader(data))
	files := map[string]bool{}
	seen := map[string]bool{}
	var manifest []byte
	n := 0
	for ; ; n++ {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("accepted an unreadable tar: %v", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeDir {
			t.Fatalf("accepted entry %q of type %q", hdr.Name, hdr.Typeflag)
		}
		parts, err := archpath.Clean(hdr.Name)
		if err != nil {
			t.Fatalf("accepted unsafe name %q: %v", hdr.Name, err)
		}
		for _, part := range parts {
			if part == ".." || strings.ContainsRune(part, 0) {
				t.Fatalf("accepted unsafe name %q", hdr.Name)
			}
		}
		name := path.Join(parts...)
		if name == "" {
			continue
		}
		if seen[name] {
			t.Fatalf("accepted duplicate %q", name)
		}
		seen[name] = true
		if hdr.Typeflag == tar.TypeReg {
			files[name] = true
			if name == "manifest.json" {
				manifest, _ = io.ReadAll(tr)
			}
		}
	}
	if n > MaxEntries {
		t.Fatalf("accepted %d entries", n)
	}
	if res.Layout == "docker" {
		var m []struct {
			Config string
			Layers []string
		}
		if json.Unmarshal(manifest, &m) != nil || len(m) != 1 || len(m[0].Layers) != res.Layers {
			t.Fatalf("accepted manifest %q as %+v", manifest, res)
		}
		for _, ref := range append([]string{m[0].Config}, m[0].Layers...) {
			parts, err := archpath.Clean(ref)
			if err != nil || !files[path.Join(parts...)] {
				t.Fatalf("accepted a manifest naming %q, not a regular file of the tarball", ref)
			}
		}
	} else if !files["index.json"] || !files["oci-layout"] || files["manifest.json"] {
		t.Fatalf("accepted an OCI layout without index.json/oci-layout: %v", files)
	}
}

// FuzzCheck mutates whole tarballs.
func FuzzCheck(f *testing.F) {
	img := `{"config":{"digest":"sha256:` + cfg + `"},"layers":[{"digest":"sha256:` + layer + `"}]}`
	for _, entries := range [][]ent{
		dockerSave(),
		{file("oci-layout", "{}"), file("index.json", `{"manifests":[{"digest":"sha256:`+mfst+`"}]}`), file("blobs/sha256/"+mfst, img),
			file("blobs/sha256/"+cfg, "{}"), file("blobs/sha256/"+layer, "l")},
		dockerSave(ent{name: "evil", typ: tar.TypeSymlink, link: "/etc/passwd"}),
		dockerSave(ent{name: "evil", typ: tar.TypeLink, link: "manifest.json"}),
		dockerSave(file("../../etc/cron.d/x", "x")),
		dockerSave(file("./manifest.json", "[]")),
		{file("manifest.json", `[{"Config":"../c","Layers":["l"]}]`), file("l", "x")},
		{file("manifest.json", `[{"Config":"c","Layers":["d"]}]`), file("c", "{}"), dir("d/")},
	} {
		f.Add(tarBytes(entries...))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		checkTarball(t, data)
	})
}

// FuzzCheckManifest keeps the tar well formed and fuzzes the JSON documents
// and the entry names and types around them.
func FuzzCheckManifest(f *testing.F) {
	img := `{"config":{"digest":"sha256:` + cfg + `"},"layers":[{"digest":"sha256:` + layer + `"}]}`
	f.Add(`[{"Config":"c","Layers":["l"]}]`, "", "c\nl", "00")
	f.Add(`[{"Config":"c","Layers":["l"]}]`, "", "c\nl", "02")
	f.Add(`[{"Config":"c","Layers":["l"]}]`, "", "c\n./l/", "05")
	f.Add("", `{"manifests":[{"digest":"sha256:`+mfst+`"}]}`, "oci-layout\nblobs/sha256/"+mfst+"\nblobs/sha256/"+cfg+"\nblobs/sha256/"+layer, "0000")
	f.Add("", `{"manifests":[{"digest":"sha256:`+mfst+`"}]}`, "oci-layout\nblobs/sha256/"+mfst+"\nblobs/sha256/"+cfg, "0010")
	f.Add(`[{"Config":"c","Layers":["l","l"]}]`, `{"manifests":[]}`, "c\nl\noci-layout", "000")
	f.Fuzz(func(t *testing.T, manifest, index, names, types string) {
		if len(manifest)+len(index)+len(names) > 16<<10 {
			return
		}
		var entries []ent
		if manifest != "" {
			entries = append(entries, file("manifest.json", manifest))
		}
		if index != "" {
			entries = append(entries, file("index.json", index))
		}
		for i, name := range strings.Split(names, "\n") {
			typ := byte('0')
			if i < len(types) {
				typ = types[i]
			}
			body := "{}"
			if strings.HasSuffix(name, mfst) {
				body = img
			}
			if typ == tar.TypeReg {
				entries = append(entries, file(name, body))
			} else {
				entries = append(entries, ent{name: name, typ: typ, link: "manifest.json"})
			}
		}
		checkTarball(t, tarBytes(entries...))
	})
}
