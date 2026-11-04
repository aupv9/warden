package layerscan

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aupv9/warden/backend/internal/scan/redact"
	"github.com/aupv9/warden/backend/internal/scan/sarif"
	st "github.com/aupv9/warden/backend/internal/scan/scantest"
)

// fakeGitleaks stands in for `gitleaks dir <batch>`: a result, in the shape
// Gitleaks writes, for every line of every file holding secret (the file
// path as walked, absolute, also in the message).
func fakeGitleaks(t *testing.T, b Batch, secret string) map[string]any {
	t.Helper()
	var results []any
	err := filepath.WalkDir(b.Dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := os.ReadFile(p)
		for i, line := range strings.Split(string(body), "\n") {
			if strings.Contains(line, secret) {
				results = append(results, st.M{
					"ruleId":              "aws-access-token",
					"message":             st.M{"text": "aws-access-token has detected secret for file " + p + "."},
					"locations":           []any{st.Loc(p, i+1, secret)},
					"partialFingerprints": st.M{"commitSha": "", "email": "", "author": "", "date": "", "commitMessage": ""},
					"properties":          st.M{"tags": []any{}},
				})
			}
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return st.RoundTrip(st.Doc(results, st.M{"id": "aws-access-token", "shortDescription": st.M{"text": "AWS"}}))
}

// The path a secret in an image takes: layers unpacked in the sandbox,
// Gitleaks, the merge, warden-redact, then the parser in the worker. The
// secret is in a file a later layer deletes, in a file named after it, and
// in a layer listed twice; nothing that leaves the sandbox holds it.
func TestSecretInImageLayersNeverLeavesRedacted(t *testing.T) {
	secret := st.FakeSecret
	base := tarOf(t, file("etc/os-release", "ID=test"))
	leak := tarOf(t, file("app/.env", "A=1\nKEY="+secret), file("app/"+secret+".txt", secret))
	del := tarOf(t, file("app/.wh..env", ""), file("app/.wh."+secret+".txt", ""))
	image := imageTar(t, base, gz(t, leak), del, gz(t, leak))

	var m Merger
	dir := filepath.Join(t.TempDir(), "layers")
	rep, err := Extract(writeImage(t, image), dir, testLimits(), func(b Batch) error {
		return m.Add(fakeGitleaks(t, b, secret), b)
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := m.Doc()
	red, err := redact.Doc(raw, st.HMACKey)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(red)
	if bytes.Contains(out, []byte(secret)) || bytes.Contains(out, []byte(dir)) {
		t.Fatalf("redacted SARIF holds the secret or the sandbox's paths: %s", out)
	}
	report, _ := json.Marshal(rep)
	if bytes.Contains(report, []byte(secret)) {
		t.Fatal("report holds the secret")
	}

	doc, err := sarif.Decode(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := sarif.Parse(doc.(map[string]any), "gitleaks", sarif.Options{ImageTarget: "ghcr.io/acme/api", ImageLayers: rep.Layers})
	if err != nil {
		t.Fatal(err)
	}
	// Two files, each at layers 1 and 3 (the same blob).
	if len(fs) != 4 {
		t.Fatalf("%d findings", len(fs))
	}
	paths := map[string]bool{}
	for _, f := range fs {
		paths[f.FilePath] = true
		if f.ImageLayer.Digest != digestOf(leak) || (f.ImageLayer.Index != 1 && f.ImageLayer.Index != 3) {
			t.Fatalf("%+v", f.ImageLayer)
		}
		if strings.Contains(f.Description, dir) || !strings.Contains(f.Description, " /app/") {
			t.Fatalf("description %q", f.Description)
		}
	}
	if !paths["ghcr.io/acme/api::/app/.env"] || !paths["ghcr.io/acme/api::/app/"+redact.Mask(secret)+".txt"] {
		t.Fatal(paths)
	}
	c := sarif.CollapseImageLayers(fs)
	if len(c) != 1 || c[0].ImageLayer.Index != 1 || c[0].ImageLayer.Count != 2 || c[0].FilePath != "ghcr.io/acme/api::/app/.env" ||
		c[0].Line() != 2 {
		t.Fatalf("%+v %+v", c, c[0].ImageLayer)
	}
}

func TestMergerRewrites(t *testing.T) {
	b := Batch{Dir: "/tmp/layers", Layers: map[int][]int{0: {0}, 2: {2, 5}}}
	doc := func(uris ...string) map[string]any {
		var rs []any
		for _, u := range uris {
			rs = append(rs, st.M{"ruleId": "r", "message": st.M{"text": "found in " + u + "."},
				"locations": []any{st.Loc(u, 1, "s3cr3t-value-1")}})
		}
		return st.RoundTrip(st.Doc(rs))
	}
	var m Merger
	if m.Doc() != nil {
		t.Fatal("doc before any batch")
	}
	if err := m.Add(doc("/tmp/layers/0/etc/a"), b); err != nil {
		t.Fatal(err)
	}
	if err := m.Add(doc("/tmp/layers/2/srv/b c", "/tmp/layers/0/x"), b); err != nil {
		t.Fatal(err)
	}
	if err := m.Add(doc(), b); err != nil {
		t.Fatal(err)
	}
	runs := m.Doc()["runs"].([]any)
	results := runs[0].(map[string]any)["results"].([]any)
	if len(runs) != 1 || len(results) != 4 {
		t.Fatal(runs)
	}
	want := []struct {
		uri   string
		layer string
	}{{"/etc/a", "0"}, {"/srv/b c", "2"}, {"/srv/b c", "5"}, {"/x", "0"}}
	for i, r := range results {
		res := r.(map[string]any)
		uri := at(res["locations"].([]any)[0], "physicalLocation", "artifactLocation", "uri")
		layer := at(res, "properties", sarif.LayerIndexProp)
		msg := at(res, "message", "text").(string)
		if uri != want[i].uri || layer != json.Number(want[i].layer) || msg != "found in "+want[i].uri+"." {
			t.Errorf("%d: %v %v %q", i, uri, layer, msg)
		}
	}
	// The two copies of a repeated layer's result are independent.
	results[1].(map[string]any)["ruleId"] = "changed"
	if results[2].(map[string]any)["ruleId"] != "r" {
		t.Fatal("copies share state")
	}

	for name, d := range map[string]map[string]any{
		"outside the batch": doc("/etc/passwd"),
		"sibling prefix":    doc("/tmp/layers-x/0/a"),
		"unknown layer":     doc("/tmp/layers/7/a"),
		"no number":         doc("/tmp/layers/a/b"),
		"leading zero":      doc("/tmp/layers/00/a"),
		"layer dir only":    doc("/tmp/layers/0/"),
		"no location":       st.RoundTrip(st.Doc([]any{st.M{"ruleId": "r"}})),
		"two runs":          {"runs": []any{st.M{}, st.M{}}},
		"result not object": st.RoundTrip(st.Doc([]any{"x"})),
	} {
		var m Merger
		if err := m.Add(d, b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Locations in two layers: refused.
	two := doc("/tmp/layers/0/a")
	res := two["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)
	res["locations"] = append(res["locations"].([]any), st.RoundTrip(st.M{"l": st.Loc("/tmp/layers/2/b", 1)})["l"])
	if err := (&Merger{}).Add(two, b); err == nil {
		t.Error("two layers accepted")
	}
}

func FuzzLayerPath(f *testing.F) {
	for _, s := range []string{"/tmp/layers/0/a", "/tmp/layers/12/a/b", "/tmp/layers/00/a", "/tmp/layers/1/", "/tmp/layers//a", "/tmp/layers/-1/a", "/tmp/layers/1e3/a"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, uri string) {
		n, p, ok := LayerPath("/tmp/layers", uri)
		if !ok {
			return
		}
		if n < 0 || n > 9999 || !strings.HasPrefix(p, "/") || len(p) < 2 || "/tmp/layers/"+itoa(n)+p != uri {
			t.Fatalf("%q -> %d %q", uri, n, p)
		}
	})
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// FuzzExtract feeds arbitrary layer bytes (as the layer of a valid image):
// Extract fails only with ErrTooLarge or ErrUnreadable, every batch holds
// only directories and regular files inside its layer directories, and
// nothing is written outside dir.
func FuzzExtract(f *testing.F) {
	f.Add(tarOf(f, file("a", "b"), ent{name: "l", typ: tar.TypeSymlink, link: "/"}, file("l/x", "y")))
	f.Add(gz(f, tarOf(f, file("../x", "y"), file("a/.wh.b", ""))))
	f.Add(zst(f, tarOf(f, file("k", "1"), file("k", "2"), file("k/x", "3"))))
	f.Add(gnuSparse("s", 1<<20))
	f.Fuzz(func(t *testing.T, layer []byte) {
		if len(layer) > 1<<20 {
			return
		}
		parent := t.TempDir()
		dir := filepath.Join(parent, "layers")
		l := testLimits()
		l.MaxExpanded, l.MaxEntries, l.BatchFiles = 4<<20, 1000, 50
		var got []seen
		n := 0
		img := filepath.Join(t.TempDir(), "image.tar")
		if err := os.WriteFile(img, imageTar(t, layer), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Extract(img, dir, l, collect(t, &got, &n))
		if err != nil && !errors.Is(err, ErrTooLarge) && !errors.Is(err, ErrUnreadable) {
			t.Fatalf("unexpected error %v", err)
		}
		entries, _ := os.ReadDir(parent)
		if len(entries) != 1 || entries[0].Name() != "layers" {
			t.Fatalf("written outside the layers directory: %v", entries)
		}
	})
}
