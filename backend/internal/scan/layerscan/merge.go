package layerscan

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/aupv9/warden/backend/internal/scan/sarif"
)

// Merger joins the raw SARIF Gitleaks wrote for each batch into one
// document, each result's location rewritten from the batch directory to the
// path in the image ("/etc/app.env") with its layer index in
// properties[sarif.LayerIndexProp]: a number, which warden-redact leaves
// alone (it masks strings). A result in a layer the image lists twice is
// reported at both indexes.
//
// The documents hold raw secrets: the merged one goes to warden-redact like
// any Gitleaks SARIF, and nothing here leaves the sandbox otherwise.
type Merger struct {
	base    map[string]any
	run     map[string]any
	results []any
}

// Add takes one batch's document.
func (m *Merger) Add(doc map[string]any, b Batch) error {
	runs, _ := doc["runs"].([]any)
	if len(runs) != 1 {
		return fmt.Errorf("gitleaks wrote %d runs, not 1", len(runs))
	}
	run, ok := runs[0].(map[string]any)
	if !ok {
		return errors.New("gitleaks run is not an object")
	}
	if m.base == nil {
		m.base, m.run = doc, run
	}
	results, _ := run["results"].([]any)
	for _, r := range results {
		res, ok := r.(map[string]any)
		if !ok {
			return errors.New("gitleaks result is not an object")
		}
		out, err := rewrite(res, b)
		if err != nil {
			return err
		}
		m.results = append(m.results, out...)
		if len(m.results) > sarif.MaxResultsPerTool {
			return fmt.Errorf("gitleaks produced more than %d results", sarif.MaxResultsPerTool)
		}
	}
	return nil
}

// Doc is the merged document (nil before the first Add).
func (m *Merger) Doc() map[string]any {
	if m.base == nil {
		return nil
	}
	results := m.results
	if results == nil {
		results = []any{}
	}
	m.run["results"] = results
	return m.base
}

// rewrite maps one result onto the image, once per index of its layer.
func rewrite(res map[string]any, b Batch) ([]any, error) {
	locs, _ := res["locations"].([]any)
	if len(locs) == 0 {
		return nil, errors.New("gitleaks result without a location")
	}
	layer := -1
	var prefix string
	for _, l := range locs {
		al, _ := at(l, "physicalLocation", "artifactLocation").(map[string]any)
		uri, _ := al["uri"].(string)
		n, p, ok := LayerPath(b.Dir, uri)
		if !ok || (layer >= 0 && n != layer) {
			return nil, errors.New("gitleaks reported a location outside the batch")
		}
		if _, ok := b.Layers[n]; !ok {
			return nil, errors.New("gitleaks reported a layer that isn't in the batch")
		}
		layer, prefix = n, b.Dir+"/"+strconv.Itoa(n)+"/"
		al["uri"] = p
	}
	// "… has detected secret for file /tmp/layers/3/app/.env."
	if msg, ok := res["message"].(map[string]any); ok {
		if s, ok := msg["text"].(string); ok {
			msg["text"] = strings.ReplaceAll(s, prefix, "/")
		}
	}
	var out []any
	for _, i := range b.Layers[layer] {
		r := res
		if len(out) > 0 {
			r = deepCopy(res).(map[string]any)
		}
		props, ok := r["properties"].(map[string]any)
		if !ok {
			props = map[string]any{}
			r["properties"] = props
		}
		props[sarif.LayerIndexProp] = json.Number(strconv.Itoa(i))
		out = append(out, r)
	}
	return out, nil
}

// LayerPath splits a path Gitleaks reports under dir ("<dir>/<n>/<path>")
// into the layer's directory number and the path in the image, with a
// leading "/".
func LayerPath(dir, uri string) (n int, p string, ok bool) {
	rest, ok := strings.CutPrefix(uri, dir+"/")
	if !ok {
		return 0, "", false
	}
	num, p, ok := strings.Cut(rest, "/")
	if !ok || p == "" || num == "" || len(num) > 4 || strings.TrimLeft(num, "0123456789") != "" || (len(num) > 1 && num[0] == '0') {
		return 0, "", false
	}
	n, err := strconv.Atoi(num)
	if err != nil {
		return 0, "", false
	}
	return n, "/" + p, true
}

func at(v any, keys ...string) any {
	for _, k := range keys {
		m, _ := v.(map[string]any)
		v = m[k]
	}
	return v
}

func deepCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = deepCopy(x)
		}
		return m
	case []any:
		a := make([]any, len(t))
		for i, x := range t {
			a[i] = deepCopy(x)
		}
		return a
	}
	return v
}
