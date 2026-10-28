// Package archpath holds the entry-name rules shared by the archive checks
// (zipcheck extracts zips, imagecheck inspects image tarballs): no NUL, no
// absolute or drive paths, no "..", bounded length and depth.
package archpath

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	MaxPathLen   = 1024
	MaxPathDepth = 50
)

var windowsDrive = regexp.MustCompile(`^[A-Za-z]:`)

// Clean returns the relative parts of an entry name ("." and empty parts
// dropped, backslashes taken as separators), an empty slice for the archive
// root itself, or an error saying why the name is unsafe.
func Clean(name string) ([]string, error) {
	if strings.ContainsRune(name, 0) {
		return nil, fmt.Errorf("entry name contains NUL")
	}
	norm := strings.ReplaceAll(name, `\`, "/")
	if utf8.RuneCountInString(norm) > MaxPathLen {
		return nil, fmt.Errorf("entry path longer than %d", MaxPathLen)
	}
	if strings.HasPrefix(norm, "/") || windowsDrive.MatchString(norm) {
		return nil, fmt.Errorf("absolute entry path %q", name)
	}
	var parts []string
	for _, p := range strings.Split(norm, "/") {
		if p != "" && p != "." {
			parts = append(parts, p)
		}
	}
	if slices.Contains(parts, "..") {
		return nil, fmt.Errorf("entry %q escapes the archive root", name)
	}
	if len(parts) > MaxPathDepth {
		return nil, fmt.Errorf("entry path deeper than %d", MaxPathDepth)
	}
	return parts, nil
}
