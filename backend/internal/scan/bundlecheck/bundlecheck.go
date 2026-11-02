// Package bundlecheck validates an uploaded `git bundle` before Gitleaks reads
// it. The bundle is hostile input and is never unpacked here (zipcheck stays
// the only place that extracts): only its header and the pack's framing are
// read. git reads the objects, inside the Gitleaks sandbox, fetching them into
// a fresh bare repository with transfer.fsckObjects (warden-gitleaks).
//
// A bundle is a text header followed by a packfile:
//
//	# v2 git bundle | # v3 git bundle
//	@<capability>[=<value>]   (v3 only)
//	-<oid> [comment]          prerequisites: commits the bundle doesn't hold
//	<oid> <refname>           references
//	<empty line>
//	PACK <version> <object count> <objects...> <checksum>
//
// Warden accepts complete bundles only: prerequisites (a bundle of part of
// the history, such as main~10..main) and the filter capability (a partial
// clone) mean commits or blobs are missing, and a secret in them would go
// unseen. A shallow clone's `git bundle create --all` has neither: it holds
// the boundary commits without their parents, which only shows when git
// reads the objects, in the sandbox (warden-gitleaks exits 3, reported as
// CodeIncomplete too).
package bundlecheck

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
)

const (
	// MaxRefs: a repository with more branches and tags than this is refused
	// (each one is a line of the header that git will write as a ref).
	MaxRefs = 10_000
	// MaxRefName bounds one reference name in bytes (git itself has no limit).
	MaxRefName = 1024
	// MaxHeaderBytes bounds the whole header, whatever the line count.
	MaxHeaderBytes = 4 << 20
	// minObjectBytes: every packed object takes at least a one-byte type and
	// size header plus a zlib stream, which is never shorter than 8 bytes
	// (2-byte header, an empty fixed-Huffman block, 4-byte Adler-32).
	minObjectBytes = 9
	packHeaderLen  = 12
)

// Error codes (scan.error_code).
const (
	// CodeInvalid: not a git bundle Warden can read: a bad signature,
	// capability, object id or reference name, no references, or a pack whose
	// framing or checksum is wrong (truncated, or trailing data).
	CodeInvalid = "BUNDLE_INVALID"
	// CodeIncomplete: the bundle doesn't hold the full history: it has
	// prerequisites, a filter (a partial clone), or (found by git in the
	// sandbox) commits whose parents are missing (a shallow clone).
	CodeIncomplete = "BUNDLE_INCOMPLETE"
	// CodeTooLarge: over scan.history_upload_max_mb, more than MaxRefs
	// references, or a header over MaxHeaderBytes.
	CodeTooLarge = "BUNDLE_TOO_LARGE"
)

// Rejected carries a stable error code; Detail is for logs only.
type Rejected struct {
	Code   string
	Detail string
}

func (e *Rejected) Error() string { return e.Code + ": " + e.Detail }

func reject(code, format string, args ...any) *Rejected {
	return &Rejected{Code: code, Detail: fmt.Sprintf(format, args...)}
}

type Limits struct {
	MaxBytes int64
}

// Result describes an accepted bundle.
type Result struct {
	Version      int    // 2 or 3
	ObjectFormat string // sha1 or sha256
	Refs         int
	Objects      uint32
}

// Object formats and the hex length of their object ids.
var oidLen = map[string]int{"sha1": 40, "sha256": 64}

// Check validates the bundle at p.
func Check(p string, limits Limits) (*Result, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, reject(CodeInvalid, "not a regular file")
	}
	if st.Size() > limits.MaxBytes {
		return nil, reject(CodeTooLarge, "bundle is %d bytes", st.Size())
	}
	res, headerLen, err := checkHeader(bufio.NewReaderSize(io.LimitReader(f, MaxHeaderBytes+1), 64<<10))
	if err != nil {
		return nil, err
	}
	if res.Objects, err = checkPack(f, headerLen, st.Size(), res.ObjectFormat); err != nil {
		return nil, err
	}
	return res, nil
}

// maxLine is the longest header line: a reference line with the longest
// object id and name, and its newline.
const maxLine = 64 + 1 + MaxRefName + 1

// readLine returns the next header line without its "\n". A line without a
// newline (the header cut short), or longer than maxLine, is invalid.
func readLine(r *bufio.Reader, total *int) (string, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > maxLine {
			return "", reject(CodeInvalid, "header line longer than %d bytes", maxLine)
		}
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if *total+len(line) > MaxHeaderBytes {
			return "", reject(CodeTooLarge, "header larger than %d bytes", MaxHeaderBytes)
		}
		if errors.Is(err, io.EOF) {
			return "", reject(CodeInvalid, "header ends without a blank line")
		}
		return "", err
	}
	*total += len(line)
	if *total > MaxHeaderBytes {
		return "", reject(CodeTooLarge, "header larger than %d bytes", MaxHeaderBytes)
	}
	return string(line[:len(line)-1]), nil
}

// checkHeader reads the header up to and including its blank line and
// returns how many bytes it took.
func checkHeader(r *bufio.Reader) (*Result, int64, error) {
	total := 0
	sig, err := readLine(r, &total)
	if err != nil {
		return nil, 0, err
	}
	res := &Result{ObjectFormat: "sha1"}
	switch sig {
	case "# v2 git bundle":
		res.Version = 2
	case "# v3 git bundle":
		res.Version = 3
	default:
		return nil, 0, reject(CodeInvalid, "not a v2 or v3 git bundle signature")
	}

	line, err := readLine(r, &total)
	if err != nil {
		return nil, 0, err
	}
	// Capabilities come first, and only in v3.
	caps := map[string]bool{}
	for res.Version == 3 && strings.HasPrefix(line, "@") {
		name, value, hasValue := strings.Cut(line[1:], "=")
		if caps[name] {
			return nil, 0, reject(CodeInvalid, "capability %q repeated", name)
		}
		caps[name] = true
		switch name {
		case "object-format":
			if _, ok := oidLen[value]; !ok || !hasValue {
				return nil, 0, reject(CodeInvalid, "unsupported object format")
			}
			res.ObjectFormat = value
		case "filter":
			// A partial clone's bundle: blobs (or trees) are missing.
			return nil, 0, reject(CodeIncomplete, "bundle has a filter (partial clone)")
		default:
			// Unknown to Warden, so it can't vouch for what the bundle holds.
			return nil, 0, reject(CodeInvalid, "unknown capability")
		}
		if line, err = readLine(r, &total); err != nil {
			return nil, 0, err
		}
	}

	hexLen := oidLen[res.ObjectFormat]
	names := map[string]bool{}
	for ; line != ""; line, err = readLine(r, &total) {
		if strings.HasPrefix(line, "-") {
			// A prerequisite: the history continues in commits the bundle
			// doesn't hold.
			oid, _, _ := strings.Cut(line[1:], " ")
			if !validOID(oid, hexLen) {
				return nil, 0, reject(CodeInvalid, "bad prerequisite object id")
			}
			return nil, 0, reject(CodeIncomplete, "bundle has prerequisites")
		}
		oid, name, ok := strings.Cut(line, " ")
		if !ok || !validOID(oid, hexLen) {
			return nil, 0, reject(CodeInvalid, "bad reference line")
		}
		if err := checkRefName(name); err != nil {
			return nil, 0, reject(CodeInvalid, "%v", err)
		}
		if names[name] {
			return nil, 0, reject(CodeInvalid, "reference listed twice")
		}
		if len(names) == MaxRefs {
			return nil, 0, reject(CodeTooLarge, "more than %d references", MaxRefs)
		}
		names[name] = true
	}
	// The loop ends on the blank line, or on a read error (line is then "").
	if err != nil {
		return nil, 0, err
	}
	if len(names) == 0 {
		return nil, 0, reject(CodeInvalid, "bundle has no references")
	}
	res.Refs = len(names)
	return res, int64(total), nil
}

// validOID: lower-case hex of the object format's length, not the null id.
func validOID(s string, n int) bool {
	if len(s) != n || strings.Trim(s, "0") == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// checkRefName applies git check-ref-format's rules to a reference name, and
// accepts only HEAD and names under refs/ (what `git bundle create --all`
// writes). git checks them again when it fetches the bundle.
func checkRefName(name string) error {
	if name == "HEAD" {
		return nil
	}
	if len(name) > MaxRefName {
		return fmt.Errorf("reference name longer than %d bytes", MaxRefName)
	}
	if !strings.HasPrefix(name, "refs/") {
		return errors.New("reference outside refs/")
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c < 0x20 || c == 0x7f || strings.IndexByte(" ~^:?*[\\", c) >= 0 {
			return errors.New("reference name has a forbidden character")
		}
	}
	if strings.Contains(name, "..") || strings.Contains(name, "@{") || strings.HasSuffix(name, ".") {
		return errors.New("reference name has a forbidden sequence")
	}
	for _, part := range strings.Split(name, "/") {
		// Empty: a leading, trailing or doubled slash ("refs/" alone too).
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return errors.New("reference name has a forbidden component")
		}
	}
	return nil
}

// checkPack checks the packfile that follows the header: signature, version,
// an object count the file can hold, and the trailing checksum over the whole
// pack, which also catches a truncated pack and anything appended to it. The
// trailer is SHA-1 in sha1 repositories: a framing check, not a signature.
func checkPack(f *os.File, start, size int64, objectFormat string) (uint32, error) {
	var h hash.Hash = sha1.New()
	if objectFormat == "sha256" {
		h = sha256.New()
	}
	sumLen := int64(h.Size())
	packLen := size - start
	if packLen < packHeaderLen+sumLen {
		return 0, reject(CodeInvalid, "pack too short")
	}
	var hdr [packHeaderLen]byte
	if _, err := f.ReadAt(hdr[:], start); err != nil {
		return 0, err
	}
	if !bytes.Equal(hdr[:4], []byte("PACK")) {
		return 0, reject(CodeInvalid, "no pack signature after the header")
	}
	if v := binary.BigEndian.Uint32(hdr[4:8]); v != 2 && v != 3 {
		return 0, reject(CodeInvalid, "unsupported pack version %d", v)
	}
	objects := binary.BigEndian.Uint32(hdr[8:12])
	if objects == 0 {
		return 0, reject(CodeInvalid, "empty pack")
	}
	// git sizes its index from this count before reading any object.
	if int64(objects) > (packLen-packHeaderLen-sumLen)/minObjectBytes {
		return 0, reject(CodeInvalid, "pack claims %d objects in %d bytes", objects, packLen)
	}
	if _, err := io.Copy(h, io.NewSectionReader(f, start, packLen-sumLen)); err != nil {
		return 0, err
	}
	trailer := make([]byte, sumLen)
	if _, err := f.ReadAt(trailer, size-sumLen); err != nil {
		return 0, err
	}
	if !bytes.Equal(h.Sum(nil), trailer) {
		return 0, reject(CodeInvalid, "pack checksum mismatch (truncated or trailing data)")
	}
	return objects, nil
}
