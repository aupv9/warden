package registry

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/secretbox"
)

func TestSealPassword(t *testing.T) {
	keys, err := secretbox.Parse("k1:"+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), "")
	if err != nil {
		t.Fatal(err)
	}
	org, id := uuid.New(), uuid.New()
	ct, kid, err := SealPassword(keys, org, id, "pa55-token")
	if err != nil || kid != "k1" || bytes.Contains(ct, []byte("pa55")) {
		t.Fatal(kid, err)
	}
	if pw, err := OpenPassword(keys, org, id, kid, ct); err != nil || pw != "pa55-token" {
		t.Fatal(pw, err)
	}
	// Bound to the org and the row.
	if _, err := OpenPassword(keys, uuid.New(), id, kid, ct); err == nil {
		t.Fatal("opened for another org")
	}
	if _, err := OpenPassword(keys, org, uuid.New(), kid, ct); err == nil {
		t.Fatal("opened for another credential")
	}
	if _, err := OpenPassword(nil, org, id, kid, ct); err == nil {
		t.Fatal("opened without keys")
	}
}
