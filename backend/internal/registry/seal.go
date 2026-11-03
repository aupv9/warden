package registry

import (
	"github.com/google/uuid"

	"github.com/aupv9/warden/backend/internal/secretbox"
)

// MaxPasswordBytes is the API's limit on a registry password or token.
const MaxPasswordBytes = 4096

// additional binds a sealed password to its org, row and column (as
// webhook URLs and secrets are), so a ciphertext copied to another
// credential or org fails to open.
func additional(org, id uuid.UUID) []byte {
	return []byte("registry_credential\x00" + org.String() + "\x00" + id.String() + "\x00password_enc")
}

// SealPassword encrypts a registry credential's password under the active
// key (secrets.key) for registry_credential.password_enc, and returns the
// key id stored beside it.
func SealPassword(keys *secretbox.Keyring, org, id uuid.UUID, password string) ([]byte, string, error) {
	return keys.Seal([]byte(password), additional(org, id))
}

// OpenPassword decrypts registry_credential.password_enc.
func OpenPassword(keys *secretbox.Keyring, org, id uuid.UUID, keyID string, sealed []byte) (string, error) {
	b, err := keys.Open(keyID, sealed, additional(org, id))
	if err != nil {
		return "", err
	}
	return string(b), nil
}
