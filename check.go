package hashers

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// CheckPassword checks if given password is matching given hash
func CheckPassword(password, encoded string) (bool, error) {
	hasher := identifyHasher(encoded)
	switch hasher {
	case "pbkdf2_sha256":
		return checkPbkdf2(password, encoded, sha256.Size, sha256.New)
	case "pbkdf2_sha1":
		return checkPbkdf2(password, encoded, sha1.Size, sha1.New)
	case "sha1":
		return checkSaltedHash(password, encoded, sha1.New)
	case "md5":
		return checkSaltedHash(password, encoded, md5.New)
	case "unsalted_sha1":
		return checkUnsaltedHash(password, encoded, sha1.New)
	case "unsalted_md5":
		return checkUnsaltedHash(password, encoded, md5.New)
	}
	return false, fmt.Errorf("Algorithm \"%s\" is not implemented", hasher)
}

func identifyHasher(encoded string) string {
	// Ancient versions of Django created plain MD5 passwords and accepted
	// MD5 passwords with an empty salt.
	if len(encoded) == 32 && !strings.Contains(encoded, "$") {
		return "unsalted_md5"
	}
	if len(encoded) == 37 && strings.HasPrefix(encoded, "md5$$") {
		return "unsalted_md5"
	}
	// Ancient versions of Django accepted SHA1 passwords with an empty salt.
	if len(encoded) == 46 && strings.HasPrefix(encoded, "sha1$$") {
		return "unsalted_sha1"
	}
	return strings.SplitN(encoded, "$", 2)[0]
}

func checkPbkdf2(password, encoded string, keyLen int, h func() hash.Hash) (bool, error) {
	parts := strings.SplitN(encoded, "$", 4)
	if len(parts) != 4 {
		return false, errors.New("Hash must consist of 4 segments")
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil {
		return false, fmt.Errorf("Wrong number of iterations: %v", err)
	}
	salt := []byte(parts[2])
	k, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, fmt.Errorf("Wrong hash encoding: %v", err)
	}
	dk := pbkdf2.Key([]byte(password), salt, iter, keyLen, h)
	return bytes.Equal(k, dk), nil
}

func checkSaltedHash(password, encoded string, h func() hash.Hash) (bool, error) {
	parts := strings.SplitN(encoded, "$", 3)
	if len(parts) != 3 {
		return false, errors.New("Hash must consist of 3 segments")
	}
	return checkHash(parts[1]+password, parts[2], h)
}

func checkUnsaltedHash(password, encoded string, h func() hash.Hash) (bool, error) {
	idx := strings.Index(encoded, "$$")
	if idx > -1 {
		encoded = encoded[idx+2:]
	}
	return checkHash(password, encoded, h)
}

func checkHash(password, encoded string, h func() hash.Hash) (bool, error) {
	k, err := hex.DecodeString(encoded)
	if err != nil {
		return false, fmt.Errorf("Wrong hash encoding: %v", err)
	}
	hf := h()
	if len(k) != hf.Size() {
		return false, fmt.Errorf("Hash is %d bytes long, but should be %d bytes long", len(k), hf.Size())
	}
	if _, err := io.WriteString(hf, password); err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(k, hf.Sum(nil)) == 1, nil
}
