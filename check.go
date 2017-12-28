package hashers

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
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
	return false, fmt.Errorf("Algorithm \"%s\" is not implemented.", hasher)
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

func checkPbkdf2(password, encoded string, size int, h func() hash.Hash) (bool, error) {
	parts := strings.SplitN(encoded, "$", 4)
	if len(parts) != 4 {
		return false, errors.New("Hash must consist of 4 segments")
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil {
		return false, fmt.Errorf("Wrong number of iterations: %v", err)
	}
	salt := []byte(parts[2])
	k, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, fmt.Errorf("Wrong hash encoding: %v", err)
	}
	dk := pbkdf2.Key([]byte(password), salt, iterations, size, h)
	return bytes.Equal(k, dk), nil
}

func checkSaltedHash(password, encoded string, h func() hash.Hash) (bool, error) {
	parts := strings.SplitN(encoded, "$", 3)
	if len(parts) != 3 {
		return false, errors.New("Hash must consist of 3 segments")
	}
	salt := parts[1]
	k, err := hex.DecodeString(parts[2])
	if err != nil {
		return false, fmt.Errorf("Wrong hash encoding: %v", err)
	}
	hasher := h()
	if _, err := io.WriteString(hasher, salt+password); err != nil {
		return false, err
	}
	return bytes.Equal(k, hasher.Sum(nil)), nil
}

func checkUnsaltedHash(password, encoded string, h func() hash.Hash) (bool, error) {
	idx := strings.Index(encoded, "$$")
	if idx > -1 {
		encoded = encoded[idx+2:]
	}
	k, err := hex.DecodeString(encoded)
	if err != nil {
		return false, fmt.Errorf("Wrong hash encoding: %v", err)
	}
	hasher := h()
	if _, err := io.WriteString(hasher, password); err != nil {
		return false, err
	}
	return bytes.Equal(k, hasher.Sum(nil)), nil
}
