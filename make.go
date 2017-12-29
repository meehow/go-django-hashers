package hashers

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"math/rand"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

var (
	// Iter is a number of iterations used to make pbkdf2 passwords.
	// 20000 is't a default value used in Django.
	Iter = 20000
	// SaltSize is a size of salt used to make passwords.
	// 12 is default size used in Django.
	SaltSize = 12
	// DefaultHasher is a default hashing algorithm.
	// pbkdf2_sha256 is used by default in Django
	DefaultHasher = "pbkdf2_sha256"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// MakePassword generates new password using algorithm set in DefaultHasher
func MakePassword(password string) (string, error) {
	switch DefaultHasher {
	case "pbkdf2_sha256":
		return makePbkdf2(password, DefaultHasher, sha256.Size, sha256.New)
	case "pbkdf2_sha1":
		return makePbkdf2(password, DefaultHasher, sha1.Size, sha1.New)
	case "sha1":
		return makeSaltedHash(password, DefaultHasher, sha1.New)
	case "md5":
		return makeSaltedHash(password, DefaultHasher, md5.New)
	}
	return "", fmt.Errorf("Algorithm \"%s\" is not implemented", DefaultHasher)
}

func makePbkdf2(password, hasher string, keyLen int, h func() hash.Hash) (string, error) {
	salt := getRandomSalt(SaltSize)
	dk := pbkdf2.Key([]byte(password), salt, Iter, keyLen, h)
	b64Hash := base64.StdEncoding.EncodeToString(dk)
	return fmt.Sprintf("%s$%d$%s$%s", hasher, Iter, salt, b64Hash), nil
}

func makeSaltedHash(password, hasher string, h func() hash.Hash) (string, error) {
	salt := getRandomSalt(SaltSize)
	hf := h()
	if _, err := hf.Write(salt); err != nil {
		return "", err
	}
	if _, err := io.WriteString(hf, password); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s$%s$%x", hasher, salt, hf.Sum(nil)), nil
}

const allowedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func getRandomSalt(size int) []byte {
	salt := make([]byte, size)
	l := len(allowedChars)
	for i := range salt {
		salt[i] = allowedChars[rand.Intn(l)]
	}
	return salt
}
