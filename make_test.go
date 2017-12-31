package hashers

import (
	"strings"
	"testing"
)

var hashers = []string{"pbkdf2_sha256", "pbkdf2_sha1", "sha1", "md5"}

func TestMakePassword(t *testing.T) {
	for _, hasher := range hashers {
		DefaultHasher = hasher
		encoded, err := MakePassword(password)
		if err != nil {
			t.Error(err)
		}
		if !strings.HasPrefix(encoded, hasher+"$") {
			t.Errorf("Hash \"%s\" should start with \"%s$\" prefix", encoded, hasher)
		}
		ok, err := CheckPassword(password, encoded)
		if err != nil {
			t.Error(err)
		} else if ok != true {
			t.Error("Password doesn't match the hash")
		}
	}
}

func BenchmarkMakePassword(b *testing.B) {
	for _, hasher := range hashers {
		DefaultHasher = hasher
		b.Run(hasher, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				MakePassword(password)
			}
		})
	}
}
