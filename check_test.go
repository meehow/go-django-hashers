package hashers

import (
	"testing"
)

const password = "secret"

var passwords = map[string]string{
	"pbkdf2_sha256": "pbkdf2_sha256$20000$xHAwgryJD2q2$PqZjhRe60ZCfa2fBDI7prOhst33qaeHoYSgsaRfiMDE=",
	"pbkdf2_sha1":   "pbkdf2_sha1$20000$eZ5FzW0FNpxe$dJlO62dNkeUQBXh5y+mG3cAaeCo=",
	"sha1":          "sha1$Lj8mOndIS539$354aa09b3c8305590aba9d61ea2eea695e66a2f3",
	"md5":           "md5$AnJwur40VmOL$b6adea34c4639397cc5defc10261837c",
	"unsalted_sha1": "sha1$$e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4",
	"unsalted_md5":  "5ebe2294ecd0e0f08eab7690d2a6ee69",
}

func TestCheckPasswordPbkdf2Sha256(t *testing.T) {
	ok, err := CheckPassword(password, passwords["pbkdf2_sha256"])
	if err != nil {
		t.Error(err)
	} else if ok != true {
		t.Error("Password doesn't match the hash")
	}
}

func TestCheckPasswordErr(t *testing.T) {
	_, err := CheckPassword("", "pbkdf2_sha256")
	if err == nil {
		t.Error("Wrong hash syntax should return an error.")
	}
}

func TestCheckPassworWrongIterations(t *testing.T) {
	_, err := CheckPassword("", "pbkdf2_sha256$not-integer$$")
	if err == nil {
		t.Error("Wrong number of iterations should return an error.")
	}
}

func TestCheckPassworWrongHash(t *testing.T) {
	_, err := CheckPassword("", "pbkdf2_sha256$20000$$not+base64")
	if err == nil {
		t.Error("Wrong hash encoding should return an error.")
	}
}

func TestCheckPassworWrongAlgorithm(t *testing.T) {
	_, err := CheckPassword("", "wrong$$$")
	if err == nil {
		t.Error("Wrong algorithm should return an error.")
	}
}

func TestCheckPasswordPbkdf2Sha1(t *testing.T) {
	ok, err := CheckPassword(password, passwords["pbkdf2_sha1"])
	if err != nil {
		t.Error(err)
	} else if ok != true {
		t.Error("Password doesn't match the hash")
	}
}

func TestCheckPasswordIncomplete(t *testing.T) {
	encoded := passwords["sha1"]
	_, err := CheckPassword(password, encoded[:len(encoded)-2])
	if err == nil {
		t.Error("Incomplete hash should return an error.")
	}
}

func TestCheckPasswordSaltedSha1(t *testing.T) {
	ok, err := CheckPassword(password, passwords["sha1"])
	if err != nil {
		t.Error(err)
	} else if ok != true {
		t.Error("Password doesn't match the hash")
	}
}

func TestCheckPasswordSaltedMd5(t *testing.T) {
	ok, err := CheckPassword(password, passwords["md5"])
	if err != nil {
		t.Error(err)
	} else if ok != true {
		t.Error("Password doesn't match the hash")
	}
}
func TestCheckPasswordUnsaltedSha1(t *testing.T) {
	ok, err := CheckPassword(password, passwords["unsalted_sha1"])
	if err != nil {
		t.Error(err)
	} else if ok != true {
		t.Error("Password doesn't match the hash")
	}
}

func TestCheckPasswordUnsaltedMd5(t *testing.T) {
	ok, err := CheckPassword(password, passwords["unsalted_md5"])
	if err != nil {
		t.Error(err)
	} else if ok != true {
		t.Error("Password doesn't match the hash")
	}
}

func BenchmarkCheckCorrectPassword(b *testing.B) {
	for hasher, encoded := range passwords {
		DefaultHasher = hasher
		b.Run(hasher, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				CheckPassword(password, encoded)
			}
		})
	}
}

func BenchmarkCheckIncorrectPassword(b *testing.B) {
	for hasher, encoded := range passwords {
		DefaultHasher = hasher
		b.Run(hasher, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				CheckPassword(password[1:], encoded)
			}
		})
	}
}
