package hashers

import (
	"testing"
)

func TestCheckPasswordPbkdf2Sha256(t *testing.T) {
	ok, err := CheckPassword("secret", "pbkdf2_sha256$20000$xHAwgryJD2q2$PqZjhRe60ZCfa2fBDI7prOhst33qaeHoYSgsaRfiMDE=")
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
	_, err := CheckPassword("", "pbkdf2_sha256$20000$$not+bash64")
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
	ok, err := CheckPassword("secret", "pbkdf2_sha1$20000$eZ5FzW0FNpxe$dJlO62dNkeUQBXh5y+mG3cAaeCo=")
	if err != nil {
		t.Error(err)
	} else if ok != true {
		t.Error("Password doesn't match the hash")
	}
}

func TestCheckPasswordSaltedSha1(t *testing.T) {
	ok, err := CheckPassword("secret", "sha1$Lj8mOndIS539$354aa09b3c8305590aba9d61ea2eea695e66a2f3")
	if err != nil {
		t.Error(err)
	} else if ok != true {
		t.Error("Password doesn't match the hash")
	}
}

func TestCheckPasswordSaltedMd5(t *testing.T) {
	ok, err := CheckPassword("secret", "md5$AnJwur40VmOL$b6adea34c4639397cc5defc10261837c")
	if err != nil {
		t.Error(err)
	} else if ok != true {
		t.Error("Password doesn't match the hash")
	}
}
func TestCheckPasswordUnsaltedSha1(t *testing.T) {
	ok, err := CheckPassword("secret", "sha1$$e5e9fa1ba31ecd1ae84f75caaa474f3a663f05f4")
	if err != nil {
		t.Error(err)
	} else if ok != true {
		t.Error("Password doesn't match the hash")
	}
}

func TestCheckPasswordUnsaltedMd5(t *testing.T) {
	ok, err := CheckPassword("secret", "5ebe2294ecd0e0f08eab7690d2a6ee69")
	if err != nil {
		t.Error(err)
	} else if ok != true {
		t.Error("Password doesn't match the hash")
	}
}
