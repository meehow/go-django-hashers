Go Django Hashers
=================

Go implementation of hashers used in Django

Implemented hashers:
- `pbkdf2_sha256`
- `pbkdf2_sha1`
- `sha1`
- `md5`
- `unsalted_sha1`
- `unsalted_md5`

Hashers based on `bcrypt` are not implemented because `golang.org/x/crypto/bcrypt` is not yet compatible with Python's bcrypt. 

So far only `CheckPassword` function is implemented. If you also need `MakePassword` function, please open an issue.

Installation
============

```
go get -u github.com/meehow/go-django-hashers
```

Usage
=====

```go
package main

import (
	"fmt"

	hashers "github.com/meehow/go-django-hashers"
)

func main() {
	ok, err := hashers.CheckPassword("secret", "pbkdf2_sha256$20000$xHAwgryJD2q2$PqZjhRe60ZCfa2fBDI7prOhst33qaeHoYSgsaRfiMDE=")
	if err != nil {
		fmt.Println(err)
	} else if ok != true {
		fmt.Println("Password doesn't match the hash")
	} else {
		fmt.Println("Password matches the hash")
	}
}
```
