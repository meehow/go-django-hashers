Go Django Hashers
=================

Go implementation of hashers used in Django

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
