Go Django Hashers [![GoDoc](https://godoc.org/github.com/github.com/meehow/go-django-hashers?status.svg)](http://godoc.org/github.com/meehow/go-django-hashers) [![Go Report Card](https://goreportcard.com/badge/github.com/meehow/go-django-hashers)](https://goreportcard.com/report/github.com/meehow/go-django-hashers)
=================

Go implementation of password hashers used in Django

Implemented hashers:
- `pbkdf2_sha256`
- `pbkdf2_sha1`
- `sha1`
- `md5`
- `unsalted_sha1`
- `unsalted_md5`

Unsalted hashers are not allowed by `hashers.MakePassword` function. You can use them just with `hashers.CheckPassword`.

Hashers based on `bcrypt` are not implemented because `golang.org/x/crypto/bcrypt` is not yet compatible with Python's bcrypt. 

By default `hashers.MakePassword` is using `pbkdf2_sha256` hasher.
If you really want to change it (i.e. when you want to have passwords compatible with Django 1.3 or older),
you can set `hashers.DefaultHasher` variable to one of supported hashers:

```go
hashers.DefaultHasher = "sha1"
```

Installation
------------

```
go get -u github.com/meehow/go-django-hashers
```


Usage
-----

Usage is quite straightforward and simple.

Check example files:

- [check_password](examples/check_password.go)
- [make_password](examples/make_password.go)
