package main

import (
	"fmt"

	hashers "github.com/meehow/go-django-hashers"
)

func main() {
	encoded, err := hashers.MakePassword("secret")
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("Encoded password:", encoded)
	}
}
