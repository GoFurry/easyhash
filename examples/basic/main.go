package main

import (
	"fmt"
	"log"

	"github.com/gofurry/easyhash"
)

func main() {
	password := "12345678"

	encoded, err := easyhash.Hash(password)
	if err != nil {
		log.Fatal(err)
	}

	ok, err := easyhash.Verify(password, encoded)
	if err != nil {
		log.Fatal(err)
	}

	needUpgrade, err := easyhash.NeedsRehash(encoded, easyhash.DefaultPolicy())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("hash:", encoded)
	fmt.Println("verified:", ok)
	fmt.Println("needs upgrade:", needUpgrade)
}
