package main

import (
	"fmt"
	"log"

	"github.com/gofurry/easyhash"
)

func main() {
	password := "12345678"

	hash, err := easyhash.Hash(password)
	if err != nil {
		log.Fatal(err)
	}

	algorithm, err := easyhash.Identify(hash)
	if err != nil {
		log.Fatal(err)
	}

	ok, err := easyhash.Verify(password, hash)
	if err != nil {
		log.Fatal(err)
	}

	needUpgrade, err := easyhash.NeedsRehash(hash, easyhash.DefaultPolicy())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("algorithm:", algorithm)
	fmt.Println("hash:", hash)
	fmt.Println("verified:", ok)
	fmt.Println("needs upgrade:", needUpgrade)
}
