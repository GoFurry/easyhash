package main

import (
	"fmt"
	"log"

	"github.com/gofurry/easyhash"
)

func main() {
	password := "12345678"

	legacyHash, err := easyhash.CreateArgon2(easyhash.DefaultArgon2(), password)
	if err != nil {
		log.Fatal(err)
	}

	legacyAlgorithm, err := easyhash.Identify(legacyHash)
	if err != nil {
		log.Fatal(err)
	}

	needBefore, err := easyhash.NeedsRehash(legacyHash, easyhash.DefaultPolicy())
	if err != nil {
		log.Fatal(err)
	}

	ok, newHash, upgraded, err := easyhash.VerifyAndUpgrade(password, legacyHash, easyhash.DefaultPolicy())
	if err != nil {
		log.Fatal(err)
	}

	newAlgorithm, err := easyhash.Identify(newHash)
	if err != nil {
		log.Fatal(err)
	}

	needAfter, err := easyhash.NeedsRehash(newHash, easyhash.DefaultPolicy())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("legacy algorithm:", legacyAlgorithm)
	fmt.Println("needs upgrade before login:", needBefore)
	fmt.Println("verified:", ok)
	fmt.Println("upgraded:", upgraded)
	fmt.Println("new algorithm:", newAlgorithm)
	fmt.Println("needs upgrade after migration:", needAfter)
}
