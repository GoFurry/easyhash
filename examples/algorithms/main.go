package main

import (
	"fmt"
	"log"

	"github.com/gofurry/easyhash"
)

type scenario struct {
	name string
	opts []easyhash.Option
}

func main() {
	password := "12345678"

	scenarios := []scenario{
		{name: "default-pbkdf2"},
		{name: "explicit-pbkdf2", opts: []easyhash.Option{easyhash.WithPBKDF2()}},
		{name: "argon2id", opts: []easyhash.Option{easyhash.WithArgon2id()}},
		{name: "scrypt", opts: []easyhash.Option{easyhash.WithScrypt()}},
		{name: "bcrypt-cost-12", opts: []easyhash.Option{easyhash.WithBcryptCost(12)}},
	}

	for _, scenario := range scenarios {
		hash, err := easyhash.Hash(password, scenario.opts...)
		if err != nil {
			log.Fatalf("%s hash failed: %v", scenario.name, err)
		}

		algorithm, err := easyhash.Identify(hash)
		if err != nil {
			log.Fatalf("%s identify failed: %v", scenario.name, err)
		}

		ok, err := easyhash.Verify(password, hash)
		if err != nil {
			log.Fatalf("%s verify failed: %v", scenario.name, err)
		}

		fmt.Printf("%s -> algorithm=%s verified=%v\n", scenario.name, algorithm, ok)
	}
}
