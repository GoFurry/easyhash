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

	ok, err := easyhash.Verify(password, hash)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("high-level verify:", ok)

	pbkdf2Hash, err := easyhash.CreatePBKDF2(easyhash.DefaultPBKDF2(), password)
	if err != nil {
		log.Fatal(err)
	}
	pbkdf2OK, err := easyhash.VerifyPBKDF2(password, pbkdf2Hash)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("pbkdf2 verify:", pbkdf2OK)

	argon2Hash, err := easyhash.CreateArgon2(easyhash.DefaultArgon2(), password)
	if err != nil {
		log.Fatal(err)
	}
	argon2OK, err := easyhash.VerifyArgon2(password, argon2Hash)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("argon2 verify:", argon2OK)

	scryptHash, err := easyhash.CreateScrypt(easyhash.DefaultScrypt(), password)
	if err != nil {
		log.Fatal(err)
	}
	scryptOK, err := easyhash.VerifyScrypt(password, scryptHash)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("scrypt verify:", scryptOK)

	bcryptHash, err := easyhash.CreateBcrypt(12, password)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("bcrypt verify:", easyhash.VerifyBcrypt(password, bcryptHash))

	fmt.Println("md5:", easyhash.CreateMD5(password))
}
