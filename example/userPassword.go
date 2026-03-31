package main

import (
	"fmt"

	"github.com/GoFurry/easyhash"
)

func main() {
	pass := "12345678"

	// MD5
	if easyhash.CreateMD5(pass) == easyhash.CreateMD5(pass) {
		fmt.Println("pass")
	}

	// PBKDF2
	pbkdf2, _ := easyhash.CreatePBKDF2(easyhash.DefaultPBKDF2(), pass)
	if ok, _ := easyhash.VerifyPBKDF2(
		pass,
		pbkdf2,
	); ok {
		fmt.Println("pbkdf2 pass")
	}

	// Argon2
	argon2, _ := easyhash.CreateArgon2(easyhash.DefaultArgon2(), pass)
	if ok, _ := easyhash.VerifyArgon2(
		pass,
		argon2,
	); ok {
		fmt.Println("argon2 pass")
	}

	// Scrypt
	scrypt, _ := easyhash.CreateScrypt(easyhash.DefaultScrypt(), pass)
	if ok, _ := easyhash.VerifyScrypt(
		pass,
		scrypt,
	); ok {
		fmt.Println("scrypt pass")
	}

	// Bcrypt
	bcrypt, _ := easyhash.CreateBcrypt(12, pass)
	if ok := easyhash.VerifyBcrypt(
		pass,
		bcrypt,
	); ok {
		fmt.Println("bcrypt pass")
	}

}
