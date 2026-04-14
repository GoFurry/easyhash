# easyhash

[![Last Version](https://img.shields.io/github/release/GoFurry/easyhash/all.svg?logo=github&color=brightgreen)](https://github.com/GoFurry/easyhash/releases)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/Go-1.26%2B-00ADD8?style=flat&logo=go&logoColor=white)
[![Go Report Card](https://goreportcard.com/badge/github.com/GoFurry/easyhash)](https://goreportcard.com/report/github.com/GoFurry/easyhash)

**English | [中文文档](README_zh.md)**

A simple Go password hashing helper that provides create/verify helpers for MD5 (legacy only), PBKDF2, Argon2id, scrypt, and bcrypt, with built-in default parameters.

## Installation

```bash
# If you use private modules, set GOPRIVATE to avoid public checksum database lookups.
go get github.com/GoFurry/easyhash
```

## Quick Start

```go
package main

import (
	"fmt"

	"github.com/GoFurry/easyhash"
)

func main() {
	pass := "12345678"

	// PBKDF2
	pbkdf2, _ := easyhash.CreatePBKDF2(easyhash.DefaultPBKDF2(), pass)
	ok, _ := easyhash.VerifyPBKDF2(pass, pbkdf2)
	fmt.Println("pbkdf2:", ok)

	// Argon2id
	argon2, _ := easyhash.CreateArgon2(easyhash.DefaultArgon2(), pass)
	ok, _ = easyhash.VerifyArgon2(pass, argon2)
	fmt.Println("argon2:", ok)

	// Scrypt
	scrypt, _ := easyhash.CreateScrypt(easyhash.DefaultScrypt(), pass)
	ok, _ = easyhash.VerifyScrypt(pass, scrypt)
	fmt.Println("scrypt:", ok)

	// Bcrypt
	bcrypt, _ := easyhash.CreateBcrypt(12, pass)
	ok = easyhash.VerifyBcrypt(pass, bcrypt)
	fmt.Println("bcrypt:", ok)

	// MD5 (legacy / not recommended)
	fmt.Println("md5:", easyhash.CreateMD5(pass))
}
```

## Notes

- The default global salt is `DefaultSalt`, appended to the password before hashing.
- Prefer `Argon2id` or `bcrypt` for password hashing.
- Example code: `example/userPassword.go`.

