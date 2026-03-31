# easyhash

[![Last Version](https://img.shields.io/github/release/GoFurry/easyhash/all.svg?logo=github&color=brightgreen)](https://github.com/GoFurry/easyhash/releases)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/Go-1.26%2B-00ADD8?style=flat&logo=go&logoColor=white)


一个简单的 Go 密码哈希工具库，提供 MD5（仅兼容）、PBKDF2、Argon2id、scrypt、bcrypt 的生成与校验函数，并内置默认参数。

## 安装

```bash
# 添加私有模块避免公网验证
go get github.com/GoFurry/easyhash
```

## 快速开始

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

	// MD5（仅兼容/不推荐）
	fmt.Println("md5:", easyhash.CreateMD5(pass))
}
```

## 说明

- 默认盐值为 `DefaultSalt`，在哈希前拼接到密码后。
- 建议优先使用 `Argon2id` 或 `bcrypt`。
- 示例代码见 `example/userPassword.go`。
