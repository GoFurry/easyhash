# easyhash

[![Last Version](https://img.shields.io/github/release/gofurry/easyhash/all.svg?logo=github&color=brightgreen)](https://github.com/gofurry/easyhash/releases)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/Go-1.26%2B-00ADD8?style=flat&logo=go&logoColor=white)
[![Go Report Card](https://goreportcard.com/badge/github.com/gofurry/easyhash)](https://goreportcard.com/report/github.com/gofurry/easyhash)

**中文文档 | [English](README.md)**

`easyhash` 是一个轻量级 Go 哈希工具库，当前聚焦于密码哈希、哈希校验，以及后续可扩展的迁移能力。

这次骨架初始化之后，仓库会同时保留两层能力：

- 兼容现有使用者的低层按算法 API
- 面向后续演进的高层统一 API 骨架

## 安装

```bash
go get github.com/gofurry/easyhash
```

## 快速开始

```go
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

	fmt.Println("verified:", ok)
}
```

## 高层 API

- `Hash(password, opts...)` 默认使用 `Argon2id`
- `Verify(password, encodedHash)` 同时支持新格式和 legacy 格式
- `Identify(encodedHash)` 用于识别算法和迁移诊断
- `NeedsRehash(encodedHash, policy)` 用于判断是否需要升级
- `VerifyAndUpgrade(password, encodedHash, policy)` 用于校验后平滑升级

## 兼容 API

现有低层 API 仍然保留：

- `CreateArgon2` / `VerifyArgon2`
- `CreatePBKDF2` / `VerifyPBKDF2`
- `CreateScrypt` / `VerifyScrypt`
- `CreateBcrypt` / `VerifyBcrypt`
- `CreateMD5`

## 当前目录骨架

```text
easyhash/
  crypto.go
  errors.go
  format.go
  hash.go
  options.go
  policy.go
  types.go
  docs/roadmap.md
  examples/basic/main.go
```

## 安全说明

- Hash 不是加密，不能被“解密”。
- 新的密码存储优先使用 `Argon2id` 或 `bcrypt`。
- `MD5` 仅用于兼容旧数据，不应用于新的密码存储。
- `DefaultSalt` 目前仍保留用于兼容，但它更接近全局 pepper 风格的后缀，而不是每条哈希独立随机 salt。
- token hash、HMAC、checksum 等能力在 roadmap 中规划，当前仓库仍然主要是密码哈希库。

## 示例

- 推荐高层示例：`examples/basic/main.go`
- 兼容旧接口示例：`example/userPassword.go`

## Roadmap

仓库内演进计划见 `docs/roadmap.md`。
