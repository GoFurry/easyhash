# easyhash

[![Last Version](https://img.shields.io/github/release/gofurry/easyhash/all.svg?logo=github&color=brightgreen)](https://github.com/gofurry/easyhash/releases)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/Go-1.26%2B-00ADD8?style=flat&logo=go&logoColor=white)
[![Go Report Card](https://goreportcard.com/badge/github.com/gofurry/easyhash)](https://goreportcard.com/report/github.com/gofurry/easyhash)

**中文文档 | [English](../../README.md)**

`easyhash` 是一个轻量级 Go 哈希工具库，当前聚焦于密码哈希、哈希校验，以及后续可扩展的迁移能力。

当前仓库同时保留两层能力：

- 面向推荐接入路径的高层统一 API
- 面向历史使用者的低层按算法兼容 API

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

- `Hash(password, opts...)` 默认使用 `PBKDF2-SHA256`
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

## 文档导航

- 英文使用说明：`docs/usage.md`
- 中文路线图：`docs/roadmap.md`
- 示例索引：`examples/README.md`

## 安全说明

- Hash 不是加密，不能被“解密”。
- 高层 `Hash` 默认使用 `PBKDF2-SHA256`，如需不同策略可显式传入 `WithArgon2id()` 或 `WithBcrypt()`。
- `MD5` 仅用于兼容旧数据，不应用于新的密码存储。
- `DefaultSalt` 目前仍保留用于兼容，但它更接近全局 pepper 风格的后缀，而不是每条哈希独立随机 salt。
- token hash、HMAC、checksum 等能力仍在后续 roadmap 中规划。
