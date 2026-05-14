# easyhash

[![Last Version](https://img.shields.io/github/release/gofurry/easyhash/all.svg?logo=github&color=brightgreen)](https://github.com/gofurry/easyhash/releases)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/Go-1.26%2B-00ADD8?style=flat&logo=go&logoColor=white)
[![Go Report Card](https://goreportcard.com/badge/github.com/gofurry/easyhash)](https://goreportcard.com/report/github.com/gofurry/easyhash)

**English | [中文文档](docs/zh/README.md)**

A small Go toolkit for password hashing, hash verification, and future migration-friendly helpers.

The repository currently keeps the existing low-level algorithm-specific APIs for compatibility, and now starts exposing a higher-level library skeleton around:

- `Hash`
- `Verify`
- `Identify`
- `NeedsRehash`
- `VerifyAndUpgrade`

## Installation

```bash
go get github.com/gofurry/easyhash
```

## Quick Start

```go
package main

import (
	"fmt"
	"log"

	"github.com/gofurry/easyhash"
)

func main() {
	pass := "12345678"

	hash, err := easyhash.Hash(pass)
	if err != nil {
		log.Fatal(err)
	}

	ok, err := easyhash.Verify(pass, hash)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("verified:", ok)
}
```

## High-Level API

- `Hash(password, opts...)` defaults to PBKDF2-SHA256.
- `Verify(password, encodedHash)` accepts the new easyhash format and legacy stored hashes.
- `Identify(encodedHash)` helps with migration and diagnostics.
- `NeedsRehash(encodedHash, policy)` reports whether a hash should be upgraded.
- `VerifyAndUpgrade(password, encodedHash, policy)` verifies and returns a replacement hash when policy requires it.

## Compatibility API

The existing low-level APIs remain available:

- `CreateArgon2` / `VerifyArgon2`
- `CreatePBKDF2` / `VerifyPBKDF2`
- `CreateScrypt` / `VerifyScrypt`
- `CreateBcrypt` / `VerifyBcrypt`
- `CreateMD5`

## Package Layout

```text
easyhash/
  crypto.go
  errors.go
  format.go
  hash.go
  options.go
  policy.go
  types.go
  docs/usage.md
  docs/zh/README_zh.md
  docs/roadmap.md
  examples/README.md
  examples/password/main.go
```

## Security Notes

- Hashing is not encryption.
- PBKDF2-SHA256 is the default high-level algorithm in `Hash`.
- Use `WithArgon2id()` or `WithBcrypt()` when you want a different tradeoff.
- `MD5` is legacy-only and should not be used for new password storage.
- `DefaultSalt` exists for backwards compatibility and behaves closer to a global pepper-like suffix than to a per-hash salt.
- File and token helpers are planned, but the current package is still primarily a password hashing library.

## Examples

- Example index: `examples/README.md`
- Password example: `examples/password/main.go`

## Usage Guide

See `docs/usage.md` for a focused walkthrough of the high-level API and migration flow.

## Roadmap

See `docs/roadmap.md` for the current Chinese roadmap used to track repository evolution.
