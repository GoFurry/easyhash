# 使用说明

本文档聚焦 `easyhash` 当前推荐的高层 API，用来帮助接入方快速理解默认使用方式、算法切换方式，以及旧数据迁移路径。

## 默认路径

`Hash(password, opts...)` 当前默认使用 `PBKDF2-SHA256`。

```go
hash, err := easyhash.Hash(password)
ok, err := easyhash.Verify(password, hash)
```

输出的哈希字符串采用 easyhash 自描述格式：

```text
$easyhash$v=1$pbkdf2-sha256$i=100000,l=32$<salt>$<hash>
```

这意味着：

- 存储时通常只需要保留一个字符串字段
- 校验时 `Verify` 可以自动识别算法和参数
- 后续迁移时 `Identify`、`NeedsRehash`、`VerifyAndUpgrade` 都能直接基于这个格式工作

## 显式选择算法

如果项目不想使用默认的 `PBKDF2-SHA256`，可以显式选择其他算法：

```go
hash, err := easyhash.Hash(password, easyhash.WithArgon2id())
hash, err := easyhash.Hash(password, easyhash.WithBcryptCost(12))
hash, err := easyhash.Hash(password, easyhash.WithScrypt())
```

推荐理解方式：

- 默认路径优先解决“开箱即用”
- 显式选项优先解决“项目已有安全策略或兼容策略”

## 查看存量哈希类型

当你接手一个已有系统，或者想根据算法做迁移判断时，可以先用 `Identify`：

```go
algorithm, err := easyhash.Identify(storedHash)
```

`Verify` 同时支持：

- easyhash 新格式
- `CreatePBKDF2` 生成的 legacy 格式
- `CreateArgon2` 生成的 legacy 格式
- `CreateScrypt` 生成的 legacy 格式
- `CreateBcrypt` 生成的 bcrypt 字符串
- `CreateMD5` 生成的 legacy MD5

## 判断是否需要升级

使用 `NeedsRehash` 可以判断一个存量哈希是否应该替换：

```go
need, err := easyhash.NeedsRehash(storedHash, easyhash.DefaultPolicy())
```

常见返回 `true` 的原因：

- 存量数据还是旧的 low-level 存储格式
- 存量数据使用的算法不是当前策略偏好的算法
- 存量数据的参数已经落后于当前策略

## 登录时平滑升级

推荐的迁移路径是 `VerifyAndUpgrade`：

```go
ok, newHash, upgraded, err := easyhash.VerifyAndUpgrade(
    password,
    storedHash,
    easyhash.DefaultPolicy(),
)
```

典型流程：

1. 用户登录时用原始密码和数据库里的旧 hash 做校验
2. 如果校验成功且 `upgraded == true`
3. 立即把 `newHash` 回写到数据库

这样可以在不打断用户的前提下，逐步把旧 hash 迁移到新策略。

## 兼容性说明

- `DefaultSalt` 目前仍然保留，用于兼容历史 low-level API 的行为
- 新接入尽量优先使用高层 API，而不是自己拼接存储格式
- `MD5` 只建议用于验证无法一次性迁移完的旧数据
- 如果你的系统已经明确要求使用 Argon2id 或 bcrypt，请显式传入对应选项，不要依赖默认值
