# Roadmap

## Current Position

`easyhash` 当前已经发布过 `v1.0.0`，并具备 PBKDF2、Argon2id、scrypt、bcrypt 和兼容性 MD5 的底层创建/校验能力，也有基础测试与 CI。

当前主要短板不是“算法数量不够”，而是开源库骨架还偏轻:

- 公开 API 还主要停留在按算法分散调用；
- 存储格式没有统一到一个更稳定的高层入口；
- 参数升级、自动迁移、令牌哈希、HMAC、checksum 这些真实工程能力还没形成正式边界；
- README、示例、目录结构和路线图还没有完全围绕“长期维护的 Go 库”组织起来。

## Roadmap Strategy

优先顺序: 先把高层 API、目录结构、文档结构和迁移入口补齐，再继续扩展 token hash、HMAC、checksum 等能力。这样可以先稳定边界，再叠加新能力，避免继续把仓库做成“越来越大的散装工具函数集合”。

## Version Plan

### v1.1.0 - Skeleton And Unified API Bootstrap

**Status:** In progress  
**Scope:** Developer-facing / Documentation / Architecture  
**Goal:** 把仓库从单文件工具集合整理为适合持续演进的 Go 库骨架，并引入统一高层入口。

#### Focus

- 高层 API 入口
- 目录和文档骨架
- 新旧 API 分层

#### Tasks

- [x] 新增 `Algorithm`、`Options`、`Hash`、`Verify`、`Identify` 的基础骨架
- [x] 新增 `Policy`、`NeedsRehash`、`VerifyAndUpgrade` 的最小迁移入口
- [x] 新增 `docs/roadmap.md`
- [x] 新增 `examples/basic`
- [x] 更新 README 说明项目定位、骨架和使用路径
- [ ] 将高层格式扩展为更完整的参数校验与更严格的格式解析
- [ ] 为新高层 API 增加更系统的回归测试和示例测试

#### Acceptance Criteria

- 仓库内存在清晰的高层 API 入口
- 旧 API 仍可继续工作
- README 和示例能同时展示推荐入口与兼容入口
- 后续功能可在不破坏目录边界的前提下继续扩展

---

### v1.2.0 - Policy Hardening And Hash Migration

**Status:** Planned  
**Scope:** Stability / User-facing / Testing  
**Goal:** 让真实业务可以安全地做参数升级和算法迁移。

#### Focus

- rehash 策略
- 参数比对
- 自动升级流程

#### Tasks

- [ ] 完善 `NeedsRehash` 的算法参数比对逻辑
- [ ] 明确 legacy hash 与新格式之间的迁移策略
- [ ] 为 `VerifyAndUpgrade` 增加多算法迁移测试
- [ ] 在 README 中补充迁移示例
- [ ] 明确 `DefaultSalt` 的兼容定位与后续替换策略

#### Acceptance Criteria

- 新旧 hash 可以在登录校验时平滑升级
- 参数变化能被稳定识别
- 迁移行为有测试覆盖
- 用户能从文档中直接理解迁移路径

---

### v1.3.0 - Token Hash Utilities

**Status:** Planned  
**Scope:** User-facing / Documentation / Testing  
**Goal:** 增加真实业务常用的一次性 token 安全存储能力。

#### Focus

- token 生成
- token hash
- token 校验

#### Tasks

- [ ] 新增 `GenerateToken`
- [ ] 新增 `HashToken`
- [ ] 新增 `VerifyToken`
- [ ] 补充可选的 HMAC token hash 方案
- [ ] 提供密码重置/邮箱验证场景示例

#### Acceptance Criteria

- 用户可以生成随机 token 并只存储 hash
- token 使用场景有最小示例
- 文档明确区分 token hash 和 password hash

---

### v1.4.0 - HMAC And Checksum Helpers

**Status:** Planned  
**Scope:** User-facing / Documentation / Testing  
**Goal:** 在不偏离仓库定位的前提下补齐 HMAC 和文件完整性校验能力。

#### Focus

- HMAC-SHA256
- `io.Reader` checksum
- 文件 checksum

#### Tasks

- [ ] 新增 `HMACSHA256` 与校验函数
- [ ] 新增 `SHA256Reader`
- [ ] 新增 `SHA256File`
- [ ] 补充 webhook 与文件校验示例
- [ ] 文档强调 checksum 不适用于密码存储

#### Acceptance Criteria

- HMAC 和 checksum 能通过最小示例直接使用
- 核心函数有测试覆盖
- README 明确安全边界

---

### v2.0.0 - Legacy API Cleanup

**Status:** Deferred  
**Scope:** Architecture / Documentation / Compatibility  
**Goal:** 在确认高层 API 稳定后，再考虑清理容易误导的旧入口。

#### Focus

- 旧 API 清理
- 兼容策略
- 迁移说明

#### Tasks

- [ ] 评估是否移除或弃用不推荐的旧 API
- [ ] 评估 `DefaultSalt` 的替代方案
- [ ] 输出清晰的迁移文档
- [ ] 只在用户迁移成本可控时推进 breaking changes

#### Acceptance Criteria

- breaking changes 有明确迁移文档
- 新公共 API 已经稳定
- 用户不需要依赖猜测来完成迁移

## Short-Term / Medium-Term / Long-Term

### Short-Term

- 完成 `v1.1.0`
- 稳定高层 API 命名、README、示例和测试
- 把“单文件工具库”升级成“可维护的 Go 开源库骨架”

### Medium-Term

- 完成 `v1.2.0` 和 `v1.3.0`
- 把参数升级和 token hash 做成真实项目可直接接入的能力

### Long-Term

- 完成 `v1.4.0`
- 评估是否以及何时进入 `v2.0.0`
- 只在迁移路径清晰时才清理 legacy API
