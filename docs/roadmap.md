# 路线图

## 当前状态

`easyhash` 已经完成 `v1.1.0` 的骨架初始化工作：

- 建立了高层统一 API：`Hash`、`Verify`、`Identify`、`NeedsRehash`、`VerifyAndUpgrade`
- 默认高层算法调整为 `PBKDF2-SHA256`
- `docs/`、`docs/zh/`、`examples/` 的目录边界已整理
- 新增了使用文档、中文文档入口、示例索引和单一示例目录
- 高层格式解析已经补上更严格的参数校验和回归测试

当前后续工作的重点，不再是继续补“骨架”，而是把迁移策略、token hash、HMAC 和 checksum 做成稳定可用的能力。

## 规划原则

优先顺序：

1. 先稳定已经暴露出来的高层行为和迁移策略
2. 再补真实项目常用的新能力
3. 最后才考虑清理 legacy API

这样可以避免仓库再次回到“功能越来越多，但边界越来越散”的状态。

## 版本计划

### v1.1.0 - 骨架初始化与统一入口

**状态：** 已完成  
**范围：** 开发者体验 / 文档 / 架构  
**目标：** 把仓库整理成可持续演进的 Go 库骨架，并建立统一高层入口。

#### Focus

- 高层 API 入口
- 文档结构
- 示例结构
- 新旧 API 分层

#### Tasks

- [x] 新增 `Algorithm`、`Options`、`Hash`、`Verify`、`Identify`
- [x] 新增 `Policy`、`NeedsRehash`、`VerifyAndUpgrade`
- [x] 引入 easyhash 自描述存储格式
- [x] 将高层默认算法调整为 `PBKDF2-SHA256`
- [x] 将 `example/` 合并进 `examples/`
- [x] 新增 `examples/README.md`
- [x] 将中文文档收拢到 `docs/zh/`
- [x] 新增 `docs/usage.md`
- [x] 只保留中文 `docs/roadmap.md`
- [x] 补全更严格的格式解析和参数校验
- [x] 补全高层 API 回归测试和示例测试

#### Acceptance Criteria

- 仓库内存在清晰的高层 API 入口
- 旧 API 仍可继续工作
- README、usage 文档和示例结构一致
- 高层格式有基本的输入校验和测试保护
- 后续功能可以继续沿当前目录边界扩展

#### 备注

`v1.1.0` 已完成，后续工作应转向迁移策略和真实业务能力，而不是继续做目录级整理。

---

### v1.2.0 - 迁移策略完善

**状态：** 计划中  
**范围：** 稳定性 / 用户侧 / 测试  
**目标：** 让真实业务可以稳定地完成参数升级和算法迁移。

#### Focus

- rehash 策略
- 参数比对
- 自动升级流程

#### Tasks

- [ ] 完善 `NeedsRehash` 的算法参数比对逻辑
- [ ] 明确 legacy hash 与新格式之间的迁移策略
- [ ] 为 `VerifyAndUpgrade` 增加更多跨算法迁移测试
- [ ] 在 `docs/usage.md` 中补充迁移示例
- [ ] 明确 `DefaultSalt` 的兼容定位与后续替换策略

#### Acceptance Criteria

- 新旧 hash 可以在登录校验时平滑升级
- 参数变化能被稳定识别
- 迁移行为有测试覆盖
- 使用文档能直接指导接入

---

### v1.3.0 - Token Hash 能力

**状态：** 计划中  
**范围：** 用户侧 / 文档 / 测试  
**目标：** 增加真实业务常用的一次性 token 安全存储能力。

#### Focus

- token 生成
- token hash
- token 校验

#### Tasks

- [ ] 新增 `GenerateToken`
- [ ] 新增 `HashToken`
- [ ] 新增 `VerifyToken`
- [ ] 补充可选的 HMAC token hash 方案
- [ ] 提供密码重置、邮箱验证等场景示例

#### Acceptance Criteria

- 用户可以生成随机 token 并只存储 hash
- token 使用场景有最小示例
- 文档明确区分 token hash 和 password hash

---

### v1.4.0 - HMAC 与 Checksum

**状态：** 计划中  
**范围：** 用户侧 / 文档 / 测试  
**目标：** 在不偏离仓库定位的前提下补齐 HMAC 和完整性校验能力。

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
- 文档明确安全边界

---

### v2.0.0 - Legacy API 清理

**状态：** 延后  
**范围：** 架构 / 文档 / 兼容性  
**目标：** 在确认高层 API 稳定后，再考虑清理容易误导的旧入口。

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

## 近中远期方向

### 短期

- 完成 `v1.2.0`
- 把迁移行为从“能工作”提升到“接入路径清晰且稳定”

### 中期

- 完成 `v1.3.0`
- 把 token hash 做成真实项目可直接接入的能力

### 长期

- 完成 `v1.4.0`
- 视高层 API 稳定度再决定是否进入 `v2.0.0`
