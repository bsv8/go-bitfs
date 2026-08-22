---
id: core-boundary-refactor-work-order
title: 核心边界重构施工单
---

# 核心边界重构施工单

本页记录已完成的核心边界硬切换的验收契约，并废止此前所有"workflow 可注入 stores/content/backend"的旧真值。协议规范 001–007 仍是 wire 字节与协议行为的权威；v4 wire 形态、CDDL、签名域与 `RefundTemplateTxID` 算法保持不变。

## 产品定义

`go-bitfs` 是**无状态、无基础设施副作用**的可执行 BitFS 协议规范，同时是买方、卖方和仲裁方实现的角色 SDK。给定显式协议输入和显式前序状态，它严格判断输入是否合法，并计算下一份协议报文、交易、签名材料或本地角色状态。

以下能力全部属于应用：

- 数据库、文件、事务、锁、CAS 与唯一约束；
- 按 `RefundTemplateTxID` 的并发串行化（SDK 无 mutex 或租约）；
- 重试、幂等、崩溃恢复与 outbox；
- 点对点传输、路由、超时策略；
- 节点广播、链上查询与结果对账——只有应用的节点适配器可以声明广播被接受；
- 区块高度来源，以 `blockHeight uint32` 参数显式提供；SDK 在每个公开入口内部读取一次系统 UTC，并用这些事实验证锁定规则；
- 内容仓库：调用前读取字节并传入，验证后的字节作为数据返回并由应用落盘；
- 多租户授权（`RefundTemplateTxID` 是路由 ID 不是授权令牌）。

MasterSeed 仍是固定的内容证明实现，MultisigPool v4 仍是固定的 BSV 池交易实现。两者都不是应用插件。

## 必须遵守的公开边界

角色 workflow 构造器只接受一种能力：

~~~go
type WorkflowConfig struct {
    PrivateKey *ec.PrivateKey // 官方 BSV Go SDK 私钥
}
~~~

不存在 store、quote store、pending-request store、content sink/source、backend、node adapter、clock、signer 端口、verifier 策略或 locker 字段。每个方法都显式接收业务输入（报价、开池证据、上一笔付款状态、交付上下文、内容字节、seed、区块高度），只返回计算得到的 wire 报文、原始交易、已验证证据以及本地角色状态（如 `buyer.BuyerOpeningState`、`seller.ContentDeliveryState`）。方法从不加载、保存、发送、广播或标记不确定结果。

签名不是钩子：所有签名都通过 SDK 的固定实现、用构造时传入的官方 BSV 私钥完成。消息签名把规范 CBOR 用 SHA-256 哈希一次，用 `(*ec.PrivateKey).Sign` 对已算好的摘要签名，规范化为 low-S DER，并在离开方法前由固定验证器对照派生角色公钥复验；交易签名使用固定的 MultisigPool sighash（`ForkID|All`），绝不做二次哈希。不需要签名的纯 Build/Read/Verify 函数继续作为公开纯函数存在，不会被强迫经过 Workflow。

## 验收检查

- `buyer.WorkflowConfig`、`seller.WorkflowConfig`、`arbitration.WorkflowConfig` 除 `PrivateKey` 外无任何字段，且构造器拒绝 nil 私钥。
- SDK 内不存在按 `RefundTemplateTxID` 自动加载状态的代码路径；由调用方提供。
- 没有任何方法执行持久化、网络发送或广播；原始交易作为返回值交给应用提交。
- 在历史文档之外的全仓静态搜索找不到 `FileStore`、`MemoryStore`、`FileQuoteStore`、`PoolStore`、`PendingRequestStore`、租约类型、进程锁或 backend 适配器。
- 001–007 wire fixture 与 MultisigPool 交易 fixture 在切换前后逐字节一致；`MajorVersion == 4`，无 v5。
- stale sequence、wrong opening/role/hash、金额倒退和到期违规仍被拒绝。
- 英文与简体中文文档与编译后的 API 一致。

## 不在范围内

- 把未来的数据库/文件适配器列为 SDK 工作：持久化按设计属于应用技术栈。
- 任何形式的传输实现。
- 通过应用配置替换 MasterSeed 或 MultisigPool。
- 修改 001–007 的规范性 wire 行为。
