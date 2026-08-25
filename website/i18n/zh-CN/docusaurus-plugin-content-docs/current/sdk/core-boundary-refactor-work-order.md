---
id: core-boundary-refactor-work-order
title: 核心边界重构施工单
---

# 核心边界重构施工单

> **已被取代：** 本页的验收契约已于 2026-08-24 被硬切换施工单取代——直接私钥
> workflow 构造被受约束的 `protocol.Signer` 端口（`protocol.NewPrivateKeySigner`）
> 替换，时间与高度改为通过 `protocol.Facts` 显式传入。此前"禁止 Signer 端口、
> 禁止公开时间事实"的旧决策不再适用。下文描述的"无基础设施副作用"边界继续
> 有效且保持不变。

本页记录已完成的核心边界硬切换的验收契约，并废止此前所有"workflow 可注入 stores/content/backend"的旧真值。协议规范 001–008 仍是 wire 字节与协议行为的权威；既有 wire 形态保持固定，007 使用当前五元 Kind 8 Claim 请求加四元 Kind 9 回执响应形态与签名域，008 固定四元 Kind 10 买方取件请求加仲裁方签名的两分支 Kind 11 响应形态，可交付分支经 content_payloads_id 绑定 payload；`RefundTemplateTxID` 算法保持不变。

## 产品定义

`go-bitfs` 是**无状态、无基础设施副作用**的可执行 BitFS 协议规范，同时是买方、卖方和仲裁方实现的角色 SDK。给定显式协议输入、显式前序状态以及每次调用一份显式的 `protocol.Facts{Now, BlockHeight}`，它严格判断输入是否合法，并计算下一份协议报文、交易、签名材料或本地角色状态。

以下能力全部属于应用：

- 数据库、文件、事务、锁、CAS 与唯一约束；
- 按 `RefundTemplateTxID` 的并发串行化（SDK 无 mutex 或租约）；
- 重试、幂等、崩溃恢复与 outbox；
- 点对点传输、路由、超时策略；
- 节点广播、链上查询与结果对账——只有应用的节点适配器可以声明广播被接受；
- 时间与区块高度的观测，以 Facts 值显式提供；SDK 不读时钟、不查节点高度；
- 内容仓库：调用前读取字节并传入，验证后的字节作为数据返回并由应用落盘；
- 多租户授权（`RefundTemplateTxID` 是路由 ID 不是授权令牌）。

MasterSeed 仍是固定的内容证明实现，MultisigPool v4 仍是固定的 BSV 池交易实现。两者都不是应用插件。

## 必须遵守的公开边界

角色 workflow 构造器只接受一种能力——构造时固定的受约束 Signer：

```go
signer, err := protocol.NewPrivateKeySigner(key) // 本地软件私钥的唯一入口；key 为 *ec.PrivateKey
buyerWf, err := buyer.NewWorkflow(signer)
sellerWf, err := seller.NewWorkflow(signer)
arbiterWf, err := arbiter.NewWorkflow(signer)
```

Signer 只是能力端口：它提供固定的压缩公钥并为 SDK 已构造好的 digest 签名；它绝不能替换哈希、preimage、sighash flag、验证、CBOR 编码、定价或角色规则。不存在 store、quote store、pending-request store、content sink/source、backend、node adapter、clock 钩子、verifier 策略或 locker 字段。每个方法都显式接收业务输入（报价、开池证据、上一笔付款状态、交付上下文、内容字节、seed），并在涉及时间或高度时额外接收一份显式 Facts；只返回计算得到的 Artifact、包装为 verified 值的交易原文、已验证证据以及 opaque 本地 checkpoint（如 `buyer.OpeningCheckpoint`、`buyer.PoolCheckpoint`、`seller.DeliveryCheckpoint`）。方法从不加载、保存、发送、广播或标记不确定结果；buyer 包的 Restore 入口从 exact 持久化字节全量重验恢复各 checkpoint。

签名固定在 SDK 内部：消息签名把规范 CBOR 哈希一次，把预计算 digest 交给 Signer，规范化为 low-S DER，并在离开方法前由固定验证器对照固定角色公钥复验；交易签名使用固定的 MultisigPool sighash（`ForkID|All`），绝不做二次哈希。不需要签名的纯 Build/Read/Verify 函数继续作为公开纯函数存在，不会被强迫经过 Workflow。

## 验收检查

- 角色 workflow 构造器只接受一个受约束 Signer；本地软件私钥只能经 `protocol.NewPrivateKeySigner` 进入，且拒绝 nil 私钥。
- SDK 内不存在按 `RefundTemplateTxID` 自动加载状态的代码路径；由调用方提供。
- 没有任何方法执行持久化、网络发送或广播，也没有任何方法读取时钟或查询节点高度；交易原文作为返回值交给应用提交，每个时间/高度判断都使用调用方的 Facts。
- 在历史文档之外的全仓静态搜索找不到 `FileStore`、`MemoryStore`、`FileQuoteStore`、`PoolStore`、`PendingRequestStore`、租约类型、进程锁或 backend 适配器。
- 当前 001–008 wire fixture 与 MultisigPool 交易 fixture 逐字节冻结；wire version 保持为 1。
- stale sequence、wrong opening/role/hash、金额倒退和到期违规仍被拒绝，并以稳定错误分类返回。
- 英文与简体中文文档与编译后的 API 一致。

## 不在范围内

- 把未来的数据库/文件适配器列为 SDK 工作：持久化按设计属于应用技术栈。
- 任何形式的传输实现。
- 通过应用配置替换 MasterSeed 或 MultisigPool。
- 未经新的硬切换规范和匹配 fixture 就修改当前规范性 wire 行为。
