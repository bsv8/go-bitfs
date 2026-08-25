---
id: external-hooks-and-data-types
title: 02 · 外部钩子与数据类型
---

# 02 · 外部钩子与数据类型

SDK 是无状态协议库：它拥有消息编码、签名验证、定价、交易构造与协议验证；调用方应用拥有持久化、并发控制、内容存储、传输、节点广播以及时间与区块高度的观测。SDK 没有 Verifier 回调、没有 Store、没有节点钩子，也没有时钟钩子；一切外部事实都以显式方法输入、`protocol.Facts{Now, BlockHeight}` 值或唯一 Signer 端口的形式跨越边界。

## 签名与私钥保管：唯一端口

SDK 中唯一的密钥托管能力是受约束的 `protocol.Signer` 端口：

```go
// package protocol
type Signer interface {
    // PublicKey 返回本 Signer 固定的压缩公钥；workflow 构造时固定并验证它，
    // 生命周期内不得变化。
    PublicKey() PublicKey
    // Sign 对 SDK 已构造好的 32 字节 digest 做 secp256k1 签名，返回不带交易
    // sighash flag 的 low-S DER。Signer 绝不能自行哈希。
    Sign(ctx context.Context, request SigningRequest) ([]byte, error)
}

// SigningRequest 携带 Purpose（wire_message / transaction）、WireKind 与 Digest；
// 只供 HSM/KMS 策略审计，不替代任何既定签名预映像。
```

Signer 是**能力端口，不是可替换的协议策略**。它不能提供自定义哈希函数、preimage、sighash flag、verifier、CBOR encoder、价格规则或角色判断；所有验证固定在 SDK 内部执行。本地软件私钥经唯一提供的适配器进入：

```go
signer, err := protocol.NewPrivateKeySigner(privateKey) // privateKey 为 *ec.PrivateKey
buyerWorkflow, err := buyer.NewWorkflow(signer)
sellerWorkflow, err := seller.NewWorkflow(signer)
arbiterWorkflow, err := arbiter.NewWorkflow(signer)
```

每个构造器固定并验证由 Signer 派生的压缩公钥；该公钥成为 workflow 的角色绑定身份：后续每个方法都会先复核传入的开池证据属于该密钥对应角色，再进行计算。公钥在 workflow 生命周期内不得变化。

SDK 同样绝不接收种子、密钥导出回调或签名验证回调。SDK 内部所有普通消息签名都走一条固定路径：先一次性构造类型化签名输入的 digest，交给 Signer 签名，规范化为 low-S DER，并在返回前对照固定的角色公钥复验。调用方不得在签名前再做一次哈希。交易签名一律使用固定的 MultisigPool sighash（`ForkID|All`），绝不做二次哈希。

报价、开池证据、内容请求或付款状态中的公钥都是协议证据。调用方不能替换参与者验证逻辑，也不能重新配置买方/卖方/仲裁方角色：验签固定且不可替换。

## 持久化属于应用

SDK 中不存在任何 Store 接口。workflow 返回 opaque checkpoint 与 verified 值——例如 `buyer.OpeningCheckpoint`、`buyer.PoolCheckpoint`、`buyer.AuthorizationCheckpoint`、`seller.OpeningCheckpoint`、`seller.DeliveryCheckpoint`、`content.VerifiedQuote` 与 `pool.VerifiedOpening`——并在后续步骤中要求把它们作为显式参数再次传入。应用以 `RefundTemplateTxID`（或授权 ID）为键在自己的数据库中保存其 evidence 字节，按池串行化并发工作，并自行实现重试、outbox 与崩溃恢复；buyer 包提供从 exact 持久化字节全量重验重建各 checkpoint 的 Restore 入口（`RestoreOpeningCheckpoint`、`RestorePoolCheckpoint`、`RestoreAuthorizationCheckpoint`）。SDK 不提供任何锁、租约、mutex 或进程内/跨进程串行化：同一方法被并发调用两次会产生两份各自合法的计算结果，去重是应用的责任。

## 内容字节由调用方提供

卖方从自己的存储读取 seed/块 payload 字节，并以有序批次通过 `seller.DeliveryCommand.ContentPayloads` 传入；买方通过 `buyer.RequestContentCommand.ContentHashes` 提供有序内容哈希，并通过 `Seed` 提供已验证的 seed。workflow 从证据推导每个内容类型（等于报价 SeedHash 的哈希即 seed，其余必须由该 seed 提交），针对这些显式字节验证哈希、seed 结构、块成员资格、期望长度、报价条款以及请求/交付签名，并原子地整批接受或拒绝。验收以数据形式返回已验证的 payload 批次（`PaymentPreparationResult.Payloads`，按授权顺序排列）；把它保存到最终存储是应用的职责，保存失败意味着该业务步骤不得视为已完成。

## 时间与高度事实是显式输入

SDK 没有时钟注入，不访问节点，也不读取系统时间。每个时间敏感调用都接收一份显式的 `protocol.Facts{Now, BlockHeight}`；只需要时间的操作会拒绝零值 Now，需要高度的操作会拒绝零值 BlockHeight。SDK 绝不向节点查询当前高度，绝不回退系统时钟，也绝不伪造数值。高度来源故障时应延迟或改道退款操作，绝不能伪造数值继续执行。

## 协议输入与结果类型

角色 API 接收 Command 结构体，返回统一 Result：待发送 Artifact 加必须先持久化的 opaque checkpoint。

- `PrepareOpeningCommand` 携带已验收报价、资金交易原文、到期锁定、费率与卖方/仲裁公钥；`PrepareOpeningResult` 返回 `Outbound wire.Artifact` 与 `OpeningCheckpoint`——发送前先持久化 checkpoint。
- `RequestContentCommand` 携带已验收报价、池 checkpoint、有序内容哈希、交付截止与 seed；`RequestContentResult` 返回 `Outbound`、typed `AuthorizationID` 以及持有 exact 已签 003 的 `AuthorizationCheckpoint`。
- `VerifyDeliveryCommand` 用已持久化的授权 checkpoint 验收 exact Kind 6 交付；`PaymentPreparationResult` 返回已验证 payload、整批唯一的出站 Kind 7 凭证与仅供审计的未签名 candidate。
- 卖方侧 `DeliveryCommand` / `DeliveryResult` 返回出站 Kind 6 Artifact 与无锁的 `DeliveryCheckpoint`——它恰好记录后续 `CompletePayment` 所需的协议上下文（费用池关联 ID、授权 ID、目标付款序号、绝对累计卖方金额），不携带任何 owner/lease/expiry 语义。
- pool.UnsignedPayment 与 pool.SignedPayment 区分本地重建的未签名状态、分离签名和完整交易。workflow 方法把完整交易字节包装为 `pool.VerifiedSignedTransaction` 返回，供应用广播；SDK 内部绝不存在名为"submitted"或"accepted"的声明。

贯穿这些类型的关联字段是 `pool.RefundTemplateTxID`——专用的 `[32]byte` 类型，承载未嵌入角色签名的规范退款模板交易的 TxID（CDDL 标签 `refund-template-txid`）。它不是原始字节的 SHA-256，也不是字节反转哈希，更不是最终广播退款交易的链上 txid。

wire 包把领域值映射为规范的 001–008 CBOR Artifact；其 `Bytes()` 被原样传输与保存，不做二次编码。传输层（HTTP、WebSocket、队列、CLI 或浏览器消息）刻意缺席；所有环境承载相同字节并使用相同的角色方法。

## 什么不是扩展点

不存在 verifier 策略、workflow 时钟、store/repository 钩子、交易引擎钩子、租约或锁、内容 source/sink、后端端口、私钥 provider 或应用提供的交易 ID 计算器。这些抽象会让调用方替换定义协议本身的业务规则，或者把基础设施副作用重新 smuggle 回 SDK。只有密钥保管跨越这条边界，且仅在构造时经受约束的 `protocol.Signer` 端口进入一次；其余一切都通过显式输入、显式事实和返回结果流转。
