---
id: external-hooks-and-data-types
title: 02 · 外部钩子与数据类型
---

# 02 · 外部钩子与数据类型

SDK 是无状态协议库：它拥有消息编码、签名验证、定价、交易构造与协议验证；调用方应用拥有持久化、并发控制、内容存储、传输、节点广播以及区块高度来源。SDK **不接受任何运行时钩子**。没有 Signer 接口、没有 Verifier 回调、没有 Clock/`NowFunc`、没有 Store，也没有节点钩子；一切外部事实都以显式方法输入或返回结果的形式跨越边界。

## 签名与私钥保管

SDK 中唯一的签名能力是应用作为构造参数传入的官方 BSV 私钥：

~~~go
import ec "github.com/bsv-blockchain/go-sdk/primitives/ec"

type WorkflowConfig struct {
    // 调用方解析的官方 BSV Go SDK 私钥。
    PrivateKey *ec.PrivateKey
}
~~~

`buyer.WorkflowConfig`、`seller.WorkflowConfig` 和 `arbitration.WorkflowConfig` 都只有这一个字段。TypeScript 调用方使用 `@bsv/sdk` 原生的 `PrivateKey`。构造器拒绝 nil 私钥，并由私钥派生压缩 secp256k1 公钥作为 workflow 的角色绑定身份：后续每个方法都会先复核传入的开池证据属于该密钥对应角色，再进行计算。

不存在需要实现的 `pool.Signer` 接口，也不需要提供钱包、HSM 或远程签名服务适配器。SDK 同样绝不接收种子、密钥导出回调或签名验证回调。所有消息签名都走一条固定路径：001/003/004 的规范 CBOR 用 SHA-256 哈希一次，官方私钥对这份已算好的摘要签名，low-S DER 结果在返回前由固定的内部验证器复验。Go 侧 `(*ec.PrivateKey).Sign` 接收已算好的 digest；TS 侧 `PrivateKey.sign(message)` 会自行对消息做 SHA-256——跨语言测试向量必须避免双重哈希。交易签名一律使用固定的 MultisigPool sighash（`ForkID|All`），绝不做二次哈希。

报价、开池证据、内容请求或付款状态中的公钥都是协议证据。调用方不能替换参与者验证逻辑，也不能重新配置买方/卖方/仲裁方角色：验签固定且不可替换。

## 持久化属于应用

SDK 中不存在任何 Store 接口。Workflow 返回本地角色状态——例如 `buyer.BuyerOpeningState`、`seller.SellerPresignResult.Opening`、`seller.ContentDeliveryState` 和每一个 `pool.PaymentState`——并在后续步骤中要求把该状态作为显式参数再次传入。应用以 `RefundTemplateTxID` 为键在自己的数据库中保存这些值，按池串行化并发工作，并自行实现重试、outbox 与崩溃恢复。SDK 不提供任何锁、租约、mutex 或进程内/跨进程串行化：同一方法被并发调用两次会产生两份各自合法的计算结果，去重是应用的责任。

## 内容字节由调用方提供

卖方从自己的存储读取 seed/块字节并通过 `seller.ContentDeliveryInput` 传入；买方通过 `buyer.ContentRequestInput.Seed` / `buyer.ContentDeliveryInput.Seed` 提供已验证的 seed。workflow 针对这些显式字节验证哈希、seed 结构、块成员资格、内容大小、报价条款以及请求/交付签名。AcceptDelivery 以数据形式返回已验证的 payload（`buyer.VerifiedDelivery.Payload`）；把它保存到最终存储是应用的职责，保存失败意味着该业务步骤不得视为已完成。

## 时间与高度事实

SDK 没有时钟注入，也不访问节点，更不接收 `now` 参数。每个公开操作入口都在内部恰好读取一次 `time.Now().UTC()`，并在本次调用的全部到期与锁定规则中复用该读数。区块高度一律由调用方以显式参数传入（例如 `blockHeight uint32`）；SDK 绝不向节点查询当前高度。高度来源故障时应延迟或改道退款操作，绝不能伪造数值继续执行。

## 协议输入与结果类型

角色 API 接收协议形态的数据并返回计算结果：

- pool.OpeningInput 包含原始资金交易字节、到期锁定时间、费率以及卖方/仲裁方公钥。
- pool.RefundPresignRequest 与 pool.RefundPresignResponse 承载 002 开池证据；pool.FundingTxDelivery 在应用持久化退款证明之后才公开资金交易。
- buyer.PreparePoolOpening 返回 PoolOpeningPreparation\{Request, *BuyerOpeningState\}：先保存 State 再发送 Request。AcceptRefundPresign 显式接收该保存的状态，返回 RefundPresignAcceptance\{Reference, Opening, InitialPayment\}。
- seller.PresignPoolOpening 返回 SellerPresignResult\{Response, Opening\}：先保存 Opening 再发送 Response。AcceptPoolFunding 接收保存的 proof 与交付报文，返回 PoolFundingAcceptance\{Opening, InitialPayment, FundingTx\}；广播 FundingTx 是应用节点适配器的职责。
- seller.BuildContentDelivery 返回 wire 交付以及 ContentDeliveryState——后续 AcceptPayment 所需的无锁协议上下文（退款关联 ID、请求哈希、基准序号、基准卖方金额、预期增量）。它不携带 owner、lease 或 expiry 语义。
- buyer.AcceptDelivery 返回 VerifiedDelivery\{Payload, Update\}：已验证的内容字节加上签名的 005 wire 更新。
- pool.PaymentUpdate、pool.UnsignedPayment 与 pool.SignedPayment 区分未签名状态、分离签名和完整交易。Build/Verify/Accept 方法返回供应用广播的原始交易；SDK 内部没有任何东西会被命名为"已提交"或"已接受"。

贯穿这些类型的关联字段是 `pool.RefundTemplateTxID`——一个专用 `[32]byte` 类型，承载未嵌入角色签名的规范退款模板交易的 canonical TxID（CDDL 标签 `refund-template-txid`）。它不是原始字节的 SHA-256，不是翻转字节序的哈希，也不是最终广播退款交易的链上 txid。

wire 包把这些值映射为规范化的 001–007 CBOR。传输（HTTP、WebSocket、队列、CLI 或浏览器消息）刻意缺席；所有环境承载同样的字节、使用同样的角色方法。

## 什么不是扩展点

不存在 signer 端口、verifier 策略、workflow 时钟、store/repository 钩子、事务引擎钩子、租约或锁、content source/sink、backend 端口、私钥提供者或应用提供的交易 ID 计算器。这些抽象会让调用方替换定义协议的业务规则，或把基础设施副作用偷运回 SDK。运行时只有密钥保管跨越这条边界，而且只在构造时通过 `WorkflowConfig{PrivateKey}` 发生一次；其余一切都通过显式输入输出流动。
