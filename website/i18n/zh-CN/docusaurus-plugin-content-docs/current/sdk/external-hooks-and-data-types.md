---
id: external-hooks-and-data-types
title: 02 · 外部钩子与数据类型
---

# 02 · 外部钩子与数据类型

SDK 边界只承载基础设施，不承载协议规则。应用提供私钥保管、持久化、
内容字节和窄 BSV 后端；go-bitfs 固定报文编码、签名验证、定价、状态
迁移、MultisigPool v4 交易构造以及提交前后的验收条件。

## 签名和私钥保管

角色工作流唯一接收的签名能力是 pool.Signer：

~~~go
type Signer interface {
    PublicKey(context.Context) ([]byte, error)
    Sign(context.Context, []byte) ([]byte, error) // 只返回 DER 签名
}
~~~

`PublicKey` 必须返回协议规定的 33 字节压缩 secp256k1 公钥编码。65 字节未
压缩公钥会在进入签名报文或费用池证据前被拒绝。

应用可以用本地钱包、HSM、浏览器钱包或远程签名服务实现它。SDK 不接收
私钥、种子、导出私钥的回调，也不接收签名验证回调。角色工作流调用 Sign
时始终传入 SDK 计算的 32 字节摘要：001/003/004 规范 CBOR 只做一次
SHA-256，费用池交易使用固定 sighash 摘要。Sign 只返回 DER 字节。需要时
核心追加协议 sighash 字节，并在返回、保存、合并或提交前按角色验证签名。

底层的 `QuoteTermsSigner` 和 `ContentTermsSigner` 回调有所不同：构造器会
把精确的规范 CBOR 字节传给它们。回调必须对这些字节执行一次 SHA-256，
返回 DER 字节；构造器在返回凭证前固定复验签名。

报价、开池证明、内容请求和支付状态中的公钥属于协议证据。应用不能用
参与者验证器替换它们，也不能重新配置买方、卖方和仲裁者角色。

## 存储接口

报价存储按角色声明，使应用可选数据库、文件或复制服务而不改变 wire
字节：

~~~go
type QuoteStore interface {
    SaveQuote(context.Context, *bitfs.SignedFileQuote) error
    LoadQuote(context.Context, bitfs.Hash32) (*bitfs.SignedFileQuote, error)
}
~~~

pool.PoolStore 保存完整开池证明、节点已接受的最新支付状态，并提供外部
状态不确定和对账标记：

~~~go
type PoolStore interface {
    OpeningProofStore
    LoadOpeningProofByFundingTxID(context.Context, Hash32) (*OpeningProof, error)
    SaveAcceptedPayment(context.Context, *PaymentState) error
    LoadAcceptedPayment(context.Context, Hash32) (*PaymentState, error)
    EnsurePoolHealthy(context.Context, Hash32) error
    EnsurePoolOpen(context.Context, Hash32) error
    MarkPoolClosing(context.Context, Hash32) error
    ReconcilePoolClosing(context.Context, Hash32) error
    MarkExternalStateUncertain(context.Context, Hash32, Hash32) error
    ReconcileExternalState(context.Context, Hash32, *PaymentState) error
}
~~~

卖方还提供 pool.PendingRequestStore 作为内容交付租约。每个租约记录 spend ID、base
sequence、base seller amount、授权哈希和预期卖方增量；只有完全匹配的租约才能在重试时释放。
TryAcquire、Load
和 Release 防止同一累计序列被并发交付。pool.MemoryStore 适合单进程和测试；
pool.FileStore 通过原子替换持久化快照并在协作进程间加咨询锁。数据库可实现
相同接口，但不能改变规范交易 ID 或支付序列。存储不接受外部交易 ID 计算器；
SDK 始终用固定 BSV 交易解析器计算 ID。

## 内容接口

买方内容和种子适配器是可选的：

~~~go
type ContentSink interface {
    SaveVerifiedContent(context.Context, bitfs.Hash32, []byte) error
}
type SeedSource interface {
    LoadSeed(context.Context, masterseed.Digest) ([]byte, error)
}
~~~

卖方 ContentSource 读取报价承诺的种子或区块：

~~~go
type ContentSource interface {
    LoadSeed(context.Context, masterseed.Digest) ([]byte, error)
    LoadBlock(context.Context, masterseed.Digest) ([]byte, error)
}
~~~

工作流在使用加载结果前验证哈希、种子结构、区块归属、内容大小、报价条款
以及请求/交付签名。内容存储外置，但内容证明和业务定价固定在 bitfs 内部。

## 窄 BSV 后端边界

买方接收只能提交非最终池状态的原始后端：

~~~go
type NonFinalPoolBackend interface {
    SubmitUpdate(context.Context, []byte) (*UpdateAcceptance, error)
    SubmitFinal(context.Context, []byte) (Hash32, error)
}
~~~

卖方需要先广播 funding，因此接收更宽的后端：

~~~go
type FundingBackend interface {
    // 相同原始交易已被接受 => 相同规范 txid，nil error。
    SubmitTransaction(context.Context, []byte) (Hash32, error)
}

type PoolBackend interface {
    NonFinalPoolBackend
    FundingBackend
}
~~~

`SubmitTransaction` 的公开契约是按规范交易 ID 幂等广播：完全相同的原始交易
若已经被接受，重试必须返回相同的 `Hash32` 和 nil error；`already-known` 应视为
成功，不能视为失败。这是工作流恢复 funding 不确定状态的必要后端行为，不是由
应用回调自行推断的业务判断。

后端调用后，普通 error 或交易 ID/sequence 与候选不完全一致都表示外部结果不确定。
工作流会用候选交易 ID 调用 `MarkExternalStateUncertain` 并返回
`ErrPoolStateUncertain`；调用者必须对同一原始交易完成对账后才能继续签名或提交。
`ReconcileExternalState` 保存外部确认的精确状态并清除不确定标记。当同一个 Store
同时持有完整匹配的 pending 租约时，它可以在校验租约全部字段后原子清理该租约。
如果 `PoolStore` 与 `PendingRequestStore` 分离，则由 005/007 幂等工作流重试在完整
密码学证据匹配后释放独立的 pending 租约。观察到最终关闭状态后仍必须调用
`ReconcilePoolClosing`，因此 close-issued 保护会跨进程重启保留，直到明确清除。

后端可以是 RPC、gRPC、厂商 SDK 或进程内节点客户端，但不负责构造和验证
协议交易。工作流会用后端和持久化开池证明在内部构造
pool.VerifiedNonFinalPoolNode；它按每份 proof 动态建立具体 MultisigPool
引擎，在转发前验证 funding/update/final 原始字节，在转发后核对交易 ID、
SpendTxID 和支付序列。即使后端“什么都接受”，畸形证据也不能进入工作流状态。

Funding 使用普通广播语义，不会误用 final 提交。区块高度退款是唯一可选的
链状态查询：后端可以实现 BlockHeight(context.Context) (uint32, error)。
应用不能注入 wall-clock 或过期策略；时间锁使用一次捕获的 SDK 操作时间，
高度锁退款在缺少权威高度源时直接失败。

## 协议输入类型

角色 API 接收协议形状的数据，而不是业务回调：

- pool.OpeningInput：原始 funding、池输出索引、过期锁时间、费用率和卖方/仲裁者公钥。
- pool.RefundPresignRequest/Response：002 开池证据；pool.FundingTxDelivery
  只有在退款证明已持久化后才揭示 funding。
- buyer.ContentRequestInput：报价哈希、`SpendTxID`、ContentRef、大小和截止时间。
  仲裁者和 base sequence 由 opening proof 推导；价格和支付序列由核心推导。
- pool.PaymentUpdate、pool.UnsignedPayment、pool.SignedPayment：分别区分
  未签名状态、分离签名和完整交易。

wire 包把这些值映射到规范 001–007 CBOR。HTTP、WebSocket、队列、CLI 或浏览器
消息只是传输方式；所有环境都携带同一字节并调用同一角色方法。

## 不属于扩展点的内容

不存在 workflow clock、交易引擎钩子、开池钩子聚合、参与者/验证器端口、私钥
提供器或应用交易 ID 计算器。它们会允许调用者替换协议业务规则。只有私钥保管、
持久化、内容和网络/后端集成跨越这条边界。
