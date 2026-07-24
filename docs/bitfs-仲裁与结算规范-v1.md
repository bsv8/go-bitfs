# BitFS 仲裁与 2-of-3 结算规范 v1

仲裁是 BitFS 核心交易的一部分。它由两层协议共同完成，二者均由 `go-bitfs` 提供。

## 代码角色

`buyer` 和 `seller` 都是完整交易角色。两者通过独立的 `FileQuote`、`HashGetTicket` 与 `HashDelivery` 异步 CBOR 报文协作；队列、WebSocket、TCP 或 libp2p 适配器只负责投递，不改变业务报文。

`arbiterclient` 是仲裁工作流的本地端口包装。`demo/arbiter` 是本仓库提供的最小处理器实现，专门用于验证标准仲裁流程；它使用内存记录，且必须由调用方注入会话映射、pool 客户端和两种仲裁签名器，不能作为生产仲裁节点。

## BitFS 业务仲裁

`ArbitrationClaim` 是申诉证据。卖方申诉必须携带买方签名的 `HashGetTicket` 与真实 payload；仲裁方依次验证票据签名、会话、期限、交付长度与 `sha256(payload) == ticket.content_hash`。票据的 `sequence` 必须对应当前费用池仍可裁决的付款位置。

买方申诉可以不带 payload。仲裁方若从卖方或现有记录恢复到匹配的 payload，应通过 `ArbitrationDecision.recovered_payload` 发布给买方，再进行资金收尾。

一旦 seller 会话进入仲裁，该 seller 会话收尾，不再继续正常交易。`ArbitrationRecord` 的状态是服务重启后的仲裁真值。

## 2-of-3 资金结算

资金池以 32 字节 `spend_txid` 为主键；BitFS 的 `session_id` 不进入 pool wire schema。运行时维护 `(bitfs_session_id, seller_pubkey) -> spend_txid` 映射。正常路径由 buyer + seller 推进付款；争议路径由 arbiter 与裁决方向对应的一方完成收尾。

`settlement.ArbitrationRequest` 是资金仲裁入口。它签名覆盖 `spend_txid`、裁定方向、原因与最终付款金额，并通过异步的 `CloseSignatureRequest`、`CloseSignature` 与 `PoolArbitrated` 三个报文完成两阶段 close。交易与交易 ID 均为原始 `bstr`，不用 hex 字符串。

BitFS 业务裁决与 pool 资金签名使用不同签名域，不能相互替代。
