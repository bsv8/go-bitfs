# go-bitfs TypeScript SDK

本目录是 BitFS Wire Protocol v1 的 TypeScript 实现。Go 与 TypeScript 测试共同读取
仓库根 `fixtures/manifest.json` 指向的冻结真值，不维护第二份协议期望值。

字段说明：

- `Artifact.kind`：报文类型（1–11）。
- `Artifact.bytes()`：通过严格解析后的完整规范 CBOR 副本。
- `expectedKind`：传输路由预期的 Kind；必须与报文自身第二项一致。
- `maxInboundFrameBytes`：本地接收的单帧上限，不发送给对端。
- `maxBufferedBytes`：TypeScript reader 的未消费字节上限；默认自动覆盖最大
  BitFS frame 加 uvarint 前缀，调用方可主动设得更小。
- `BITFS_PROTOCOL_ID`：libp2p stream 协议标识 `/bitfs/wire/1.0.0`。

网络使用 `bitcoin-libp2p` 的标准 Noise/Yamux 身份宿主和 uvarint stream 分帧。
BitFS transport 只投递 exact Artifact bytes，不增加 session、pool ID 或 JSON envelope。

## 角色工作流

应用代码应优先使用 `BuyerWorkflow`、`SellerWorkflow`、`ArbiterWorkflow`，而不是
自行拆解 CBOR 或手工调用验签函数。三个对象分别固定一个受约束 `Signer`：

- `BuyerWorkflow`：验证报价、开池预签与合并、资金交付、创建付款授权、准备付款/关闭、
  验证内容交付、创建仲裁取回请求；
- `SellerWorkflow`：创建报价、完成开池预签、验收资金交易、验证付款授权、完成付款/关闭、
  交付内容、提交仲裁托管证据；
- `ArbiterWorkflow`：验证完整托管证据、签署回执、认证取回请求、返回可用或不可用结果，
  并完成 Seller/Arbiter 仲裁交易签名合并；
- `WorkflowFacts.nowUnixSeconds`：调用方显式传入的 UTC Unix 秒，SDK 不读取系统时钟；
- `VerifiedQuote`、`VerifiedContentRequest`、`VerifiedArbitrationRequest`：完成对应验证后的
  不可变语义结果；所有公开字节均为副本。

角色 API 和底层 typed encoder 使用同一个严格 `parse` 末端门禁。Kind 8 解析会验证
角色顺序锁定脚本、规范退款模板、付款序号与余额边界，以及买方 Kind 5 签名；仲裁方
工作流再验证卖方 Kind 8 签名和每个 payload 的授权哈希。

安全状态约束：

- Workflow 构造时冻结 Signer 公钥；后续签名前若底层 Signer 换钥，会在调用签名能力前
  返回 `unauthorized`，不会静默切换角色；
- 卖方接收 Kind 4 时会重建退款模板，并验证 funding output[0] 金额、三方脚本、outpoint、
  fee rate 和双方退款签名，不能只凭 `refund_template_txid` 接受资金交易；
- Kind 9 只能由 `prepareArbitration` 返回的 `PreparedArbitration` 进入
  `signPreparedArbitration`；不存在接受任意 `receiptCBOR` 或调用方 candidate 的公开签名
  入口。candidate 由退款模板、付款授权和仲裁费在 SDK 内部唯一重建。
