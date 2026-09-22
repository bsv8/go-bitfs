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

## 纯函数边界

SDK 不再提供 `BuyerWorkflow`/`SellerWorkflow`/`ArbiterWorkflow` 等跨步骤对象。角色
步骤是无状态纯函数：原始报文/交易字节与一次调用专用的受约束 `Signer` 进，原始报文/
交易字节或普通证据包出。应用自行持有进度、存储、重试与广播。

公开面：

- `content`：`sanitizeRecommendedFilename`、`validateFileQuoteTerms`、
  `classifyContentHashes`、`contentHashesPriceSatoshis`、
  `verifyContentRequestEvidence`、`checkContentRequestTiming`、
  `verifyContentPayloads` 等算价与证据函数；
- `steps`：卖方（`createSellerQuote`、`prepareSellerPresign`、`verifySellerFunding`、
  `prepareSellerDelivery`、`completeSellerPayment`、`completeSellerClose`、
  `prepareSellerArbitration`、`completeSellerArbitratedPayment`）、买方
  （`acceptBuyerQuote`、`prepareBuyerOpening`、`completeBuyerOpening`、
  `prepareBuyerFundingDelivery`、`prepareBuyerContentRequest`、`verifyBuyerDelivery`、
  `prepareBuyerClose`、`verifyBuyerCompletedClose`、`buildBuyerMaturedRefund`、
  `requestBuyerArbitratedContent`、`verifyBuyerArbitratedContent`、`generateRetrievalNonce`、
  `newRetrievalNonce`）与仲裁方（`prepareArbiterArbitration`、
  `signArbiterPreparedArbitration`、`authenticateArbiterRetrieval`、
  `buildArbiterAvailableRetrieval`、`buildArbiterUnavailableRetrieval`、
  `completeArbiterArbitratedPayment`）步骤；
- `evidence`：`BuyerOpeningEvidence`、`BuyerPoolEvidence`、`BuyerAuthorizationEvidence`、
  `SellerOpeningEvidence`、`SellerPoolEvidence`、`SellerDeliveryEvidence`、
  `PreparedArbitrationEvidence`、`SignedArbitrationEvidence` 与全部输入类型；它们
  只是可序列化的普通数据，无行为、无令牌；
- `PureFunctionFacts.nowUnixSeconds`：调用方显式传入的 UTC Unix 秒，SDK 不读取系统时钟；
- `VerifiedQuote`：完成证据验证后的不可变语义结果；所有公开字节均为副本。

每个签名入口都按调用绑定 Signer：先校验其 33 字节压缩公钥、必要时再与协议角色比对，
并在任何密钥操作之前完成全部证据重验。任一类验证失败时签名能力不会被调用；等价于
每个步骤都从原始证据全量重验，绝不信任调用方缓存的派生字段。纯验证入口
（`acceptBuyerQuote`、`verifyBuyerCompletedClose`、`buildBuyerMaturedRefund`、
`verifyBuyerArbitratedContent`、`verifySellerFunding`）不需要 Signer：`acceptBuyerQuote`
不绑定买方身份，调用方必须自行比较 `terms.buyerPublicKey` 与本地身份；
`verifyBuyerArbitratedContent` 用开池证据中的买方公钥验证 exact Kind 10 签名。

安全状态约束：

- `prepareBuyerOpening` 先用 exact Kind 1 报价条款绑定买方身份、卖方公钥与受支持
  仲裁方，拒绝把资金池开给报价之外的角色；
- `completeSellerPayment` 要求传入生成本批次 Kind 6 时保存的交付证据包，并交叉核对
  exact Kind 5 与已发 Kind 6 的授权 ID 逐字节一致，不能只凭 Kind 7 自证；
- 卖方接收 Kind 4 时会重建退款模板，并验证 funding output[0] 金额、三方脚本、outpoint、
  fee rate 和双方退款签名，不能只凭 `refund_template_txid` 接受资金交易；
- `PreparedArbitrationEvidence` 是普通数据；`signArbiterPreparedArbitration` 从其中
  的 exact Kind 8 独立重建交易与 digest 后才签名，不存在接受任意 `receiptCBOR` 或
  调用方 candidate 的公开签名入口；candidate 由退款模板、付款授权和仲裁费在 SDK
  内部唯一重建；
- 买方推进池状态的唯一方式是从链上取得完整付款交易原文并按 `latestPaymentRawTx`
  传入下一步，由 SDK 全量重验；不存在跳过链上结果的入口。
