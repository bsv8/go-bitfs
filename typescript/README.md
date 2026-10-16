# go-bitfs TypeScript SDK

本目录是 BitFS Wire Protocol v1 的 TypeScript 实现。Go 与 TypeScript 测试共同读取
仓库根 `fixtures/manifest.json` 指向的冻结真值，不维护第二份协议期望值。

字段说明：

- `Artifact.kind`：报文类型（1–13）。
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
  `inspectSellerDeliveryRequest`、`prepareSellerDelivery`、`completeSellerPayment`、`completeSellerClose`、
  `completeSellerCloseArtifact`、`prepareSellerArbitration`、`completeSellerArbitratedPayment`）、买方
  （`acceptBuyerQuote`、`prepareBuyerOpening`、`completeBuyerOpening`、
  `prepareBuyerFundingDelivery`、`inspectBuyerPool`、`inspectBuyerContentRequest`、
  `prepareBuyerContentRequest`、`verifyBuyerDelivery`、
  `prepareBuyerClose` / `prepareBuyerCloseArtifact`、
  `verifyBuyerCompletedCloseArtifact`、
  `verifyBuyerCompletedClose`、`buildBuyerMaturedRefund`、
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

卖方可先调用 `inspectSellerDeliveryRequest(facts, { quoteRaw, pool, requestRaw })`，
在读取内容仓库前验证 Kind 5，并取得 `paymentAuthorizationID`（授权查找 ID）、
`paymentSequence`（目标付款序号）与 `contentHashes`（签名绑定的有序哈希清单）。
授权 ID 与付款序号是两个不同字段。该预检不接收 payload，也不证明内容存在、属于报价
seed 或满足授权价格；读取后仍须把同一 Kind 5 和池证据连同 payload 交给
`prepareSellerDelivery` 完成内容和价格验证，SDK 才会签署 Kind 6。

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
- 买方通过 `latestBuyerPayment: { rawKind5, rawKind7 }` 传入已签本地付款，或通过
  `latestPaymentRawTx` 传入完整双签交易，两者不能同时提供。池内付款不要求逐笔上链。
  `inspectBuyerPool` 重验签名、池绑定、交易构造后返回序号和累计金额；应用负责选择
  最新状态、保证本地付款日志连续，并在发送报文之前持久化原文；
- 开池退款状态的 `sequence` 为 2，付款按 3、4、5 递增，普通付款始终延续开池时
  固定的 `lockTime`。高度锁由应用按当前真实链高度加等待区块数计算，再通过
  `expiryLockTime` 传入 SDK；SDK 不推算链高度。最终关闭的 `sequence` 和 `lockTime`
  均为 `0xffffffff`；
- 关池目标金额不能低于所给基准中的已签付款。`verifyBuyerCompletedCloseArtifact`
  可携带保存的 `requestRaw`（Kind 12），逐字节核对候选与买方签名，拒绝替换响应；
- `SigningRequest` 的 `transactionRaw` / `documentCBOR` 为原文副本；卖方退款预签
  另携带 `openingRequestRaw`，Kind 5 携带 `authorizationContext` 的资金交易、退款
  模板与本次未签付款交易。钱包可独立核验固定摘要和额度，但不能改变 SDK 哈希规则。
  SDK 仍用绑定公钥立即验证返回签名。

## 0.4.0 报价参数

`createSellerQuote` 和 `createFileQuote` 的报价必填 `maxBlocksPerBatch: number`（卖方每批最多接受的非 Seed Block 数，整数 1–64）。`acceptBuyerQuote` 返回验签后的同名字段；买方策略器据此选择本批块数，`prepareBuyerContentRequest` 在签名前、`inspectSellerDeliveryRequest` / `prepareSellerDelivery` 在接受请求前检查上限。SDK 不提供买方批次设置，也不自动拆分请求。Seed 不占 Block 数，总条目仍受 64 限制。

Wire v1 与传输标识保持不变；本次开发期升级以九项报价直接替换旧八项报价。历史仲裁与买方取回不追加批次上限追溯检查。历史仲裁、买方本地证据取回及仲裁费用检查接口已包含在正式源码与构建产物中，不需要应用侧 patch。

## 0.5.0 报价 MIME

报价第十项为必填 `MediaType`（Go）/ `mediaType`（TypeScript）：卖方声明的规范小写 `type/subtype`，最多 255 字节，不携带参数。此字段与文件名一起进入签名和报价 ID；不得从扩展名补默认值。开发期直接采用十项报价，拒绝缺失 MIME 的旧结构；WireVersion 仍为 1，协议路径不变。内容类型是卖方声明的展示元数据，不改变 Seed/Block 的内容哈希或仲裁计费。多个卖家的类型选择由应用策略负责。
