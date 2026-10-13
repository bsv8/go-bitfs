# Go/TypeScript 纯函数边界硬切换施工单

> 状态：待施工。本单同时改 Go 与 TypeScript 两个实现，原子硬切换、一起测试、共享同一套
> 测试数据；不保留旧公开 API、不保留双接口。
>
> 本单取代 `2026-09-22/002-TypeScript角色API与Keymaster集成补齐施工单`（v3）中
> 「Go 暂不动」的约定；v3 的缺口清单与 API 目标并入本单。

## 0. 施工性质、缘由与唯一目标态

### 0.1 施工性质

- **一次性原子硬切换**：Go 与 TypeScript 在同一迭代内切换到纯函数边界；代码、测试、
  Demo、集成测试、当前文档与生成文档一起切换，不允许中间态合并主分支；
- **两语言行为等价**：同一输入必须得到相同报文、相同交易、相同接受/拒绝与相同错误码；
- **共享一套测试数据**：根 `fixtures/manifest.json` 是唯一真值索引，两种语言都消费它，
  任何一方不得在语言目录内复制期望值；
- **协议零变化**：不新增 WireVersion、不新增 Kind、不新增 wire 字段、不修改任何既有
  golden bytes。

### 0.2 缘由

现有 Go/TypeScript 角色 API 把三样东西绑在了一起，导致应用状态机被 SDK 牵着走：

1. **角色 Workflow 类**持有跨步骤状态（开池、池、授权、交付 checkpoint），应用必须
   拿着 SDK 的不透明对象才能走下一步，无法自由序列化、重排或跳过；
2. **checkpoint/restore 入口**把「应用进度」做成 SDK 公开面，SDK 升级会牵动应用状态模型；
3. **`NextPool` 之类的返回值**让 SDK 暗示「业务已完成」，而真正的完成只能由链上结果决定。

Keymaster 本地 BitFS 买方/卖方需要自己拥有进度、存储、广播与恢复；SDK 只应提供
「按协议计算、按协议校验、按步骤产出原始报文」的工具。

### 0.3 唯一目标态

> SDK = 无状态计算器 + 验钞机：
>
> - 输入原始报文/交易字节与受约束 Signer，输出原始报文/交易字节或验证结果；
> - 不持有跨步骤对象、不保存进度、不定价、不碰钱包、不广播、不读时钟、不访问存储；
> - 算价公式与证据校验留在 SDK（双方必须独立算出同一结果）；
> - 进度、状态机、存储、恢复、重试、对账、定价策略全部归应用。

## 1. 不可突破的兼容边界

以下事实必须逐字节保持不变：

- `WireVersion == 1`、Kind 1–11 数值/方向/字段顺序/整数值/bstr 内容；
- 全部 `*_cbor` 子文档的 deterministic-CBOR 编码与 typed ID 算法；
- `WireSignatureInput("bitfs/wire-signature", 1, kind, exact_document_cbor)` 语义与 low-S DER；
- MultisigPool 的锁定脚本、输出顺序、金额、手续费、nLockTime、ForkID|All sighash、
  签名合并与 raw transaction；
- Kind 11 available/unavailable 分支与 exact `content_payloads_cbor` attachment；
- `fixtures/manifest.json` 指向的全部 wire/交易/CDDL/transport golden 与无效真值。

断言：

```text
旧 Go 与旧 TS 产生的 Kind 1–11 bytes == 新 Go 与新 TS 产生的 Kind 1–11 bytes
旧实现产生的交易 raw bytes             == 新实现产生的交易 raw bytes
旧实现交给 Signer 的 digest             == 新实现交给 Signer 的 digest
旧实现接受/拒绝的协议证据               == 新实现接受/拒绝的协议证据
```

固定测试 Signer 下必须逐字节相等；任意合法 Signer 下 digest、角色绑定、low-S 与验签
结果相等。已产生的 exact 报文只能原样持久化与重放。

## 2. 授权修改范围

允许修改：

- Go：`seller/`、`buyer/`、`arbiter/`、`content/`、`pool/`、`protocol/`、`wire/`、
  `transaction/`（如存在）中与角色 API、证据类型、错误分类相关的文件；
- Go：`demo/`、`integration/`、各包 `*_test.go`；
- Go：`docs/api_signature_lint_test.go` 与 `website/docs/protocol/**` 中描述角色
  API 的页面；
- TypeScript：`typescript/src/{roles,pool,transaction,wire,index}.ts`；新增
  `typescript/src/{content,steps,evidence}.ts`；
- TypeScript：`typescript/test/**`、`typescript/README.md`、`typescript/package.json`
  （`exports` 增加 `./content`、`./steps`，移除 `./roles`；依赖增加 `masterseed@1.1.0`）；
- `fixtures/**` 与 `fixtures/manifest.json`；
- `Makefile`、`.github/workflows/ci.yml`：联合一致性门禁。

禁止修改：

- `parse`/`parseAs` 行为、既有 encoder 输出、WireVersion、Kind、CBOR 字段顺序、
  签名域、ID 算法、MultisigPool 交易规则；
- 既有 golden bytes 与 `fixtures/invalid-wire-v1.json` 既有条目语义；
- 协议 CDDL 结构。

## 3. 职责边界（唯一架构真值）

| 能力 | 归属 | 说明 |
| --- | --- | --- |
| Wire 编解码、验签、ID | SDK | 协议密码学 |
| 内容分类与算价公式 | SDK | 双方必须独立算出同一金额 |
| 交易/支付池构造、签名合并、证据校验 | SDK | 协议规则 |
| 纯步骤函数（原始报文进 → 原始报文出） | SDK | 无状态，不记进度 |
| 定价多少、卖给谁、买不买 | 应用 | 卖家设置/买家决策 |
| 钱包出钱、广播、txid 对账、重试 | 应用 | 不可逆 I/O |
| 进度、状态机、存储、恢复、锁与并发 | 应用 | SDK 不提供进度对象 |
| 报价发现、transport | 应用/另立项 | 不在本单 |

证据包规则：

- 证据包是**普通数据**：只含原始字节与明确字段，可序列化、可复制、无行为；
- SDK 不提供不透明 checkpoint 类、不提供 restore 入口、不提供跨步骤令牌；
- 安全由「每个步骤都从原始证据全量重验」保证，而不是由对象不可构造保证。

## 4. 目标 API（双语言对照）

两语言函数语义、输入输出字段与错误码必须一一对应；命名按各语言习惯，但对照表内的
职责不得增减。

### 4.1 报价与 content（P0）

| 能力 | Go | TypeScript |
| --- | --- | --- |
| 文件名 sanitize | `content.SanitizeRecommendedFilename(name) string` | `sanitizeRecommendedFilename(name): string` |
| 条款校验 | `content.ValidateFileQuoteTerms(terms) error` | `validateFileQuoteTerms(terms): void` |
| 创建报价 | `seller.CreateQuote(facts, signer, draft) (outbound, terms, error)` | `createSellerQuote(facts, signer, terms): Promise<{ outbound; terms }>` |
| 接受报价 | `buyer.AcceptQuote(facts, rawKind1) (*VerifiedQuote, error)` | `acceptBuyerQuote(facts, rawKind1): VerifiedQuote` |
| 仲裁方白名单 | `VerifiedQuote.AllowsArbiter(pub) bool` | `VerifiedQuote.allowsArbiter(pub): boolean` |
| 内容分类 | `content.ClassifyContentHashes(ctx, terms, hashes, seed)` | `classifyContentHashes(terms, hashes, seed)` |
| 算价 | `content.ContentHashesPriceSatoshis(ctx, terms, hashes, seed)` | `contentHashesPriceSatoshis(terms, hashes, seed)` |
| 请求证据 | `content.VerifyContentRequestEvidence(auth, quote, opening)` | `verifyContentRequestEvidence(...)` |
| 时序 | `content.CheckContentRequestTiming(auth, terms, facts)` | `checkContentRequestTiming(...)` |
| payload/seed | `content.VerifyContentPayloads(ctx, terms, hashes, payloads, seed)` | `verifyContentPayloads(...)` |

算价与校验规则（两语言逐条一致）：

- seed 条目 = `SeedPriceSatoshis`；
- 完整 256 KiB 块 = `FullBlockPriceSatoshis`；
- 末块 = `ceil(整块价 × 末块字节数 × 90 / (262144 × 100))`，为 0 时取 1；整块价为 0
  时末块为 0；
- 块长度 0 或超过 262144 拒绝；总额溢出 uint64 按 `insufficient_balance` 拒绝；
- 批次 1..64、hash 32 字节且不重复；
- 时序：`now < 报价失效` 且 `now < 交付截止`，否则 `expired`；交付截止 > 报价失效
  返回 `invalid_evidence`。

### 4.2 卖方步骤（P0）

证据包（两语言同形，普通数据）：

| 证据包 | 字段 |
| --- | --- |
| `SellerOpeningEvidence` | `rawKind2`、`rawKind3` |
| `SellerPoolEvidence` | `opening`、`fundingTransactionRaw`、`latestPaymentRawTx?`（省略=初始状态） |
| `SellerDeliveryEvidence` | `rawKind1`、`rawKind5`、`rawKind6` |

| 能力 | Go | TypeScript |
| --- | --- | --- |
| 开池预签 | `seller.PreparePresign(ctx, rawKind2, signer) (outboundKind3, SellerOpeningEvidence, error)` | `prepareSellerPresign(rawKind2, signer)` |
| 验资 | `seller.VerifyFunding(rawKind4, opening) (fundingRaw, SellerPoolEvidence, error)` | `verifySellerFunding(rawKind4, opening)` |
| 交付 | `seller.PrepareDelivery(ctx, facts, input, signer) (outboundKind6, SellerDeliveryEvidence, error)` | `prepareSellerDelivery(facts, input, signer)` |
| 收款 | `seller.CompletePayment(ctx, facts, input, signer) (rawTransaction, nextPool, error)` | `completeSellerPayment(facts, input, signer)` |
| 关池 | `seller.CompleteClose(ctx, facts, input, signer) (rawTransaction, error)` | `completeSellerClose(facts, input, signer)` |
| 仲裁证据 | `seller.PrepareArbitration(ctx, facts, input, signer) (outboundKind8, claimID, error)` | `prepareSellerArbitration(facts, input, signer)` |
| 仲裁收款 | `seller.CompleteArbitratedPayment(ctx, facts, input, signer) (rawTransaction, error)` | `completeSellerArbitratedPayment(facts, input, signer)` |

要求：

- `PreparePresign` 顺序固定：解析 → 角色/模板/费率 → 买方退款签名 → 才调用 Signer；
  金额从退款模板推导，不接收调用方金额；
- `VerifyFunding` 验证资金交易 output[0] 金额/脚本与退款模板重建一致；
- `PrepareDelivery` 完成 quote/opening/时序/序号/容量/价格/payload 全量校验；
- `CompletePayment` 从输入重建池状态，校验序号 +1、金额不倒退、授权 ID 与交付证据
  一致、容量足够；不接收裸池状态；
- `nextPool` 是普通证据包，应用自行决定何时持久化。

### 4.3 买方步骤（P0）

证据包：

| 证据包 | 字段 |
| --- | --- |
| `BuyerOpeningEvidence` | `rawKind2`、`rawKind3`、`fundingTransactionRaw` |
| `BuyerPoolEvidence` | `opening`、`latestPaymentRawTx?`（省略=初始状态） |
| `BuyerAuthorizationEvidence` | `rawKind1`、`rawKind5` |

| 能力 | Go | TypeScript |
| --- | --- | --- |
| 开池 | `buyer.PrepareOpening(input, signer) (outboundKind2, BuyerOpeningEvidence, error)` | `prepareBuyerOpening(input, signer)` |
| 完成开池 | `buyer.CompleteOpening(opening, rawKind3) (BuyerOpeningEvidence, BuyerPoolEvidence, error)` | `completeBuyerOpening(opening, rawKind3)` |
| 注资交付 | `buyer.PrepareFundingDelivery(pool) (wire.Artifact, error)` | `prepareBuyerFundingDelivery(pool)` |
| 请求内容 | `buyer.PrepareContentRequest(facts, input, signer) (outboundKind5, BuyerAuthorizationEvidence, error)` | `prepareBuyerContentRequest(facts, input, signer)` |
| 验货付款 | `buyer.VerifyDelivery(facts, input, signer) (payloads, outboundKind7, error)` | `verifyBuyerDelivery(facts, input, signer)` |
| 关池准备 | `buyer.PrepareClose(facts, input, signer) (unsignedRaw, buyerSignature, error)` | `prepareBuyerClose(facts, input, signer)` |
| 验收关闭 | `buyer.VerifyCompletedClose(input) (rawTransaction, error)` | `verifyBuyerCompletedClose(input)` |
| 到期退款 | `buyer.BuildMaturedRefund(facts, pool) (rawTransaction, error)` | `buildBuyerMaturedRefund(facts, pool)` |
| 取回请求 | `buyer.RequestArbitratedContent(input) (wire.Artifact, error)` | `requestBuyerArbitratedContent(input)` |
| 取回验收 | `buyer.VerifyArbitratedContent(input) (*ArbitratedContentResult, error)` | `verifyBuyerArbitratedContent(input)` |
| nonce | `protocol.GenerateRetrievalNonce()` / `protocol.NewRetrievalNonce(raw)` | `generateRetrievalNonce()` / `newRetrievalNonce(raw)` |

要求：

- 买方推进池状态的唯一方式：从链上取得完整付款交易原文，作为 `latestPaymentRawTx`
  传入下一步，由 SDK 全量重验；不存在跳过链上结果的入口；
- `VerifyDelivery` 先验 payload 与 seed 归属，再签 Kind 7；不产生“已付款”状态；
- `BuildMaturedRefund` 使用开池双方预签的退款模板，不调用 Signer；未到期 `not_matured`；
- `RequestArbitratedContent` 默认内部生成 nonce；重试必须重放已持久化的 exact Kind 10；
- `VerifyArbitratedContent` 时间无关；unavailable 是 typed 结果（0 未收到、1 未就绪、
  2 托管已丢失），不是 error；不产生付款状态。

### 4.4 仲裁步骤（P1，边界一致性）

| 能力 | Go | TypeScript |
| --- | --- | --- |
| 准备 | `arbiter.PrepareArbitration(facts, rawKind8, fee) (PreparedArbitrationEvidence, error)` | `prepareArbiterArbitration(facts, rawKind8, fee)` |
| 签署 | `arbiter.SignPreparedArbitration(facts, prepared, signer) (outboundKind9, error)` | `signArbiterPreparedArbitration(facts, prepared, signer)` |
| 鉴权取回 | `arbiter.AuthenticateRetrieval(rawKind10, storedKind8) error` | `authenticateArbiterRetrieval(...)` |
| 可用取回 | `arbiter.BuildAvailableRetrieval(requestID, custody, signer)` | `buildArbiterAvailableRetrieval(...)` |
| 不可用取回 | `arbiter.BuildUnavailableRetrieval(requestID, reason, signer)` | `buildArbiterUnavailableRetrieval(...)` |
| 合并仲裁付款 | `arbiter.CompleteArbitratedPayment(signed, sellerSignature)` | `completeArbiterArbitratedPayment(...)` |

要求：

- `PreparedArbitrationEvidence` 是普通数据（exact Kind 8、candidate、claimID、fee），
  调用方可持久化；`SignPreparedArbitration` 必须从该数据重新验证全部证据后才签名；
- 删除 `PreparedArbitration` 不透明类与 `unique symbol` 令牌；安全性由重验保证。

### 4.5 池与交易纯函数（P0）

| 能力 | Go | TypeScript |
| --- | --- | --- |
| 构建开池状态 | `pool.MultisigPoolEngine.BuildOpeningState(...)`（保留） | 保留 |
| 验证开池证据 | `pool.MultisigPoolEngine.VerifyOpeningEvidence(...)`（保留） | 保留 |
| 构建状态 | `pool.MultisigPoolEngine.BuildState(...)`（保留） | 保留 |
| 签名/合并 | `SignState` / `MergeBuyerSeller` / `MergeSellerArbiter`（保留） | 保留 |
| 验证付款状态 | `pool.VerifyPaymentState(...)`（保留） | 新增等价导出 |
| 交易 ID/解析 | `pool.TransactionID` / `ParsePaymentState`（保留） | 新增等价导出 |

### 4.6 删除清单（硬切换）

Go 删除（或降为内部实现，不再公开）：

- `seller.Workflow`、`buyer.Workflow` 类与其 `*Command`/`*Result` 工作流类型；
- `OpeningCheckpoint`、`PoolCheckpoint`、`AuthorizationCheckpoint`、`DeliveryCheckpoint`；
- `RestoreOpeningCheckpoint`、`RestorePoolCheckpoint`、`RestoreAuthorizationCheckpoint`、
  `RestoreDeliveryCheckpoint`；
- 所有返回 `NextPool`/`InitialPool` 的公开签名（改为普通证据包）；
- `arbiter.PreparedArbitration` 不透明类（改为普通证据包）。

TypeScript 删除：

- `BuyerWorkflow`、`SellerWorkflow`、`ArbiterWorkflow` 类；
- `PreparedArbitration` 类与令牌；
- 任何 checkpoint/restore 概念（v3 中尚未实现，不得再补）；
- `./roles` 子路径导出。

保留：

- `wire`、`messages`（typed encoder）、`transaction`、`pool`、`protocol`
  （Signer、Facts、错误码、ID）、`transport`；
- `fixtures` 与既有 golden。

## 5. 共享测试数据与联合验收

### 5.1 fixtures 清单（根 manifest 登记）

| fixture | 内容 |
| --- | --- |
| `role_quote_kind1` | 固定 Signer 的 Kind 1 与最终条款 |
| `role_seller_opening_kind2` | Kind 2 + 期望 `pool_output_satoshis` |
| `role_seller_presign_kind3` | 固定 Signer 的 Kind 3 |
| `role_buyer_request_kind5` | 固定 Signer 的 Kind 5 与授权 ID |
| `role_seller_delivery_kind6` | 固定 Signer 的 Kind 6 |
| `role_buyer_payment_kind7` | 固定 Signer 的 Kind 7 |
| `role_close_unsigned` / `role_close_signed` | 关闭 candidate 与完整交易 |
| `role_refund_matured` | 到期退款完整交易 |
| `role_arbitration_kind8` / `role_arbitration_receipt_kind9` | 仲裁证据与回执 |
| `price_vectors` | seed/整块/末块/组合/边界计价向量 |
| `evidence_reject_vectors` | 语义无效真值（见下） |

语义无效真值（两语言必须同码拒绝）：买方签名伪造、角色不符、模板/费率错误、报价
过期、deadline 越界、序号陈旧、金额倒退、容量不足、价格不符、payload 错配、块不在
seed、缺 seed、零 nonce、Kind 11 attachment 哈希不符。

### 5.2 联合验收方式

- Go 与 TS 测试都从根 manifest 读取同一批 fixture；任一语言出现接受/拒绝或错误码
  漂移，`make conformance` 直接阻断；
- CI 增加依赖两种语言基础 job 的独立一致性 job（沿用 001 单的 conformance 结构）；
- 每个新入口至少一条成功路径 + 一条「验证失败 Signer 调用 0 次」；
- 失败断言只使用稳定错误码，不匹配错误文本；
- 纯函数重复调用同一输入结果一致（无隐藏状态）。

## 6. 验收矩阵

| 编号 | 场景 | 通过条件 |
| --- | --- | --- |
| T01 | 报价工具 | 两语言 sanitize/validate 一致；创建报价返回最终条款 |
| T02 | Kind 2 金额推导 | 两语言推导金额一致；Kind 3 与固定 Signer golden 逐字节一致 |
| T03 | 先验后签 | 任一类验证失败时拒绝且 Signer 调用 0 次 |
| T04 | 计价向量 | 两语言与 golden 一致；溢出/越界同码拒绝 |
| T05 | 请求证据与时序 | 两语言同码拒绝错报价/模板/过期/deadline 越界 |
| T06 | payload 与 seed | 两语言同码拒绝错 hash/缺 seed/块不在 seed/长度不符 |
| T07 | 卖方步骤 | 开池/验资/交付/收款输出与 golden 一致；错序/金额倒退拒绝 |
| T08 | 买方步骤 | 开池/注资/请求/验货输出与 golden 一致；无跳过链上入口 |
| T09 | 关池与退款 | 固定 Signer 下 raw 与 golden 一致；未到期 `not_matured` 且零签名 |
| T10 | 仲裁 | 卖方证据顺序正确；买方 available/unavailable 正确；仲裁 prepare/sign 重验 |
| T11 | 纯函数性 | 同一输入重复调用结果一致；公开面不存在跨步骤对象 |
| T12 | 跨语言一致性 | `make conformance` 与两语言测试全部消费同一 manifest 并通过 |
| T13 | 无时钟/存储/网络 | 两语言新增代码不含时钟、存储或网络调用 |

最终必须通过：`gofmt`、`go vet ./...`、`go test ./...`、TypeScript
`npm run typecheck`、`npm run build`、`npm test`、`npm run test:conformance`、
`make conformance`、`npm pack --dry-run`。

## 7. 实施顺序（两语言同步）

1. fixtures 与 manifest 扩展（先冻结测试数据）；
2. content/算价 + 报价工具（两语言同时）；
3. pool 纯函数补齐（付款状态验证、交易解析）；
4. 卖方步骤（两语言同时，含先验后签）；
5. 买方步骤（两语言同时，含关池/退款/取回）；
6. 仲裁步骤与删除清单；
7. Demo、集成测试、README、website 文档；
8. 联合 conformance 与发布准备。

每完成一层，两语言同时通过 `go test` 与 `npm test`；不允许单语言先行合并。

## 8. 发布前置决策（非代码任务）

1. **依赖版本（Keymaster G0.2）**：TS 包锁定 `keymaster-multisig-pool@4.0.0`、
   `@bsv/sdk@2.0.5`、`@noble/hashes@2.0.1`；Keymaster 使用 1.5.0 / 1.x / 1.8。
   二选一：Keymaster 升级（另立单），或 TS 改 `peerDependencies` 并提供单 bundle
   无行为分叉证据；
2. **许可证（Keymaster G0.3）**：本仓库 TS 包 AGPL-3.0-only，Keymaster ISC；需明确决策；
3. **发布形态**：Keymaster 现用 `file:` 链接；需发布 npm 版本（建议 `0.3.0`）并改为
   精确版本依赖。

## 9. Keymaster 下游影响

1. `packages/plugin-msfile/src/bitfs/sdk.ts` 改为导入纯步骤函数与 content；
2. Keymaster 自己写买方/卖方状态机（`bitfs/` 内）：进度、存储、重试、退款/仲裁时机；
3. 交易原文与报文由应用持久化；发送前先存、重试只重放原样；
4. 广播与对账继续使用 Keymaster 的 outbox 与中心广播；
5. 替换 `file:` 链接为发布版本，验证 Worker bundle 无双份协议行为分叉。

## 10. 完工记录

### 10.1 唯一目标态落地

- SDK 公开面已切换为纯函数 + 普通证据包：`buyer`/`seller`/`arbiter` 只导出包级
  步骤函数与 plain evidence/input 结构；不存在 `Workflow` 类、checkpoint/restore
  公开入口、`NextPool`/`InitialPool` 公开签名或 `PreparedArbitration` 不透明类。
  旧 workflow 实现降为包内实现，仅由角色包测试与内部测试适配器驱动。
- `content` 导出 `ClassifyContentHashes`；`VerifyContentPayloadsContext` 硬改名为
  `VerifyContentPayloads`。
- `arbiter.PreparedArbitrationEvidence` 为普通数据；`SignPreparedArbitration` 每次
  从 exact Kind 8 重新验证 Claim/费用/角色/deadline/candidate 后才签名。
- TypeScript 新增 `src/content.ts`、`src/evidence.ts`、`src/steps.ts`，删除
  `src/roles.ts`；`package.json` 移除 `./roles`，新增 `./content`、`./steps`，依赖
  锁定 `masterseed@1.1.0`。

### 10.2 改动文件

- Go：`content/content.go`、`content/verified.go`；`seller/{api.go,workflow.go,types.go,restore.go}`；
  `buyer/{api.go,workflow.go,types.go,restore.go}`；`arbiter/{api.go,workflow.go,types.go,restore.go}`；
  `internal/flowtest/{buyer,seller,arbiter}`（测试适配器，非公开面）；`demo/**`、
  `integration/**` 全部切换到新 API。
- TypeScript：`typescript/src/{content,evidence,steps,pool,transaction,wire,index}.ts`、
  `typescript/test/shared-fixtures.test.ts`、`typescript/README.md`、`typescript/package.json`。
- fixtures：`fixtures/role-v1.json`、`fixtures/manifest.json`、`fixtures/README.md`；
  生成器/校验器 `internal/conformance/role_fixture_test.go`、`internal/conformance/manifest.go`。
- 文档/门禁：`Makefile`、`.github/workflows/ci.yml`、`README.md`、
  `website/docs/sdk/{role-workflow-api,external-hooks-and-data-types,protocol-foundations-and-cbor,sdk-api-framework-design,implementation-roadmap}.md`、
  `website/docs/protocol/007-*.md` 与对应 `website/i18n/zh-CN/**` 副本。

### 10.3 fixture 登记（`fixtures/manifest.json` → `role_manifest`）

`fixtures/role-v1.json` 冻结：固定 Signer 的 Kind 1/2/3/4/5（含授权 ID）/6/7、
合并付款原文、关闭 candidate/完整交易、到期退款原文、Kind 8（含 Claim ID）/
Kind 9、Kind 10（含请求 ID）/Kind 11 available+unavailable；`price_vectors`
覆盖 seed/整块/末块/组合/零整块价/块不在 seed/缺 seed/重复哈希/错误宽度/溢出；
`evidence_reject_vectors` 覆盖报价过期、买方签名翻转、deadline 越界、payload
错配、授权 ID 错配、回执签名翻转、零 nonce、Kind 11 attachment 哈希不符。
两语言测试都从根 manifest 读取同一批数据，`make conformance` 阻断漂移。

### 10.4 两语言验收命令与结果

```text
gofmt（make fmt-check-go）             通过
go vet ./...                            通过
go test ./...                           通过
npm run typecheck --prefix typescript   通过
npm run build --prefix typescript       通过
npm test --prefix typescript            通过（59/59）
npm run test:conformance                通过（59/59）
make conformance                        通过
npm pack --dry-run                      通过（55 files，无 roles 产物）
```

### 10.5 剩余未覆盖路径与说明

- `demo/` 与 `integration/` 已切换到新公开 API；角色包的既有安全回归测试通过
  `internal/flowtest` 测试适配器继续驱动同一套内部实现（适配器不进入发布包）。
- TypeScript `parse` 不再在 Kind 11 available 分支内做 attachment 哈希检查，与
  Go `wire.Parse` 的分层一致；该哈希仍由 `verifyBuyerArbitratedContent` 以
  `invalid_evidence` 拒绝，并已进入共享拒绝向量。
- `website/docs/sdk/core-boundary-refactor-work-order.md` 是 2026-08-24 历史施工
  记录，按历史文档保留，不作为现行 API 真值。
- 第 8 节发布前置决策（Keymaster 依赖版本、许可证、发布形态）为非代码任务，
  未在本单内改变。

### 10.6 审查收口修复（B1/B2 + D1–D4）

- **B1 拒绝向量门禁**：新增 `internal/conformance` 的
  `TestRoleRejectVectorsMatchFrozen`，用与 TypeScript 相同的 mutation 名称与
  基线在 Go 新公开面上逐条重放；`Makefile`/`ci.yml` 的 conformance 过滤加入
  `RoleReject`，Go 侧错误码漂移现在会直接阻断。
- **B2 共享拒绝真值补齐**：`fixtures/role-v1.json` 的 `evidence_reject_vectors`
  由 8 条扩展为 14 条，新增角色不符（foreign signer）、模板错误（退款模板翻转）、
  序号陈旧、金额倒退、容量不足、价格不符；后四类由 `malicious` 字段冻结“买方已签
  但业务非法”的 Kind 5/6/7 基线，两语言同码拒绝。
- **D1**：`buyer.PrepareOpeningInput` 增加 `quoteRaw`；`PrepareOpening` 先用
  exact Kind 1 条款绑定买方身份、卖方公钥与受支持仲裁方。TS
  `prepareBuyerOpening` 同步。
- **D2**：`buyer.VerifyArbitratedContent` 去掉 Signer 参数，Kind 10 买方签名直接
  对照开池证据中的买方公钥验证；TS `verifyBuyerArbitratedContent` 同步。
- **D3**：`seller.CompletePaymentInput` 增加 `Delivery SellerDeliveryEvidence`；
  `CompletePayment` 交叉核对 exact Kind 5 与已发 exact Kind 6 的授权 ID 与卖方签名。
  TS `completeSellerPayment` 同步。
- **D4**：`buyer.AcceptQuote` 保持无身份参数（与施工单目标 API 一致），在 GoDoc、
  根 README 与 `typescript/README.md` 显著提示应用必须自行比较
  `Terms().BuyerPublicKey` 与本地身份。

修复后重新执行全部验收命令（gofmt、go vet、go test、TS typecheck/build/test、
`make conformance`、`npm pack --dry-run`）均通过；TS 测试 59 项、Go 拒绝向量
14 项全部与冻结真值一致。
