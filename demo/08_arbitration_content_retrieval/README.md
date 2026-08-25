# 008：买方仲裁托管内容取回

这一步演示 Seller 与 Buyer 无法直连、但二者均能连接 Arbiter 时，Buyer 如何取回已托管的精确内容：Buyer 用角色 API 构造 exact Kind 10（SDK 生成安全随机 nonce），Arbiter 验签后按结果返回由自己签名的两分支 Kind 11——可交付分支经 `content_payloads_id` 绑定 exact payload bundle（不内嵌 Kind 8/9），不可交付分支携带结构化原因。

角色 workflow 只持有受约束 Signer。托管记录、nonce 占用表和传输全部由本 demo（调用方应用）实现；SDK 不查数据库、不记录下载次数。本 demo 演示两个分支：先在 Kind 9 落库前请求一次得到签名 not_ready（typed 结果，不是 error），随后用新 nonce 重试得到 available。验收不产生付款凭证、不改池状态、不关池、不广播任何交易。

运行：

```sh
go run ./demo/08_arbitration_content_retrieval/01_retrieve_content
```

核心调用顺序是：

```text
// 应用侧（一次性）：Seller 托管 + Arbiter 签署（复用 007）
rawKind8 = seller.PrepareArbitration(...).Bytes()   // 内含唯一 payload 真值
persist(exact Kind 8)                                // 此时尚无 Kind 9
prepared = arbiter.PrepareArbitration(ctx, facts, rawKind8, fee)
persist(Claim ID、冻结费用等托管字段)
kind9 = arbiter.SignPreparedArbitration(ctx, facts, prepared).Bytes()
persist(exact canonical Kind 9)                      // 此后记录才可取回

// Buyer 取件：只需要池 checkpoint + exact 已签 003。
k10 = buyer.RequestArbitratedContent(ctx, buyer.ArbitrationRetrievalCommand{
    Pool:          buyerPoolCheckpoint,
    Authorization: authorizationCheckpoint, // 本地持久化的 003 checkpoint
}).Bytes()
persist(exact Kind 10 before send)          // 先持久化再发送

// Arbiter 应用：按请求状态选择分支并签署 Kind 11。
custody = arbiter.VerifyRetrievableCustody(k10.Bytes(), storedKind8, storedKind9)
answer = arbiter.BuildAvailableRetrieval(ctx, requestID, custody)   // 可交付
//   或 arbiter.BuildUnavailableRetrieval(ctx, requestID, reason)   // 不可交付

// Buyer 完整验收（时间无关）。
outcome = buyer.VerifyArbitratedContent(ctx, buyer.ArbitratedContentCommand{
    Quote: verifiedQuote, Pool: buyerPoolCheckpoint,
    Request: authorizationCheckpoint,
    RetrievalRequestRaw: k10.Bytes(), RetrievalResponseRaw: answer.Bytes(),
    Seed: seedBytes,
})
```

关键边界：

- **nonce 由 SDK 生成且必须原样重放**。`RequestArbitratedContent` 的默认入口由 SDK 生成安全随机 nonce；网络超时重试必须原样重发已持久化的 exact Kind 10 Artifact，绝不能重新调用生成新 nonce。只有明确收到 not_ready 才换新 nonce 重新构造。
- **unavailable 是 typed 结果，不是 error**。`VerifyArbitratedContent` 返回的 Result 带 `Available=false` 与结构化 `UnavailableReason`；应用据此决定换新 nonce、等待或终止。
- **Claim ID 不是下载密码**。只提交 Claim ID 或只知道 URL 的请求没有 Buyer 签名，鉴权一律拒绝。
- **验收是时间无关的**。取件不重新执行 Quote 过期、delivery deadline 或 refund 未过期判断；这些门禁在 Arbiter 当初签署 Kind 9 之前已经执行过。
- **Kind 11 不声称链上结算**。它只证明 exact Kind 9 已由 Arbiter 签署并持久化；Seller 是否合并签名、广播或上链由 Seller 应用负责对账。
- nonce 不能代替传输的机密性/完整性/身份认证——生产必须使用 TLS 或等价安全通道。

输出说明：命令打印 Claim ID、不可交付原因码、Kind 10/11 尺寸、payload 数量与最终验证结果；不输出原始内容、私钥或完整可重放请求。

当 Seller 从未提交 007 时，Arbiter 没有可取回的内容：Buyer 只能继续尝试直连 Seller 或等待网络恢复，或在 refund locktime 到期后按 002 的预签名 RefundTx 广播退款（`buyer.BuildMaturedRefund`）。协议中没有 Buyer+Arbiter 关池路径。
