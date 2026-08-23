# 008：买方仲裁托管内容取回

这一步演示 Seller 与 Buyer 无法直连、但二者均能连接 Arbiter 时，Buyer 如何用自己可独立计算的 `ArbitrationClaimID` 从 Arbiter 取回已托管的精确内容：Arbiter 返回内嵌 exact Kind 8/9 的四元 Kind 11，Buyer 完整验收后保存 payload。

go-bitfs SDK 无状态：workflow 只持有官方 BSV 私钥。托管记录、nonce 占用表和传输全部由本 demo（调用方应用）实现；SDK 不查数据库、不生成 nonce、不记录下载次数。本 demo 不产生 005、不演示 Buyer 关池、不广播任何交易。

运行：

```sh
go run ./demo/08_arbitration_content_retrieval/01_retrieve_content
```

核心调用顺序是：

```text
// 应用侧（一次性）：Seller 托管 + Arbiter 签署（复用 007）
arbitrationRequest = seller.BuildArbitrationRequest(opening, signed003, delivery, blockHeight)
persist(exact Kind 8, Claim ID, payload, frozen fee)
arbitrationResponse = arbiter.SignPreparedPayment(prepared)
persist(exact canonical Kind 9)          // 此后记录才进入 Retrievable

// Buyer 取件
nonce = crypto/rand(32 bytes)            // 应用生成；SDK 不产生 nonce
retrievalRequest = buyer.BuildArbitrationContentRequest(opening, signed003, nonce)
persist(exact Kind 10 before send)
rawKind11 = app.handleContentRetrieval(marshal(kind10), arbiter)
result = buyer.AcceptArbitratedContent(
    quote, opening, previous, signed003, kind10, kind11, {seed})
persist(exact Kind 11 and payloads)      // 验收后保存
```

应用侧 `handleContentRetrieval` 的固定顺序：

```text
strict decode Kind 10
→ 按 Claim ID 查 custody record          // 查不到 → NotFound
→ 要求 exact Kind 8 + exact Kind 9 都已持久化   // 缺 Kind 9 → NotReady
→ SDK 完整验证存储证据与 Buyer 签名       // 失败 → Unauthorized（统一语义）
→ 原子占用 unique(ClaimID, Nonce)        // 已占用 → NonceReused
→ 构造 Kind 11，内嵌已保存 exact Kind 8/9 原文
```

关键边界：

- **Claim ID 不是下载密码**。只提交 Claim ID 或只知道 URL 的请求没有 Buyer 签名，一律 `Unauthorized`。
- **nonce 不是 TLS**。同一 `(ClaimID, Nonce)` 只能成功占用一次；请求超时后 Buyer 必须用新 nonce 重新签名重试。nonce 不能代替传输的机密性/完整性/身份认证——生产必须使用 TLS 或等价安全通道。
- **retention 属于应用**。留存期内允许 Buyer 用新 nonce 重复下载；留存期结束并安全删除后返回 `Gone`，且 nonce 去重记录至少保留到记录删除。
- **验收是时间无关的**。取件不重新执行 Quote 过期、delivery deadline 或 refund 未过期判断；这些门禁在 Arbiter 当初签署 Kind 9 之前已经执行过。
- **Kind 11 不声称链上结算**。它只证明 exact Kind 9 已由 Arbiter 签署并持久化；Seller 是否合并签名、广播或上链由 Seller 应用负责对账。

输出说明：命令打印 Claim ID、nonce hex、Kind 10/11 尺寸、payload 数量与最终验证结果；不输出原始内容、私钥或完整可重放请求。

当 Seller 从未提交 007 时，Arbiter 没有可取回的内容：Buyer 只能继续尝试直连 Seller 或等待网络恢复，或在 refund locktime 到期后按 002 的预签名 RefundTx 广播退款。协议中没有 Buyer+Arbiter 关池路径。
