---
id: 008-buyer-arbitrated-content-retrieval-requirements
title: 008 · 买方仲裁托管内容取回需求
---

# 008 · 买方仲裁托管内容取回需求

## 业务目标

Seller 与 Buyer 无法直连、但二者均能连接 Arbiter 时，Buyer 必须能恢复一次已完成 007 仲裁的精确托管内容，而不是每个应用自定一套下载 token 或 HTTP 字段。取件链是简单且可离线验证的：

```text
Buyer 原始 OpeningProof + Buyer 原始 signed 003
  -> 独立构造与 Seller 相同的 exact ClaimCBOR
  -> ArbitrationClaimID
  -> content_retrieval_request_cbor = [arbitration_claim_id, retrieval_nonce]
     经统一 SignWireDocument(1, 10, ...) 签名
  -> Arbiter 按 Claim ID 查托管并完整验证
  -> Buyer 独立验证 Arbiter 签名的 Kind 11 结果与 payload
```

## 硬边界

协议 **MUST NOT 提供 Buyer 仲裁关池**。不存在 Buyer+Arbiter 关池 candidate、挑战期、快速退款，也不存在"仲裁方查不到 Seller Claim 就替 Buyer 花费池输出"的规则。Seller 失联或拒绝协商时，Buyer 等 `nLockTime` 成熟后广播 002 的预签名 RefundTx。当前真值保持不变：协商关池走 006，或到期后广播退款。

## SDK 职责

SDK MUST：

- 通过 Seller 007 与 Buyer 008 共用的唯一 builder 构造 ClaimCBOR/ArbitrationClaimID；
- 用 strict deterministic CBOR 编解码 Kind 10/11，并使用派生尺寸上限（Kind 10 为 334 字节；Kind 11 按分支派生）；
- 以统一 `SignWireDocument(1, 10, ...)` 语义签署 `content_retrieval_request_cbor = [arbitration_claim_id, retrieval_nonce]` 并立即自验；
- 不读任何时钟地验证存储 Kind 8/9 证据链：两份子签名、Kind 10 / Kind 8 / Kind 9 三方 ArbitrationClaimID 一致、payload 数量/顺序/hash，以及重建 candidate 后的 Arbiter 交易签名；
- 要求 Kind 10 请求绑定本地重建的 ArbitrationClaimID，并携带本买方对 exact 请求文档的统一签名——不需要也不信任任何内嵌 Claim 字节；
- 验收时复核 payload membership、协议长度、聚合定价与 previous 连续性；
- 只返回深拷贝结果。

SDK MUST NOT 新增 Store/Repository/HTTP client/server/nonce cache/random source/clock injection/node/broadcaster/retention scheduler。

## 应用职责

应用 MUST：

- 按公钥找到可连接的仲裁 endpoint；
- 用密码学安全随机源生成 32 字节 nonce；
- 发送前持久化 exact Kind 10，验收后持久化 exact Kind 11 和 payload；
- 按 Claim ID 查托管库，并要求 exact Kind 8 与 exact Kind 9 同时存在（只有 Kind 8 的 `CustodyPrepared` 记录在完成 Buyer 鉴权后回答签名的 not_ready 分支）;
- 在验签成功之后原子占用 unique (Claim ID, Nonce)——数据库唯一键、事务/CAS 或等价机制——保证验签失败的请求不污染 nonce 表；not_ready 与 custody_gone 分支与 available 分支一样占用 nonce；
- 按 content_retrieval_request_id 持久化首次签署的 Kind 11 并在重放时原样重发：已捕获的 not_ready 请求在记录就绪后绝不能升级为 available 授权——Buyer 必须换新 nonce 重试；
- 把 `seller_arbitration_not_received` 作为唯一明确例外：没有 Claim 就无法鉴权 Buyer，该应答不占用 nonce、不持久化，但 endpoint 必须限流且不得返回任何记录元数据；
- 用 TLS 或等价安全传输保护请求与响应；nonce 不能代替机密性；
- 定义并公开 retention 策略：留存期内允许 Buyer 用新 nonce 重复下载；留存期结束并安全删除后由签名的 custody_gone 分支应答——缓存的首次应答与内容一起删除；
- nonce 去重记录至少保留到对应 custody record 删除，防止旧签名恢复可重放；
- 日志不写原始 payload、私钥或完整可重放请求；审计日志只使用 Claim ID / nonce hash 与状态。

## 重试语义

- nonce 是单次请求的重放键，不是长期 token。
- Arbiter 在 Buyer 鉴权通过后为 `not_ready`、`custody_gone`、`available` 原子占用 (Claim ID, Nonce)，并把首次签署的 Kind 11 持久化为该请求的唯一答案。
- 同一 content_retrieval_request_id 重放逐字节返回第一份持久化响应；状态变化绝不升级或重新评估它。
- 网络超时或响应未收完时，Buyer 优先**重发相同 exact Kind 10**：幂等重放会逐字节返回首次持久化的 Kind 11。只有明确收到 `not_ready` 应答后，Buyer 才生成新 nonce 和新 Kind 10 签名重试；Arbiter 绝不把旧 nonce 升级为新内容。
- 并发的相同 (Claim ID, Nonce) 在同一原子提交内由唯一键裁决唯一胜者；其余并发败者读取并返回胜者持久化的 exact Kind 11——对 Buyer 而言与首次响应完全一致，没有任何瞬态占用错误。
- 过期 Quote/deadline/refund 不拒绝已签证据：时间门禁在签署 Kind 9 之前已经执行。
- 内容保存失败不得标记批次完成；Buyer 重发相同 exact Kind 10（幂等重放取回已持久化的 Kind 11）直到自身原子保存成功。

## 验收清单

- [ ] 只有 exact Kind 8 + exact Kind 9 都已持久化的记录可以返回 payload。
- [ ] Claim ID 只是路由键；不匹配的 Kind 10 Claim ID 按无效证据拒绝，绝不做模糊查找。
- [ ] 每次取件都携带有效 Buyer 签名，密钥从存储 Claim 恢复。
- [ ] 仅凭 Claim ID 授权不了任何下载。
- [ ] available 附件经 content_payloads_id 绑定验证过的证据 bundle；payload 只出现一份，没有第二份 Receipt 拷贝。
- [ ] 重放的请求在所有分支下都逐字节返回其首次持久化的 Kind 11。
- [ ] 整条路径没有 005、没有关池交易、没有任何广播副作用。
