# 跨语言签名向量（Go ⇄ TypeScript）

本目录承载施工单要求的 Go/TypeScript 共享签名向量，分三类：

1. **普通消息签名**：证明规范 CBOR 只做一次 SHA-256；
2. **MultisigPool v4 交易签名（`transaction_sighash_vector.json`）**：
   规范退款模板（费用池关联 ID 源）——证明交易 sighash 是
   `SHA-256d(BSV preimage)`（`ForkID|All`），ECDSA 直接对该摘要签名，
   绝不被普通消息路径二次哈希；
3. **真实的 005 累计付款状态交易（`payment_state_sighash_vector.json`）**：
   由 OpeningProof、previous PaymentState、目标 sequence/amount 经唯一的
   `BuildPaymentUpdate` 确定性重建。它按 `[Buyer, Seller, Arbiter]` 三输出
   分配并携带本轮 `PaymentSequence`，与退款模板共用同一费用池来源但**不是
   同一笔交易**，不能互换或复用签名。005 wire 不携带 raw，确定性重建是删除
   wire raw 的互操作前提。

## 真值

```
digest   = SHA-256(canonical CBOR)          —— 恰好一次
signature = ECDSA(secp256k1, digest), low-S DER
pubkey   = 33 字节压缩公钥，由签名私钥派生
```

交易向量额外包含：

```
unsignedTxHex            规范未签名 MultisigPool 状态交易（单输入）
inputIndex               0
sourceSatoshis           资金池输出金额
sourceLockingScriptHex   资金池 2-of-3 锁定脚本
sighashFlag              65 (ForkID|All)
preimageHex              BSV replay-protected preimage
sighashDigestHex         SHA-256d(preimage)
goDerSignatureHex        Go 买方角色交易签名（DER，不含 flag 字节）
tsDerSignatureHex        TS 买方角色交易签名（DER，不含 flag 字节）
buyer/seller/arbiterPubkeyHex  三个角色公钥
```

005 payment state 向量再额外包含：

```
previousRawTxHex         初始退款状态（重建上下文）
targetPaymentSequence    本轮目标序号
sellerAmountAfterSat     目标绝对累计卖方金额
expectedUnsignedRawHex   BuildPaymentUpdate 冻结的未签名状态交易原文
mergedRawTxHex           Buyer+Seller 合并后的完整交易原文
```

所有数值从固定 MultisigPool v4 fixture（角色私钥 `11…11`/`22…22`/`33…33`、
100000 satoshis、lockTime 500000100、费率 1 sat/KB）确定性派生：

```bash
# 从仓库根目录执行；生成器直接写文件，绝不重定向标准输出。
go run -mod=vendor ./crosslang/gen-tx --out-dir crosslang

# CI 漂移检查：只在内存中重算并与已提交 fixture 比较，不写任何文件。
go run -mod=vendor ./crosslang/gen-tx --out-dir crosslang --check
```

## Go → TypeScript

```bash
node crosslang/verify-go-vector.mjs                     # 普通消息
node crosslang/verify-go-transaction-vector.mjs          # 退款模板 sighash（需要 npm ci）
node crosslang/verify-ts-payment-state-vector.mjs        # 005 payment state sighash
```

Go 侧 `(*ec.PrivateKey).Sign(digest)` 只接收已算好的摘要；TS 侧验证脚本用
`@bsv/sdk` 官方路径重算 preimage 与 `SHA-256d` 摘要后逐字节比较，再用
`ECDSA.verify` 验证 Go DER。**禁止**在 TS 里对 raw tx 或 digest 再调用
`PrivateKey.sign(message)`——该方法会对输入自行做一次 SHA-256，造成双哈希。

## TypeScript → Go

消息向量：TS 侧 `generate-ts-vector.mjs` 用
`new PrivateKey(...).sign(canonicalCBORBytes)` 生成 DER 写入同结构 JSON。
交易向量：TS 侧 `generate-ts-transaction-vector.mjs` 解析同一份 raw tx，
挂上同一 source output，经官方 `Transaction.preimage` + `SHA-256d`
计算摘要并直接 ECDSA 签名。005 向量：TS 侧
`generate-ts-payment-state-vector.mjs` 对冻结的 expected unsigned raw 做
同样的 preimage/摘要计算与 Buyer 签名。
Go 侧由 `crosslang/vector_test.go` 与 `crosslang/transaction_vector_test.go`
的固定验证入口复验。

### 互操作承诺边界（重要）

当前 TypeScript 侧**没有**完整的 `BuildPaymentUpdate` 等价实现：上述 005
payment state 向量证明的是"TS 能对 Go 重建出的精确状态交易计算相同
preimage/sighash 并互相验证 DER"，而**不是**"TS 能从 OpeningProof、
previous、sequence、amount 独立重建出相同交易"。因此 v4 005 目前只承诺
**Go 实现互操作**：TS 客户端在补齐等价构造并通过本目录向量之前不得发布，
也不允许把 TS 自己提供的 raw 当作隐藏兼容路径塞回 005。

## 回归测试

```bash
cd crosslang
npm ci
npm test          # Go→TS / TS→TS / fixture drift check（消息 + 交易 + 005 payment state）
cd ..
go test -mod=vendor -count=1 ./crosslang   # TS 签名 / Go 固定 verifier 验证 / 重建一致性
```

`npm test` 覆盖：Go message → TS verify、TS message → TS verify、全部
fixture 的 drift check（`--check` 只在内存比较，绝不写文件）、
Go transaction → TS verify、TS transaction → TS verify、以及
Go 005 payment state → TS verify。
