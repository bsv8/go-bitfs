# 跨语言签名向量（Go ⇄ TypeScript）

本目录承载施工单要求的 Go/TypeScript 共享签名向量，分两类：

1. **普通消息签名**：证明规范 CBOR 只做一次 SHA-256；
2. **MultisigPool v4 交易签名（`transaction_sighash_vector.json`）**：
   证明交易 sighash 是 `SHA-256d(BSV preimage)`（`ForkID|All`），
   ECDSA 直接对该摘要签名，绝不被普通消息路径二次哈希。

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

所有数值从固定 MultisigPool v4 fixture（角色私钥 `11…11`/`22…22`/`33…33`、
100000 satoshis、lockTime 500000100、费率 1 sat/KB）确定性派生：

```bash
go run -mod=vendor ./crosslang/gen-tx > crosslang/transaction_sighash_vector.json
```

## Go → TypeScript

```bash
node crosslang/verify-go-vector.mjs                 # 普通消息
node crosslang/verify-go-transaction-vector.mjs     # 交易 sighash（需要 npm ci）
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
计算摘要并直接 ECDSA 签名。Go 侧由 `crosslang/vector_test.go` 与
`crosslang/transaction_vector_test.go` 的固定验证入口复验。

## 回归测试

```bash
cd crosslang
npm ci
npm test          # Go→TS / TS→TS / fixture drift check（消息 + 交易）
cd ..
go test -mod=vendor -count=1 ./crosslang   # TS 签名 / Go 固定 verifier 验证
```

`npm test` 覆盖：Go message → TS verify、TS message → TS verify、两个
fixture 的 drift check（`--check` 只在内存比较，绝不写文件）、
Go transaction → TS verify、TS transaction → TS verify。
