# Go/TypeScript 双语言一致性审查收口施工单

## 1. 目标

本施工单处理双语言实现审查中的三个阻断项：TypeScript wire parser 的深层语义弱于
Go、TypeScript 缺少买方/卖方/仲裁方角色 API、共享无效真值不足。同时修复根
`fixtures/manifest.json` 未被 Go golden 测试实际消费，以及 CI 没有独立一致性门禁的问题。

唯一目标态是：Go 与 TypeScript 从同一根清单读取同一组 Wire v1、交易、transport
和无效输入真值；任一语言对同一输入出现接受/拒绝或错误分类漂移时，独立 CI job 阻断。

## 2. 授权修改范围

- `internal/conformance/`：根 fixture 清单解析；
- `wire/*_test.go`、`pool/*_test.go`：由根清单解析 golden 路径；
- `fixtures/invalid-wire-v1.json`：Kind 1–11 共用拒绝真值；
- `typescript/src/{wire,transaction,roles,index}.ts`：严格解析、Claim 结构验证和角色 API；
- `typescript/test/`、`typescript/README.md`、`typescript/package.json`：验收与中文字段说明；
- `.github/workflows/ci.yml`、`Makefile`：独立 conformance 入口；
- `pool/cbor.go`：补齐 Kind 7 零 ID 的结构化错误分类。

禁止修改 WireVersion、Kind 数值、CBOR 字段顺序、签名域、ID 算法、MultisigPool 交易
规则和现有 golden bytes。

## 3. 实现约束

1. Go golden 测试不得再自行硬编码主 manifest 路径；更新模式也必须写回根清单指向位置。
2. TypeScript `parse` 对 Kind 8 必须验证规范 2-of-3 角色脚本、三方角色顺序、退款模板
   的单输入三输出、空 unlocking script、funding output index、sequence、角色 P2PKH 输出、
   初始金额和余额边界，并验证买方 Kind 5 签名。
3. 零 ID、无效公钥、非法分支、非规范编码必须在两端产生同一稳定 `error_code`；测试不
   匹配语言相关错误文本。
4. 角色工作流固定 `Signer` 身份；应用显式提供时间事实；所有返回字节为副本。
5. `ArbiterWorkflow` 必须在 wire 结构验证之外继续验证卖方 Claim 签名、当前仲裁方身份
   和 payload/hash 一一绑定。

## 4. 验收矩阵

| 验收项 | Go | TypeScript | 失败门禁 |
|---|---|---|---|
| 根 fixture 清单解析 | `internal/conformance` | shared fixture test | conformance job |
| Kind 1–11 frozen bytes | golden manifest | `parseAs` | conformance job |
| Kind 1–11 无效深层字段 | `wire.Parse` | `parse` | 相同 `error_code` |
| 交易 raw/preimage/digest/txid | pool manifest | transaction + pool engine | conformance job |
| 角色验签与 payload 绑定 | Go 既有 workflow tests | 三角色 workflow test | language jobs |
| transport profile 与 framing | Go transport tests | bitcoin-libp2p stream test | conformance job |

最终必须通过 `gofmt`、`go vet ./...`、`go test ./...`、TypeScript typecheck/build/test、
`make conformance` 和 `npm pack --dry-run`。

## 5. 完工记录

- 根清单已成为 Go/TypeScript 实际路径真值，不再只是说明文件；
- 无效共享真值由 5 条扩展为覆盖外壳与 Kind 1–11 深层字段的 27 条；
- TypeScript 增加三角色工作流及中文字段说明；
- TypeScript Kind 8 增加退款交易/角色/买方签名深校验；
- CI 增加依赖两种语言基础 job 的独立跨语言一致性 job。

### 5.1 角色 API 安全复查追加收口

复查发现并已补齐以下角色层状态机门禁：

- Workflow 使用冻结公钥的 Signer 适配器，签名前后都复核底层 Signer 身份；换钥时在
  调用签名能力前失败；构造阶段同时拒绝长度错误、非法前缀和曲线外的压缩公钥；
- `SellerWorkflow.acceptFundingTransaction` 不再只比较关联 ID，而是重建退款模板并验证
  funding output[0] 金额/脚本、refund outpoint、fee rate 以及双方退款签名；
- 删除任意 `receiptCBOR` 直签 Kind 9 的入口，改为
  `prepareArbitration -> PreparedArbitration -> signPreparedArbitration`；签名前重新验证
  Kind 8、deadline、退款锁、candidate、费用、角色归属和 evidence commitment。

新增负向测试覆盖 Signer 换钥、伪造 funding raw 和伪造/跳过 PreparedArbitration；另有
成功路径测试证明合法 Prepare 可以生成 Kind 9。

### 5.2 仲裁 candidate 确定性重建追加收口

- `prepareArbitration` 不再接收调用方构造的 candidate；
- TypeScript 按 Go `BuildArbitrationPaymentFromClaim` 相同算法复制规范退款模板，只替换
  input sequence 与 Buyer/Seller/Arbiter 三个绝对金额；version、outpoint、角色脚本、
  nLockTime 和冻结矿工费均继承退款模板；
- `signPreparedArbitration` 在调用 Signer 前再次从冻结 Claim 重建 candidate，并要求与
  Prepare 快照逐字节相等；
- 共享交易真值测试断言内部重建结果与 `arbitration_candidate.raw_hex` 逐字节相等；
  修改 version 或 nLockTime 均返回 `state_conflict`，且 Signer 调用次数保持为 0。
