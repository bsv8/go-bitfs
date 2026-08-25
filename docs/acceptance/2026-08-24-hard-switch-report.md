# SDK 安全易用性与显式状态一次性硬切换——最终实施报告

- 施工单：`docs/施工单/2026-08-24/001-SDK安全易用性与显式状态一次性硬切换施工单.md`
- 基线提交：`95f5a90`（feat(protocol): 统一线协议为 v1）
- 状态：**已完成，待签收复核**

本报告对应施工单 §12.6 的签收证据要求。所有结论均可由仓库内测试与冻结
文件独立复现，不依赖实施者自述。

## 1. Wire 与交易 golden 新旧对照摘要

对照方法：在旧提交 `95f5a90` 的独立 worktree 上，用**旧 API 编写导出器**
（wire: `TestExportGoldenVectors`；pool: `TestExportTransactionVectors`），
输出与当前实现同 schema 的 name→hex 向量集；当前实现用新唯一主 API 的导出器
生成同名集合后逐键比对。

### 1.1 Wire 报文向量（13 组）

冻结文件：

- `wire/testdata/v1/legacy_95f5a90_export.json`（旧 API 导出）
- `wire/testdata/v1/current_export.json`（当前 API 导出）

覆盖：Kind 004 交付、005 授权子文档、007 request/claim/claim_id/receipt/response、
Kind 010 请求及子文档、Kind 11 unavailable/available。

常驻校验：`wire/golden_legacy_diff_test.go` 的
`TestLegacyExportMatchesCurrent` 每次运行实时重算当前实现全部向量，
并与两份冻结文件逐字节比对。结果：**13/13 逐字节一致**。
另有内联 golden（`wire/golden_messages_test.go`）对 Kind 004/005/007/008 的
exact hex、签名 digest、preimage、merged raw 全部 PASS。

### 1.2 交易向量（17 组）

冻结文件：

- `pool/testdata/v1/legacy_95f5a90_transactions.json`（旧 API 导出）
- `pool/testdata/v1/current_transactions.json`（当前 API 导出，含 4 组额外 txid 键的超集）

覆盖：refund_template(+txid)、opening 双签名、refund_merged、payment
unsigned/preimage/sighash_digest/buyer_signature/merged(+txid)、close
unsigned/merged(+txid)、arbitration candidate/preimage/digest/seller_signature/
merged(+txid)。

常驻校验：`pool/transaction_golden_manifest_test.go` 的
`TestLegacyTransactionExportMatchesCurrent` 实时重算并双向比对；
`TestTransactionGoldenManifestMatchesFrozenFile` 锁定机器可读 manifest
（`-update-*` flag 仅允许携带协议级证据时重建）。
结果：**17/17 同名键逐字节一致，diff 为空**。

### 1.3 结论

```
旧实现产生的 Kind bytes == 新实现产生的 Kind bytes   （13 组 + 内联 golden）
旧实现产生的交易 raw bytes == 新实现产生的交易 raw bytes（17 组）
旧实现使用的签名 digest == 新实现交给 Signer 的 digest （007 preimage/digest 向量）
```

`spec/v1/wire-messages.cddl` 在整个迭代中零结构 diff（git diff 为空）。

## 2. 公开 API 删除/新增清单

### 删除（不留转发包/alias/wrapper）

- 包：`bitfs/`（errors/protocol/signature 文件删除；DTO/编码迁入 `content/`）
- `wire.Packet`、`Marshal(kind, any)`、`Unmarshal(kind, any)` 及全部
  `Marshal*/Unmarshal*` 包装函数 → `Artifact` + `Parse/ParseAs` + typed codec
- 构造器：`buyer/seller/arbitration.WorkflowConfig{PrivateKey}`、`arbitration.NewWorkflow`
- 方法：`AcceptDelivery`、`BuildImmediateClose`、`BuildContentRequest`、
  `BuildRefundAfterExpiry`、`BuildArbitrationContentRequest`、`CompleteImmediateClose`、
  `PresignPoolOpening`、`AcceptPoolFunding`、`BuildContentDelivery`、`AcceptPayment`、
  `SignImmediateClose`、`PreparePayment`、`SignPreparedPayment`、
  `VerifySignedContentRequest(WithSeed)` 等
- 哨兵：`bitfs.ErrInvalidEvidence`、`pool.ErrInvalidEvidence/ErrStalePaymentSequence/
  ErrInsufficientBalance`、`arbitration.ErrContentUnavailable`（unavailable 改为 typed result）
- 隐藏时钟：`internal/protoclock` 整包删除；生产代码零 `time.Now()`
- 无验证构造：`NewVerified*` 全部私有化

### 新增

- `protocol`：Hash32/Digest32/PublicKey/Satoshis/BlockHeight/PaymentSequence/
  RetrievalNonce/RefundLockTime/SatoshisPerKilobyte；typed ID 文本前缀
  fq_/pa_/ac_/cr_/cp_（String/Parse/MarshalText）；`Facts`（RequireNow/
  RequireBlockHeight/CheckRefundNotExpired/CheckRefundMatured，按锁类型按需读取）；
  `Signer/SigningRequest/Purpose`；`PrivateKeySigner`；ErrorCode×13 + `Error`
  （errors.Is/As、CodeOf/IsCode）
- `content`：VerifiedQuote（唯一路径 `VerifyQuoteForBuyer`，Facts 门禁+归属绑定）
- `pool`：`VerifyOpeningProof/VerifyPaymentState/VerifySignedTransaction/
  VerifyRefundPresignRequestEvidence`；原子合并入口 `CompleteArbitratedTransaction`
  （双签验证→canonical 合并→Verified 构造一次完成）；adapters 持 `protocol.Signer`
- `arbiter`（新角色包）：`NewWorkflow(Signer)`、`PrepareArbitration(facts, rawKind8, fee)`、
  `SignPreparedArbitration`、`AuthenticateRetrieval`、`VerifyRetrievableCustody`、
  `BuildUnavailableRetrieval/BuildAvailableRetrieval`、`RestorePreparedArbitration`
- `buyer/seller`：§6.1/§6.2 目标方法全集（Command/Result/opaque checkpoint）、
  Restore 三入口（buyer）/三入口（seller），全部从 exact evidence 签名级重验
- `wire`：`Artifact`（字段私有、Bytes 复制）、`Parse/ParseAs`（全局大小门禁
  maxWireParseBytes 先于任何 CBOR 解码）、typed Encode×11 / Decode×11
- 取消语义：Signer 返回 canceled/deadline → `CodeCanceled`；仅托管故障 →
  `CodeSignerUnavailable`（普通消息与交易 sighash 双路径均覆盖并有测试）

## 3. 特殊情况矩阵与测试

| 特殊情况 | 测试 |
|---|---|
| HSM/KMS 故障、超时、canceled/deadline、错误公钥 | seller/restore_test `TestContextCancellationIsCanceledNotSignerUnavailable`（4 错误 × wire/交易双路径） |
| 过期前一秒/等于/后一秒 | buyer `TestAcceptQuote…`、seller CreateQuote 边界组 |
| Facts 按需读取（只有 Now / 只有 Height / 缺失拒绝） | buyer/facts_test 三测试；seller restore_test 同类 |
| 退款门禁稳定分类矩阵（事实缺失→invalid_evidence；真正成熟→expired；真正未成熟→not_matured，timestamp/height 双锁定） | protocol/facts_test `TestRefundGateClassificationMatrix`；入口层 buyer `TestRefundGateClassificationAtEntryPoints`、seller `TestSellerDeliverContentMissingHeightFactStaysInvalidEvidence`、arbiter `TestSignPreparedArbitrationMissingFactKeepsInvalidEvidence`（均以 CodeOf 精确断言）；integration error_boundary 对 refund 门禁路径精确断言 |
| 伪造数据无法获得 Verified | seller/restore_test `TestForgedEvidenceCannotBecomeVerified` |
| Restore 往返 + 篡改拒绝 | buyer `TestCheckpointRestore…`、seller `TestRestoreOpeningCheckpoint…/TestRestorePoolAndDelivery…`、arbiter `TestArbiterRestorePreparedArbitration` |
| valid Kind 11 unavailable = typed 结果 | buyer VerifyArbitratedContent、integration 008 分支 |
| Artifact 不可变/输入变异 | wire fuzz smoke + replay 断言 |
| 超大输入 | wire `TestParseRejectsOversizedInputBeforeDecoding` |
| 公开角色错误全分类 | integration/error_boundary_test（三角色全方法代表拒绝路径 + 领域验证入口，CodeOf 必须命中） |

## 4. 验收命令及退出码（本地复现记录）

| 命令 | 结果 |
|---|---|
| `gofmt -l .`(除 vendor) | 空 |
| `git diff --check` / `--cached --check` | 通过 |
| `go vet ./...` | 通过（0 问题） |
| `go test ./... -count=1` | 12 包 ok |
| `go test -race ./... -count=1` | 通过 |
| wire fuzz smoke ×3 | 通过 |
| Demo 01 / Demo 03–08 | 运行通过 |
| Demo 02 空状态离线冒烟（0201→0205，DEMO_02_OFFLINE=1） | 通过（`TestDemo02OfflineEmptyStateSmoke` 已纳入 CI） |
| `cd website && npm run build` | en + zh-CN 双语 SUCCESS |
| 中文字段 lint（8 包）/ terminology lint（含硬切换禁词与 workflow-held-private-key 模式） | PASS |

CI 变更（`.github/workflows/docs.yml`）：新增 race 步骤；demo 步骤扩展为
01 + Demo02 离线冒烟（go test 驱动）+ 03–08；文档禁词检查改由 Go lint 测试执行。

## 5. 当前文档旧术语扫描结果

- `TestCurrentDocumentsExcludeRetiredProtocol` PASS：当前代码/文档无旧 import、
  旧构造器、旧方法名、隐藏时钟、重复哨兵、`Marshal(any)`、workflow-held 私钥设计表述
- 非 legacy 网站/文档无 `bitfs.*` API 引用（仅剩 `ProtocolFamily` 协议标识字符串值，属协议真值非旧 API）
- `api-translations.json` 与生成 API 逐行同步（488 条），双语站点构建通过

## 6. 未完成项

零。第四轮复核阻断项已闭环：

- **文档残留旧调用**：role-workflow-api.md（英文源与中文页）的
  `PreparePoolOpening(ctx, facts, …)` 示例改为新签名；terminology lint 新增
  调用表达式负向规则（`PreparePoolOpening( ctx, facts,` 与
  `CompletePoolOpening( ctx,`，声明形态原有规则继续生效）；CI 文档门禁的
  `-run` 参数由逗号分隔（Go 视为普通字符导致 "no tests to run"、门禁空转）
  改为 `^(TestA|TestB)$` 正则分组
- **退款门禁错误分类被调用层覆盖**：新增 `protocol.WrapClassified`
  （链上已有分类原样透传，无分类才落 invalid_evidence；附加上下文一律 `%w`
  保持错误链），并替换全部无条件包装点——buyer RequestContent /
  VerifyDeliveryAndPreparePayment / PrepareClose / BuildMaturedRefund、
  seller refundGate（DeliverContent/CompletePayment/CompleteClose/
  PrepareArbitration 四入口，op 随入口透传）/ CompleteArbitratedPayment、
  arbiter PrepareArbitration / SignPreparedArbitration、pool
  CheckArbitrationRefundNotExpired。事实缺失现在稳定报 invalid_evidence，
  绝不被误报成 expired/not_matured
- 非阻断清理：`protocol.ProtocolFamily` 注释改为"外部协议族/manifest 标识"
  （wire 报文不携带族名称）；`signer_test` 删除重复 rotate、失败文本计数
  改为 want 2；终审建议两项——BindSigner(nil) 断言改为精确校验
  `CodeOf == signer_unavailable`，`IsCode` 注释改为"报告最外层稳定分类
  是否匹配"（errors.As 只命中链上第一个 *Error，非全链扫描）

第三轮复核补充项已闭环：

- **Prepare→Sign 退款锁重检**：SignPreparedArbitration 在任何 Signer 调用前
  从 freshClaim 重提取 locktime 并以显式 Facts 执行 CheckRefundNotExpired
  （timestamp/height 双覆盖）；跨边界拒绝时 Signer 调用次数为 0，Restore
  产物走同一门禁。测试：TestSignPreparedArbitrationRechecksRefundLockAfterPrepare
- **绑定公钥 Signer**：新增 protocol.BindSigner（构造时冻结公钥的包装器），
  三角色 Workflow 构造时统一绑定；远程托管中途换钥在所有 Kind 统一得到
  invalid_signature/unauthorized，Kind 1 不可能静默写入新身份。测试：
  TestWorkflowBindsSignerPublicKeyAcrossKinds（可轮换 fake Signer 覆盖
  Kind 1/5/6/10/11 与交易签名路径）
- 清理：PreparedAt 删除（观测元数据归应用）；buyer.PreparePoolOpening 去
  无效 facts、CompletePoolOpening 去无效 ctx、seller.PreparePoolOpening 去
  无效 facts；pool.Hash32 → protocol.Hash32 别名；删除 pool.ProtocolFamily
  （统一 protocol.ProtocolFamily）与未使用的 pool.Reference；low-S 注释修正；
  buyer/seller Result 类型统一为 PreparePoolOpeningResult；CI 新增 fuzz job
  （三个 target 各 30s）
- 第二轮复核补充项已闭环：

- Demo 02 离线冒烟使用 `DEMO_02_STATE_DIR` 指向 `t.TempDir` 的真空状态目录
  （测试前断言不存在、结束后断言三个 checkpoint 齐全且不含私钥材料），
  不再触碰仓库共享的 `demo/.state`；两个误暂存的运行产物已移出索引，
  `.gitignore` 追加 `**/demo/.state/`
- 新增文档签名一致性门禁 `docs/api_signature_lint_test.go`
  （TestRoleWorkflowAPIDocSignaturesMatchSource）：AST 提取三角色包全部
  导出方法/函数的类型序列，按包作用域与 role-workflow-api.md（英文源，
  中文页同步）逐符号比对，缺失或漂移即失败——本轮正是由它定位并修正了
  seller.PreparePoolOpening、arbiter Prepare/Sign 及 Restore 系列在文档中的过期签名

遗留说明两条（均非缺口）：

1. Demo 02 真实 JungleBus 资金路径需要链上 UTXO，属手工演示范畴；其自动化
   验收由离线空状态冒烟覆盖并在 CI 执行。
2. `PrivateKeySigner.Sign(_ context.Context, …)` 是接口实现中已文档化的
   "纯本地计算不消耗 ctx"约定，不属于被禁的"忽略 ctx 的公开入口"。
