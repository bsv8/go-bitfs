# RefundTxHash 全角色归属、并发重放修复与最终验收记录

## 1. 状态与实施边界

状态：**通过最终验收**。

本记录承接 `001`—`004` 施工单，并取代它们对当前工作树的最终状态判断。协议仍为尚未上线前的 **v4 一次性硬切换**：不升级 v5，不增加 session 关联，不恢复 `SpendTxID`、旧 CBOR/CDDL、兼容别名或持久 presign reservation。

代码、测试和现有产品文档的修改全部由 `luna_worker` 子代理实施；根代理只负责设计、代码审查、实施退回、独立测试验收和本施工单回填。

## 2. 本轮 review 发现的问题

### 2.1 RefundTxHash 是路由键，不是角色授权

多个 Buyer 或 Seller workflow 共用同一 `PoolStore`/`PendingRequestStore` 时，部分后续入口仅按公开的 `RefundTxHash` 加载状态，没有在返回私有证据、签名、提交后端或释放租约前，确认 workflow signer 与 opening 中的 Buyer/Seller 角色一致。这会把关联 ID 误用为跨租户授权凭证。

受影响的高风险路径包括 Buyer 过期退款、立即关闭构建/提交、内容请求/接收，以及 Seller 已有预签重放、funding 接收、内容交付、付款幂等重试、关闭签名和仲裁构建/提交。仲裁人也必须在调用 signer 前与 opening 中的 Arbiter 公钥一致。

### 2.2 0202 并发首次接受可被合法进度打断

并发请求 A 已读取 pending 后，请求 B 可先保存完整 opening 和 sequence 2、删除 pending，然后业务继续推进到 sequence 3。A 恢复后再保存 sequence 2 会正确收到 `ErrStalePaymentSequence`，但旧路径会把合法并发成功报告为失败。

### 2.3 坏签名测试强度不足

原有坏 Seller 签名测试主要破坏 DER 结构，只能证明解析器拒绝非法字节，不能证明存储和重放路径会对“DER 完全合法、sighash flag 正确，但由错误私钥签署”的密码学无效签名执行真实验签。

### 2.4 首版并发测试存在假覆盖

`luna_worker` 首轮增加的同步钩子在底层 `LoadPendingPoolOpening` **之前**暂停。B 完成后 A 恢复只会读到 nil，直接走普通 replay，不会触发 stale-save 生产分支。根代理未放行该测试，并退回同一子代理重做。

## 3. 一次性修复设计

### 3.1 全角色 opening ownership

- Buyer 和 Seller workflow 分别提供统一 ownership helper：读取当前 signer 的规范压缩公钥，与 `OpeningProof.BuyerPubKey` 或 `OpeningProof.SellerPubKey` 比较。
- 所有加载 opening 的池操作，在私钥签名、后端提交、池状态修改、pending lease 释放或 Buyer 私有 FundingTx 返回前必须先通过 ownership。
- Seller 0201 预签在进入原子 `EnsurePresignedOpening`/builder 前，先把 signer 与 request 中 `SellerPubKey` 绑定。
- Arbiter 复用核心 signer-role 检查；错误仲裁签名器在 `Sign` 被调用前拒绝。
- 返回错误统一可被 `errors.Is(err, pool.ErrInvalidEvidence)` 识别，不泄漏或修改其他角色的池状态。

### 3.2 stale-save 精确收敛

`AcceptRefundPresign` 只在以下条件同时成立时，把初始状态保存的 `ErrStalePaymentSequence` 收敛为幂等 replay：

1. 本次保存初始 sequence 2 明确返回 stale；
2. 重新加载同一 `RefundTxHash` 的 pending 已为 nil；
3. completed proof、Seller 签名、Buyer ownership 和当前 accepted/arbitrated state 全部通过既有 replay 完整校验。

pending 仍存在、存储加载失败、proof 不完整或当前状态无效时，不能把 stale 吞成成功。Replay 只读，返回 opening 原始 `BasePaymentSequence == 2`，不覆盖已推进的 sequence 3+ 状态。

### 3.3 存储证据的密码学边界

- `EnsurePresignedOpening` 命中已有 presign proof 时，验证 request 全字段、规范 `RefundTxHash` 和 Seller detached signature；已含 FundingTx 时执行完整 `VerifyOpening`。
- `SaveOpeningProof` 和 FileStore snapshot 恢复使用相同的密码学边界。
- 存储中的坏 proof 统一拒绝，不调用 builder/signer，不自动覆盖或猜测修复。
- 测试使用错误 secp256k1 私钥对正确 sighash 签名，生成结构完整但密码学无效的 DER+flag 字节。

## 4. 明确不能做

- 不能把 `RefundTxHash`、HTTP request ID、WebSocket/MQ session 或数据库主键当作 Buyer/Seller/Arbiter 授权。
- 不能在 ownership 失败后调用 signer、节点后端、`Save*`/`Mark*`/`Reconcile*` 或 `PendingRequestStore.Release`。
- 不能对所有 `ErrStalePaymentSequence` 无条件返回 replay 成功；否则会隐藏未完成 opening、损坏状态或真实序号冲突。
- 不能在并发 replay 中重新保存 sequence 2、重建 pending 或回退当前付款状态。
- 不能只修改 DER 头/长度字节作为坏签名的唯一验收；必须包含可解析的错密钥签名。
- 不能让并发测试在真实读取 pending 之前暂停，也不能仅根据最终成功反推 stale 分支已覆盖。
- 不能修改 v4 版本、报文数组形状、`RefundTxHash` 计算真值或硬切换边界。

## 5. 特殊情况处理

- **共享存储中的错角色 workflow**：返回 `ErrInvalidEvidence`；不签名、不提交、不释放租约、不返回 FundingTx。
- **A/B 并发完成后已推进付款**：A 精确转为只读 replay，仍返回 base sequence 2，并保留最新 sequence。
- **A 保存 stale 但 pending 仍存在**：保持失败，不得猜测 B 已成功。
- **pending 已删但 proof/state 不完整**：按损坏或不完整证据拒绝，交给显式恢复/运维流程，SDK 不补写。
- **FileStore snapshot 中是可解析的错密钥签名**：`NewFileStore` 恢复立即失败，坏 proof 不进入索引。
- **signer 公钥读取失败**：传播可诊断错误，不降级为仅 hash 授权。
- **池已关闭或外部状态不确定**：继续使用现有 `EnsurePoolOpen/Healthy` 与 reconciliation 规则；ownership 通过不代表业务状态自动通过。

## 6. 文件级施工与核查结果

- `buyer/workflow.go`
  - 统一 Buyer opening ownership；覆盖首次/完成重放、FundingTx 交付、过期退款、立即关闭、内容请求和交付接受。
  - 初始状态 stale 后仅在 pending 已删时进入完整只读 replay。
- `buyer/workflow_pending_test.go`
  - 覆盖跨 Buyer replay/FundingTx 读取拒绝。
  - 并发钩子先真实读取并缓存非 nil pending，再暂停 A；可观测 store 断言 `SaveAcceptedPayment` 恰好一次 stale，无 sleep、无 goroutine 泄漏。
- `seller/workflow.go`
  - 统一 Seller request/opening ownership；覆盖预签、funding、交付、付款、立即关闭和仲裁入口，并放在签名/提交/状态或租约修改前。
- `arbitration/workflow.go`、`pool/multisigpool.go`、`pool/multisigpool_engine.go`
  - 仲裁人候选状态签名复用 role key 检查，错 signer 在实际 `Sign` 前拒绝。
- `pool/memory.go`、`pool/file_store.go`、`pool/opening_test.go`
  - 已有 presign/complete proof、普通保存和 FileStore 恢复的密码学检查一致。
  - 测试使用可解析的错密钥 Seller 签名，并证明坏记录不调用 builder。
- `integration/protocol_test.go`
  - 覆盖错 Arbiter 不签名，错 Buyer 不进后端，错 Seller 的预签/幂等付款/仲裁不签名、不提交、不释放 pending lease。
- `docs/complete-file-purchase/README.md`、`website/docs/sdk/*`、中文镜像、`website/api-translations.json`
  - 明确 `RefundTxHash` 仅用于路由/关联，角色授权必须来自 signer 与已验证 opening。
  - 保留 FileStore 建议性进程文件锁、非 Unix 快速失败和非 crash-safe exactly-once 边界。
- `spec/v4/*`、`wire/*`、各报文类型
  - 复核未因本轮修复改变 v4 常量、报文形状或 `RefundTxHash` 计算真值。

## 7. 实施迭代记录

1. 根代理将全角色 ownership、stale-save 竞态、真实坏签名和共享存储副作用测试一次性交给同一 `luna_worker`。
2. 子代理完成代码、测试和现有技术文档修改，并报告定向/全仓验收通过。
3. 根代理逐行审查时发现并发测试在真实 load 前暂停，属于假覆盖，因此退回同一子代理，没有以“测试绿色”直接放行。
4. 子代理改为先读并缓存 pending，增加 stale 次数可观测包装和恰好一次断言，再通过 count=100 和 race。
5. 根代理独立重复定向测试、全仓、race、vet、网站中英文构建、Windows 交叉编译、静态扫描与 diff 检查，全部通过。

## 8. 最终验收清单

### 8.1 功能、授权与副作用

- [x] Buyer 的所有池入口在签名、返回 FundingTx、提交或修改状态前验证 Buyer ownership。
- [x] Seller 的所有池入口在签名、提交、修改状态或释放 lease 前验证 Seller ownership。
- [x] 错误 Arbiter 的 signer 调用计数为 0。
- [x] 错 Buyer/Seller 共享 store 时返回 `ErrInvalidEvidence`，后端、store mutation、signer 和 lease release 计数不增加。
- [x] `RefundTxHash` 只是统一关联/路由 ID，文档不再将其表述为跨租户授权。

### 8.2 并发与幂等

- [x] 测试确定性构造 A 已读 pending、B 完成删除并推进 sequence 3、A 再保存 sequence 2 的交错。
- [x] 可观测 store 断言 A 恰好收到一次 `ErrStalePaymentSequence`，不是直接命中普通 replay。
- [x] A 最终成功返回 `BasePaymentSequence == 2`，存储中最新状态仍为 sequence 3。
- [x] pending 未删或 replay 证据无效时不吞掉 stale 错误。

### 8.3 密码学与持久化

- [x] MemoryStore 已有 presign 与 complete proof 都拒绝可解析的错 Seller 密钥签名，builder 不执行。
- [x] FileStore snapshot 恢复拒绝同类密码学无效签名。
- [x] signer-role 检查发生在私钥 `Sign` 调用前。
- [x] v4 常量、CBOR/CDDL 报文形状、FileStore schema 和 `RefundTxHash` 唯一计算真值保持不变。

### 8.4 根代理独立验收证据

以下命令均以退出码 0 完成：

```text
go test -mod=vendor -count=1 ./...
go test -race -mod=vendor -count=1 ./...
go vet -mod=vendor ./...

go test -mod=vendor -count=100 ./buyer \
  -run '^TestAcceptRefundPresignReplaysAfterConcurrentCompletionAndProgress$'
go test -race -mod=vendor -count=10 ./buyer \
  -run '^TestAcceptRefundPresignReplaysAfterConcurrentCompletionAndProgress$'

go test -mod=vendor -count=100 ./pool \
  -run '^(TestMemoryStoreRejectsInvalidExistingPresignWithoutBuilder|TestMemoryStoreRejectsInvalidExistingCompleteWithoutBuilder|TestFileStoreRejectsInvalidOpeningSignatureOnRestart)$'

go test -mod=vendor -count=25 ./integration \
  -run '^(TestWrongArbiterSignerDoesNotSignValidArbitrationEvidence|TestWrongBuyerCannotSubmitOrRefundSharedPool|TestWrongSellerPresignAndIdempotentPaymentCannotMutateSharedPool|TestWrongSellerCannotSubmitArbitratedPayment)$'

GOOS=windows GOARCH=amd64 go test -mod=vendor -run '^$' -c ./pool \
  -o /tmp/go-bitfs-pool-windows.test.exe
GOOS=windows GOARCH=amd64 go test -mod=vendor -run '^$' -c ./buyer \
  -o /tmp/go-bitfs-buyer-windows.test.exe
GOOS=windows GOARCH=amd64 go test -mod=vendor -run '^$' -c ./seller \
  -o /tmp/go-bitfs-seller-windows.test.exe

cd website && npm run check

git diff --check
git diff --cached --check
git diff HEAD --check
```

静态结果：

- 规定目录内 `SpendTxID|spendTxID|spend_txid|SPEND_TX_ID`：0 处；
- `ReservePresignEvidence|presignReservations|presign_reservations`：0 处；
- `wire.ProtocolFamily == "bitfs.protocol.v4"`，`pool.ProtocolFamily == "bitfs.pool.workflow.v4"`，pool/arbitration major 与 FileStore schema 均为 4；
- 网站英文和 `zh-CN` 均成功生成；
- 所有 worktree/index/HEAD diff whitespace 检查均通过。

## 9. 交付边界

最终结论：**没有已知阻断问题或验收错误**。

本轮未创建 Git commit，未回退或重排用户现有暂存选择。工作树同时包含原硬切换的已暂存内容和后续审查修复的未暂存内容；正式提交时必须以完整工作树为一个原子交付单位，不能只提交当前 index，否则会遗漏安全修复和最终测试。
