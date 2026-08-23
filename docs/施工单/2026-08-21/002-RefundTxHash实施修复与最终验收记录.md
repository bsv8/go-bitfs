# RefundTxHash 实施修复与最终验收记录

## 1. 施工目的

本记录承接 `001-RefundTxHash统一关联ID一次性硬切换施工单.md`，用于收口实施检查中发现的最后一组阻断问题，并记录最终验收证据。

协议仍为一次性 v4 硬切换，不增加 v5，不恢复 `SpendTxID`、旧 CBOR、旧 JSON、session 关联或兼容分支。

## 2. 本轮阻断问题

此前 Seller 的处理顺序为独立的 `LoadOpeningProof -> SignSellerRefund -> SaveOpeningProof`。串行冲突虽然能够在签名前发现，但两个线程或两个共享同一 FileStore 的进程仍可能同时观察到“尚无 proof”，随后同时调用 signer。这是逻辑 TOCTOU；Go race detector 不一定报告。

后续增加的持久 `presignReservations` 能阻止不同证据并发签名，但存在以下未收口语义：

- 完全相同请求并发时，多个调用方都可能得到“已预留但无 proof”的结果并重复签名；随机化但有效的 ECDSA 签名可能让第二次保存变成冲突。
- signer 或进程在预留后失败时，持久 reservation 缺少明确的 owner、租期和接管协议，可能永久阻塞或只能以重复签名方式恢复。
- `ReservePresignEvidence` 遇到已有 proof 时没有在 store 层完成证据比较；`SaveOpeningProof` 删除 reservation 前也没有强制比较 reservation 与 proof。

## 3. 最终设计

不保留持久 presign reservation。PoolStore 提供单个原子“确保预签 proof”操作，其原子区间固定为：

1. 严格验证 RefundPresignRequest，并从规范 RefundTx 派生 RefundTxHash；
2. 在 MemoryStore mutex 内；FileStore 还必须在同一个进程文件锁和快照事务内执行后续步骤；
3. 若已有 OpeningProof：逐字段比较 request 的 RefundTx、三方公钥、fee、buyer signature 和版本；完全一致则返回深复制，不同则 `ErrInvalidEvidence`；
4. 若无 proof：只调用一次由 Seller workflow 提供的 builder；builder 内完成 engine 构造、Seller 签名和 presign-form OpeningProof 构造；
5. 重新验证 builder 返回 proof 的规范 hash 和全部 presign evidence；
6. 检查 RefundTxHash 主索引与 FundingTxID 次级索引冲突；
7. 全部通过后同时写入索引；FileStore 原子刷新快照；
8. builder、验证或刷新失败时不得留下 proof、索引或中间 reservation。

该操作可以在持锁期间调用外部 signer。代价是同一 FileStore 的其他写操作在 signer 返回前等待；它保证协作进程的修改串行化，以及完全相同请求并发时 builder 至多执行一次。它不提供跨崩溃的 signer exactly-once：进程若在签名完成后、快照持久化前崩溃，重试仍可能再次调用 signer。context 取消和 signer 错误必须正常释放锁，后续相同请求可以重试。

## 4. 明确不能做

- 不能只在 Seller Workflow 增加进程内 mutex；它无法保护两个 FileStore 实例或两个进程。
- 不能用 session、连接 ID、请求文件名作为锁键或 pool ID。
- 不能让 store 只返回已有 proof 而不比较 request evidence。
- 不能在持有 MemoryStore mutex 的 builder 内再次调用公开 `SaveOpeningProof`，否则会重入死锁。
- 不能在失败后保留没有 owner/租期/接管规则的持久 reservation。
- 不能在主索引写入后才检查次级索引；失败必须零状态变化。
- 不能改变 v4 版本、CDDL 报文或 OpeningProof 九元素编码。

## 5. 文件级责任

- `pool/types.go`
  - 定义原子 builder 类型和 PoolStore 原子方法；删除 reservation API。
- `pool/memory.go`
  - 实现单 mutex 原子比较、builder、验证与双索引写入；删除 reservation map。
- `pool/file_store.go`
  - 在单次进程锁/快照事务中委托 MemoryStore 原子操作；删除 reservation JSON/snapshot/restore。
- `seller/workflow.go`
  - 将签名和 proof 构造放入 store builder；响应使用 store 最终返回 proof。
- `pool/*test.go`、`seller/workflow_conflict_test.go`
  - 覆盖相同/冲突请求的线程与跨 FileStore 并发、builder 失败重试、错 proof 零状态变化。
- `integration/two_pools_test.go`、`wire/wire_pool_test.go`
  - 保留两池乱序/互换和 002/004/005/007 typed wire 验收。
- `website/api-translations.json`
  - 同步最终公开 Go doc，删除 reservation 当前 API 文案。

## 6. 最终验收清单

### 6.1 原子性与幂等

- [x] MemoryStore 相同请求并发：builder/signer 恰好一次，两次调用都成功且返回相同 proof/response。
- [x] 两个共享同一路径的 FileStore 相同请求并发：builder/signer 恰好一次。
- [x] 同 hash 不同证据并发：只有胜者可进入 signer，败者为 `ErrInvalidEvidence`。
- [x] signer/builder 首次失败：store 零变化；相同请求随后可成功重试。
- [x] 已有 proof 与请求冲突：store 层在 builder 前拒绝。
- [x] builder 返回错 proof：主索引、次级索引和磁盘快照均不改变。
- [x] 相同已完成请求重试：不重新签名，返回已保存签名。

### 6.2 原施工单总验收

- [x] v4 常量、CDDL 数组长度、RefundTxHash 唯一计算真值保持不变。
- [x] 当前代码/文档无旧 `SpendTxID`、`spend_txid` 和旧 demo 标签。
- [x] 全零/短/长 hash、旧 CBOR 数组和旧 JSON key 严格拒绝。
- [x] 0201 pending、0202/0203 hash 关联、Funding delivery、004、005、007 交叉校验全部保留。
- [x] 两池响应逆序、Funding delivery 乱序/互换、004/005/007 跨池证据互换测试通过。
- [x] 当前英文/中文文档、demo README、SDK 页和 API 翻译一致。
- [x] 生成 API/build/node_modules 未被 Git 跟踪。

### 6.3 命令

```sh
go test -mod=readonly -count=1 ./...
go test -mod=vendor -count=1 ./...
go test -race -mod=vendor -count=1 ./...
go vet -mod=vendor ./...

(
  cd website
  npm run check
)

git diff --check

rg -n 'SpendTxID|spendTxID|spend_txid|SPEND_TX_ID' \
  arbitration bitfs buyer demo integration pool seller wire spec/v4 \
  docs/complete-file-purchase website/docs/protocol website/docs/sdk \
  website/i18n/zh-CN/docusaurus-plugin-content-docs/current/protocol \
  website/i18n/zh-CN/docusaurus-plugin-content-docs/current/sdk \
  website/api-translations.json
```

## 7. 实施与验收结果

状态：**通过**。截至 2026-08-21，未发现阻断问题或已知验收错误。

### 7.1 实施结果

- `luna_worker` 将 Seller 预签路径收敛到 `PoolStore.EnsurePresignedOpening`；根代理仅负责设计复审、逐项验收和本记录回填。
- MemoryStore 在单一互斥区内完成已有证据比较、builder 调用、返回 proof 验证和双索引写入；失败不留中间状态。
- FileStore 在同一实例锁、跨进程文件锁和快照事务内执行上述原子操作；builder、验证或刷盘失败均回滚内存快照。
- 新 builder 只能返回 `FundingTx == nil` 的 presign-form proof；提前携带完整 FundingTx 会以 `ErrInvalidEvidence` 拒绝。已有且已升级为完整 proof 的相同请求仍可幂等重放。
- Seller signer 首次失败后不会留下 proof；清除故障后相同请求可立即重试，成功后的再次重放不重新签名。
- 删除了临时 reservation API、内存字段和 JSON 状态；没有 owner/租期的持久预留不会进入最终设计。
- 补齐同请求/冲突请求的线程与双 FileStore 并发、主/次索引与磁盘零残留、004/005/007 旧数组拒绝测试，并同步英文/中文 SDK 接口文档和 demo 说明。

### 7.2 最终验收证据

以下命令均以退出码 0 完成：

```text
go test -mod=readonly -count=1 ./...
go test -mod=vendor -count=1 ./...
go test -race -mod=vendor -count=1 ./...
go vet -mod=vendor ./...
cd website && npm run check
git diff --check
git diff --cached --check
git diff HEAD --check
```

静态检查结果：

- 当前验收目录中的 `SpendTxID|spendTxID|spend_txid|SPEND_TX_ID`：0 处；
- `ReservePresignEvidence|presignReservations|presign_reservations`：0 处；
- Git 跟踪的 website API/build/node_modules、生成中文 API 和 demo state：0 个；
- `ProtocolFamily`、pool/arbitration/content major 和 FileStore schema 仍为 v4/4。

### 7.3 交付边界

本轮未创建 Git commit，也未改变用户已有的暂存选择。当前索引和工作树之间仍有本次后续补修差异；正式提交时必须把完整工作树作为一个提交/PR 纳入，不能只提交当前暂存区，否则会遗漏原子预签修复与最终测试。
