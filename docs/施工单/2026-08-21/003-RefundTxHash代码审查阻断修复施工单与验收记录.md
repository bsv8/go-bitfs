# RefundTxHash 代码审查阻断修复施工单与验收记录

## 1. 状态与边界

状态：**通过最终验收**。

本施工单承接 `001-RefundTxHash统一关联ID一次性硬切换施工单.md` 和 `002-RefundTxHash实施修复与最终验收记录.md`。后续代码审查发现三项新的阻断问题，因此 `002` 中的“最终通过”结论由本记录取代；只有本记录的全部检查完成后，才能重新宣布通过。

协议边界不变：仍为尚未上线的 **v4 一次性硬切换**。不升级版本，不增加 session，不恢复 `SpendTxID`，不保留旧报文兼容分支，不恢复持久 presign reservation。

代码实施全部由 `luna_worker` 完成；根代理只负责设计、实施核查、测试验收和本施工单回填。

## 2. 修复缘由

### 2.1 Buyer 的 0202 成功响应不能真实重放

首次 `AcceptRefundPresign` 成功后会删除 0201 pending。相同 0202 响应再次到达，或 Buyer 重启后由对端重发时，当前实现因找不到 pending 而拒绝。网络重传、响应超时后的安全重试因此失效。

### 2.2 无效 Buyer 签名仍会触发 Seller 私钥签名

当前 Seller 路径先调用 Seller signer，再在构造 proof 时校验 `BuyerRefundSignature`。结构合法但 Buyer 签名损坏的请求仍会触发 HSM/私钥操作，违反“所有可在签名前验证的外部证据必须先验证”的边界，也放大昂贵 signer 和外部 HSM 的滥用面。

### 2.3 非 Unix 平台静默退化为无跨进程锁

FileStore 宣称同路径、多实例乃至多进程下 builder/signer 至多执行一次，但 `process_lock_other.go` 当前直接执行回调而不加锁。在 Windows 等非 Unix 构建上，该公开保证不成立，两个进程可能重复签名并覆盖快照。不能以平台 fallback 的名义静默降低安全语义。

## 3. 一次性硬切换设计

### 3.1 已完成 0202 的幂等重放

`AcceptRefundPresign` 保持两条明确路径：

1. pending 存在：执行首次接受流程，严格验证 response hash、request、Seller 签名、完整 proof 和初始状态，成功持久化后删除 pending。
2. pending 不存在：只允许进入“已完成结果核验”路径。按 `response.RefundTxHash` 加载完整 `OpeningProof`，从规范 RefundTx 重算 hash，要求响应签名与 proof 内 Seller 签名字节完全一致并且密码学验证通过；再加载该 hash 的已接受状态，确认其属于同一池且仍是合法的 accepted 或 arbitrated 状态。状态序号允许已继续推进，但返回值必须是打开池时的初始 `BasePaymentSequence`，不能冒充最新付款序号。

重放路径只读，不重写 proof、accepted state 或 pending。未知 hash、全零 hash、签名篡改、不完整 proof、错池状态、损坏状态均返回 `ErrInvalidEvidence` 或现有等价验证错误。

初始 sequence 必须从可信的 opening/refund 证据确定，不得从当前最新状态猜测。若已有数据不足以无歧义恢复，则拒绝重放，而不是返回可能错误的引用。

### 3.2 Seller 签名前验证

Pool 核心提供可复用的严格请求验证逻辑，统一完成：

1. v4、字段长度、三方角色、公钥和退款交易结构校验；
2. 从规范 RefundTx 派生唯一 `RefundTxHash`；
3. 校验退款金额、fee 和交易 terms；
4. 使用 Buyer 公钥校验 detached `BuyerRefundSignature`。

只有以上全部成功，`SignSellerRefund` 才能调用 Seller signer。`BuildOpeningProof`/proof 验证路径复用同一逻辑或其已验证结果，不能复制一套逐渐漂移的规则。无效 Buyer 签名必须满足：signer 调用计数为 0、store 无 proof/索引/快照变化，随后合法重试可成功且 signer 仅调用一次。

### 3.3 FileStore 平台保证

Unix 支持集合继续使用真实的进程文件锁。未提供等价跨进程锁的其他平台必须 **fail fast**，返回明确的 unsupported 错误；不能执行无锁回调。公开 Go doc、SDK 文档和 API 翻译应准确说明 FileStore 的平台约束、协作进程修改串行化和并发相同请求 builder 至多一次的适用范围，并明确它不提供跨崩溃的 signer exactly-once。

若选择支持 Windows，必须提供真正的 Windows 进程锁实现、错误传播和交叉编译/测试证据；仅让代码在 Windows 编译通过不等于实现了锁。对仍未实现锁的平台仍须 fail fast。

## 4. 明确不能做

- 不能依赖 TCP/WebSocket session、连接 ID、请求文件名或内存 map 来关联 0201 与 0202；唯一业务关联 ID 仍是 `RefundTxHash`。
- 不能在 pending 缺失时无条件视作重复成功；必须从持久化证据重新完成全部关联和签名验证。
- 不能以当前最新 `PaymentSequence` 作为 opening 的 `BasePaymentSequence` 返回。
- 不能为了重放重新创建 pending、重复保存 proof 或回退 accepted state。
- 不能先调用 Seller signer，再验证 Buyer 签名。
- 不能让签名前校验与 proof 校验维护两套不一致的交易规则。
- 不能在不支持文件锁的平台静默执行 FileStore 操作，也不能把进程内 mutex 描述成跨进程保证。
- 不能修改 v4 常量、CBOR 版本、报文元素数量或恢复新旧双轨。
- 不能修改用户现有暂存选择、创建提交或清理无关脏文件。

## 5. 特殊情况处理

- 相同 0202 并发重放：所有成功结果必须一致；允许一个首次路径和若干只读重放路径串行化，但不得产生第二份状态或回退状态。
- Buyer 在首次接受后崩溃：只要完整 proof 与 accepted state 已一致落盘，重启后相同响应应成功；若只落了一半，按损坏/不完整证据拒绝并交由既有恢复机制处理，不能猜测补写。
- 池已发生后续付款：相同 0202 仍可幂等返回 opening 引用，前提是当前状态仍属于该 `RefundTxHash` 且证据合法；返回 opening 初始 sequence。
- 池已仲裁：允许按现有 store 生命周期语义验证后返回原 opening 引用；不得把仲裁交易 ID 当作 `RefundTxHash`。
- 0202 hash 相同但签名字节不同：即使另一签名在密码学上也有效，仍按与已持久 proof 冲突拒绝，避免响应身份歧义。
- Seller signer/HSM 失败：原子 builder 回滚且不留 proof；合法请求可以重试。
- FileStore 运行于不支持的平台：初始化或首次受保护操作立即返回稳定且可诊断的 unsupported 错误，不允许无锁降级。

## 6. 文件级施工范围

- `buyer/workflow.go`
  - 增加无 pending 的已完成重放核验路径；保持首次接受路径和错误语义严格。
- `buyer/workflow_pending_test.go`
  - 覆盖首次成功后的即时重复、FileStore 重启重复、已推进状态重复、签名篡改、未知 hash、不完整证据及必要的并发场景。
- `pool/multisigpool_engine.go`
  - 抽取并复用退款请求与 Buyer detached signature 的签名前验证；保证 Seller signer 是最后一步。
- `seller/workflow.go`
  - 按核心验证 API 调整原子 builder 调用顺序，不绕过签名前验证。
- `seller/workflow_conflict_test.go`、`pool/opening_test.go` 或相应测试文件
  - 用计数 signer 证明损坏 Buyer 签名不触发 signer、不写 store，合法重试恰好签名一次。
- `pool/process_lock_other.go`
  - 删除无锁 fallback，改为明确 unsupported；如新增平台专用实现，必须使用互斥的 build tags。
- `pool/process_lock_unix.go`、`pool/file_store.go`、`pool/types.go`
  - 核查 build tags、错误传播和公开合同，确保实现与注释一致。
- `wire/wire.go`
  - 修正“每个 payload 显式携带 RefundTxHash”的不准确描述：0201 从规范 RefundTx 派生，0202 起的独立后续报文显式携带。
- `website/docs/sdk/*`、中文镜像、`website/api-translations.json` 和相关协议文档
  - 仅在公开 FileStore/重放合同受影响处同步，不引入版本变化或兼容叙述。

## 7. 最终验收清单

### 7.1 功能与安全

- [x] 首次 `AcceptRefundPresign` 成功后不重新插入 pending，立即重放同一 response 仍成功且返回相同 reference。
- [x] FileStore 关闭并重新打开后，无 pending 的相同 response 重放成功。
- [x] accepted state 已推进或按既有语义仲裁后，重放返回 opening 初始 sequence，而非最新 sequence。
- [x] 未知 hash、篡改 Seller 签名、不完整 proof、错池 state 全部拒绝且不写状态。
- [x] 损坏 Buyer 签名在 Seller signer 前被拒绝，signer 计数为 0，store 无变化。
- [x] 随后合法请求成功，signer 计数为 1；相同请求重试不再签名。
- [x] Unix FileStore 同路径、相同请求并发时 builder 至多执行一次的测试继续通过；不把该结果表述为跨崩溃 exactly-once。
- [x] 未实现真实进程锁的平台明确 fail fast，不存在无锁 fallback。
- [x] `MajorVersion`、各协议 family 和 FileStore schema 仍为 v4/4。

### 7.2 定向与全仓命令

```sh
gofmt -w <本轮由 luna_worker 修改的 Go 文件>

go test -mod=vendor -count=1 ./buyer ./seller ./pool
go test -race -mod=vendor -count=1 ./buyer ./seller ./pool

# 使用只编译不执行的方式验证 Windows build；输出必须位于 /tmp
GOOS=windows GOARCH=amd64 go test -mod=vendor -run '^$' -c ./pool -o /tmp/go-bitfs-pool-windows.test.exe

go test -mod=readonly -count=1 ./...
go test -mod=vendor -count=1 ./...
go test -race -mod=vendor -count=1 ./...
go vet -mod=vendor ./...

(
  cd website
  npm run check
)

git diff --check
git diff --cached --check
git diff HEAD --check
```

### 7.3 静态核查

- [x] `process_lock_other.go` 不再直接调用受保护回调。
- [x] 当前协议实现和文档无 `SpendTxID|spendTxID|spend_txid|SPEND_TX_ID` 残留。
- [x] 无 session 关联、持久 presign reservation 和旧报文兼容分支。
- [x] 0201 的描述为“由 RefundTx 派生 hash”，0202 及后续独立报文才显式携带 `RefundTxHash`。
- [x] 未跟踪生成 API、website build/node_modules 或 demo 运行态文件。

## 8. 实施与验收结果

### 8.1 实施结果

- 第一轮 `luna_worker` 完成三项代码修复：Buyer 无 pending 的只读 replay、Seller signer 前的 Buyer 签名校验、非 Unix FileStore 快速失败。
- 根代理第一轮复审未直接放行：指出缺少“合法已推进状态仍返回初始 sequence”的测试，以及手写 SDK 中英文文档仍无条件声明 FileStore 进程锁。
- 第二轮继续回派同一 `luna_worker`：使用真实 Buyer/Seller 签名合并 sequence 3 的完整付款状态，保存后重放原 0202 并断言 base sequence 仍为 2；同时补齐 Go doc、英文/中文 SDK 和完整购买文档的平台限制。
- Seller 请求验证收敛到核心共享逻辑。结构、角色、规范退款条款和 Buyer detached signature 全部验证成功后，才会调用 Seller signer；坏签名测试证明 signer 为 0 次且 store 无 proof，合法重试为 1 次。
- `process_lock_other.go` 不再调用传入 operation，统一返回 `ErrUnsupportedFileStorePlatform`；受支持 Unix build 继续使用 advisory process lock。Windows 的 pool、buyer、seller 均完成交叉编译验证。
- `wire.Kind`/`Packet` 文档已纠正：0201 从 RefundTx 派生关联 ID，不重复编码 hash；定义该字段的 0202 及后续独立报文显式携带 `RefundTxHash`。

### 8.2 根代理独立验收证据

以下命令均以退出码 0 完成：

```text
go test -mod=readonly -count=1 ./...
go test -mod=vendor -count=1 ./...
go test -race -mod=vendor -count=1 ./...
go vet -mod=vendor ./...

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

go test -mod=vendor -count=100 ./buyer \
  -run 'TestAcceptRefundPresign(RecoversOnlyFromResponseHash|ReplaysAfterFileStoreRestart)$'
go test -mod=vendor -count=100 ./seller \
  -run 'TestPresignPoolOpening(ConcurrentConflictNeverSignsTwice|ConcurrentAcrossFileStoreInstances|SameRequestAcrossFileStoreInstancesBuildsOnce|RejectsInvalidBuyerRefundSignatureBeforeSigning)$'
```

静态结果：

- 规定范围内旧 `SpendTxID` 命名：0 处；
- `ReservePresignEvidence|presignReservations|presign_reservations`：0 处；
- Git 跟踪的 generated-api、website build/node_modules、生成中文 API、demo state：0 个；
- `pool.MajorVersion`、`arbitration.MajorVersion`、pool/wire protocol family、Multisig 和 FileStore schema 均保持 v4/4；
- session 的扫描命中仅为“无 session 语义/不能只依赖 session”的禁止性文档，不存在 session 关联实现。

### 8.3 交付边界

最终结论：**没有已知阻断问题或验收错误**。

本轮未创建 Git commit，也未改变用户已有暂存选择。工作树仍同时包含已暂存的原硬切换以及未暂存的后续修复；正式提交必须包含完整工作树，不能只提交当前 index，否则会漏掉本轮安全修复。网站检查生成的 API/build 产物仍按仓库规则忽略，未进入 Git 跟踪。
