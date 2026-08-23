# RefundTxHash 再次代码审查修复与验收记录

## 1. 状态与范围

历史状态：**已由 `005-RefundTxHash全角色归属并发重放修复与最终验收记录.md` 取代**。`004` 保留当时的审查与验收证据，不再代表当前工作树的最终状态。

本记录承接 `001-RefundTxHash统一关联ID一次性硬切换施工单.md`、`002-RefundTxHash实施修复与最终验收记录.md` 和 `003-RefundTxHash代码审查阻断修复施工单与验收记录.md`，记录再次 review 发现的问题、实施边界和最终验收证据。本记录取代此前记录中的最终状态判断。

协议仍为尚未上线的 v4 一次性硬切换：不升级版本，不恢复 `SpendTxID`，不增加 session 关联、旧报文兼容分支或持久 presign reservation。

代码、测试和现有产品文档的修改全部由 `luna_worker` 完成；根代理只负责设计、逐轮实施核查、独立验收和本施工单回填。

## 2. 再次 review 发现的问题

### 2.1 Seller 会重放存储中的无效签名

`EnsurePresignedOpening` 命中已有 proof 时只比较请求字段，没有重新验证 `SellerRefundSignature`；通用 `SaveOpeningProof` 和 FileStore snapshot 恢复又只做结构校验。因此，结构合法但密码学无效的签名可能成为该 `RefundTxHash` 的持久坏记录，Seller 随后不再调用 builder/signer，只会持续返回无效 0202。

### 2.2 Buyer 重放与 FundingTx 交付缺少身份绑定

首次 `AcceptRefundPresign` 会校验 workflow signer 等于 `OpeningProof.BuyerPubKey`，但无 pending 的 completed replay 和 `BuildFundingTxDelivery` 没有同等检查。多个 Buyer workflow 共用一个 `PoolStore` 时，另一个 Buyer 可能仅凭公开 `RefundTxHash` 重放响应或取出不属于自己的 FundingTx。

### 2.3 完整购买文档仍调用旧 API

`docs/complete-file-purchase/README.md` 仍把原 request 和 FundingTx 传回 `AcceptRefundPresign`，并直接把 FundingTx 传给 `BuildFundingTxDelivery`，与当前仅通过 `RefundTxHash` 从可信存储恢复证据的 API 冲突。

### 2.4 FileStore 保证表述超过实现

进程文件锁能保证协作进程修改串行化，以及完全相同请求并发时 builder 至多执行一次；但 signer 完成后到 snapshot 持久化之间存在崩溃窗口，重试可能再次签名。因此不能宣称跨崩溃 signer exactly-once。

## 3. 一次性修复设计

1. `EnsurePresignedOpening` 命中已有 proof 后必须重新验证请求字段、规范 `RefundTxHash` 和 Seller 签名；若 proof 已含 FundingTx，还必须执行完整 `VerifyOpening`。
2. 坏记录统一返回 `ErrInvalidEvidence`；不得调用 builder/signer，不得返回坏签名，也不得静默重新签名覆盖。
3. `SaveOpeningProof` 必须执行与 proof 形态相符的密码学校验，使 MemoryStore、FileStore 写入和 snapshot 恢复共享同一可信边界。
4. Buyer 抽取统一 opening ownership 校验；首次接受、completed replay 和 FundingTx delivery 都要求当前 signer 公钥等于 `OpeningProof.BuyerPubKey`。
5. `BuildFundingTxDelivery` 在输出私有 FundingTx 前重新执行完整 `VerifyOpening`，不能只相信 hash 索引和非空字节。
6. 完整购买示例切换到 `AcceptRefundPresign(ctx, response)` 和 `BuildFundingTxDelivery(ctx, reference.RefundTxHash)`。
7. FileStore 文档统一为“建议性进程文件锁、协作进程修改串行化、并发相同请求 builder 至多一次”，明确崩溃窗口；协议版本保持 v4。

## 4. 明确不能做

- 不能把 `RefundTxHash` 当成 Buyer 身份或授权凭证。
- 不能在已存在 proof 分支只比较外围字段而跳过密码学验证。
- 不能遇到坏存储记录时重新签名并覆盖，从而掩盖损坏或证据冲突。
- 不能让 `BuildFundingTxDelivery` 只按 hash 读取并输出 FundingTx，而不核对 Buyer signer 和完整 opening。
- 不能要求调用方重新提供 request、FundingTx 或 session 来弥补 workflow 的关联责任。
- 不能把并发互斥表述为跨进程崩溃级 exactly-once。
- 不能修改 v4 常量、CBOR/CDDL 数组结构、`RefundTxHash` 计算真值或旧状态硬拒绝规则。

## 5. 特殊情况处理

- 已有 presign proof 的 Seller 签名损坏：拒绝且 builder 调用为 0；由运维显式处理坏状态，SDK 不猜测修复。
- 已有 complete proof 损坏：完整 `VerifyOpening` 失败，不能返回 0202 或交付 FundingTx。
- FileStore snapshot 被篡改或损坏：`NewFileStore` 恢复时失败，不能把坏记录装入内存索引。
- 多 Buyer 共用同一 PoolStore：非 owner workflow 的 completed replay 和 FundingTx delivery 均返回 `ErrInvalidEvidence`。
- signer 公钥读取失败：传播可诊断错误，不降级为仅 hash 授权。
- signer 完成后、快照持久化前进程崩溃：允许重试再次签名；若业务要求跨崩溃不重复调用 HSM，必须由 signer/数据库提供以 `RefundTxHash` 为幂等键的外部事务能力。
- 非 Unix 或没有受支持文件锁的平台：`NewFileStore` 继续以 `ErrUnsupportedFileStorePlatform` 快速失败。

## 6. 文件级实施结果

- `pool/memory.go`
  - 新增已存 proof 与通用 Save 的密码学校验；presign 和 complete proof 分别走 Seller 签名验证与完整 opening 验证。
- `pool/opening_test.go`
  - 覆盖 MemoryStore 坏签名命中时拒绝且不调用 builder；覆盖 FileStore snapshot 坏签名重启拒绝。
- `buyer/workflow.go`
  - 抽取 Buyer ownership 校验；首次接受、completed replay、FundingTx delivery 共用；delivery 输出前完整验签。
- `buyer/workflow_pending_test.go`
  - 覆盖不同 Buyer signer 共用 PoolStore 时，replay 和 funding delivery 都拒绝。
- `docs/complete-file-purchase/README.md`
  - 修复两处旧 API 调用，并使用准确的 FileStore 平台/锁边界。
- `pool/errors.go`、`pool/process_lock_other.go`、`pool/types.go`
  - 将保证收敛为跨进程修改串行化和并发相同请求 builder 至多一次；明确非 crash-safe exactly-once。
- `website/docs/sdk/*`、中文镜像、`website/api-translations.json`、生成 API 文档
  - 同步接口、身份/存储语义、崩溃窗口和“建议性进程文件锁”术语。

## 7. 最终验收清单

### 7.1 功能与安全

- [x] 已有 presign proof 的无效 Seller 签名返回 `ErrInvalidEvidence`，builder/signer 不执行。
- [x] 已有 complete proof 在重放前执行完整 `VerifyOpening`。
- [x] `SaveOpeningProof` 和 FileStore snapshot 恢复拒绝密码学无效 proof。
- [x] completed 0202 replay 绑定当前 Buyer signer。
- [x] FundingTx delivery 绑定当前 Buyer signer并重新完整验证 opening。
- [x] 不同 Buyer signer 共用 PoolStore 的两个越权入口均被拒绝。
- [x] 完整购买文档不再调用旧 API。
- [x] FileStore 文档不再承诺跨崩溃 signer exactly-once。
- [x] v4、CDDL/CBOR、RefundTxHash 计算和硬切换边界未改变。

### 7.2 根代理独立验收命令

以下命令均须以退出码 0 完成：

```sh
go test -mod=vendor -count=1 ./...
go test -race -mod=vendor -count=1 \
  ./buyer ./seller ./pool ./bitfs ./wire ./arbitration ./integration
go vet -mod=vendor ./...

(
  cd website
  npm run check
)

git diff --check
git diff --cached --check
git diff HEAD --check

rg -n -U 'AcceptRefundPresign\([\s\S]{0,180}(openingRequest|fundingTx)|BuildFundingTxDelivery\([\s\S]{0,100}fundingTx' \
  --glob '*.md' --glob '*.go' --glob '!vendor/**' --glob '!website/node_modules/**' .
rg -n '咨询锁|咨询进程锁' --hidden \
  --glob '!vendor/**' --glob '!website/node_modules/**' .
```

静态搜索的期望结果均为 0 处。

## 8. 实施核查记录

1. 第一轮 `luna_worker` 完成四项代码、测试和现有文档修复。
2. 根代理逐行复核后没有直接结束；发现中文把 advisory lock 误译为“咨询锁”，继续回派同一 `luna_worker`。
3. 第二轮统一改为“建议性进程文件锁”，同步翻译源和生成 API 文档，并重新通过 website 检查。
4. 根代理独立复跑全量、race、vet、website build、三种 diff check 和旧 API/误译静态搜索，均通过。

最终结论：本轮 review 的两个阻断问题和两个普通问题均已关闭；未发现剩余阻断问题或已知验收错误。
