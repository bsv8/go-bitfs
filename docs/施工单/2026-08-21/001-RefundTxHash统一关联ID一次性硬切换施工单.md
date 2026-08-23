# RefundTxHash 统一关联 ID 一次性硬切换施工单

## 0. 施工性质与唯一结论

本施工单把预签名退款交易的规范交易哈希统一为费用池全生命周期的关联 ID，并将公开名称固定为 `RefundTxHash`。

本次是尚未上线前的一次性破坏式硬切换，所有代码、CBOR、CDDL、持久化字段、demo、测试和当前文档必须在同一个迭代内完成，不分阶段实施，不提供新旧双栈，不保留兼容别名、旧字段、旧解码器或迁移开关。

协议版本保持 v4：

```text
wire family               = bitfs.protocol.v4
pool workflow major       = 4
MultisigPool protocol     = bitfs.pool.v4
MultisigPool version      = 4
FileStore schema version  = 4
```

虽然 CBOR 结构发生不兼容变化，但项目尚未上线，本次直接重写 v4 当前真值，不增加 v5，不接受施工前的 v4 报文和本地状态。

最终只有一个池关联主键：

```text
RefundTxHash = 当前固定 SDK 对规范、未嵌入签名的 RefundTx 计算出的 TxID().CloneBytes()
```

当前公开名 `SpendTxID`、CBOR/CDDL 名 `spend-txid`、JSON 名 `spend_txid`、demo 标签 `SPEND_TX_ID_HEX` 全部硬切换为 `RefundTxHash`、`refund-tx-hash`、`refund_tx_hash`、`REFUND_TX_HASH_HEX`。不得保留 type alias、双字段或双标签。

## 1. 缘由

当前 `RefundPresignResponse` 只携带卖方退款签名。Buyer 必须依靠同步调用栈、文件参数或连接上下文，才能先找到某个 0201 请求，再尝试验签。`FundingTxDelivery` 也只携带 FundingTx，Seller 需要先计算 FundingTxID，再通过次级索引反查 opening proof。

这种设计在 demo 的单请求管道中可用，但在 WebSocket、消息队列、异步回调、重试或同连接并发请求中缺少稳定的业务关联键。session ID 或 transport correlation ID 只能表示一次传输，不能由双方从协议证据独立重建，也不能贯穿费用池后续付款、关闭和仲裁生命周期。

RefundTx 在 0201 已经确定，并且买卖双方都必须验证同一份规范未签名交易。它的规范交易哈希具备以下性质：

- 双方可独立计算，不依赖连接、进程、数据库自增 ID 或随机 session；
- 在 detached buyer/seller 签名交换期间保持不变；
- 与现有 `SpendTxID` 的计算真值完全相同，现有 store、付款状态和内容授权已经把它当作池锚点；
- 可以从 0202 响应开始直接用于路由、持久化、幂等和冲突检测；
- 后续连接断开、进程重启或消息乱序时仍能找回同一资金池。

本施工的本质不是新增第二个 ID，而是把现有 `SpendTxID` 的真实含义改成准确、统一、从 0202 开始显式传输的 `RefundTxHash`。

## 2. RefundTxHash 计算真值

### 2.1 唯一算法

只允许通过 `pool` 中央函数计算：

```go
func RefundTxHash(ctx context.Context, proof *OpeningProof) (Hash32, error)
```

对只有 0201 request、尚无 OpeningProof 的调用点，应提供同一内部计算入口，例如：

```go
func RefundPresignRequestHash(request *RefundPresignRequest) (Hash32, error)
```

两个入口最终必须复用同一个规范交易解析与 TxID 计算函数，结果必须逐字节相等。计算顺序固定为：

1. 要求 RefundTx 非空；
2. 使用项目唯一的 `parseCanonicalTransaction` 严格解析；
3. 拒绝非规范编码、尾随字节、畸形 input/output；
4. 对解析出的未嵌入角色签名 RefundTx 调用固定 SDK 的 `TxID().CloneBytes()`；
5. 复制为 `pool.Hash32` 返回，不进行显示字节序翻转。

### 2.2 明确不能使用的算法

以下值均不得命名或充当 `RefundTxHash`：

- `sha256.Sum256(RefundTx)`；
- RefundPresignRequest CBOR 的 SHA-256；
- FundingTxID 或 funding outpoint；
- buyer/seller 签名合并后、可广播退款交易的 txid；
- 当前或历史累计付款交易的 txid；
- `PaymentAuthorizationHash`、内容 hash、quote hash；
- hex 文本的哈希、反序 hex、大小写字符串或数据库自增 ID；
- transport session ID、HTTP request ID、WebSocket connection ID 或 MQ correlation ID。

传输层可以额外携带 trace/request ID 用于观测，但它不能进入池主键、验签判断或持久化关联真值。

### 2.3 未签名与最终链上 txid 的区别

`RefundTxHash` 来自 OpeningProof 保存的未嵌入角色签名 RefundTx。buyer/seller detached signature 合并进 unlocking script 后，可广播退款交易的链上 txid 会改变。最终链上 txid 只能作为提交结果记录，绝不能覆盖或替换 `RefundTxHash`。

## 3. v4 最终报文真值

所有新增 `refund_tx_hash` 均为 32 字节 CBOR `bstr`。接收方必须先做长度和规范编码检查，再做与原始证据的派生值比较。

### 3.1 001 Quote

001 不属于某个已建立费用池，不增加 `RefundTxHash`，编码保持不变。

### 3.2 002 RefundPresignRequest

请求仍以 RefundTx 作为 ID 源，不重复编码派生字段：

```text
[4, refund_tx, buyer_pubkey, seller_pubkey, arbiter_pubkey,
 fee_rate, buyer_signature]
```

Buyer 发送前、Seller 解码后都必须立即计算 `RefundTxHash`。Buyer 按该值保存唯一 pending request；Seller 按该值保存预签 opening proof。

Buyer 在把 request 返回给传输调用方之前，必须原子持久化：

```go
type PendingPoolOpening struct {
    RefundTxHash Hash32
    Request      *RefundPresignRequest
    FundingTx    []byte
}
```

该记录是 0202 response 到达后找回原请求和 buyer 私有 FundingTx 的唯一应用状态。0203 不再接收原 request 参数，也不再依赖 request 文件、连接顺序或 session。

### 3.3 002 RefundPresignResponse

结构硬切换为：

```go
type RefundPresignResponse struct {
    Version               uint64
    RefundTxHash          Hash32
    SellerRefundSignature []byte
}
```

确定性 CBOR 固定为四元素数组：

```text
[4, 13, refund_tx_hash, seller_refund_signature]
```

Seller 必须用收到的 request 重新派生 hash 后填写，禁止由 API 调用方传入任意 hash。Buyer 必须用响应 hash 找回原请求，重新从原请求派生并比较，然后针对该原请求验证 SellerRefundSignature。

Buyer 接收 API 固定为由 workflow 自行关联：

```go
func (workflow *Workflow) AcceptRefundPresign(
    ctx context.Context,
    response *pool.RefundPresignResponse,
) (*pool.Reference, error)
```

workflow 必须从 `PendingPoolOpeningStore.LoadPendingPoolOpening(ctx, response.RefundTxHash)` 取得原 request 和 FundingTx。不得继续要求调用方同时传入 request/fundingTx；否则关联责任仍被留在 transport/application 层。

### 3.4 002 FundingTxDelivery

结构硬切换为：

```go
type FundingTxDelivery struct {
    Version      uint64
    RefundTxHash Hash32
    FundingTx    []byte
}
```

确定性 CBOR 固定为四元素数组：

```text
[4, 14, refund_tx_hash, funding_tx]
```

Buyer 只能从已经验证并持久化的 OpeningProof 派生 `RefundTxHash`，不得提供只接收裸 FundingTx、由调用方另行拼接 hash 的构造路径。Seller 必须先按 hash 加载 opening proof，再验证：

```text
delivery.RefundTxHash
== Hash(stored OpeningProof.RefundTx)
== FundingTx 所匹配 opening proof 的 RefundTxHash
```

全部一致后才允许保存完整 proof 和提交 FundingTx。

Buyer 构造 API 固定为从自己的 store 加载完整 proof：

```go
func (workflow *Workflow) BuildFundingTxDelivery(
    ctx context.Context,
    refundTxHash pool.Hash32,
) (*pool.FundingTxDelivery, error)
```

调用方只选择已经由 workflow 返回的池 ID；不能再次提供 FundingTx 或伪造 delivery 字段。

### 3.5 003 ContentRequest

原 `SpendTxID` 字段硬改名为 `RefundTxHash`，数组位置和字节值不变：

```text
[4, quote_hash, refund_tx_hash, base_sequence, payment_sequence_after,
 seller_amount_after, fee_rate, buyer_pubkey, seller_pubkey, arbiter_pubkey,
 content_type, content_hash, deadline]
```

Buyer 签名必须覆盖 `refund_tx_hash`；Seller 必须比较签名条款中的 hash 与已验证 OpeningProof 的派生 hash。

### 3.6 004 ContentDelivery

为了让独立投递的 004 可直接路由到费用池，delivery terms 硬切换为：

```go
type ContentDeliveryTerms struct {
    RefundTxHash             []byte
    PaymentAuthorizationHash []byte
    ContentBytes             []byte
}
```

确定性 CBOR 固定为：

```text
[4, refund_tx_hash, payment_authorization_hash, content_bytes]
```

外层 SignedContentDelivery 仍为 `[4, terms_cbor, seller_signature]`。Seller 签名自然覆盖新增 hash。Buyer 必须同时验证 delivery hash、003 authorization 中的 hash 和本地 opening proof 派生 hash 相等。

### 3.7 005 CumulativePayment

结构硬切换为：

```go
type PaymentUpdate struct {
    Version                   uint64
    RefundTxHash              Hash32
    PaymentAuthorizationHash  []byte
    UnsignedStateTxRaw        []byte
    BuyerTransactionSignature []byte
}
```

确定性 CBOR 固定为五元素数组：

```text
[4, refund_tx_hash, payment_authorization_hash,
 unsigned_state_tx_raw, buyer_transaction_signature]
```

Seller 必须检查显式 hash、pending 003 authorization、解析后的 unsigned payment 和 OpeningProof 派生 hash 全部一致。`RefundTxHash` 不是 buyer 交易签名的替代物；原有授权 hash、交易内容、sequence、金额和 buyer signature 验证一个都不能减少。

### 3.8 006 关闭与退款路径

当前没有独立 wire 006 容器，但所有公开输入、返回状态、节点接受结果、本地 store key、关闭/不确定状态和 demo 输出中的 `SpendTxID` 全部改名为 `RefundTxHash`。链节点提交接口仍以 raw transaction 和真实提交 txid 为真值，不把协议关联 ID 冒充链上 txid。

如果以后增加可独立投递的 006 报文，其第一个业务关联字段必须是 `refund_tx_hash`，并遵守本施工单的交叉校验规则。

### 3.9 007 ArbitrationRequest / ArbitrationResponse

007 请求和响应都必须可脱离同步连接独立路由，因此显式携带 `RefundTxHash`：

```go
type ArbitrationRequest struct {
    Version                    uint64
    RefundTxHash               Hash32
    PoolOpeningProofCBOR       []byte
    PaymentAuthorizationCBOR   []byte
    UnsignedStateTxRaw         []byte
    SellerTransactionSignature []byte
}

type ArbitrationResponse struct {
    Version                     uint64
    RefundTxHash                Hash32
    PaymentAuthorizationHash    []byte
    UnsignedStateTxHash         []byte
    ArbiterTransactionSignature []byte
}
```

确定性 CBOR 固定为：

```text
request  = [4, refund_tx_hash, opening_proof_cbor,
            payment_authorization_cbor, unsigned_state_tx,
            seller_signature]

response = [4, refund_tx_hash, payment_authorization_hash,
            unsigned_state_tx_hash, arbiter_signature]
```

Arbiter 必须比较 request hash、OpeningProof 派生 hash、003 authorization hash 字段和 unsigned payment 解析结果。Seller 接收 response 时还必须比较 response hash 与原 007 request hash；原有 authorization hash、unsigned state hash 和 arbiter signature 验证全部保留。

### 3.10 OpeningProof

OpeningProof CBOR 保持九元素，不增加 `RefundTxHash`：

```text
[4, refund_tx, buyer_pubkey, seller_pubkey, arbiter_pubkey,
 fee_rate, buyer_signature, seller_signature, funding_tx]
```

OpeningProof 是证据真值，`RefundTxHash` 可从其中确定性派生。不得为了查询方便把派生值重复写回 proof。

## 4. API、状态与存储统一规则

### 4.1 公共 Go API

所有表示费用池主键的公开字段、参数、返回值和注释统一改名：

```text
SpendTxID / spendTxID  -> RefundTxHash / refundTxHash
SpendTxID(...)         -> RefundTxHash(...)
```

`Hash32` 类型保留，FundingTxID、TxID、PaymentAuthorizationHash 等其他哈希名保持原义，不做机械替换。

禁止保留：

```go
type SpendTxID = Hash32
func SpendTxID(...) { ... }
```

也禁止同一个 struct 同时出现 `SpendTxID` 和 `RefundTxHash`。

### 4.2 MemoryStore

主索引统一为 `openingsByRefund`，accepted、pending、uncertain、closing 全部以 `RefundTxHash` 为键。`openingsByFunding` 可作为节点根据 raw transaction 的 funding outpoint 验证时使用的内部派生次级索引，但不得暴露为协议报文关联 ID，也不得绕过主键一致性校验。

新增 `PendingPoolOpeningStore`，由 buyer 在 0201 发送前保存、0203 接收响应时读取：

```go
type PendingPoolOpeningStore interface {
    SavePendingPoolOpening(context.Context, *PendingPoolOpening) error
    LoadPendingPoolOpening(context.Context, Hash32) (*PendingPoolOpening, error)
    DeletePendingPoolOpening(context.Context, Hash32) error
}
```

`PoolStore` 必须包含该能力，使 buyer workflow 不再依赖进程内 map 或 demo 专用文件。保存时必须重新计算 Request.RefundTx 的 hash、验证 FundingTx 与 request 的 funding outpoint/金额/脚本关系，并确保记录拥有自己的 byte copies。

同一 `RefundTxHash`：

- 完全相同的 opening evidence 可按幂等重试处理；
- RefundTx 相同但参与方、公钥、费率或签名不同，必须返回明确 conflict/invalid evidence；
- 不得覆盖已有 proof、accepted state、pending lease 或 uncertain/closing 状态。

### 4.3 FileStore

JSON 字段硬切换为 `refund_tx_hash`；嵌套 Go 状态中的字段也统一为 `RefundTxHash`。FileStore schema version 保持 4，但加载器必须严格拒绝未知字段和缺失/全零 `refund_tx_hash`，从而让施工前使用 `spend_txid` 的同版本快照明确失败，不能静默恢复成零值。

本次不提供状态迁移器。demo 的旧 `.state` 必须删除并从 0201 重跑；若开发者确需保留人工测试证据，应在施工前离线导出，施工后按新类型重新生成，不能把旧 JSON 文本做字段替换后冒充验证过的新状态。

snapshot 增加 buyer pending openings 集合，键为 `refund_tx_hash`，内容为 request 和 FundingTx 原始字节。AcceptRefundPresign 只有在完整 OpeningProof 和初始 accepted state 都持久化成功后才删除 pending；若中途崩溃，重启后的同一 response 必须可幂等重试。不得先删除 pending 再写入完整 opening。

### 4.4 Wire 与传输层

`wire.Kind` 继续只表示消息类型，`RefundTxHash` 表示具体费用池实例；两者职责不得混合。`wire.Packet` 不引入 session 语义。HTTP/WebSocket/MQ 可以额外用 request ID，但接收业务层时必须以 payload 内的 `RefundTxHash` 加证据验证为准。

## 5. 固定校验顺序

所有接收路径按以下顺序执行，任何一步失败都必须在签名、持久化或节点提交前返回：

1. 限制输入大小，严格解码确定性 CBOR，拒绝错误数组长度、错误 kind、尾随字节和旧结构；
2. 检查 `refund_tx_hash` 恰好 32 字节，拒绝未设置的全零值；
3. 按显式 hash 加载本地 pending request/opening proof；未知 hash 不创建占位记录；
4. 从原始 RefundTx 或 OpeningProof 重新计算 hash，并与显式值做常量语义的逐字节比较；
5. 检查嵌套 003、004、005、007 证据中的所有 `RefundTxHash` 相互一致；
6. 执行原有参与方、公钥、fee、FundingTx outpoint、金额、sequence、授权 hash 和 detached signature 验证；
7. 完成幂等/冲突判断；
8. 先持久化协议要求的本地证据；成功状态全部落盘后才删除相应 pending opening/request；
9. 只有协议顺序允许时才调用外部节点/backend；
10. 核对节点返回 txid/sequence/RefundTxHash，失败时按现有 uncertain 机制记录，键改为 `RefundTxHash`。

不得只因为 hash 相等就接受响应、资金交易、内容、付款或仲裁签名。Hash 用于定位证据，证据和签名用于证明归属。

## 6. 特殊情况与规定处理

### 6.1 相同 RefundTx、不同请求外围字段

RefundTx 不直接编码参与方公钥、fee rate 和 detached buyer signature。理论上两个 request 可以携带相同 RefundTx、但外围字段不同，因此得到相同 `RefundTxHash`。

规定：一个 `RefundTxHash` 只能对应一份不可变的规范 RefundPresignRequest/opening evidence。首个通过完整验证的请求占用该 ID；之后只有规范请求字节和证据完全一致的重试才可幂等接受，任何字段不同都必须硬冲突，不能靠 session 拆成两个池，也不能最后写入者覆盖。

### 6.2 未知或乱序消息

- 未知 hash 的 RefundPresignResponse：Buyer 拒绝，不遍历全部 pending 请求尝试验签；
- FundingTxDelivery 早于 Seller 保存 presign proof：拒绝为“opening proof missing”，不广播、不暂存为可信 proof，发送方可在前序成功后重试；
- 004/005/007 找不到 opening/pending authorization：按已有 missing/stale/busy 错误返回，不创建池；
- 不允许退回 session/file-name 配对逻辑作为兜底。

### 6.3 重复消息与重试

- 同 hash、同规范内容、同状态的重复请求必须保持幂等；
- 同 hash、不同内容必须冲突；
- FundingTx 已被节点接受时，backend 仍按相同真实 FundingTxID 返回成功，workflow 再核对 `RefundTxHash`；
- 已完成的响应不能让 sequence 回退、重复计费或覆盖更高付款状态。

### 6.4 Hash 不一致

显式 `RefundTxHash` 与任意可派生证据不一致时统一视为 `ErrInvalidEvidence` 类错误。必须在签名、store mutation、内容释放、付款合并和节点提交前失败。日志可以记录 kind 和 hash，但不得打印私钥、完整签名材料或把错误 hash 写进有效索引。

### 6.5 非规范或畸形 RefundTx

无法通过唯一规范 parser 的 RefundTx 不生成 ID。不得退回对原始 bytes 直接 SHA-256，也不得“先 hash 后解析”并把无效交易放进 pending map。

### 6.6 旧报文和旧状态

旧三元素 RefundPresignResponse、旧三元素 FundingTxDelivery、旧三元素 004 terms、旧四元素 PaymentUpdate、旧五/四元素 007 request/response一律解码失败。旧 `SpendTxID` Go API 不编译，旧 `spend_txid` FileStore JSON 加载失败，旧 demo 标签读取失败。

这是预期硬切换行为，不做自动识别、字段补全或错误消息引导下的隐式升级。开发环境删除旧状态后从 0201 重跑。

### 6.7 最终链上退款与其他交易 ID

节点返回的 FundingTxID、累计付款 txid、关闭 txid和最终签名退款 txid继续单独保存和核对。它们不等于 `RefundTxHash`，不得因为名字相近而替换字段或比较对象。

### 6.8 极端 hash 冲突与全零值

协议不尝试解决密码学 hash 碰撞。同一 hash、不同规范证据按冲突拒绝并要求人工审计，不允许自动挑选。全零 `Hash32` 作为“未设置”哨兵硬拒绝，不进入存储或网络发送路径。

## 7. 明确不能做

1. 不增加 v5，不改变 `ProtocolFamily`、`MajorVersion`、MultisigPool v4 或 FileStore schema version 数字。
2. 不保留旧 CBOR 数组长度、可选字段、union decoder、版本探测或 feature flag。
3. 不保留 `SpendTxID` 类型、字段、函数、参数、JSON key、CDDL 名、demo 输出标签或当前文档术语。
4. 不把 `RefundTxHash` 换成 request CBOR hash；后者可以作为同 hash 冲突检查的内部辅助值，但不是池 ID。
5. 不把 FundingTxID、签名后退款 txid、付款 txid、授权 hash 或 session ID 当作池主键。
6. 不因增加关联 ID 而删除或弱化任何原有交易、角色、公钥、金额、sequence、授权和签名验证。
7. 不把 `RefundTxHash` 重复编码进 OpeningProof；proof 保持原始证据集合。
8. 不让 API 调用方任意填写响应 hash；每个发送 workflow 必须从其已验证上下文生成。
9. 不在未知 hash 时遍历全部池尝试匹配、创建占位 opening、广播 FundingTx 或缓存未经验证的内容。
10. 不机械修改真正表示链上 spend、FundingTxID、最终 txid 或普通 SHA-256 的名称。
11. 不修改 `docs/legacy/`、`spec/v1/`、`spec/v3/` 中作为历史真值保存的术语；当前页面不得继续把历史页当作 v4 实现依据。
12. 不手工编辑或提交 `website/generated-api/`、`website/build/`、`website/node_modules/` 和生成的中文 API Markdown；只修改 Go doc、当前 docs 源和 `website/api-translations.json`，由构建验证生成物。

## 8. 一次性实施顺序

以下顺序用于同一个开发分支内降低中间混乱，不代表可以拆分上线或合并：

1. 先修改 `spec/v4`，冻结最终字段名、数组位置和长度；
2. 修改 `pool` 类型、统一 hash 计算、CBOR、clone 和验证；
3. 修改 MemoryStore/FileStore 主键、buyer pending opening 持久化和严格旧状态拒绝；
4. 修改 bitfs 003/004 和 pool 005；
5. 修改 buyer、seller、arbitration 的构造、接收和交叉校验；
6. 修改 wire、demo 和 fixture 调用；
7. 同步修改全部单元/集成/字节级测试；
8. 更新当前英文文档、中文当前文档和 API 翻译目录；
9. 执行完整验收，确认旧符号和旧报文均不可用；
10. 只允许以一个完整提交/PR 合并，任何中间步骤不得进入主分支。

## 9. 文件级施工清单

### 9.1 协议真值

- `spec/v4/pool.cddl`
  - 增加 RefundPresignResponse、FundingTxDelivery 的最终四元素定义；
  - 定义 `refund-tx-hash = bstr .size 32`；
  - 保持 request 和 OpeningProof 不重复派生 hash；
  - 删除 `spend txid` 当前术语。
- `spec/v4/content.cddl`
  - `spend-txid` 硬改为 `refund-tx-hash`；
  - 004 terms 增加 `refund-tx-hash` 并固定数组位置。
- `spec/v4/payment.cddl`
  - 005 增加首个业务字段 `refund-tx-hash`，数组从 4 项改为 5 项。
- `spec/v4/arbitration.cddl`
  - 007 request/response 都增加 `refund-tx-hash`，分别固定为 6 项和 5 项。
- `spec/v4/bitfs.cddl`
  - 继续声明 v4 wire family；补充“当前未上线 v4 硬切换后只接受新结构”的注释，不新增版本。

### 9.2 pool 核心生产代码

- `pool/types.go`
  - 为 RefundPresignResponse、FundingTxDelivery、PaymentUpdate 增加 `RefundTxHash`；
  - 新增 PendingPoolOpening 和 PendingPoolOpeningStore，并把该能力纳入 PoolStore；
  - 将 Reference、OpeningDetails、PaymentState、UnsignedPayment、UpdateAcceptance、PendingRequest 及所有 store 接口的 `SpendTxID` 统一改为 `RefundTxHash`；
  - 更新公开注释，明确其来源是未签名规范 RefundTx，而非最终链上退款 txid。
- `pool/opening.go`
  - 将 `SpendTxID` 函数硬改为 `RefundTxHash`；
  - 提取 request/proof 共用的唯一计算实现；
  - 保持规范 parser 和固定 SDK TxID 字节序。
- `pool/cbor.go`
  - 更新 0202 response、FundingTxDelivery、PaymentUpdate 的编码、解码、数组长度、clone 和结构校验；
  - 加入 32 字节/全零 hash 检查；
  - 旧数组长度必须失败，deterministic 重编码检查保留。
  - Hash32 字段编码时必须显式作为 32 字节 `bstr`（例如切片视图），不得让 Go `[32]byte` 被 CBOR 编成 32 元素整数数组。
- `pool/clones.go`
  - 所有新增 hash 做值复制；更新硬改名后的 clone 字段。
- `pool/multisigpool_engine.go`
  - 全部内部 `SpendTxID` 语义改为 `RefundTxHash`；
  - 所有解析出的 payment state 必须带 OpeningProof 派生 hash；
  - 不改变 MultisigPool 交易构造、sighash、签名或合并算法。
- `pool/multisigpool.go`
  - 更新 adapter 输出、状态比较和错误消息中的主键名；
  - 保持资金 outpoint 与真实交易 txid 逻辑不变。
- `pool/memory.go`
  - 主 map 和方法参数切换为 RefundTxHash；
  - 增加 buyer pending opening 的保存、加载、删除、深复制和重启 snapshot 支持；
  - 同 hash 相同证据幂等，不同证据冲突；
  - 保留 FundingTxID 次级索引仅供 raw transaction 反查验证。
- `pool/file_store.go`
  - snapshot 字段和 JSON key 改为 `RefundTxHash` / `refund_tx_hash`；
  - schema 数字仍为 4；
  - 使用 `DisallowUnknownFields` 和单文档 EOF 检查严格拒绝未知 `spend_txid`、缺失新字段及尾随 JSON；
  - snapshot restore 对每条记录重新派生 hash 并核对，不信任磁盘 key。
  - pending opening 的 request/FundingTx 必须随 snapshot 原子写入，并在重载时重新验证对应关系。
- `pool/node_adapter.go`
  - 返回值和一致性检查中的池主键改为 RefundTxHash；
  - FundingTxID 次级查找仍只作为 raw 链交易到 OpeningProof 的内部桥接；
  - 不改变 backend 所要求的真实 txid 校验。

### 9.3 bitfs 003/004

- `bitfs/content.go`
  - ContentRequestTerms 字段改为 `RefundTxHash`，保持其在 003 terms 中原位置；
  - ContentDeliveryTerms 新增 `RefundTxHash`，纳入 seller 签名 bytes；
  - 003/004 构造、解码、clone、验证和 request-delivery 关系校验全部同步；
  - 错误字段名统一为 `refund_tx_hash`。

### 9.4 Buyer workflow

- `buyer/workflow.go`
  - `PreparePoolOpening` 构造 request 后、返回前，以 RefundTxHash 持久化 PendingPoolOpening；持久化失败不得发送 request；
  - `AcceptRefundPresign` API 只接收 response，用 response.RefundTxHash 从 store 加载原 request/FundingTx，再派生比较和验签；
  - 完整 OpeningProof 和初始 accepted state 成功保存后才删除 pending opening；失败/崩溃可重试；
  - `BuildFundingTxDelivery(ctx, refundTxHash)` 从已验证 OpeningProof 加载 FundingTx，不再接收裸 FundingTx；
  - 004 接收时交叉校验 003、004、OpeningProof 三处 hash；
  - 构造 005 时填写 RefundTxHash；
  - 所有退款、付款、关闭、状态和错误文本使用新名。

### 9.5 Seller workflow

- `seller/workflow.go`
  - `PresignPoolOpening` 从 request RefundTx 派生 hash，保存 proof 后填入 response；
  - `AcceptPoolFunding` 按 delivery.RefundTxHash 直接加载 proof，派生复核后再验证/提交 FundingTx；
  - 003/004/005/007 构造和接收路径逐层交叉校验 hash；
  - pending lease、accepted state、uncertain/closing key 和所有错误文本统一改名；
  - 不允许 hash 不一致时进入 signer、store mutation 或 backend。

### 9.6 Arbitration workflow

- `arbitration/workflow.go`
  - ArbitrationRequest/Response 增加 RefundTxHash；
  - 更新 6/5 元素 CBOR 编解码、clone 和结构校验；
  - Arbiter 从 OpeningProof 派生并核对 request hash、003 hash、unsigned state；
  - response 原样携带已验证 hash；Seller 必须把它与原 request 再绑定。

### 9.7 wire

- `wire/wire.go`
  - kind 数值和 ProtocolFamily 保持不变；
  - 更新相关注释，明确 CBOR payload 内含 RefundTxHash；
  - 不新增旧结构分派、session 或自动兼容。

### 9.8 Demo 与 fixture

- `demo/internal/fixture/fixture.go`
  - fixture Reference、backend acceptance 和构造参数全部切换为 RefundTxHash；
  - fixture 必须走正式派生函数，不能硬编码替代算法。
- `demo/internal/poolopening/poolopening.go`
  - 删除 buyer FundingTx 专用文件的 Save/Load/Path 交接机制；PendingPoolOpening 由 FileStore 跨 0201/0203 持久化；
  - 保留通用 hex 报文 helper，但不得用文件名承担协议关联。
- `demo/02_pool_opening/0202_seller_accept_refund_request/main.go`
  - 输出响应时打印 RefundTxHash，保留签名日志边界。
- `demo/02_pool_opening/0201_buyer_build_refund_request/main.go`
  - 由 `PreparePoolOpening` 在返回 request 前把 request/FundingTx 保存为 PendingPoolOpening；
  - 删除单独保存 buyer FundingTx 交接文件的调用和相关注释。
- `demo/02_pool_opening/0203_buyer_accept_refund_response/main.go`
  - 删除 `--request-file` / `DEMO_02_REQUEST_FILE` 和读取 0201 报文逻辑；
  - 只从 stdin 读取 response，workflow 用响应 hash 从 buyer FileStore 查找/核对 0201 request 和 FundingTx；
  - stdout 标签硬改为 `REFUND_TX_HASH_HEX`；
  - 不再把完整 `BUYER_OPENING_PROOF_HEX` 作为 0204 的进程间交接物；OpeningProof 只保存在可信 FileStore，stdout 仅输出 hash 和可观察状态；
  - 删除所有把文件配对描述为关联真值或验签前置条件的注释。
- `demo/02_pool_opening/0204_buyer_build_funding_delivery/main.go`
  - 从 stdin 读取 `REFUND_TX_HASH_HEX`，以 hash 调用 workflow 从 FileStore 中的已保存 proof 构造 delivery；
  - 删除从 stdin 解码/逐字节比较完整 OpeningProof 的逻辑，不再从调用方输入 proof 或 FundingTx。
- `demo/02_pool_opening/0205_seller_accept_funding_delivery/main.go`
  - 展示按 hash 加载 proof、交叉验证和提交；输出新标签。
- `demo/03_content_request/01_build_request/main.go`
  - 输入/输出和字段名改为 RefundTxHash。
- `demo/04_content_delivery/01_deliver_content/main.go`
  - 解码并展示 004 中已由 Seller 签名覆盖的 RefundTxHash，验证它与 fixture pool 一致。
- `demo/05_cumulative_payment/01_accept_payment/main.go`
  - 展示 005 显式 RefundTxHash，并在 Seller 接收前后保持同一池关联。
- `demo/06_pool_close/01_close_pool/main.go`
  - 关闭调用和日志改为 RefundTxHash。
- `demo/07_arbitration/01_arbitrate_payment/main.go`
  - 展示 007 request/response 中相同的 RefundTxHash，并保留原证据 hash 与签名验证日志。
- `demo/02_pool_opening/README.md`
  - 更新 0201～0205 报文形状、关联逻辑、重试与旧 state 清理说明。
- `demo/README.md`
  - 更新 002 跨进程交接说明：0203/0204 只传 RefundTxHash，原 request、FundingTx 和 OpeningProof 都由 buyer FileStore 恢复。
- `demo/03_content_request/README.md`
- `demo/04_content_delivery/README.md`
- `demo/05_cumulative_payment/README.md`
- `demo/07_arbitration/README.md`
  - 更新代码示例和术语；说明各自报文必须携带/验证同一 RefundTxHash。

### 9.9 单元与集成测试

- `pool/cbor_test.go`
  - 精确断言 response/delivery/payment 新数组长度、字段位置和 canonical round trip；
  - 旧数组、短/长/全零/错 hash、尾随字节全部拒绝。
- `pool/opening_test.go`（新增）
  - 固定 RefundTxHash golden value 和字节序；
  - 证明 request/proof 两个入口结果相同、签名合并后链上 txid 不会替换池 ID、非规范 RefundTx 不产生 ID。
- `pool/memory_test.go`
  - 覆盖主键重命名、pending opening 深复制/重启/删除时序、同 hash 幂等、同 RefundTx 不同外围证据冲突、snapshot 一致性。
- `pool/node_adapter_test.go`
  - 覆盖 RefundTxHash 返回一致性，确保 FundingTxID 次级查找没有被误当主键。
- `pool/multisigpool_test.go`
  - 更新 PaymentState/UnsignedPayment/Reference 断言，并覆盖交易解析后的 RefundTxHash 始终来自 OpeningProof。
- `bitfs/content_test.go`
  - 更新 003 byte fixture；覆盖 004 seller 签名确实绑定 RefundTxHash，错配拒绝。
- `bitfs/constructor_signature_test.go`
  - 更新构造签名测试字段，证明 003 中 hash 被 buyer 签名覆盖。
- `buyer/workflow_test.go`
  - 增加 Prepare 先持久化、持久化失败不返回 request、仅凭 response hash 找回 request/FundingTx、unknown/mismatched hash、崩溃重试、004 hash错配、005 正确传播测试。
- `seller/workflow_test.go`
  - 覆盖 response hash 派生、FundingTxDelivery 直接索引、未知/错 hash 不提交、重复交付幂等。
- `arbitration/workflow_test.go`
  - 覆盖 007 request/response 新 shape、三份证据 hash一致、错配时 Arbiter 不签名/Seller 不提交。
- `wire/wire_test.go`
  - 对 002、004、005、007 新 payload 做 typed round trip，确认 kind 不承担实例关联。
- `integration/protocol_test.go`
  - 全流程只使用一个 RefundTxHash；覆盖两个并发池响应乱序、Funding delivery 乱序、004/005/007 错池交换全部失败；
  - 覆盖最终链上退款 txid 与 RefundTxHash 不同但各自用途正确。

### 9.10 当前文档与网站

- `website/docs/protocol/002-pool-opening-requirements.md`
- `website/docs/protocol/002-pool-opening-spec.md`
- `website/docs/protocol/003-content-request-requirements.md`
- `website/docs/protocol/003-content-request-spec.md`
- `website/docs/protocol/004-content-delivery-requirements.md`
- `website/docs/protocol/004-content-delivery-spec.md`
- `website/docs/protocol/005-cumulative-payment-requirements.md`
- `website/docs/protocol/005-cumulative-payment-spec.md`
- `website/docs/protocol/006-pool-close-requirements.md`
- `website/docs/protocol/006-unconditional-pool-close-spec.md`
- `website/docs/protocol/007-seller-arbitration-submission-requirements.md`
- `website/docs/protocol/007-seller-arbitration-submission-spec.md`
  - 用 RefundTxHash 统一当前 v4 术语，列出新 CBOR 和必做交叉验证；明确不使用 session 作为真值。
- `website/docs/sdk/external-hooks-and-data-types.md`
- `website/docs/sdk/protocol-foundations-and-cbor.md`
- `website/docs/sdk/role-workflow-api.md`
  - 更新公开 API、store key、构造调用、异常和重试示例。
- `website/i18n/zh-CN/docusaurus-plugin-content-docs/current/protocol/*.md`
- `website/i18n/zh-CN/docusaurus-plugin-content-docs/current/sdk/*.md`
  - 只更新与上述英文当前页一一对应的受影响文件，保持字段名和数组一致。
- `website/api-translations.json`
  - 更新由 Go doc 产生的 API 中文条目，清除当前 API 的 SpendTxID 文案。
- `docs/complete-file-purchase/README.md`
  - 全链路审计、幂等、关闭和恢复示例统一用 RefundTxHash。
- `website/README.md`
  - 原则不需修改；实施者必须遵守其中“生成 API 不提交”的规则。

以下文件/目录不作为手工修改目标：

```text
docs/legacy/**
spec/v1/**
spec/v3/**
website/docs/legacy/**
website/generated-api/**
website/build/**
website/node_modules/**
website/i18n/zh-CN/docusaurus-plugin-content-docs-api/current/**
```

历史材料允许保留 `SpendTxID`，但当前导航和当前 v4 文档不得引用它作为现行名称。

## 10. 必须新增的关键测试矩阵

| 场景 | 预期 |
|---|---|
| 正常 0201 → 0202 | response hash 等于 request RefundTx 派生值，卖方签名通过 |
| 两个池响应逆序到达 | Buyer 按 hash 找到各自 request，均正确验签 |
| response hash 指向 A、签名属于 B | A 上验签失败，不遍历 B，不写状态 |
| response hash 未知 | 立即拒绝，不创建 pending/opening |
| 0201 pending opening 持久化失败 | 不返回/发送 RefundPresignRequest |
| 0203 无 request 文件且进程已重启 | 仅凭 response hash 从 FileStore 找回原请求并完成验签 |
| 0203 写完整 opening 后、删 pending 前崩溃 | 重启重试幂等完成，不覆盖或重复计费 |
| 同 RefundTx、不同角色/fee/signature request | 同 hash 冲突，第二份拒绝 |
| 完全相同 request 重试 | 幂等，不产生第二个池 |
| FundingTxDelivery hash 错误 | Seller 不验收、不保存完整 proof、不提交节点 |
| FundingTxDelivery hash 正确、FundingTx 不匹配 | 交易验证失败，不提交 |
| 004 hash 与 003 不同 | Buyer 拒绝内容，不构造 005 |
| 005 hash 与 authorization/opening 不同 | Seller 不签名、不提交、不释放 lease |
| 007 request 三处 hash 不同 | Arbiter 不签名 |
| 007 response hash 与 request 不同 | Seller 不合并、不提交 |
| 旧 CBOR 数组 | strict decoder 拒绝 |
| 旧 FileStore `spend_txid` | 启动明确失败，不迁移 |
| 签名后退款 txid | 可与 RefundTxHash 不同，提交结果单独记录 |
| backend 结果 hash/sequence/txid 不一致 | 进入既有 uncertain 处理，不接受为成功 |
| 非规范 RefundTx | 不生成 hash，不保存 pending，不调用 signer |
| 全零/31/33 字节 hash | 结构校验失败 |

## 11. 最终验收清单

### 11.1 协议与结构

- [ ] `ProtocolFamily`、pool major、MultisigPool 和 FileStore schema 数字均保持 4。
- [ ] 0202 response、FundingTxDelivery、004、005、007 的 CDDL 与 Go encoder 数组长度和位置完全一致。
- [ ] RefundPresignRequest 和 OpeningProof 不重复编码 RefundTxHash。
- [ ] 所有 pool-scoped 独立后续报文显式携带 RefundTxHash，或其签名 terms 中直接携带该字段。
- [ ] 旧数组长度、旧字段名和尾随字节全部严格拒绝。

### 11.2 身份与安全

- [ ] 全仓只有一个 RefundTxHash 计算实现，使用 canonical RefundTx 和固定 SDK TxID。
- [ ] 发送 workflow 自行派生 hash；调用方不能伪造填入。
- [ ] 接收 workflow 都重新派生并比较，不信任 wire/store key。
- [ ] Hash 只用于查找，所有原有签名和业务证据验证均保留。
- [ ] 同 hash 不同证据硬冲突，不能覆盖；相同证据重试幂等。
- [ ] 未知/错 hash 在 signer、store mutation、内容释放和 backend 调用前失败。
- [ ] RefundTxHash 与最终链上退款 txid、FundingTxID、付款 txid保持明确区分。

### 11.3 API 与存储

- [ ] 当前 Go 代码不存在公开 `SpendTxID` 字段、函数、参数或兼容 alias。
- [ ] 当前 JSON snapshot 使用 `refund_tx_hash`，严格拒绝旧 `spend_txid`。
- [ ] MemoryStore/FileStore 以 RefundTxHash 为主键，FundingTxID 只保留为内部必要次级索引。
- [ ] Buyer 在 0201 发送前持久化 PendingPoolOpening；0203 不需要调用方提供原 request 或 FundingTx。
- [ ] PendingPoolOpening 只在完整 opening 和初始状态落盘后删除，进程重启可重试。
- [ ] demo 输出只使用 `REFUND_TX_HASH_HEX`，不同时输出旧标签。
- [ ] demo 不再使用 `--request-file`、`DEMO_02_REQUEST_FILE` 或 buyer FundingTx 专用交接文件完成关联。
- [ ] 0203→0204 不再传完整 OpeningProof，只传 `REFUND_TX_HASH_HEX`，0204 从 FileStore 加载并复核 proof。
- [ ] 删除本地旧 demo state 后，0201～0205 可从零完整运行。

### 11.4 测试与文档

- [ ] 单元测试覆盖新 CBOR golden bytes、旧结构拒绝、错配、乱序、重试和冲突。
- [ ] 集成测试覆盖两个并发池的消息互换攻击/误配。
- [ ] `spec/v4`、当前英文/中文协议页、SDK 页、demo README 和 Go doc 使用相同术语。
- [ ] 历史目录未被机械重写，当前页不把历史术语当作现行 API。
- [ ] 网站 API 由 Go doc 成功生成，`website/api-translations.json` 无缺失/陈旧条目。
- [ ] 未提交任何生成的 API、website build、node_modules 或 demo state。

### 11.5 验收命令

在仓库根目录执行：

```sh
find arbitration bitfs buyer demo integration pool seller wire \
  -type f -name '*.go' -print0 | xargs -0 gofmt -w
go test -mod=readonly -count=1 ./...
go test -mod=vendor -count=1 ./...
go test -race -mod=vendor -count=1 ./...
go vet -mod=vendor ./...

(
  cd website
  npm run check
)

git diff --check
git status --short
```

旧符号检查必须分别区分当前代码与历史文档：

```sh
rg -n 'SpendTxID|spendTxID|spend_txid|SPEND_TX_ID' \
  arbitration bitfs buyer demo integration pool seller wire spec/v4 \
  docs/complete-file-purchase website/docs/protocol website/docs/sdk \
  website/i18n/zh-CN/docusaurus-plugin-content-docs/current/protocol \
  website/i18n/zh-CN/docusaurus-plugin-content-docs/current/sdk \
  website/api-translations.json
```

该命令必须无结果。不得为了让搜索通过而修改 legacy、旧 spec 或旧施工单。

生成物清洁检查：

```sh
test -z "$(git ls-files -- \
  website/generated-api website/build website/node_modules \
  website/i18n/zh-CN/docusaurus-plugin-content-docs-api/current \
  demo/.state)"
```

该命令必须无结果。

## 12. 完成定义

只有以下条件同时成立，本施工才算完成：

- v4 新报文、API、store、demo、规范和文档一次性切换；
- RefundTxHash 从 0202 响应开始成为所有后续 pool-scoped 报文的统一关联 ID；
- Buyer 能在跨进程、无 session、无原请求文件参数的情况下，仅凭 response RefundTxHash 从可信本地 store 恢复原请求并验签；
- 所有接收方都从原始证据复算并交叉验证；
- 旧 v4 CBOR、旧 Go API、旧 JSON 和旧 demo 标签不可再使用；
- 错配、乱序、重复、未知 hash、同 hash 不同证据和最终 txid 分离均有自动测试；
- 完整 Go、race、vet、网站构建和工作区清洁验收全部通过。

仅仅“给 RefundPresignResponse 增加一个 hash 字段”不算完成；只要后续某个独立报文仍依赖 session、文件名、连接顺序、FundingTxID 反查或未验证的调用方配对作为关联真值，就判定本次硬切换未完成。
