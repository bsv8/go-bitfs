# MultisigPool v4 / BitFS v3 统一费用池一次性硬切换施工单

## 0. 施工性质与唯一真值

本施工单定义 go-bitfs 从旧费用池实现和
`github.com/bsv8/MultisigPool v0.1.0` 一次性切换到：

```text
github.com/bsv8/MultisigPool/v4 v4.0.0
MultisigPool protocol = bitfs.pool.v4
MultisigPool version  = 4
go-bitfs workflow    = bitfs.pool.workflow.v3
go-bitfs major       = 3
```

本次是破坏式硬切换。不提供双栈、兼容别名、自动识别旧协议、灰度开关、旧实现回退或静默迁移。最终依赖必须使用正式 v4.0.0 版本，不得使用本地 `replace`、分支、浮动提交或脏工作区目录。

代码、公共类型、CBOR、存储 schema、文档、fixture、测试和 vendored 依赖必须在同一个合并窗口完成。旧施工单、旧 v1/v2 CDDL 和 legacy 文档只可作为历史资料，不得作为当前实现或验收真值。

## 1. 业务与角色真值

业务规则保持不变：

- Buyer 是出资方和正常付款发起方；
- Seller 是内容提供方和累计收款方；
- Arbiter 只参与卖方仲裁签名；
- 正常付款、到期退款、协商关闭使用 Buyer + Seller；
- 卖方仲裁使用 Seller + Arbiter；
- 当前版本不收取池内仲裁服务费，所有业务状态的 ArbiterAmount 固定为 0。

MultisigPool v4 的角色和锁定顺序永久固定为：

```text
[Buyer, Seller, Arbiter]
```

go-bitfs 的所有公钥、输出归属、签名和合并调用都必须使用 v4 的角色对象，禁止再使用 `server`、`A`、`B` 作为当前 API 语义。

## 2. 链上交易真值

MultisigPool v4 是费用池交易的唯一真值，负责：

- 2-of-3 锁定脚本；
- 初始、累计、最终状态交易构造；
- 输入 source output、序号、locktime 和费用；
- SIGHASH_ALL | FORKID 摘要；
- Buyer、Seller、Arbiter detached 签名；
- Buyer+Seller、Buyer+Arbiter、Seller+Arbiter 合并；
- 输入、输出、金额、协议和签名验证。

go-bitfs 只负责业务对象转换、调用编排、持久化和节点提交，不得复制脚本、P2PKH 输出、费用公式、sighash、签名排序或交易构造算法。

### 2.1 输出布局

go-bitfs 当前业务产生的每个状态交易都必须恰好有三个输出：

| 输出 | 固定归属 | 约束 |
|---|---|---|
| output[0] | Buyer | 池余额扣除 Seller 累计金额和矿工费后的余额 |
| output[1] | Seller | Seller 的绝对累计金额 |
| output[2] | Arbiter | 固定为 0 sat，作为 v4 角色输出保留 |

业务状态不携带 `PaymentProof`，因此不得产生第四个 OP_RETURN 输出。官方 MultisigPool v4 通用 fixture 可以覆盖 PaymentProof 和非零 ArbiterAmount 的库能力，但 go-bitfs 当前业务适配必须严格使用三输出、零 ArbiterAmount。

### 2.2 序号和最终状态

- v4 初始开池状态序号固定为 2；
- 正常累计状态序号必须严格递增且不能为 `0xffffffff`；
- `0xffffffff` 仅用于协商关闭；
- nLockTime 小于 `500000000` 时只按区块高度判断，必须有 `BlockHeight` 提供器；nLockTime 大于等于该值时只按 Unix 时间判断；
- 到期退款使用已经 Buyer+Seller 合并完成的初始状态；
- 初始合法状态为序号 2，因此只有序号大于 2 的已接受累计状态才阻止到期退款；
- 退款不得修改金额、费率、输出或签名。

## 3. 签名和报文真值

### 3.1 detached 签名

单角色签名入口只接受空解锁脚本交易，并只返回独立签名字节：

- Buyer 对空解锁状态签名；
- Seller 对空解锁状态签名；
- Arbiter 对空解锁状态签名；
- 最终交易只能由对应的 v4 `Merge...Signatures` 函数产生。

不得恢复 `Attach...`、`PartialSpendTx`、单签交易或把签名写入交易后再跨边界传输的 API。

### 3.2 005 累计付款

005 `PaymentUpdate` 固定为：

```text
[workflow_version=3, payment_authorization_hash,
 unsigned_state_tx_raw, buyer_detached_signature]
```

它不包含半签交易，不包含 Seller 签名，不重新声明金额真值。Seller 验证 Buyer detached signature 后，对同一空解锁交易签名，再通过 v4 Buyer+Seller 合并并提交非最终节点。

### 3.3 仲裁

仲裁请求必须包含：

- 完整开池证明；
- 003 最终付款授权；
- Seller 构造的空解锁候选交易；
- Seller detached signature。

Arbiter 只验证授权、候选交易和 Seller 签名，然后对同一空解锁交易产生 Arbiter detached signature。Seller 最终按 Seller+Arbiter 合并。仲裁请求不得要求 Buyer 为本次状态交易签名，也不得携带旧的买方半签交易、001、004、payload 或历史付款链。

解析完整交易时，PaymentState 的签名字段必须通过 MultisigPool v4 实际验签识别角色：

- Buyer+Seller：填充 BuyerTransactionSignature 和 SellerTransactionSignature；
- Seller+Arbiter：填充 SellerTransactionSignature 和 ArbiterTransactionSignature；
- 不得根据签名在 unlocking script 中的位置固定标记为 Buyer/Seller。

## 4. 存储、CBOR 和拒绝规则

- FileStore schema 固定为 4；
- 启动或重新加载时遇到旧 schema 必须明确失败，不得静默迁移或猜字段；
- 002、003、004、005、006、007 只接受当前 major 3；
- MultisigPool 嵌入字段只接受 `bitfs.pool.v4` / version 4；
- CBOR 必须 deterministic，固定数组长度，拒绝尾随字节、未知字段和旧版本；
- PaymentState 只表示完整合并交易，RawTx 必须与完整状态一致；
- 所有 detached 验签入口对空交易、零输入、少于三个输出、错误解锁脚本和错误角色都必须返回协议错误，不能 panic；
- 节点接受结果与本地 txid、序号或交易字节不一致时硬失败。

## 5. 代码边界

### MultisigPool

go.mod、go.sum 和 vendor 只能保留：

```text
github.com/bsv8/MultisigPool/v4 v4.0.0
```

旧 `github.com/bsv8/MultisigPool`、旧 triple endpoint、旧 fixture 和旧公共 API 必须从活动代码和 vendor 删除。官方 v4 仓库的
`testdata/arbitrated_pool_v4_fixture.json` 是跨仓字节真值。

### go-bitfs

- `pool/multisigpool_engine.go` 只做 v4 适配和验证编排；
- 不得保留第二套脚本、费用、sighash、输出或签名合并算法；
- buyer、seller、arbiter 私钥只能通过进程内密钥提供端口取得，不进入 CBOR、存储、日志或网络报文；
- `NonFinalPoolBackend` 继续由调用方注入，不固定节点地址；
- 开池、正常付款、卖方仲裁、到期退款和协商关闭都必须走当前 v4 适配层。

## 6. 测试和验收

必须至少覆盖：

- 初始 v4 状态序号 2、三输出和 ArbiterAmount=0；
- 初始序号 2 的到期退款成功；
- 已接受序号 3 或更高状态时到期退款拒绝；
- Buyer+Seller 正常付款；
- Seller+Arbiter 买方拒签仲裁；
- 协商关闭；
- 零输出/少输出 detached 验签返回错误而不 panic；
- 仲裁完整交易解析后的 Seller/Arbiter 字段正确；
- 旧 FileStore schema 启动失败；
- 旧 major、尾随 CBOR、错误角色、错配签名、篡改金额/序号/输出全部拒绝；
- 读取 `pool/testdata/arbitrated_pool_v4_fixture.json`，逐字节比较锁定脚本、资金交易、每个状态交易、txid、输出、三种 detached 签名和三种合并交易；
- vendor v4 与官方 fixture 一致；
- 从干净 checkout 构建，不依赖工作区外的本地仓库。

验收命令：

```text
go test -mod=readonly -count=1 ./...
go test -mod=vendor -count=1 ./...
go test -race -mod=vendor -count=1 ./...
go vet -mod=vendor ./...
git diff --check
```

最终合并前还必须确认：

- 当前提交包含全部实现、测试、文档、fixture、go.mod/go.sum 和 vendor 修改；
- 干净 checkout 能复现同样结果；
- `git status --short` 不包含测试生成文件；
- 施工单、README、protocol、SDK、Go 注释和示例全部描述 Buyer/Seller/Arbiter、BitFS v3、MultisigPool v4；
- 未提交的脏工作区不能作为验收证据。

## 7. 完成定义

只有代码、不可变依赖、CBOR、存储 schema、官方跨仓 fixture、正常支付、买方拒签仲裁、到期退款、文档和干净 checkout 验证同时通过，施工单才算完成。

“go-bitfs 能调用 MultisigPool v4”不等于完成；任何旧角色、旧 major、旧两输出状态、半签交易、第二套费用池真值、未提交实现或文档冲突，均判定硬切换未完成。
