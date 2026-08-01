# MultisigPool 统一费用池一次性硬切换施工单

## 0. 施工单性质

本施工单是一次性破坏性升级施工单，同时覆盖：

- `/home/david/Workspaces/MultisigPool` 的三方费用池语义修正和公共 API 收口；
- `/home/david/Workspaces/go-bitfs` 删除自建 BSV 交易实现并改用 MultisigPool；
- go-bitfs 001～007 协议中已经走偏的付款授权和仲裁模型修正；
- 代码、CBOR、文档、示例、测试和依赖锁定的同步切换。

本次改造只允许一次合并、一次发布、一次启用，不提供双栈、兼容层、灰度协议或旧实现回退开关。下文的任务顺序只是同一次迭代内的依赖顺序，不代表可以拆分发布。

002、003、005、007 及相关存储对象的协议 major 从当前 `1` 统一提升为 `2`，新代码只接受 major `2`。本文所称“V1 不实现仲裁服务费”是产品能力范围，即仲裁服务费第一版不做，不是继续接受旧 major `1` 编码。

`施工单/MultisigPool费用池硬切换施工单.md` 是未完成旧稿，不是真值，不参与本施工单的需求判断、实现取舍或验收。

## 1. 缘由

当前 go-bitfs 在 `pool/bsv_engine.go` 中自行实现了 2-of-3 脚本、交易构造、费用计算、签名摘要、签名合并、累计更新、关闭和校验。这形成了独立于 MultisigPool 的第二套费用池真值。即使节点/WoC 已通过 `NonFinalPoolBackend` 注入，链上交易语义仍然没有统一。

同时，现有协议把卖方仲裁理解成“买方已经签署 005 付款交易，仲裁者只补一个签名”。真实场景却是：卖方已经按买方的最终签名授权交付内容，但买方拒绝签署本次付款交易；卖方应根据最后授权构造交易并先签名，仲裁者只验证该授权和交易的一致性后签名。

因此，本次必须同时修复库、SDK 和协议，不能只把 `BSVEngine` 的若干函数机械替换为同名库调用。

## 2. 不可变真值

### 2.1 角色映射

MultisigPool 三方锁定脚本中的位置永久固定为：

| MultisigPool 槽位 | go-bitfs 角色 | 应用职责 |
|---|---|---|
| `server` / pubkey[0] | 卖方 | 正常收款；构造并签署仲裁交易 |
| `A` / pubkey[1] | 买方 | 出资；签署正常累计付款和退款 |
| `B` / pubkey[2] | 仲裁者 | 验证最后授权；签署仲裁交易 |

链上三个公钥的权限都是平等的 2-of-3。角色名称不表示脚本权限高低，但它们决定输出归属、业务责任和 CHECKMULTISIG 签名排列，任何调用点都不得换位。

签名排列固定为：

- 正常付款、到期退款、协商关闭：`server + A`，即卖方签名在前、买方签名在后；
- 卖方仲裁：`server + B`，即卖方签名在前、仲裁者签名在后；
- V1 不使用 `A + B` 业务路径。

### 2.2 费用池交易真值

MultisigPool 是以下内容的唯一实现者：

- `[server, A, B]` 2-of-3 锁定脚本；
- 资金池输出和花费交易模板；
- `nLockTime`、`nSequence` 和最终化规则；
- output[0]/output[1] 的脚本和金额；
- 矿工费计算和交易大小估算；
- `SIGHASH_ALL | FORKID` 摘要；
- server、A、B 单签；
- `server+A`、`server+B` 合签；
- 签名、输入、输出和金额验证。

go-bitfs 只允许做业务对象到 MultisigPool 参数的无损转换、调用编排、持久化和节点提交。不得复制脚本字节、重算 sighash、重建输出、修补费用或在适配器中实现“等价算法”。

### 2.3 输出和费用

所有 V1 状态交易只有两个价值输出：

| 输出 | 固定归属 | 金额 |
|---|---|---|
| output[0] | `server` / 卖方 | 卖方累计金额 |
| output[1] | `A` / 买方 | 池余额减卖方累计金额和矿工费 |

`B` / 仲裁者不出现在普通或仲裁状态交易的价值输出中。

矿工费仍由 MultisigPool 按费用池建立时固定的整数费率策略计算。go-bitfs 不再传入自行计算的 `MinerFeeSat`。费率必须采用整数单位并由库定义唯一舍入规则，禁止 go-bitfs 与 MultisigPool 分别使用 `float64` 计算。

V1 不实现仲裁服务费：

- 不查询仲裁者费率；
- 不在授权、仲裁请求或响应中携带仲裁费；
- 不创建金额为 0 的仲裁费输出；
- 不调用 `TripleFeePoolLoadArbitrationTx`；
- 不从买方余额或卖方累计金额中扣除仲裁费。

未来仲裁服务费必须使用新的协议 major version 设计，不得在 V1 上追加可选字段或隐式输出。

### 2.4 网络边界

真实节点、WoC 或其他非最终交易池连接继续通过 `NonFinalPoolBackend` 注入。MultisigPool 不负责网络请求，go-bitfs 也不内置固定节点地址。

节点返回只表示外部节点的处理结果；SDK 必须先用 MultisigPool 本地校验，再提交后端。后端拒绝、超时或返回不一致 txid 时不得推进本地已接受状态。

## 3. 最终付款授权模型

### 3.1 003 从“请求引用”改为“最终签名授权”

003 仍由买方在卖方交付前签署，但它不再只是指向报价的弱引用。它是本次购买唯一可用于仲裁的业务真值，必须自包含仲裁所需的经济结果。

建议将对象明确命名为：

```text
ContentPaymentAuthorizationTerms
SignedContentPaymentAuthorization
ContentPaymentAuthorizationTermsHash
```

如果为减少公开 API 改名而继续使用 `ContentRequestTerms`，其注释、字段和文档也必须完整改成“最终付款授权”语义；仓库中不得同时存在两种有效票据模型。

授权条款至少固定签入：

| 字段 | 约束 |
|---|---|
| `version` | 使用本次破坏性升级后的唯一 major version |
| `quote_terms_hash` | 供买卖双方在签发前验证和审计；仲裁者不沿此引用回查 001 |
| `spend_txid` | 唯一费用池锚点 |
| `base_payment_sequence` | 买方签发时双方最后接受的状态序号 |
| `payment_sequence_after` | 本次目标序号；V1 必须等于 `base + 1` |
| `seller_amount_after_sat` | 本次之后卖方绝对累计金额；是仲裁金额真值 |
| `miner_fee_rate_sat_per_kb` | 整数矿工费率；必须与开池约定一致 |
| `buyer_pubkey` | 必须等于池的 A |
| `seller_pubkey` | 必须等于池的 server |
| `selected_arbiter_pubkey` | 必须等于池的 B |
| `content_type` | Seed 或 Block |
| `content_hash` | 被请求内容的精确哈希 |
| `delivery_deadline_unix` | 卖方接受和正常交付窗口，不是仲裁请求失效时间 |

买方签名覆盖上述完整 deterministic CBOR。`seller_amount_after_sat` 是绝对累计值，仲裁者不得根据 `PriceSat`、报价或历史订单重新求和。

签发授权前，买方仍须验证报价、内容引用、费用池参与者、当前序号、余额和价格；卖方收到授权后也须在交付前完成同样的本地业务校验。上述检查决定双方是否签发或接受授权，但它们不成为仲裁证据包。

### 3.2 唯一仲裁业务证据

卖方仲裁只提交一条业务证据：完整原始 `SignedContentPaymentAuthorization`。

以下对象不得作为仲裁前置证据：

- 001 完整报价；
- 004 内容交付凭证；
- 文件块或 seed payload；
- 历史 003/004/005 链；
- 买卖双方数据库记录；
- 买方为本次交易签署的 005，因为争议场景正是买方没有签它。

仲裁者不推断历史，也不重算业务；它直接认定最后一条买方签名授权中的有效信息。

开池证明、无解锁脚本的候选交易和卖方交易签名属于完成密码学验证与签名所需的执行材料，不是额外业务证据。

### 3.3 仲裁请求和响应

仲裁请求固定包含：

```text
version
pool_opening_proof_cbor
payment_authorization_cbor
unsigned_state_tx_raw
seller_transaction_signature
```

其中 `unsigned_state_tx_raw` 的费用池输入解锁脚本必须为空。卖方签名独立传输，避免把旧签名、假签名或签名顺序混入交易模板。

仲裁者只执行：

1. 确认授权 deterministic CBOR、买方签名有效；
2. 确认授权的 server/A/B 与开池脚本固定映射一致，且 B 是自己；
3. 确认候选交易由 MultisigPool 校验通过；
4. 确认输入、目标序号、卖方累计金额和矿工费率严格等于授权；
5. 确认候选交易只有卖方和买方两个价值输出，没有仲裁费或额外输出；
6. 确认卖方 server 签名有效；
7. 使用 B 私钥对同一无解锁脚本交易签名。

仲裁响应固定包含：

```text
version
payment_authorization_hash
unsigned_state_tx_hash
arbiter_transaction_signature
```

响应不包含批准金额、拒绝金额、重新定价结果、仲裁费、业务决定 ID 或新的交易模板。卖方必须复核两个哈希和 B 签名，再通过 MultisigPool 按 `server+B` 合并。

## 4. 目标工作流

### 4.1 开池和到期退款

1. 买方 A 用自己的 UTXO 构造资金交易，资金输出脚本固定为 `[server=卖方, A=买方, B=仲裁者]`。
2. MultisigPool 构造初始远期状态：卖方累计金额为 0，余款给买方，包含固定到期 `nLockTime` 和初始非最终序号。
3. 买方 A 签署初始远期状态并把签名交给卖方。
4. 卖方验证后以 server 签名，将 `server+A` 完整退款交易持久化。
5. 只有卖方签名已验证且双方都持久化必要开池材料后，才允许广播资金交易。
6. 到期时直接提交已经完成 `server+A` 签名的退款状态，不得临时改变金额、费率或输出。

### 4.2 正常购买和累计付款

1. 买方根据已验证报价和最新接受状态计算 `seller_amount_after_sat`，签出 003 最终付款授权。
2. 卖方验证授权并建立单池单请求门闩，然后发送 004。
3. 买方验证 004 后，让 MultisigPool 从同一资金池输出构造目标状态，以 A 签名并发送 005。
4. 005 只承载授权哈希、无解锁脚本的状态交易和 A 签名；金额以授权和交易为准，不在 CBOR 中再建第二套金额字段。
5. 卖方用 MultisigPool 验证 A 签名和交易与授权一致，以 server 签名，按 `server+A` 合并并提交非最终节点。
6. 节点确认接受更高序号后，卖方才保存新接受状态并释放门闩。

### 4.3 卖方仲裁

1. 买方已签出 003 最终付款授权，但没有交付有效 005。
2. 卖方从节点已接受的基础状态和最后授权出发，调用 MultisigPool 构造同样的两输出目标状态。
3. 卖方以 server 签名，发送第 3.3 节定义的请求。
4. 仲裁者不构造交易、不获取报价、不验证内容，只验证最后授权、候选交易和 server 签名，然后以 B 签名。
5. 卖方复核响应，按 `server+B` 合并并提交。
6. 节点接受后保存状态并释放相应门闩。

### 4.4 协商关闭

协商关闭继续使用卖方和买方两方签名。MultisigPool 构造 `nSequence`、`nLockTime` 均为最终值的两输出交易，签名顺序固定为 `server+A`。仲裁者不参与协商关闭。

## 5. MultisigPool 仓库施工

MultisigPool 的修改必须先在同一次迭代分支中完成并通过测试，然后 go-bitfs 锁定到该不可变提交或正式 tag。不得让 go-bitfs 用 `replace` 长期指向本地目录。

### 5.1 文件级任务

| 文件 | 必须完成的修改 |
|---|---|
| `pkg/triple_endpoint/2client_spend_tx.go` | output[0] 地址改为 `serverPublicKey`；output[1] 保持 A；删除“B 是收钱方”的注释；费用估算后清空假解锁脚本；余额不足在无符号减法前返回明确错误。 |
| `pkg/triple_endpoint/4client_spend_tx_update.go` | `TripleFeePoolLoadTx` 只更新固定两输出的金额、序号和可选 locktime；每次返回前清空旧解锁脚本和 SourceTx 临时状态；验证输出数量、脚本、总额和目标金额，禁止依赖输入交易中残留签名。 |
| `pkg/triple_endpoint/4client_spend_tx_update.go` 中仲裁函数 | V1 路径不得使用 `TripleFeePoolLoadArbitrationTx`；函数可以为未来 major version 保留，但必须修正仲裁者地址为 B 并明确不属于本次 V1 API。不得用 `arbiterFee=0` 模拟无费用。 |
| `pkg/triple_endpoint/5server_sign_update.go` | 注释和参数语义改为 `server=卖方`；保留纯 server 单签，不再把 server 称为 arbiter。 |
| `pkg/triple_endpoint/2client_spend_tx.go`、`3server_sign.go`、`5server_sign_update.go` | 对齐 server/A/B 的单签入口；所有入口都验证私钥确实对应指定槽位，交易输入 SourceTxOutput 与同一池一致。 |
| `pkg/triple_endpoint/script.go` | 增加角色明确的 `server+A` 和 `server+B` 合并函数，内部固定签名顺序；拒绝空签名、重复签名和角色错位。go-bitfs 不直接调用无角色语义的通用合并函数。 |
| `pkg/triple_endpoint/6verify.go` | 增加/整理 server、A、B 对同一无解锁脚本状态交易的独立验签函数；验证结束必须恢复输入临时 SourceTxOutput，不得污染调用方对象。 |
| `pkg/triple_endpoint/fee.go`（新增） | 用整数费率定义唯一交易费计算和舍入规则；初始状态、累计更新、关闭、仲裁共用同一纯函数。禁止 `float64` 在公共协议路径中决定聪金额。 |
| `pkg/triple_endpoint/state.go`（新增或等价文件） | 提供只依赖公开材料的纯状态构造/校验 API。卖方必须能在没有 A 私钥时构造仲裁候选交易；构造函数返回空解锁脚本交易。 |
| `pkg/index.go` | 只导出角色明确的 canonical API、输入类型和错误；把旧的含混 API 标记 deprecated 或从新 major API 移除。 |
| `pkg/libs/multisig.go` | 如需调整，只负责通用 P2MS 单签与合签原语；不得写入 BitFS 价格、仲裁或角色业务。 |
| `pkg/triple_endpoint/*_test.go` | 新增固定角色、输出脚本、费用、空解锁脚本、三种单签、两种合签和负例测试。 |
| `examples/online_triple_test/main.go` 及 triple 示例 | 示例统一改成 server=卖方、A=买方、B=仲裁者；删除把 B 称为 server/收款方或把 server 称为 arbiter 的内容。 |
| `go.mod`、`go.sum` | 清理依赖并保证干净 checkout 下 `-mod=readonly` 可构建测试；发布不可变版本，建议提升到新的 minor/major tag。 |

### 5.2 MultisigPool 必须提供的能力契约

函数名可以按仓库风格调整，但能力不得缺失：

```text
BuildTriplePoolLock(serverPub, aPub, bPub)
BuildTriplePoolInitialState(..., integerFeeRate)
BuildTriplePoolState(previousState, sequence, sellerAmountAfter, integerFeeRate)
BuildTriplePoolFinalState(previousState, sellerAmountAfter, integerFeeRate)

SignTriplePoolAsServer(unsignedTx, source, serverPrivateKey, aPub, bPub)
SignTriplePoolAsA(unsignedTx, source, serverPub, aPrivateKey, bPub)
SignTriplePoolAsB(unsignedTx, source, serverPub, aPub, bPrivateKey)

VerifyTriplePoolServerSignature(...)
VerifyTriplePoolASignature(...)
VerifyTriplePoolBSignature(...)

MergeTriplePoolServerA(unsignedTx, serverSig, aSig)
MergeTriplePoolServerB(unsignedTx, serverSig, bSig)
VerifyTriplePoolState(...)
```

这些 API 应为纯函数或显式输入输出函数，不建立持有可变交易状态的中心对象。

## 6. go-bitfs 仓库施工

### 6.1 依赖和删除第二套实现

| 文件 | 必须完成的修改 |
|---|---|
| `go.mod`、`go.sum` | 增加 `github.com/bsv8/MultisigPool` 的直接、不可变版本依赖；版本必须包含第 5 节全部修正；禁止最终提交保留本地 `replace`。 |
| `pool/bsv_engine.go` | 删除。不得保留 build tag、legacy 副本或备用引擎。 |
| `pool/bsv_engine_test.go` | 删除，以 MultisigPool 适配和跨仓 fixture 测试替代。 |
| `pool/multisigpool.go`（新增） | 只做 go-bitfs 数据结构与 MultisigPool 类型转换、角色调用编排和错误映射；禁止出现手写 P2MS opcode、sighash、P2PKH 输出、矿工费公式或签名排序算法。 |
| `pool/multisigpool_test.go`（新增） | 使用 MultisigPool 固定 fixture 验证适配层不改字节、不换角色、不重算金额。 |

go-bitfs 可以直接使用 go-sdk 的 `ec.PrivateKey`/`ec.PublicKey` 作为 MultisigPool 边界类型，但除 MultisigPool 适配器外，不得直接使用 go-sdk 的 transaction、script、sighash API 实现费用池规则。

### 6.2 pool 数据模型和端口

| 文件 | 必须完成的修改 |
|---|---|
| `pool/types.go` | 把 `OpeningProof` 补齐 server/A/B 公钥和整数矿工费率，使每份证明可独立调用 MultisigPool；删除由 go-bitfs 自己解释交易规则的字段和 `MinerFeeSat` 输入；将 `ContentRequestTermsHash` 全部改为最终授权哈希语义。 |
| `pool/types.go` | 拆除宽泛的 `TransactionEngine` 第二真值接口，改为 MultisigPool 薄适配所需的角色明确端口。业务凭证签名可继续使用通用 `Signer`；费用池交易签名改用只在进程内返回本角色 `*ec.PrivateKey` 的密钥提供端口。 |
| `pool/clones.go` | 跟随新对象字段更新深拷贝，私钥不得进入任何 clone、CBOR 或 store 对象。 |
| `pool/cbor.go`、`pool/cbor_test.go` | 更新开池证明和 005 编码；005 固定为授权哈希、空解锁脚本状态交易、A 签名；严格拒绝旧 major、尾随数据、错误长度和非确定编码。 |
| `pool/opening.go`、`pool/opening_ports.go` | 用 MultisigPool 完成资金池脚本、初始远期状态、A/server 预签和完整退款交易校验；保持“退款签完并持久化后才广播资金交易”的顺序。 |
| `pool/memory.go`、`pool/file_store.go` | 更新持久化 schema、幂等键和比较逻辑；启动时发现旧 schema 必须明确报错并停止，不得猜测迁移。 |
| `pool/node_adapter.go` | 保留后端注入；把提交前的交易校验改成 MultisigPool 校验；后端接受结果与本地 txid/序号不一致时继续硬失败。 |
| `pool/*_test.go` | 删除所有以 `BSVEngine` 为基准的断言，改为以 MultisigPool fixture 和公共 API 为基准。 |

密钥提供端口必须满足：

- 买方进程只能取得 A 私钥；
- 卖方进程只能取得 server 私钥；
- 仲裁进程只能取得 B 私钥；
- 私钥不进入 CBOR、日志、数据库、WoC/RPC 请求或错误消息；
- 密钥不可用或角色不匹配时直接失败，不回退到自建签名算法。

### 6.3 最终授权和内容协议

| 文件 | 必须完成的修改 |
|---|---|
| `bitfs/content.go` | 将 003 改为第 3.1 节的最终付款授权；编码、哈希、签名、验证和 clone 使用新字段；买卖双方正常路径仍可验证 001/seed/内容关系，仲裁验证入口不得要求这些对象。 |
| `bitfs/content_test.go` | 增加累计金额、序号、角色、池、费率被篡改后买方签名失败的测试；增加最后授权可脱离 001/004 单独验签的测试。 |
| `bitfs/messages.go`、`bitfs/ticket.go`、`bitfs/arbitration.go`、`bitfs/clone_legacy.go` 及对应测试 | 删除或收编旧 `HashGetTicket`/旧仲裁模型。只允许保留一种 canonical 最终授权，禁止 legacy 与新 003 同时作为有效仲裁票据。 |
| `bitfs/quote.go` | 正常签发授权前仍验证报价；明确报价不是仲裁输入。 |
| `bitfs/errors.go` | 增加稳定的授权冲突、角色错位、金额不符、费率不符错误；错误消息使用英文。 |

### 6.4 买方、卖方和仲裁者工作流

| 文件 | 必须完成的修改 |
|---|---|
| `buyer/client.go` | `RequestContent` 在签名之前读取最新接受状态、计算本次价格和目标累计金额，并签出最终授权；`AcceptDelivery` 不重新决定另一份金额真值，而是用 MultisigPool 按授权构造交易并产生 A 签名。 |
| `buyer/runtime.go` | 注入买方业务凭证 signer 和 A 私钥提供者；二者职责明确，不得把私钥序列化。 |
| `seller/service.go` | 交付前验证授权中的绝对累计金额、序号、角色、费率和余额并持久化门闩；正常 005 用 MultisigPool 验 A 签名、签 server、按 server+A 合并。 |
| `seller/service.go` | 完全重写 `BuildArbitrationRequest`：输入是最后授权和当前接受状态，而不是买方已签 005；卖方调用 MultisigPool 构造候选交易并产生 server 签名。 |
| `seller/service.go` | 重写 `SubmitArbitratedPayment`：复核授权哈希、无解锁脚本交易哈希和 B 签名，按 server+B 合并并提交。 |
| `seller/runtime.go` | 注入 server 私钥提供者和节点后端；删除旧 BSVEngine 装配。 |
| `arbiter/types.go` | 按第 3.3 节重建请求、响应、CBOR 和服务；只验证最后授权、池上下文、候选交易和 server 签名；使用 B 私钥签名。 |
| `arbiter/types_test.go`（新增或重写） | 覆盖最小请求成功、缺少授权、错误买方签名、错误 B、篡改金额/序号/交易、错误 server 签名、夹带第三输出、响应重放等负例。 |

### 6.5 wire、结算、集成与文档

| 文件 | 必须完成的修改 |
|---|---|
| `wire/wire.go`、`wire/wire_test.go` | 更新 003、005、007 的对象类型和新 major；旧 payload 必须明确拒绝，不能尝试两种 schema。 |
| `settlement/*.go`、`settlement/*_test.go` | 检查是否重复承担交易签名或关闭构造；凡属于费用池链上语义的代码改为 MultisigPool 调用，结算包只保留消息编排和持久化职责。 |
| `integration/new_protocol_test.go` | 重写完整开池、授权、交付、正常支付、买方拒签后的卖方仲裁、到期退款和协商关闭流程。仲裁成功用例不得创建买方本次交易签名。 |
| `integration/transaction_test.go` 及其他集成测试 | 移除旧决策签名、旧仲裁金额和旧引擎假对象；测试端不得复制交易实现来制造期望结果。 |
| `README.md` | 删除 `pool.BSVEngine` 描述；说明 MultisigPool 是唯一交易真值，WoC/节点仍注入。 |
| `docs/protocol/002-*` | 固定 server/A/B、整数矿工费率、退款预签和 MultisigPool 交易语义。 |
| `docs/protocol/003-*` | 把 003 定义为最终累计付款授权；明确签票形成可仲裁义务。 |
| `docs/protocol/004-*` | 保留正常买方验货语义；删除“仲裁必须提交 004/证明送达”的要求。 |
| `docs/protocol/005-*` | 改为授权哈希 + 空解锁交易 + A 签名；正常支付使用 server+A。 |
| `docs/protocol/006-*` | 关闭和退款统一使用 MultisigPool server+A。 |
| `docs/protocol/007-*` | 完全改写为最后授权 + 卖方候选交易 + server 签名；仲裁者只验不构造，使用 server+B，无仲裁服务费。 |
| `docs/sdk/*.md` | 公共 API、端口、数据类型和示例同步更新；删除第二引擎、买方已签 005 仲裁和全证据包描述。 |
| `docs/legacy/*` | 保留时必须加醒目的“历史、不可用于当前实现”声明；任何测试和当前文档不得链接其作为真值。 |

## 7. 同一次迭代内的执行顺序

本次没有可发布的中间状态，但施工时必须遵守以下依赖顺序：

1. 在 MultisigPool 修正 triple 角色、输出、费用、空解锁脚本、角色签名和合并 API。
2. 为 MultisigPool 建立固定 fixture 和负例，干净 checkout 全部通过后生成不可变提交/tag。
3. 在 go-bitfs 一次性更新 003/005/007 CBOR、pool 数据模型和密钥端口。
4. 新建 MultisigPool 薄适配，切换开池、正常付款、仲裁、退款和关闭。
5. 删除 `BSVEngine`、旧票据/仲裁模型和所有兼容装配。
6. 更新存储 schema、wire、角色服务、文档和集成测试。
7. 在两个仓库分别从干净 checkout 验收，再做跨仓 fixture 和端到端验收。
8. 两仓变更和协议 major 同时发布；任一部分未完成都不得发布另一部分。

## 8. 明确禁止的做法

- 禁止保留 `BSVEngine` 作为 fallback、legacy build tag、测试辅助实现或“临时兼容”。
- 禁止 go-bitfs 自行拼 P2MS/P2PKH 脚本、自算 sighash、自排签名、自算矿工费。
- 禁止用 `TripleFeePoolLoadArbitrationTx(..., arbiterFee=0, ...)` 表示无仲裁费。
- 禁止创建 0 sat 仲裁费 output、OP_RETURN 仲裁证明输出或第三个价值输出。
- 禁止映射为 `server=仲裁者`、`B=卖方`，也禁止按运行时场景交换槽位。
- 禁止让仲裁者构造、修改、重新定价或自动修复卖方候选交易。
- 禁止要求仲裁请求携带 001、004、payload 或全部历史证据。
- 禁止把买方本次 005 签名作为卖方拒付仲裁前提。
- 禁止让 003 只签报价哈希而不签目标累计金额，然后要求仲裁者回查报价。
- 禁止同时接受旧、新 CBOR major，禁止静默升级旧持久化对象。
- 禁止最终 `go.mod` 使用本地路径 `replace`，禁止依赖脏工作区中的 `go.sum` 才能构建。
- 禁止节点失败时只更新本地数据库，或本地校验失败时仍向节点提交。
- 禁止以日志、错误、CBOR、store 或 RPC 传递私钥。

## 9. 特殊情况处理

| 情况 | 唯一处理方式 |
|---|---|
| MultisigPool 尚未完成 server 收款修正或没有干净 tag | 停止 go-bitfs 集成；不得在 go-bitfs 适配层补丁式改输出。 |
| 发现存量旧协议费用池 | 停止新版本部署；先用旧版本完成关闭/到期退款并清空活动池。新版本不读取、不续用、不迁移旧池。 |
| 启动时发现旧 CBOR/store schema | 返回明确版本错误并停止相关服务；不得猜字段、默认补值或双解码。 |
| 授权的 base sequence 已过时 | 卖方拒绝交付和仲裁；买方基于最新接受状态重新签一张新授权。禁止自动 rebase 旧签名。 |
| 同池已有未完成授权 | 返回 pool busy；只允许完全相同授权哈希的幂等重试，其他授权一律冲突。 |
| 授权金额不足、溢出或余额不足以覆盖矿工费 | 在卖方交付前拒绝；不得减少卖方金额、提高买方输入、吞掉手续费或生成负找零。 |
| 授权费率与开池费率不一致 | 拒绝授权；不得选择两者之一继续执行。 |
| 授权已过 `delivery_deadline_unix` 才首次到达卖方 | 卖方拒绝交付。 |
| 已在期限内接受的授权稍后发起仲裁 | 仲裁者不以当前墙钟重新判定交付期限；`delivery_deadline_unix` 不是仲裁证据失效时间。未来若需仲裁时效，必须新增签名字段并升级 major。 |
| 卖方提交的候选交易与授权有任一字节语义不符 | 仲裁者拒绝并返回稳定错误；不得修改后替卖方签名。 |
| 候选交易带旧/假解锁脚本 | 拒绝；卖方必须重新调用 MultisigPool 得到空解锁脚本模板。 |
| server、A、B 任一私钥与槽位不符或不可用 | 立即失败；不尝试其他槽位、不调用通用签名兜底。 |
| 仲裁响应哈希不匹配当前请求 | 按重放或错配拒绝；不得尝试把 B 签名合并到另一交易。 |
| 非最终节点超时或拒绝 | 不推进已接受状态，不释放能支持安全重试的授权材料；向调用方暴露错误。 |
| 节点声称接受但 txid、序号或状态不一致 | 视为后端协议错误并停止该池处理，进入人工/外部状态核对；不得本地猜测成功。 |
| 提交成功但本地持久化失败 | 标记该池需要外部状态核对并停止新购买；通过注入后端核对后恢复，不得沿用旧本地状态继续签名。 |
| 未来提出池内仲裁服务费 | 拒绝在本版本追加；单独设计费率查询、报价时效、扣费方、余额不足和输出布局，升级协议 major。 |

## 10. 最终验收清单

以下项目必须全部勾选；任一项失败即视为整次硬切换未完成。

### 10.1 MultisigPool 仓库

- [ ] 三方锁定脚本公钥顺序严格为 `[server=卖方, A=买方, B=仲裁者]`。
- [ ] 初始状态、累计状态、仲裁状态和关闭状态的 output[0] 都支付 server，output[1] 都支付 A。
- [ ] 所有 V1 状态交易只有两个价值输出，不存在 B 收款或 0 sat 仲裁费输出。
- [ ] 构造/更新 API 返回的候选交易解锁脚本为空，不残留 fake 或旧签名。
- [ ] 卖方仅凭公开池材料即可构造仲裁候选交易，不需要 A 私钥或 B 私钥。
- [ ] server、A、B 三种单签分别通过，错误槽位私钥分别失败。
- [ ] `server+A` 与 `server+B` 合并交易分别通过脚本验证，反序和错配签名失败。
- [ ] 矿工费只使用一个整数算法，边界和舍入有 fixture。
- [ ] 输入不足、输出数错误、脚本被换、金额溢出、序号倒退均明确失败。
- [ ] triple 示例、注释和导出 API 不再把 server 称为 arbiter 或把 B 称为收款方。
- [ ] `go test -mod=readonly -count=1 ./...` 在干净 checkout 通过。
- [ ] `go vet -mod=readonly ./...` 在干净 checkout 通过。
- [ ] `git status --short` 在验收构建前后均无生成性脏文件。
- [ ] 已产生 go-bitfs 可锁定的不可变 commit/tag，且 `go.sum` 完整。

### 10.2 go-bitfs 依赖与代码边界

- [ ] `go.mod` 直接依赖合格的 MultisigPool commit/tag，且无本地 `replace`。
- [ ] `pool/bsv_engine.go`、`BSVEngine` 构造器和所有引用均已删除。
- [ ] 搜索 transaction/script/sighash 实现后，不存在 go-bitfs 自建费用池算法。
- [ ] go-bitfs 费用池适配器只转换参数和调用 MultisigPool，不复制库逻辑。
- [ ] 业务 signer 与 server/A/B 私钥提供端口职责分离，私钥不进入可序列化对象。
- [ ] `NonFinalPoolBackend` 仍可注入，代码中没有固定 WoC/RPC 地址。

### 10.3 协议与仲裁

- [ ] 003 最终授权签入 pool、base/target sequence、绝对累计卖方金额、整数费率和 server/A/B。
- [ ] 修改授权的任一经济或角色字段都会使买方签名验证失败。
- [ ] 仲裁者只凭最后授权完成业务判断，不读取 001、004、payload 或历史付款链。
- [ ] 卖方拒付仲裁成功用例中不存在买方对本次状态交易的签名。
- [ ] 卖方构造并签 server；仲裁者只验证并签 B；最终严格按 server+B 合并。
- [ ] 仲裁者无法修改金额、序号、输出、费率或交易后继续复用原请求。
- [ ] 仲裁请求没有仲裁费字段，交易没有仲裁费输出。
- [ ] 正常付款继续使用 server+A，仲裁路径不会被普通 005 意外触发。
- [ ] 旧 007“买方已签 005 后仲裁”的代码、文档和测试全部删除。
- [ ] 旧 `HashGetTicket` 和新最终授权没有并存为两套有效真值。

### 10.4 端到端行为

- [ ] 开池退款交易在资金交易广播前完成 A/server 双签和持久化。
- [ ] 正常路径完成：报价 → 最终授权 → 交付 → A 签名 → server 签名 → 非最终节点接受。
- [ ] 仲裁路径完成：最终授权 → 交付 → 买方拒签 → server 构造/签名 → B 验证/签名 → 节点接受。
- [ ] 到期退款完成且使用 server+A。
- [ ] 协商关闭完成且使用 server+A，序号和 locktime 为最终值。
- [ ] stale sequence、同池并发、余额不足、费率不符、角色错位、签名错配、节点拒绝均有端到端负例。
- [ ] 后端失败时本地接受状态不前进；后端结果不一致时硬失败。
- [ ] 同一输入 fixture 在 MultisigPool 与 go-bitfs 得到相同锁定脚本、状态交易、输出、序号、locktime、费用和签名验证结果。

### 10.5 编码、存储、文档和构建

- [ ] 002/003/005/007 新 CBOR 均为 deterministic encoding，round-trip 字节完全一致。
- [ ] 新代码明确拒绝旧 major、尾随数据、未知字段和非确定编码。
- [ ] 存储层能识别新 schema，遇到旧活动池明确停止，不静默迁移。
- [ ] README、protocol、SDK 文档、Go 注释和示例对角色、授权和仲裁的表述完全一致。
- [ ] `rg "BSVEngine|server.*arbiter|output\[0\].*B|LatestPaymentStateCBOR|ArbiterFeeSat"` 的剩余命中逐条审核，当前实现路径中应为零。
- [ ] `go test -count=1 ./...` 通过。
- [ ] `go test -race -count=1 ./...` 通过。
- [ ] `go vet ./...` 通过。
- [ ] 从干净 checkout、空 module cache 条件完成一次依赖下载和全量测试。

## 11. 完成定义

只有当两个仓库的修改、不可变依赖版本、协议文档、存储版本、跨仓 fixture、正常支付和买方拒签仲裁端到端测试同时通过时，本施工单才算完成。

“go-bitfs 已能调用 MultisigPool”不等于完成；只要 go-bitfs 仍保留第二套脚本、费用、签名、金额或仲裁真值，均判定硬切换失败。
