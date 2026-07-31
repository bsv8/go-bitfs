# go-bitfs

BitFS v1 的 Go 协议真值库，覆盖文件交换、自动仲裁与 2-of-3 费用池结算。

历史兼容 wire schema 位于 [`spec/v1/bitfs.cddl`](spec/v1/bitfs.cddl)，并使用严格 deterministic CBOR 编码；其中旧 `HashGetTicket` 会话模型已不再是新施工依据。当前业务语义以本 README 下的 001–007 编号文档为准。BitFS 不定义发现或网络传输，队列、WebSocket、TCP、libp2p 等适配器只负责投递同一组 CBOR bytes。

协议按业务顺序编号；每一步都有供实现对照的规范和解释设计意图的需求文档：

| 编号 | 施工规范 | 需求与业务意图 |
|---:|---|---|
| 001 | [`报价凭证`](docs/protocol/001-报价凭证规范.md) | [`报价凭证需求`](docs/protocol/001-报价凭证需求.md) |
| 002 | [`费用池开池`](docs/protocol/002-费用池开池规范.md) | [`费用池开池需求`](docs/protocol/002-费用池开池需求.md) |
| 003 | [`内容获取请求`](docs/protocol/003-内容获取请求规范.md) | [`内容获取请求需求`](docs/protocol/003-内容获取请求需求.md) |
| 004 | [`内容交付凭证`](docs/protocol/004-内容交付凭证规范.md) | [`内容交付凭证需求`](docs/protocol/004-内容交付凭证需求.md) |
| 005 | [`累计支付`](docs/protocol/005-累计支付规范.md) | [`累计支付需求`](docs/protocol/005-累计支付需求.md) |
| 006 | [`费用池无条件关闭`](docs/protocol/006-费用池无条件关闭规范.md) | [`费用池关闭需求`](docs/protocol/006-费用池关闭需求.md) |
| 007 | [`卖方仲裁提交`](docs/protocol/007-卖方仲裁提交规范.md) | [`卖方仲裁提交需求`](docs/protocol/007-卖方仲裁提交需求.md) |

001 的正式 CDDL 位于 [`spec/file-quote.cddl`](spec/file-quote.cddl)，002 的正式 CDDL 位于 [`spec/v1/pool.cddl`](spec/v1/pool.cddl)，003/004 位于 [`spec/v1/content.cddl`](spec/v1/content.cddl)，005 位于 [`spec/v1/payment.cddl`](spec/v1/payment.cddl)，007 位于 [`spec/v1/arbitration.cddl`](spec/v1/arbitration.cddl)。005 同时定义 BSV 非最终交易池覆盖拓扑，原始 BSV 交易字节仍按 Bitcoin 交易序列化规则编码。新协议的数字版本在 `pool.ProtocolFamily` / `wire.ProtocolFamily` 命名空间内解释；`settlement.ProtocolFamily` 是独立的 legacy 兼容族，即使两者数字版本都为 1，也不得混用。

面向应用开发者的公开 Go API 设计见 [`SDK API 框架设计`](docs/sdk/SDK-API框架设计.md)，对应代码已拆成 `buyer.Client`、`seller.Service`、`pool`、`arbiter` 和 `wire` 包。费用池交易语义由 MultisigPool 提供，数据库、钱包和非最终交易池仍通过接口注入。

执行测试：

```bash
go test ./...
```

legacy 兼容路径单独验证：

```bash
go test -tags legacy ./...
```

目录职责：

- `bitfs/`：报价、003/004 内容凭证、seed、哈希和证据校验；
- `pool/`：独立的 002/005/006 费用池状态机、交易引擎、持久化端口和内存参考实现；
- `buyer/`、`seller/`：新协议角色工作流；旧 V1 会话运行时已从当前构建删除；
- `arbiter/`、`wire/`：007 仲裁证据签名服务和新协议报文分派；
- `arbiterclient/`、`demo/arbiter/`、`settlement/`：旧协议兼容或演示代码，默认构建不会编译，使用 `-tags legacy` 启用；不能作为新协议状态真值，新协议代码不得依赖它们。
