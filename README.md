# go-bitfs

BitFS v2 的 Go 协议真值库，覆盖文件交换、自动仲裁与 2-of-3 费用池结算。

历史兼容 wire schema 位于 [`spec/v1/bitfs.cddl`](spec/v1/bitfs.cddl)，不可用于当前协议。当前 v2 业务语义以本 README 下的 001–007 编号文档和对应 CDDL 为准，并使用严格 deterministic CBOR 编码。BitFS 不定义发现或网络传输，队列、WebSocket、TCP、libp2p 等适配器只负责投递同一组 CBOR bytes。

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

001 的正式 CDDL 位于 [`spec/file-quote.cddl`](spec/file-quote.cddl)，002 的正式 CDDL 位于 [`spec/v1/pool.cddl`](spec/v1/pool.cddl)，003/004 位于 [`spec/v1/content.cddl`](spec/v1/content.cddl)，005 位于 [`spec/v1/payment.cddl`](spec/v1/payment.cddl)，007 位于 [`spec/v1/arbitration.cddl`](spec/v1/arbitration.cddl)；这些文件当前只描述 major 2，目录名因历史兼容保留。005 同时定义 BSV 非最终交易池覆盖拓扑，原始 BSV 交易字节仍按 Bitcoin 交易序列化规则编码。交易脚本、费用、签名和状态构造的唯一真值是发布版 MultisigPool，节点/WoC 仍通过接口注入。

面向应用开发者的公开 Go API 设计见 [`SDK API 框架设计`](docs/sdk/SDK-API框架设计.md)，对应代码已拆成 `buyer.Client`、`seller.Service`、`pool`、`arbiter` 和 `wire` 包。费用池交易语义由 MultisigPool 提供，数据库、钱包和非最终交易池仍通过接口注入。

执行测试：

```bash
go test ./...
```

目录职责：

- `bitfs/`：报价、003/004 内容凭证、seed、哈希和证据校验；
- `pool/`：独立的 002/005/006 费用池状态机、交易引擎、持久化端口和内存参考实现；
- `buyer/`、`seller/`：v2 协议角色工作流；历史会话运行时已从当前构建删除；
- `arbiter/`、`wire/`：007 仲裁证据签名服务和新协议报文分派。
