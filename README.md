# go-bitfs

BitFS v1 的 Go 协议真值库，覆盖文件交换、自动仲裁与 2-of-3 费用池结算。

历史兼容 wire schema 位于 [`spec/v1/bitfs.cddl`](spec/v1/bitfs.cddl)，并使用严格 deterministic CBOR 编码；其中旧 `HashGetTicket` 会话模型已不再是新施工依据。当前业务语义以本 README 下的 001–006 编号文档为准。BitFS 不定义发现或网络传输，队列、WebSocket、TCP、libp2p 等适配器只负责投递同一组 CBOR bytes。

协议按业务顺序编号；每一步都有供实现对照的规范和解释设计意图的需求文档：

| 编号 | 施工规范 | 需求与业务意图 |
|---:|---|---|
| 001 | [`报价凭证`](docs/001-报价凭证规范.md) | [`报价凭证需求`](docs/001-报价凭证需求.md) |
| 002 | [`费用池开池`](docs/002-费用池开池规范.md) | [`费用池开池需求`](docs/002-费用池开池需求.md) |
| 003 | [`内容获取请求`](docs/003-内容获取请求规范.md) | [`内容获取请求需求`](docs/003-内容获取请求需求.md) |
| 004 | [`内容交付凭证`](docs/004-内容交付凭证规范.md) | [`内容交付凭证需求`](docs/004-内容交付凭证需求.md) |
| 005 | [`累计支付`](docs/005-累计支付规范.md) | [`累计支付需求`](docs/005-累计支付需求.md) |
| 006 | [`费用池无条件关闭`](docs/006-费用池无条件关闭规范.md) | [`费用池关闭需求`](docs/006-费用池关闭需求.md) |
| 007 | [`卖方仲裁提交`](docs/007-卖方仲裁提交规范.md) | [`卖方仲裁提交需求`](docs/007-卖方仲裁提交需求.md) |

001 的正式 CDDL 位于 [`spec/file-quote.cddl`](spec/file-quote.cddl)，002 的正式 CDDL 位于 [`spec/v1/settlement.cddl`](spec/v1/settlement.cddl)。003–006 已记录施工约束；005 已定义 BSV 非最终交易池覆盖拓扑和 CBOR 传输容器，原始 BSV 交易字节仍按 Bitcoin 交易序列化规则编码。

面向应用开发者的公开 Go API 蓝图见 [`SDK API 框架设计`](docs/SDK-API框架设计.md)。它定义角色工作流、外部存储/签名/节点钩子及后续实施顺序；当前仅为设计文档，尚未开始该框架的代码迁移。

执行测试：

```bash
go test ./...
```

目录职责：

- `bitfs/`：CBOR 报文、seed、哈希、票据签名与证据校验；
- `buyer/`、`seller/`：不绑定网络的买卖工作流；
- `arbiterclient/`：仲裁工作流的本地端口包装；
- `demo/arbiter/`：只用于测试和标准演示的内存仲裁处理器；
- `settlement/`：独立的 CBOR 结算协议；当前结算机制使用 2-of-3。
