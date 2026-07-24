# go-bitfs

BitFS v1 的 Go 协议真值库，覆盖文件交换、自动仲裁与 2-of-3 费用池结算。

正式 wire schema 位于 [`spec/v1/bitfs.cddl`](spec/v1/bitfs.cddl)，并使用严格 deterministic CBOR 编码；业务语义位于 [`spec/v1/protocol.md`](spec/v1/protocol.md)。BitFS 不定义发现或网络传输，队列、WebSocket、TCP、libp2p 等适配器只负责投递同一组 CBOR bytes。

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
