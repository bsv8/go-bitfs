# go-bitfs

BitFS v1 的 Go 协议真值库，覆盖文件交换、自动仲裁与 2-of-3 费用池结算。

正式规范见 [docs](docs/)；所有 wire 对象以 `proto/` 为准。生成 proto 后执行：

```bash
go test ./...
```

目录职责：

- `bitfs/`：协议真值、seed、哈希、票据签名与证据校验；
- `buyer/`：报价服务端、取货与付款客户端；
- `seller/`：主动报价客户端、票据与交付服务端；
- `arbiterclient/`：买卖双方使用的正式仲裁客户端；
- `demo/arbiter/`：只用于测试和标准演示的内存仲裁服务端，能走完整两阶段 pool 收尾。
