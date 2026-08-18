# BitFS 协议 Demo

这些 demo 按协议步骤编号，目标是观察每个报文、签名和状态变化。所有程序都输出较多调试信息；二进制报文和交易使用 hex 显示，方便复制、保存和对照源码。

## 步骤目录

| 步骤 | 目录 | 含义 |
|---|---|---|
| 001 | [`01_quote`](./01_quote/) | 生成并解析 `SignedFileQuote` 报价单 |
| 002 | [`02_pool_opening`](./02_pool_opening/) | 买卖双方开启费用池 |
| 003 | [`03_content_request`](./03_content_request/) | 买家构造文件内容请求 |
| 004 | [`04_content_delivery`](./04_content_delivery/) | 卖家根据请求交付内容 |
| 005 | [`05_cumulative_payment`](./05_cumulative_payment/) | 买家确认交付并完成累计付款 |
| 006 | [`06_pool_close`](./06_pool_close/) | 双方协商关闭费用池 |
| 007 | [`07_arbitration`](./07_arbitration/) | 发生争议时由仲裁人签署付款 |

大多数步骤下面的 `01_...` 是该步骤的完整观察命令。002 是报文流动示例，特意拆成 `0201_...` 到 `0205_...`，每个程序只执行一个角色的一次业务动作，并用 stdin/stdout 传递报文或本地状态。002 的 0201 还会在 demo 层通过 JungleBus 地址历史和交易原文重建真实 UTXO；`BITFS_NETWORK` 缺省为 testnet，详情见 [`02_pool_opening`](./02_pool_opening/)。

## 公共环境和测试数据

```sh
cp demo/.env.example demo/.env
```

`demo/.env` 包含卖家、买家、仲裁人的私钥，以及文件路径和报价参数。它被 git 忽略。`demo/file.bin` 是用于观察的随机 10 MiB 文件。

后续 demo 使用内存中的模拟 backend，不连接 BSV 网络；002 的细分命令另外使用临时 FileStore 保存跨进程的开池证据。除 002 外，每个命令会重新创建一套 fixture，并在内存中重放它前面需要的协议状态，因此可以从任意一步单独运行。

建议按编号阅读并运行：先看 001 了解报价报文，再看 003 了解买家如何表达文件需求，最后看 004–007 如何交付、付款、关闭和仲裁。
