# BitFS 协议 Demo

这些 demo 按协议步骤编号，目标是观察每个报文、签名和状态变化。所有程序都输出较多调试信息；二进制报文和交易使用 hex 显示，方便复制、保存和对照源码。

## 责任边界：SDK 无状态、无基础设施副作用

go-bitfs SDK 是无状态的 BitFS Wire Protocol v1 协议库：角色 workflow 只持有构造时固定的受约束 Signer（本地软件私钥经 `protocol.NewPrivateKeySigner` 进入），每个方法都是「显式输入 + 显式事实 → 计算结果」，不加载、不保存、不发送、不广播任何状态；时间与区块高度由调用方以 `protocol.Facts{Now, BlockHeight}` 显式传入，SDK 不读系统时钟、不查节点。数据库/文件存储、事务与锁、并发串行化、重试/幂等、节点广播与链上对账全部属于调用方应用。

为了让多个独立命令能够衔接运行，demo 自己实现了一些最简持久化：002 使用 `DEMO_02_STATE_DIR` 下的 JSON checkpoint，其余步骤使用进程内的内存 fixture。这些只是示例应用行为，不是 SDK 能力，也不构成生产建议。checkpoint 是直接整文件写入的简单示例：没有原子性保证，不承诺并发、事务或崩溃安全；真实应用应使用自己的数据库与一致性策略。

## 步骤目录

| 步骤 | 目录 | 含义 |
|---|---|---|
| 001 | [`01_quote`](./01_quote/) | 卖方签署并解析 `SignedFileQuote` 报价单（exact Artifact 先保存后发送） |
| 002 | [`02_pool_opening`](./02_pool_opening/) | 买卖双方开启费用池 |
| 003 | [`03_content_request`](./03_content_request/) | 买家构造批量内容授权（一个付款序号授权一组内容 hash） |
| 004 | [`04_content_delivery`](./04_content_delivery/) | 卖家验证整批授权后原子交付 payload 批次 |
| 005 | [`05_cumulative_payment`](./05_cumulative_payment/) | 买家全量验收批次后完成累计付款：最小凭证 = payment_authorization_id + 买家交易签名，卖家按 ID 取回原始 003、本地重建交易并合并（一个批次只生成一个凭证） |
| 006 | [`06_pool_close`](./06_pool_close/) | 双方协商关闭费用池 |
| 007 | [`07_arbitration`](./07_arbitration/) | 发生争议时由仲裁人验证托管证据并签署付费交易 |
| 008 | [`08_arbitration_content_retrieval`](./08_arbitration_content_retrieval/) | Seller/Buyer 无法直连时，Buyer 从 Arbiter 取回已托管内容（只读恢复，不产生付款凭证，不关池） |

大多数步骤下面的 `01_...` 是该步骤的完整观察命令。002 是报文流动示例，特意拆成 `0201_...` 到 `0205_...`，每个程序只执行一个角色的一次业务动作，并用 stdin/stdout 传递 wire 报文。本地 checkpoint 与 wire 报文严格分离；跨进程关联只使用 `RefundTemplateTxID`：0203 打印、0204 只读取 `REFUND_TEMPLATE_TXID_HEX`。002 的 0201 还会在 demo 层通过 JungleBus 地址历史和交易原文重建真实 UTXO；`BITFS_NETWORK` 缺省为 testnet，详情见 [`02_pool_opening`](./02_pool_opening/)。

## 公共环境和测试数据

```sh
cp demo/.env.example demo/.env
```

`demo/.env` 包含卖家、买家、仲裁人的私钥，以及文件路径和报价参数。它被 git 忽略。`demo/file.bin` 是用于观察的随机 10 MiB 文件。

除 002 外，每个命令会重新创建一套内存 fixture：fixture 扮演调用方应用，显式持有报价、开池证据、最新付款状态、内容字节等全部状态（包括每一步的 exact wire Artifact 字节与角色 checkpoint），并在每次 SDK 调用时逐个显式传入，因此可以从任意一步单独运行；SDK 不保存其中任何一项。002 的细分命令则把跨进程需要的开池证据保存在各自的 JSON checkpoint 中，同样由 demo 而不是 SDK 持有。

建议按编号阅读并运行：先看 001 了解报价报文（私钥 → Signer → 角色 workflow → 角色 API 的最小样例），再看 003 了解买家如何用一个付款序号授权一组内容 hash，最后看 004–007 如何原子交付批次、按序号恰好推进一次的累计付款、关闭和仲裁。007 中卖方用本地证据形成 Claim 并签署 Kind 8；仲裁方两阶段处理：先 `arbiter.PrepareArbitration` 完整验证（应用在此持久化托管证据），再 `SignPreparedArbitration` 基于冻结字节独立重建并签署 Kind 9，不接收开池证明或候选交易原文。008 演示 Seller/Buyer 无法直连时的只读取件：Buyer 凭池 checkpoint + 精确签名 003 构造 Kind 10（SDK 默认入口生成安全随机 nonce，超时重试必须原样重放已持久化的 Artifact）；Arbiter 验签后返回自己签名的 Kind 11——可交付分支经 `content_payloads_id` 绑定 exact payload bundle，不可交付分支携带结构化原因（typed 结果，不是 error），Buyer 收到 not_ready 后必须换新 nonce 重试；它不是关池或退款 demo。
