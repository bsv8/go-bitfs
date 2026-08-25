---
id: sdk-api-framework-design
title: BitFS SDK API 框架
---

# BitFS SDK API 框架

go-bitfs 是 001–008 的可执行协议规范，同时是一个**无状态、无基础设施副作用的协议 SDK**：`buyer`、`seller`、`arbiter` 三个角色包中的 workflow 只持有构造时固定的受约束 Signer（`protocol.Signer`；本地软件私钥经 `protocol.NewPrivateKeySigner` 进入），对显式传入的输入执行确定性的 Build/Verify/Sign/Merge 计算。

其余一切由调用方应用提供：以 `RefundTemplateTxID` 与授权 ID 为键的持久化、事务与锁、并发串行化、重试与幂等、内容存储、点对点传输、节点广播以及多租户授权。SDK 从不加载或保存状态，从不读取或写入内容，从不广播交易，也从不查询节点或时钟——每个时间或高度敏感的调用都接收一份显式的 `protocol.Facts{Now, BlockHeight}`，SDK 只用这些事实验证协议规则。

分层如下：

```text
protocol/    共享基础：受约束 Signer 端口（+ NewPrivateKeySigner）、显式 Facts、
             typed ID、带 ErrorCode 分类的结构化错误
content/     001/003/004 凭证、seed、哈希与定价；不可变 VerifiedQuote
pool/        002/005/006 结算状态机与交易引擎；不透明 verified 值
             （VerifiedOpening、VerifiedPaymentState、VerifiedSignedTransaction）
arbitration/ 007/008 托管证据的纯领域函数（无角色状态）
wire/        类型化 encoder 与严格 decoder，返回承载 exact bytes 的不可变
             wire.Artifact
buyer/, seller/, arbiter/
             角色 workflow：唯一推荐给应用的入口路径
```

角色 workflow 是面向应用的唯一推荐表面。领域包保持公开，服务于钱包、审计与工具场景；但每一笔普通购买都应走 [03 · 角色 workflow API](role-workflow-api.md) 描述的 workflow 方法。
