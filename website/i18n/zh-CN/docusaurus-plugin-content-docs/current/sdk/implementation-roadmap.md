---
id: implementation-roadmap
title: 04 · 实施路线
---

# 04 · 实施路线

返回 [BitFS SDK API 框架](sdk-api-framework-design.md)。

1. `wire`、`bitfs` 中的 001/003/004、`pool` 中的 002/005/006、`arbitration` 中的 007，实现确定性 CBOR、严格解码与证据验证。
2. MultisigPool 是支付池交易的唯一实现，涵盖 `SIGHASH_ALL|FORKID`、2-of-3 脚本、累计付款、最终关闭和退款到期检查。退款到期验证在内部读取一次系统 UTC，并显式接收调用方提供的区块高度；SDK 不访问节点。
3. 角色 workflow（`buyer`、`seller`、`arbitration`）只持有 `WorkflowConfig{PrivateKey}` 传入的官方 BSV 私钥。每个方法都显式接收业务输入（报价、开池证据、上一笔付款状态、交付上下文、内容字节、seed、区块高度），只返回计算得到的 wire 报文、原始交易、已验证证据以及需要应用自行持久化的本地角色状态。
4. 端到端测试覆盖完整 001–007 生命周期，测试代码扮演调用方应用：所有中间状态保存在测试变量中并逐次显式传给 SDK。
5. SDK 不提供任何存储适配器。生产部署在自己的技术栈中实现持久化、串行化、outbox 与节点对账；这些按设计属于应用关注点，而不是未来的 SDK 工作项。
