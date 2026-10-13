---
id: implementation-roadmap
title: 04 · 实施路线
---

# 04 · 实施路线

返回 [BitFS SDK API 框架](sdk-api-framework-design.md)。

本页描述的硬切换**已经完成**；以下条目描述的是已交付状态，而不是未来计划。

1. `wire` 通过类型化 encoder 与严格 decoder 为全部十三种 Kind 返回不可变的 exact-bytes Artifact；001/003/004 位于 `content`，002/005/006 位于 `pool`，007/008 托管证据位于 `arbitration`——确定性 CBOR、严格解码与证据验证均已完成。
2. MultisigPool 是支付池交易的唯一实现，涵盖 `SIGHASH_ALL|FORKID`、2-of-3 脚本、累计付款、最终关闭和退款到期检查。退款到期验证在每次调用时通过 `protocol.Facts` 显式接收调用方的时间与区块高度；SDK 不访问节点，也不读取时钟。
3. 角色纯函数步骤（`buyer`、`seller`、`arbiter`）每次调用接收受约束 Signer（本地软件私钥的唯一入口是 `protocol.NewPrivateKeySigner`）。每个入口都显式接收原始报文字节与业务输入（报价字节、普通池证据、交付上下文、内容字节、seed）加一份显式 Facts，只返回计算得到的 Artifact、交易原文和需要应用自行持久化的普通证据包。
4. 端到端测试覆盖完整 001–008 生命周期，测试代码扮演调用方应用：所有中间状态保存在测试变量中并逐次显式传给 SDK；另有 documented-API 冒烟测试编译 README 风格的主路径片段，保证指南不会与真实签名漂移。
5. SDK 不提供任何存储适配器。生产部署在自己的技术栈中实现持久化、串行化、outbox 与节点对账；这些按设计属于应用关注点，而不是未来的 SDK 工作项。
