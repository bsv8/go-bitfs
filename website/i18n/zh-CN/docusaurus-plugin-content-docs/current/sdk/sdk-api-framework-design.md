---
id: sdk-api-framework-design
title: BitFS SDK API 框架
---

# BitFS SDK API 框架

go-bitfs 是 001–007 的可执行协议规范，同时是一个**无状态、无基础设施副作用的协议 SDK**：角色 workflow 只持有传入 `WorkflowConfig{PrivateKey}` 的官方 BSV 私钥，对显式传入的输入执行确定性的 Build/Verify/Sign/Merge 计算。

其余一切由调用方应用提供：以 `RefundTemplateTxID` 为键的持久化、事务与锁、并发串行化、重试与幂等、内容存储、点对点传输、节点广播、区块高度来源、时间来源以及多租户授权。SDK 从不加载或保存状态，从不读取或写入内容，从不广播交易，也从不查询节点或时钟——每个公开入口在内部读取一次系统 UTC，区块高度以显式的 `blockHeight uint32` 参数传入，SDK 只用这些事实验证协议规则。
