---
id: sdk-api-framework-design
title: BitFS SDK API 框架
---

# BitFS SDK API 框架

go-bitfs 是 001–007 的可执行协议规范，负责确定性的 Build/Read/Verify、
协议计算、状态转换，以及固定的 MasterSeed 和 MultisigPool 实现。

应用只提供基础设施：`Signer`、持久化、内容 source/sink 和窄的 BSV 验收
后端。对端传输完全位于 SDK 外部。交易构造、验证、定价和过期规则都属于
固定核心能力。
