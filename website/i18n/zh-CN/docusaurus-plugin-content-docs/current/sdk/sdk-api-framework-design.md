---
id: sdk-api-framework-design
title: BitFS SDK API 框架设计
---

# BitFS SDK API 框架设计

本文是 BitFS SDK 的公开 API 蓝图入口，不是 wire 规范，也不是可直接编译的 Go 代码。实际实现必须服从 001–007 协议规范；若本文与编号规范冲突，以编号规范为准。

为避免把协议、外部能力和角色流程混在一个超大文档中，API 框架拆分如下：

| 文档 | 说明 |
|---|---|
| [01 · 协议基础与 CBOR](protocol-foundations-and-cbor.md) | 包边界、通用约定、错误模型、统一 `wire` 编解码与纯协议函数。 |
| [02 · 外部钩子与数据类型](external-hooks-and-data-types.md) | 签名、存储、内容、交易引擎、BSV 节点钩子及关键输入类型。 |
| [03 · 角色工作流 API](role-workflow-api.md) | 买方、卖方、仲裁者 API，以及最短端到端调用顺序。 |
| [04 · 实施路线](implementation-roadmap.md) | 实施先后顺序与必须覆盖的验证场景。 |

SDK 只构造、验证和保存自证明凭证；网络投递、私钥托管、内容存储、数据库和 BSV 节点均由调用方通过接口接入。数据库记录只用于查找、幂等和卖方交付保护，不能替代原始 CBOR、原始交易和签名。
