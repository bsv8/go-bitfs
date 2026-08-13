---
title: go-bitfs
linkTitle: 首页
type: docs
description: BitFS v3 的 Go 协议真值库
---

# go-bitfs

BitFS v3 的 Go SDK。覆盖文件交换、自动仲裁，以及基于 MultisigPool v4 的 2-of-3 费用池结算。

```bash
go get github.com/bsv8/go-bitfs
```

## 从这里开始

- [SDK 设计与使用指南](guide/sdk/)：理解包边界、外部端口和角色工作流。
- [协议规范](guide/protocol/)：按 001–007 的业务顺序查阅凭证与结算规则。
- [API Reference](reference/)：从当前 Go 源码、签名和 doc comments 自动生成。

## 六个公开包

| 包 | 职责 |
|---|---|
| `bitfs` | 报价、内容凭证、seed、哈希与证据校验 |
| `pool` | 费用池状态机、交易端口与参考存储 |
| `buyer` | 买方角色工作流 |
| `seller` | 卖方角色工作流 |
| `arbitration` | 卖方仲裁签名工作流 |
| `wire` | 协议报文编解码与分派 |

API Reference 不维护手写副本。修改导出类型、方法或源码注释后，重新构建站点即可得到对应页面。
