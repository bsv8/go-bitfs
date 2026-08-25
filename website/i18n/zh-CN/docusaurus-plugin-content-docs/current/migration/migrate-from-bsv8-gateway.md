---
id: migrate-from-bsv8-gateway
title: 从 bsv8-gateway 迁移
---

# 从 bsv8-gateway 迁移

`go-bitfs` 现在是 BitFS v1 文件交换、仲裁与费用池协议的唯一来源。当前 wire 真值是 `protocol.WireVersion = 1`、`spec/v1/` 下的 CDDL 文件以及 001–008 号文档；退役的 v1 之前报文体系只保留在 `spec/legacy/` 下，新实现不得使用。

- 删除对 `proto/bitfs/*` 及其生成代码的依赖；当前 BitFS 业务 wire schema 以 001/003/004 对应的 v1 CDDL 和 deterministic CBOR 为准。
- 删除对旧费用池 proto 与 gRPC 生成代码的依赖；当前 002/005/006/007 以 v1 wire 文档和发布版 MultisigPool 交易字节为准。
- 替换本地 seed 编解码、内容哈希、票据签名和仲裁证据校验为 `go-bitfs/content`（报价/内容凭证）、`pool`（结算交易）与 `arbiter`（托管签署）；应用通过 `buyer`、`seller`、`arbiter` 三个角色 workflow 驱动它们。
- 删除 BSE1 seed 格式：seed 仅是 32 字节 block hash 的顺序拼接。
- 删除尾块补零哈希：所有 block 均哈希真实交付的原始字节。
- gateway、libp2p、数据库、策略与 daemon 只实现运行时适配，不再定义 BitFS 协议真值。
