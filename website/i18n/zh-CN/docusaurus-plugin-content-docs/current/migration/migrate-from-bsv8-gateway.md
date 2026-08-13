---
id: migrate-from-bsv8-gateway
title: 从 bsv8-gateway 迁移
---

# 从 bsv8-gateway 迁移

`go-bitfs` 现在是 BitFS v3 文件交换、仲裁与 MultisigPool v4 费用池协议的唯一来源。目录名为 `spec/v1` 的 CDDL 文件仅因历史路径保留，不能用于当前协议；当前真值是 `spec/v3` 和 001–007 的 v3 文档。

- 删除对 `proto/bitfs/*` 及其生成代码的依赖；当前 BitFS 业务 wire schema 以 001/003/004 对应的 v3 CDDL 和 deterministic CBOR 为准。
- 删除对旧费用池 proto 与 gRPC 生成代码的依赖；当前 002/005/006/007 以 v3 pool/arbitration CDDL 和发布版 MultisigPool 交易字节为准。
- 替换本地 seed 编解码、内容哈希、票据签名和仲裁证据校验为 `go-bitfs/bitfs`。
- 删除 BSE1 seed 格式：v3 seed 仅是 32 字节 block hash 的顺序拼接。
- 删除尾块补零哈希：所有 block 均哈希真实交付的原始字节。
- gateway、libp2p、数据库、策略与 daemon 只实现运行时适配，不再定义 BitFS 协议真值。
