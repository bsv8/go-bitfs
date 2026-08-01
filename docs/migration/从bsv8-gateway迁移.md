# 从 bsv8-gateway 迁移

`go-bitfs` 现在是 BitFS v2 文件交换、仲裁与 2-of-3 费用池协议的唯一来源。目录名为 `spec/v1` 的现行 CDDL 文件因历史路径保留，但其文档头和 `version` 均为 major 2；同目录下未标明 current 的 `bitfs.cddl`、`settlement.cddl`、`protocol.md` 仅作历史兼容参考。

- 删除对 `proto/bitfs/*` 及其生成代码的依赖；当前 BitFS 业务 wire schema 以 001/003/004 对应的 v2 CDDL 和 deterministic CBOR 为准。
- 删除对旧费用池 proto 与 gRPC 生成代码的依赖；当前 002/005/006/007 以 v2 pool/arbitration CDDL 和发布版 MultisigPool 交易字节为准。
- 替换本地 seed 编解码、内容哈希、票据签名和仲裁证据校验为 `go-bitfs/bitfs`。
- 删除 BSE1 seed 格式：v2 seed 仅是 32 字节 block hash 的顺序拼接。
- 删除尾块补零哈希：所有 block 均哈希真实交付的原始字节。
- gateway、libp2p、数据库、策略与 daemon 只实现运行时适配，不再定义 BitFS 协议真值。
