# 从 bsv8-gateway 迁移

`go-bitfs` 现在是 BitFS 文件交换、仲裁与 2-of-3 结算协议的唯一来源。

- 删除对 `proto/bitfs/*` 及其生成代码的依赖；BitFS 业务 wire schema 改为 `spec/v1/bitfs.cddl` 定义的 deterministic CBOR。
- 删除对旧费用池 proto 与 gRPC 生成代码的依赖；结算协议以 `spec/v1/settlement.cddl` 定义的 deterministic CBOR 为准。
- 替换本地 seed 编解码、内容哈希、票据签名和仲裁证据校验为 `go-bitfs/bitfs`。
- 删除 BSE1 seed 格式：v1 seed 仅是 32 字节 block hash 的顺序拼接。
- 删除尾块补零哈希：所有 block 均哈希真实交付的原始字节。
- gateway、libp2p、数据库、策略与 daemon 只实现运行时适配，不再定义 BitFS 协议真值。
