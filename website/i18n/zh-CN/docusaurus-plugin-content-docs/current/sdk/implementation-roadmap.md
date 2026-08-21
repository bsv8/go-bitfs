---
id: implementation-roadmap
title: 04 · 实施路线
---

# 04 · 实施路线

返回 [SDK API 框架入口](sdk-api-framework-design.md)。

1. `wire`、`bitfs` 的 001/003/004、`pool` 的 002/005/006、`arbitration` 的 007 已实现 deterministic CBOR、严格解码和证据校验。
2. MultisigPool 是费用池交易、SIGHASH_ALL|FORKID、2-of-3 脚本、累计付款、最终关闭和退款到期校验的唯一实现；角色工作流在内部用 `NonFinalPoolBackend` 或 `PoolBackend` 构造 `pool.VerifiedNonFinalPoolNode`。
3. `pool.MemoryStore` 和 `bitfs.FileQuoteStore` 已实现线程安全/可重启的参考存储；生产多进程环境应替换为事务数据库，并保留其原子升级、不可变和幂等语义。
4. `buyer.Workflow`、`seller.Workflow`、`arbitration.Workflow` 已接入端到端集成测试，覆盖报价、开池、内容交付、付款推进和重复付款重试。
5. 当前发布面只包含 BitFS v4 的 `buyer.Workflow`、`seller.Workflow`、`arbitration.Workflow` 与 `pool` 角色适配器；旧 `settlement`/runtime 双栈已删除，不存在 `legacy` build tag 验收路径。
