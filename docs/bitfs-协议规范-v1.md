# BitFS 协议规范 v1

> **历史兼容文档，不作为新施工依据。** 本文描述的 `FileQuote`、`HashGetTicket`、`session_id`、`content_index`、`expected_size`、票据价格和签名域，均属于旧 V1 会话模型。新设计按业务顺序以 [001-报价凭证规范](001-报价凭证规范.md) 至 [006-费用池无条件关闭规范](006-费用池无条件关闭规范.md) 为准；新实现不得混用两套字段或把本文件的会话 ID 当作真值。

本文件说明 BitFS 的业务规则。wire schema 以 [`../spec/v1/bitfs.cddl`](../spec/v1/bitfs.cddl) 为准，编码、稳定 ID 和签名规则以 [`../spec/v1/protocol.md`](../spec/v1/protocol.md) 为准。买方、卖方、仲裁方及其运行时不得自行复制或改变这些规则。

## 文件模型

- block 固定上限为 `262144` 字节；最后一个 block 可以更短。
- 每个 block 的哈希固定为 `sha256(raw_block_bytes)`，最后一个 block **不补零**。
- seed 是全部 block hash 的顺序拼接：`seed_bytes = hash[0] || hash[1] || ... || hash[n-1]`。
- 每个 block hash 是 32 字节原始摘要。因此两个 block 的 seed 恰好是 64 字节；seed 内不包含 BSE1 头、版本、文件大小、块数或其他元数据。
- `seed_hash = sha256(seed_bytes)`。

## 发现与报价

发现不属于 BitFS 核心协议。DHT、pubsub、tracker 或手工连接可自行使用 `seed_hash` 发现对端，但其地址、端口、广播和反滥用规则不进入 BitFS wire schema。

> 本节的 `FileQuote` 是为 V1 兼容保留的旧无签名报文。新的 1 对 1、自证明报价必须使用 [`001-报价凭证规范.md`](001-报价凭证规范.md) 中的 `SignedFileQuote`。

卖方以一个 `seed_hash` 对应的完整文件报价，使用 `FileQuote` CBOR 报文。报价必须含 seed、普通 block、最后 block 的价格，文件大小、建议文件名与过期时间。若文件大小整除 block 大小，`endblock_price_sat` 必须等于 `block_price_sat`。

## 会话

一条 BitFS seller 会话必须绑定 `session_id`、`seed_hash`、买方公钥和卖方公钥。后续所有 hash → payload 的购买都在此会话内完成；不得用某个 block hash 重新进入发现流程。

## 购买与交付

唯一购票对象是 `HashGetTicket`，没有 seed/block 两套消息。`content_index = -1` 表示 seed，非负值表示 block 序号。一票只授权一个 `content_hash` 和一个 `price_sat`。

`expected_size` 是实际交付 payload 的字节数：seed 为 `block_count * 32`；普通 block 为 `262144`；最后一块可以更小。seed 票据的 `content_hash` 必须等于 `root_seed_hash`。

卖方发布独立的 `HashDelivery` 异步报文。买方必须先验证：

```text
sha256(payload) == ticket.content_hash
```

并确认 session、sequence、content hash 与票据一致，才允许推进付款。

## 票据签名

买方签名覆盖以下字段的确定性二进制编码：`session_id`、`sequence`、`root_seed_hash`、`content_hash`、`content_index`、`expected_size`、`price_sat`、`buyer_pubkey`、`seller_pubkey`、`expires_at_unix`。

编码使用域分隔 `bitfs.ticket.v1`、签名版本字节 `1` 与 deterministic CBOR；具体实现以 `bitfs.HashGetTicketSigningPayload` 为准。签名不覆盖 `buyer_signature` 本身。

## 正常支付顺序

1. 买方为当前 seller 会话建立或恢复 2-of-3 池。
2. 买方发布票据，卖方异步校验后发布交付报文。
3. 买方收到交付报文并验收 payload 哈希。
4. 验收成功后才 prepare 与 commit 票据付款。
5. commit 成功后，该票据才能标记为已支付。

买方可以向多个卖方购买不同 block，但每个 seller 会话只能绑定一条独立的 2-of-3 费用池。
