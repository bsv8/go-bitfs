---
id: 003-content-request-requirements
title: 003 · 内容获取请求需求
---

# 003 · 内容获取请求需求

## 要解决什么

买方已经选中报价并拥有可用费用池后，需要向卖方发出“请交付这一批有序内容”的最终付款授权：一个付款序号授权一组内容哈希，价格逐项推导后安全累加。请求必须让卖方能够验证：买方选择了自己的哪份报价、使用哪个费用池、授权对应哪个目标付款状态、请求哪些内容，以及最晚何时交付。

它不是 005 交易签名，但它已经签入验货后应执行的绝对累计金额和目标序号；买方尚未验货，费用池金额仍未推进。整个批次原子成功或原子失败：不存在部分交付、部分付款或按前缀接受。

## 内容怎样定位

003 携带 1–64 个不重复的有序内容哈希批次（`ContentHashesCBOR`，先确定性 CBOR 编码再作为 `bstr` 嵌入的子文档）。协议没有任何由发送方声明的内容类型：

- 等于报价 `SeedHash` 的哈希被识别为 seed，按 `SeedPriceSat` 计价。
- 其余哈希必须出现在该 seed 的文件块哈希列表中，并按其位置的协议期望长度计价（完整块按 `FullBlockPriceSat`；尾块按比例上取整及约定的 10% 卖方计算规则）。
- 找不到的哈希返回 `ErrContentNotInSeed`。
- 顺序是授权的一部分：哈希不会被排序、去重或重排后接受；重复条目直接拒绝。
- 同一哈希若在 seed 中出现多次，购买一次即可复用到文件中所有相同位置；若这些位置推导出冲突的期望长度，证据不可消歧，整批拒绝。
- 批次包含任何块时，买方必须已持有 hash 等于报价 `SeedHash` 的已验证 seed。只有在该条件下才允许混合 seed+block 批次；尚未取得 seed 的买方应先单独购买 seed。

## 费用池怎样定位

买方用 `RefundTemplateTxID` 选择可用费用池，并只承诺一个目标 `PaymentSequence`：接收方验证 `request.PaymentSequence == previous.PaymentSequence + 1`（相对其当前已接受状态），且目标不得超过 `0xfffffffe`。

`SellerAmountAfterSat` 是付款后卖方的绝对累计金额——不是本批增量。聚合批次价格必须精确等于 `SellerAmountAfterSat - previous.SellerAmountSat`，并在签名前用 checked-add 累加；溢出、容量不足或任一项分类失败都会让整个构造在任何签名存在之前失败。

同一个池不能同时被卖方接受为多张未完成请求，否则同一笔余额会被重复承诺。这是调用方应用的本地运行约束（应用负责按池串行化批次）；SDK 仅验证显式输入，不在 SDK 内新增 store、mutex 或 lease。

买方在 003 中签入目标序号和绝对累计金额，并不要求卖方对这些字段反签确认。卖方可以交付 004，也可以拒绝或不作为；若卖方无法正常交付且买方拒签 005，卖方可按 007 使用这张最终授权请求仲裁。

## 为什么只带引用

003 不携带公钥和矿工费率：Buyer/Seller/Arbiter 公钥与费率由 `RefundTemplateTxID` 对应且不可修改的 OpeningProof 唯一确定。因此任何密码学验签都必须同时持有对应 OpeningProof（`VerifySignedContentRequestForOpening`）；007 已携带一份并走该路径。报价仅由 `QuoteTermsHash` 选择——费用池不能替代报价，因为同一池可以购买同一组角色下不同报价的内容。

精确的 `TermsCBOR` 随后产生 `PaymentAuthorizationHash = SHA-256(TermsCBOR)`。004 用它引用授权，005 用它把付款和具体批次取件关联；007 只提交完整 003 授权和费用池执行材料，不要求仲裁者读取 001、004、payload 或历史付款链。

编码细节见[内容获取请求规范](003-content-request-spec.md)。
