import type { Artifact } from './wire.js'

/**
 * 完整开池证据（普通数据，可序列化）：镜像 Go `pool.OpeningProof` 字段。
 * 所有字节字段均为原始报文/交易字节，不经 SDK 重新编码。
 */
export interface OpeningProof {
  /** 预签名退款模板交易原文；费用池统一关联 ID 的唯一来源。 */
  refundTemplateRaw: Uint8Array
  /** 买方 33 字节压缩 secp256k1 公钥。 */
  buyerPublicKey: Uint8Array
  /** 卖方 33 字节压缩 secp256k1 公钥。 */
  sellerPublicKey: Uint8Array
  /** 仲裁方 33 字节压缩 secp256k1 公钥。 */
  arbiterPublicKey: Uint8Array
  /** 构造池内交易时采用的矿工费率，单位 satoshi/KB。 */
  minerFeeRateSatoshisPerKilobyte: bigint
  /** 买方对退款模板的 detached DER 交易签名。 */
  buyerRefundSignature: Uint8Array
  /** 卖方对同一退款模板的 detached DER 交易签名。 */
  sellerRefundSignature: Uint8Array
  /** 资金交易原文；未交付时为空。 */
  fundingTransactionRaw: Uint8Array
}

/** 买方开池阶段的普通证据包：exact Kind 2 请求、exact Kind 3 响应与资金交易原文。 */
export interface BuyerOpeningEvidence {
  /** 买方发出的 exact Kind 2 预签请求字节。 */
  rawKind2: Uint8Array
  /** 卖方返回的 exact Kind 3 预签响应字节；PrepareOpening 阶段为空。 */
  rawKind3: Uint8Array
  /** 买方资金交易原文；交付前绝不进入其他网络报文。 */
  fundingTransactionRaw: Uint8Array
}

/**
 * 买方视角的资金池普通证据包：完整开池证明加当前链上付款状态原文。
 * 省略 `latestPaymentRawTx` 表示池仍处于初始退款状态，SDK 会从 opening 重建；
 * 提供时 SDK 逐字节解析并全量重验，绝不信任调用方声明的序号或金额。
 */
export interface BuyerPoolEvidence {
  /** 含资金交易原文的完整开池证明。 */
  opening: OpeningProof
  /** 链上取得的最新完整付款交易原文；省略/空表示初始退款状态。 */
  latestPaymentRawTx?: Uint8Array
}

/** 一次已签授权的普通证据包：exact Kind 1 报价与买方 exact Kind 5 授权。 */
export interface BuyerAuthorizationEvidence {
  /** 卖方签署的 exact Kind 1 报价字节。 */
  rawKind1: Uint8Array
  /** 买方签署的 exact Kind 5 付款授权字节。 */
  rawKind5: Uint8Array
}

/** 卖方预签阶段的普通证据包：买方 exact Kind 2 与卖方 exact Kind 3。 */
export interface SellerOpeningEvidence {
  /** 买方发来的 exact Kind 2 预签请求字节。 */
  rawKind2: Uint8Array
  /** 卖方发出的 exact Kind 3 预签响应字节（含卖方退款签名）。 */
  rawKind3: Uint8Array
}

/** 卖方视角的资金池普通证据包：完整开池证明、资金交易原文与最新付款原文。 */
export interface SellerPoolEvidence {
  /** 含资金交易原文的完整开池证明。 */
  opening: OpeningProof
  /** 资金交易原文副本；必须与 Opening 内部一致。 */
  fundingTransactionRaw: Uint8Array
  /** 链上取得的最新完整付款交易原文；省略/空表示初始退款状态。 */
  latestPaymentRawTx?: Uint8Array
}

/** 卖方交付阶段的普通证据包：exact Kind 1 报价、Kind 5 授权与本方公开的 Kind 6。 */
export interface SellerDeliveryEvidence {
  /** 卖方签署的 exact Kind 1 报价字节。 */
  rawKind1: Uint8Array
  /** 买方签署的 exact Kind 5 付款授权字节。 */
  rawKind5: Uint8Array
  /** 卖方发出的 exact Kind 6 内容交付字节（含 payload attachment）。 */
  rawKind6: Uint8Array
}

/**
 * 已完整验证但尚未签名的普通仲裁证据包：exact Kind 8、按显式正费用独立
 * 重建的 candidate、Claim ID 与冻结费用。可序列化持久化。
 */
export interface PreparedArbitrationEvidence {
  /** 卖方发来的 exact Kind 8 托管请求字节。 */
  rawKind8: Uint8Array
  /** 从 Claim primitives 按显式费用唯一重建的未签名仲裁交易原文。 */
  candidateRaw: Uint8Array
  /** SHA-256(exact arbitration_claim_cbor)，托管记录身份。 */
  arbitrationClaimID: Uint8Array
  /** 本次仲裁的绝对仲裁费（正数，聪）。 */
  feeSatoshis: bigint
}

/**
 * 签名阶段产出的普通证据包：冻结的 Prepare 证据、待发送 exact Kind 9 与
 * 仲裁交易签名。CompleteArbitratedPayment 需要它合并双签名。
 */
export interface SignedArbitrationEvidence {
  /** 签名前的完整证据快照；合并时会再次全量重验。 */
  prepared: PreparedArbitrationEvidence
  /** 待发送 exact Kind 9 回执 Artifact。 */
  outbound: Artifact
  /** 仲裁方对 candidate 的 detached 交易签名。 */
  arbiterTransactionSignature: Uint8Array
}

/** 已验证的托管内容证据：Claim ID、exact payload 子文档与解码后的 payload。 */
export interface VerifiedCustodyEvidence {
  /** 重算并与回执比对一致的托管 Claim 身份。 */
  arbitrationClaimID: Uint8Array
  /** exact content_payloads_cbor 字节。 */
  payloadsCBOR: Uint8Array
  /** 按授权顺序深拷贝的 payload 内容。 */
  payloads: Uint8Array[]
}

/** 构造 exact Kind 2 所需的全部显式输入。 */
export interface PrepareOpeningInput {
  /** 本池对应的 exact Kind 1 报价字节；SDK 用其条款绑定买方身份、卖方公钥与受支持仲裁方。 */
  quoteRaw: Uint8Array
  /** 买方资金交易原文；输出 0 必须是池输出。 */
  fundingTransactionRaw: Uint8Array
  /** 退款交易到期锁定时间（低于阈值按区块高解释，否则按 UTC Unix 时间戳）。 */
  expiryLockTime: number
  /** 池内交易矿工费率（每千字节聪数）。 */
  minerFeeRateSatoshisPerKilobyte: bigint
  /** 卖方压缩公钥。 */
  sellerPublicKey: Uint8Array
  /** 仲裁方压缩公钥。 */
  arbiterPublicKey: Uint8Array
}

/** 构造一次 exact Kind 5 授权的全部输入。 */
export interface RequestContentInput {
  /** 本池对应的 exact Kind 1 报价字节。 */
  quoteRaw: Uint8Array
  /** 当前池普通证据包（初始状态可省略 latestPaymentRawTx）。 */
  pool: BuyerPoolEvidence
  /** 有序不重复的内容哈希批次（1..64）；等于 SeedHash 即购 seed。 */
  contentHashes: Uint8Array[]
  /** 交付截止时间（UTC Unix 秒）；必须晚于 Facts.Now 且不超过报价有效期。 */
  deliveryDeadline: bigint
  /** 批次含块时提供已验证 seed 原文；纯 seed 批次可空。 */
  seed?: Uint8Array
}

/** 验收一次 exact Kind 6 所需的全部证据。 */
export interface VerifyDeliveryInput {
  /** 本批次的已签授权证据包（exact Kind 1 + exact Kind 5）。 */
  authorization: BuyerAuthorizationEvidence
  /** 当前池普通证据包。 */
  pool: BuyerPoolEvidence
  /** 对端发来的 exact Kind 6 字节。 */
  deliveryRaw: Uint8Array
  /** 批次含块时提供已验证 seed 原文；纯 seed 批次可空。 */
  seed?: Uint8Array
}

/** 立即关闭所需的输入：调用方自选基准池证据与目标金额。 */
export interface PrepareCloseInput {
  /** 当前池普通证据包；latestPaymentRawTx 就是本关闭的基准状态。 */
  pool: BuyerPoolEvidence
  /** 最终关闭中卖方的累计金额（绝对聪数）。 */
  targetSellerAmountSatoshis: bigint
}

/** 验收卖方完整关闭交易所需的证据。 */
export interface VerifyCompletedCloseInput {
  /** 当前池普通证据包（用于 opening 归属绑定）。 */
  pool: BuyerPoolEvidence
  /** 卖方合并后的完整关闭交易原文。 */
  closeRaw: Uint8Array
}

/** 构造 exact Kind 10 所需的本地证据。 */
export interface RetrievalRequestInput {
  /** 当前池普通证据包。 */
  pool: BuyerPoolEvidence
  /** 取回所引用授权的普通证据包（exact Kind 1 + exact Kind 5）。 */
  authorization: BuyerAuthorizationEvidence
  /** 可选的 32 字节重放键；省略时由 SDK 用安全随机源生成。 */
  nonce?: Uint8Array
}

/** exact Kind 10/11 验收所需的本地证据。 */
export interface ArbitratedContentInput {
  /** 取回所引用授权的普通证据包（exact Kind 1 + exact Kind 5）。 */
  authorization: BuyerAuthorizationEvidence
  /** 当前池普通证据包。 */
  pool: BuyerPoolEvidence
  /** 本地保存的 exact Kind 10 字节（重放原请求）。 */
  retrievalRequestRaw: Uint8Array
  /** 对端返回的 exact Kind 11 字节。 */
  retrievalResponseRaw: Uint8Array
  /** 取回批次含块时提供已验证 seed 原文；纯 seed 批次可空。 */
  seed?: Uint8Array
}

/** 构造一次内容交付所需的全部普通输入；授权哈希绝不重复提供。 */
export interface DeliveryInput {
  /** 本池对应的 exact Kind 1 报价字节。 */
  quoteRaw: Uint8Array
  /** 当前池普通证据包。 */
  pool: SellerPoolEvidence
  /** 买方发来的 exact Kind 5 字节。 */
  requestRaw: Uint8Array
  /** 原始 payload 批次，顺序与授权哈希一一对应。 */
  contentPayloads: Uint8Array[]
  /** 批次含块时提供 seed 原文；纯 seed 批次可空。 */
  seed?: Uint8Array
}

/** 预检一次 exact Kind 5 所需的原始证据；不要求先读取或提供 payload。 */
export interface InspectDeliveryRequestInput {
  /** 与费用池绑定的 exact Kind 1 报价字节。 */
  quoteRaw: Uint8Array
  /** 包含完整开池证明和当前链上付款状态的卖方证据。 */
  pool: SellerPoolEvidence
  /** 买方签署的 exact Kind 5 付款授权字节。 */
  requestRaw: Uint8Array
}

/** 已通过 Kind 5、报价、开池、签名、时间、付款状态与容量预检的摘要。 */
export interface DeliveryRequestSummary {
  /** SHA-256(exact payment_authorization_cbor)，授权查找 ID；不同于付款序号。 */
  paymentAuthorizationID: Uint8Array
  /** 授权引用的 exact 报价条款 ID。 */
  fileQuoteTermsID: Uint8Array
  /** 授权绑定的费用池 ID。 */
  refundTemplateTxID: Uint8Array
  /** 目标付款状态序号，必须等于当前序号加一。 */
  paymentSequence: number
  /** 交付后卖方的绝对累计金额，单位 satoshi。 */
  sellerAmountAfterSatoshis: bigint
  /** 授权签入的交付截止时间，UTC Unix 秒。 */
  deliveryDeadlineUnixSeconds: bigint
  /** 授权签入的有序内容哈希；调用方按此顺序读取和传入 payload。 */
  contentHashes: Uint8Array[]
}

/** 完成一笔累计付款所需的全部普通证据。 */
export interface CompletePaymentInput {
  /** 当前池普通证据包。 */
  pool: SellerPoolEvidence
  /** 生成本批次 exact Kind 6 时保存的交付证据包；SDK 用它交叉核对授权 ID 与本方已发交付。 */
  delivery: SellerDeliveryEvidence
  /** 按 Kind 7 携带的授权 ID 取回的 exact 已签 Kind 5；必须与 delivery.rawKind5 逐字节相等。 */
  requestRaw: Uint8Array
  /** 对端发来的 exact Kind 7 字节。 */
  updateRaw: Uint8Array
}

/** 完成立即关闭所需的买方材料。 */
export interface CompleteCloseInput {
  /** 当前池普通证据包。 */
  pool: SellerPoolEvidence
  /** 买方准备好的未签名关闭 candidate 原文。 */
  unsignedRaw: Uint8Array
  /** 买方对该 candidate 的 detached 交易签名。 */
  buyerSignature: Uint8Array
}

/** 构造 exact Kind 8 所需的本地普通证据。 */
export interface PrepareArbitrationInput {
  /** 当前池普通证据包。 */
  pool: SellerPoolEvidence
  /** 被托管批次的 exact 已签 Kind 5。 */
  requestRaw: Uint8Array
  /** 本方发出的 exact Kind 6 字节。 */
  deliveryRaw: Uint8Array
}

/** 完成仲裁收款所需的 exact Kind 8/9 与本地证据。 */
export interface CompleteArbitratedPaymentInput {
  /** exact Kind 8 字节。 */
  requestRaw: Uint8Array
  /** exact Kind 9 字节。 */
  responseRaw: Uint8Array
  /** 本方保存的 exact content_payloads_cbor（可选；提供时与 Kind 8 attachment 逐字节比对）。 */
  deliveryPayloadsCBOR?: Uint8Array
}
