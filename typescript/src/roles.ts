import { sha256 } from '@noble/hashes/sha2.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { decodeCanonical, encodeCanonical, type CBORValue } from './cbor.js'
import { WireError } from './errors.js'
import {
  createArbitrationRequest, createArbitrationResponse, createContentDelivery,
  createContentRequest, createContentRetrievalAvailable, createContentRetrievalRequest,
  createContentRetrievalUnavailable, createFileQuote, encodeFundingTransactionDelivery,
  encodePaymentUpdate, encodeRefundPresignRequest, encodeRefundPresignResponse,
  type FileQuoteTerms, type PaymentAuthorization
} from './messages.js'
import { type Signer, verifyWireDocument } from './protocol.js'
import { MultisigPoolEngine, type PoolStateInput } from './pool.js'
import { buildArbitrationCandidate, transactionID, transactionLockTime, verifyArbitrationCandidate } from './transaction.js'
import { Artifact, parseAs } from './wire.js'

/** 调用方提供的确定性事实；SDK 不读取系统时钟。 */
export interface WorkflowFacts {
  /** 当前 UTC Unix 秒，由上层可信时钟显式传入。 */
  nowUnixSeconds: bigint
  /** 当前区块高度；退款模板使用高度锁时必须提供。 */
  blockHeight?: number
}

/** 已验证报价；所有字节字段均为防御性副本。 */
export interface VerifiedQuote {
  terms: FileQuoteTerms
  termsCBOR: Uint8Array
  termsID: Uint8Array
  sellerPublicKey: Uint8Array
}

/** 已验证付款授权；用于后续交付与付款状态构造。 */
export interface VerifiedContentRequest {
  authorization: PaymentAuthorization
  authorizationCBOR: Uint8Array
  authorizationID: Uint8Array
}

/** 已验证内容交付。payload 顺序与买方授权哈希顺序相同。 */
export interface VerifiedContentDelivery {
  authorizationID: Uint8Array
  payloads: Uint8Array[]
}

/** 已验证仲裁托管请求的必要证据。 */
export interface VerifiedArbitrationRequest {
  claimCBOR: Uint8Array
  claimID: Uint8Array
  buyerPublicKey: Uint8Array
  sellerPublicKey: Uint8Array
  arbiterPublicKey: Uint8Array
  payloads: Uint8Array[]
  /** Claim 冻结的退款模板。 */
  refundTemplateRaw: Uint8Array
  /** Claim 冻结的费用池输入金额。 */
  poolOutputSatoshis: bigint
  /** 买方授权的目标付款序号。 */
  paymentSequence: bigint
  /** 买方授权的卖方绝对金额。 */
  sellerAmountAfterSatoshis: bigint
  /** 买方授权的交付截止 UTC Unix 秒。 */
  deliveryDeadlineUnixSeconds: bigint
}

const preparedArbitrationToken: unique symbol = Symbol('prepared arbitration')

/** 经过完整 Prepare、可先持久化再签名的仲裁状态；调用方不能自行构造。 */
export class PreparedArbitration {
  readonly #requestRaw: Uint8Array
  readonly #custody: VerifiedArbitrationRequest
  readonly #candidateRaw: Uint8Array
  readonly #feeSatoshis: bigint
  readonly #owner: object
  readonly #commitment: Uint8Array
  /** @internal 仅 ArbiterWorkflow.prepareArbitration 可提供有效 token。 */
  constructor (requestRaw: Uint8Array, custody: VerifiedArbitrationRequest, candidateRaw: Uint8Array, feeSatoshis: bigint, owner: object, commitment: Uint8Array, token: typeof preparedArbitrationToken) {
    if (token !== preparedArbitrationToken) throw new WireError('invalid_evidence', 9, 'prepared', 'PreparedArbitration 只能由 Prepare 阶段构造')
    this.#requestRaw = copy(requestRaw); this.#custody = cloneCustody(custody); this.#candidateRaw = copy(candidateRaw)
    this.#feeSatoshis = feeSatoshis; this.#owner = owner; this.#commitment = copy(commitment)
  }
  /** 返回待签名仲裁 candidate 的副本，供应用持久化和审计。 */
  candidateRaw (): Uint8Array { return copy(this.#candidateRaw) }
  /** 返回 Claim ID 副本。 */
  claimID (): Uint8Array { return copy(this.#custody.claimID) }
  /** @internal Workflow 重验所需的冻结快照。 */
  snapshot (): { requestRaw: Uint8Array, custody: VerifiedArbitrationRequest, candidateRaw: Uint8Array, feeSatoshis: bigint, owner: object, commitment: Uint8Array } { return { requestRaw: copy(this.#requestRaw), custody: cloneCustody(this.#custody), candidateRaw: copy(this.#candidateRaw), feeSatoshis: this.#feeSatoshis, owner: this.#owner, commitment: copy(this.#commitment) } }
}

/** SignPreparedArbitration 的原子结果：Kind 9 与其绑定的交易签名。 */
export interface SignedArbitration {
  response: Artifact
  candidateRaw: Uint8Array
  arbiterTransactionSignature: Uint8Array
  engine: MultisigPoolEngine
  poolOutputSatoshis: number
}

/** 买方开池准备结果；调用方应在发送 request 前原子持久化这些 exact bytes。 */
export interface BuyerOpeningPreparation {
  request: Artifact
  engine: MultisigPoolEngine
  refundTemplateRaw: Uint8Array
  buyerRefundSignature: Uint8Array
  poolOutputSatoshis: number
}

/** 卖方开池准备结果；保留到收到 Kind 4 资金交易。 */
export interface SellerOpeningPreparation {
  response: Artifact
  engine: MultisigPoolEngine
  refundTemplateRaw: Uint8Array
  buyerRefundSignature: Uint8Array
  sellerRefundSignature: Uint8Array
  poolOutputSatoshis: number
  /** 构造退款模板时冻结的矿工费率，单位 satoshi/KB。 */
  minerFeeRateSatoshisPerKilobyte: number
}

/** 已完成双方退款签名的开池证据。 */
export interface CompletedOpening {
  engine: MultisigPoolEngine
  refundTemplateRaw: Uint8Array
  mergedRefundRaw: Uint8Array
  refundTemplateTxID: Uint8Array
  poolOutputSatoshis: number
}

/** 买方准备的付款或关闭候选及 detached 签名。 */
export interface BuyerPaymentPreparation {
  unsignedRaw: Uint8Array
  buyerSignature: Uint8Array
  paymentUpdate: Artifact
}

/** 买方角色编排：验报价、发授权、验交付、请求仲裁内容。 */
export class BuyerWorkflow {
  readonly #signer: FrozenSigner
  constructor (signer: Signer) { this.#signer = freezeSigner(signer, 'buyer_signer') }
  /** 返回固定买方身份公钥的副本。 */
  publicKey (): Uint8Array { return copy(this.#signer.publicKey()) }

  /** 严格解析并验证卖方报价签名、买方绑定和显式失效时间。 */
  acceptQuote (facts: Readonly<WorkflowFacts>, rawKind1: Uint8Array): VerifiedQuote {
    const outer = decodeOuter(parseAs(1, rawKind1), 5)
    const termsCBOR = bytes(outer[2], 1, 'file_quote_terms_cbor')
    const sellerPublicKey = bytes(outer[3], 1, 'seller_public_key')
    verifyWireDocument(sellerPublicKey, 1, termsCBOR, bytes(outer[4], 1, 'seller_signature'))
    const terms = decodeQuoteTerms(termsCBOR)
    if (!equal(terms.buyerPublicKey, this.publicKey())) invalid(1, 'buyer_public_key', '报价绑定的买方不是当前工作流身份')
    if (facts.nowUnixSeconds > terms.quoteExpiresAtUnixSeconds) throw new WireError('expired', 1, 'quote_expires_at_unix_seconds', '报价已经失效')
    return { terms, termsCBOR: copy(termsCBOR), termsID: sha256(termsCBOR), sellerPublicKey: copy(sellerPublicKey) }
  }

  /** 构造并签署 Kind 5 累计付款授权。 */
  requestContent (authorization: Readonly<PaymentAuthorization>, signal?: AbortSignal): Promise<Artifact> {
    return createContentRequest(this.#signer, authorization, signal)
  }

  /** 从资金交易 output[0] 构造退款模板、买方预签名和 Kind 2。 */
  async preparePoolOpening (fundingTransactionRaw: Uint8Array, poolOutputSatoshis: number, expiryLockTime: number, minerFeeRateSatoshisPerKilobyte: number, sellerPublicKey: Uint8Array, arbiterPublicKey: Uint8Array, signal?: AbortSignal): Promise<BuyerOpeningPreparation> {
    const engine = new MultisigPoolEngine({ buyerPublicKey: this.publicKey(), sellerPublicKey, arbiterPublicKey })
    const refundTemplateRaw = await engine.buildOpeningState(fundingTransactionRaw, poolOutputSatoshis, expiryLockTime, minerFeeRateSatoshisPerKilobyte)
    const buyerRefundSignature = await engine.signState(this.#signer, refundTemplateRaw, poolOutputSatoshis, signal)
    const request = encodeRefundPresignRequest({ refundTemplateRaw, buyerPublicKey: this.publicKey(), sellerPublicKey, arbiterPublicKey, minerFeeRateSatoshisPerKilobyte: BigInt(minerFeeRateSatoshisPerKilobyte), buyerRefundTransactionSignature: buyerRefundSignature })
    return { request, engine, refundTemplateRaw: copy(refundTemplateRaw), buyerRefundSignature: copy(buyerRefundSignature), poolOutputSatoshis }
  }

  /** 验证 Kind 3 关联 ID 和卖方签名，并合并双方退款签名。 */
  completePoolOpening (prepared: Readonly<BuyerOpeningPreparation>, rawKind3: Uint8Array): CompletedOpening {
    const outer = decodeOuter(parseAs(3, rawKind3), 4)
    const refundTemplateTxID = bytes(outer[2], 3, 'refund_template_txid')
    if (!equal(refundTemplateTxID, transactionID(prepared.refundTemplateRaw))) invalid(3, 'refund_template_txid', '卖方响应未引用当前退款模板')
    const sellerSignature = bytes(outer[3], 3, 'seller_refund_signature')
    const mergedRefundRaw = prepared.engine.mergeBuyerSeller(prepared.refundTemplateRaw, prepared.poolOutputSatoshis, prepared.buyerRefundSignature, sellerSignature)
    return { engine: prepared.engine, refundTemplateRaw: copy(prepared.refundTemplateRaw), mergedRefundRaw, refundTemplateTxID: copy(refundTemplateTxID), poolOutputSatoshis: prepared.poolOutputSatoshis }
  }

  /** 构造 Kind 4 资金交易交付。 */
  deliverFundingTransaction (opening: Readonly<CompletedOpening>, fundingTransactionRaw: Uint8Array): Artifact { return encodeFundingTransactionDelivery(opening.refundTemplateTxID, fundingTransactionRaw) }

  /** 构造下一状态、签署买方交易签名并生成 Kind 7。关闭时在 input 中传 final sequence/lockTime。 */
  async preparePayment (engine: MultisigPoolEngine, input: Readonly<PoolStateInput>, authorizationID: Uint8Array, signal?: AbortSignal): Promise<BuyerPaymentPreparation> {
    const unsignedRaw = await engine.buildState(input)
    const buyerSignature = await engine.signState(this.#signer, unsignedRaw, input.poolOutputSatoshis, signal)
    return { unsignedRaw, buyerSignature, paymentUpdate: encodePaymentUpdate(authorizationID, buyerSignature) }
  }

  /** 验证 Kind 6 的关联 ID、卖方签名以及每个 payload 的授权哈希。 */
  verifyDelivery (rawKind6: Uint8Array, request: Readonly<VerifiedContentRequest>, sellerPublicKey: Uint8Array): VerifiedContentDelivery {
    const outer = decodeOuter(parseAs(6, rawKind6), 5)
    const deliveryCBOR = bytes(outer[2], 6, 'content_delivery_cbor')
    const delivery = child(deliveryCBOR, 6, 'content_delivery_cbor', 1)
    const authorizationID = bytes(delivery[0], 6, 'payment_authorization_id')
    if (!equal(authorizationID, request.authorizationID)) invalid(6, 'payment_authorization_id', '交付未引用当前付款授权')
    verifyWireDocument(sellerPublicKey, 6, deliveryCBOR, bytes(outer[3], 6, 'seller_delivery_signature'))
    const payloads = decodeByteArray(bytes(outer[4], 6, 'content_payloads_cbor'), 6, 'content_payloads_cbor')
    verifyPayloadHashes(payloads, request.authorization.contentHashes, 6)
    return { authorizationID: copy(authorizationID), payloads }
  }

  /** 构造并签署 Kind 10 仲裁内容取回请求。 */
  requestArbitratedContent (claimID: Uint8Array, nonce: Uint8Array, signal?: AbortSignal): Promise<Artifact> {
    return createContentRetrievalRequest(this.#signer, claimID, nonce, signal)
  }
}

/** 卖方角色编排：发报价、验授权、交付内容、提交仲裁证据。 */
export class SellerWorkflow {
  readonly #signer: FrozenSigner
  constructor (signer: Signer) { this.#signer = freezeSigner(signer, 'seller_signer') }
  /** 返回固定卖方身份公钥的副本。 */
  publicKey (): Uint8Array { return copy(this.#signer.publicKey()) }
  /** 构造并签署 Kind 1 报价。 */
  createQuote (terms: Readonly<FileQuoteTerms>, signal?: AbortSignal): Promise<Artifact> { return createFileQuote(this.#signer, terms, signal) }

  /** 严格解析 Kind 5，并用费用池买方公钥验证授权签名。 */
  acceptContentRequest (rawKind5: Uint8Array, buyerPublicKey: Uint8Array): VerifiedContentRequest {
    const outer = decodeOuter(parseAs(5, rawKind5), 4)
    const authorizationCBOR = bytes(outer[2], 5, 'payment_authorization_cbor')
    verifyWireDocument(buyerPublicKey, 5, authorizationCBOR, bytes(outer[3], 5, 'buyer_authorization_signature'))
    return { authorization: decodeAuthorization(authorizationCBOR), authorizationCBOR: copy(authorizationCBOR), authorizationID: sha256(authorizationCBOR) }
  }

  /** 构造并签署 Kind 6 内容交付。 */
  deliverContent (authorizationID: Uint8Array, payloads: readonly Uint8Array[], signal?: AbortSignal): Promise<Artifact> {
    return createContentDelivery(this.#signer, authorizationID, payloads, signal)
  }

  /** 对已经由严格 parser 验证的 Claim 提交 Kind 8 托管证据。 */
  requestArbitration (claimCBOR: Uint8Array, payloads: readonly Uint8Array[], signal?: AbortSignal): Promise<Artifact> {
    return createArbitrationRequest(this.#signer, claimCBOR, payloads, signal)
  }

  /** 验证 Kind 2 买方预签名，生成卖方退款签名和 Kind 3；合并动作同时完成买方签名验收。 */
  async preparePoolOpening (rawKind2: Uint8Array, poolOutputSatoshis: number, signal?: AbortSignal): Promise<SellerOpeningPreparation> {
    const outer = decodeOuter(parseAs(2, rawKind2), 8)
    const refundTemplateRaw = bytes(outer[2], 2, 'refund_template_raw')
    const buyerPublicKey = bytes(outer[3], 2, 'buyer_public_key')
    const sellerPublicKey = bytes(outer[4], 2, 'seller_public_key')
    if (!equal(sellerPublicKey, this.publicKey())) throw new WireError('unauthorized', 2, 'seller_public_key', '开池请求未绑定当前卖方身份')
    const arbiterPublicKey = bytes(outer[5], 2, 'arbiter_public_key')
    const feeRate = integer(outer[6], 2, 'miner_fee_rate_satoshis_per_kilobyte')
    if (feeRate > BigInt(Number.MAX_SAFE_INTEGER)) invalid(2, 'miner_fee_rate_satoshis_per_kilobyte', '矿工费率超过 JavaScript 安全整数')
    const engine = new MultisigPoolEngine({ buyerPublicKey, sellerPublicKey, arbiterPublicKey })
    const buyerRefundSignature = bytes(outer[7], 2, 'buyer_refund_signature')
    const sellerRefundSignature = await engine.signState(this.#signer, refundTemplateRaw, poolOutputSatoshis, signal)
    engine.mergeBuyerSeller(refundTemplateRaw, poolOutputSatoshis, buyerRefundSignature, sellerRefundSignature)
    const response = encodeRefundPresignResponse(transactionID(refundTemplateRaw), sellerRefundSignature)
    return { response, engine, refundTemplateRaw: copy(refundTemplateRaw), buyerRefundSignature: copy(buyerRefundSignature), sellerRefundSignature, poolOutputSatoshis, minerFeeRateSatoshisPerKilobyte: Number(feeRate) }
  }

  /** 验证 Kind 4 与当前开池关联，并返回资金交易原文副本。 */
  async acceptFundingTransaction (prepared: Readonly<SellerOpeningPreparation>, rawKind4: Uint8Array): Promise<Uint8Array> {
    const outer = decodeOuter(parseAs(4, rawKind4), 4)
    if (!equal(bytes(outer[2], 4, 'refund_template_txid'), transactionID(prepared.refundTemplateRaw))) invalid(4, 'refund_template_txid', '资金交易未引用当前退款模板')
    const fundingRaw = bytes(outer[3], 4, 'funding_transaction_raw')
    await prepared.engine.verifyOpeningEvidence({
      fundingTransactionRaw: fundingRaw, refundTemplateRaw: prepared.refundTemplateRaw,
      buyerRefundSignature: prepared.buyerRefundSignature, sellerRefundSignature: prepared.sellerRefundSignature,
      poolOutputSatoshis: prepared.poolOutputSatoshis,
      minerFeeRateSatoshisPerKilobyte: prepared.minerFeeRateSatoshisPerKilobyte
    })
    return copy(fundingRaw)
  }

  /** 重建买方声明的状态、验证 Kind 7 签名、添加卖方签名并返回完整交易。 */
  async completePayment (engine: MultisigPoolEngine, input: Readonly<PoolStateInput>, rawKind7: Uint8Array, expectedAuthorizationID: Uint8Array, signal?: AbortSignal): Promise<Uint8Array> {
    const outer = decodeOuter(parseAs(7, rawKind7), 4)
    if (!equal(bytes(outer[2], 7, 'payment_authorization_id'), expectedAuthorizationID)) invalid(7, 'payment_authorization_id', '付款更新未引用当前授权')
    const unsignedRaw = await engine.buildState(input)
    const buyerSignature = bytes(outer[3], 7, 'buyer_payment_signature')
    const sellerSignature = await engine.signState(this.#signer, unsignedRaw, input.poolOutputSatoshis, signal)
    return engine.mergeBuyerSeller(unsignedRaw, input.poolOutputSatoshis, buyerSignature, sellerSignature)
  }
}

/** 仲裁方角色编排：验托管证据、签回执、认证取回请求并返回托管内容。 */
export class ArbiterWorkflow {
  readonly #signer: FrozenSigner
  readonly #owner = Object.freeze({})
  constructor (signer: Signer) { this.#signer = freezeSigner(signer, 'arbiter_signer') }
  /** 返回固定仲裁方身份公钥的副本。 */
  publicKey (): Uint8Array { return copy(this.#signer.publicKey()) }

  /** 验证 Kind 8 的卖方签名、仲裁方身份和 payload/hash 一一绑定。 */
  acceptArbitrationRequest (rawKind8: Uint8Array): VerifiedArbitrationRequest {
    const outer = decodeOuter(parseAs(8, rawKind8), 5)
    const claimCBOR = bytes(outer[2], 8, 'arbitration_claim_cbor')
    const claim = child(claimCBOR, 8, 'arbitration_claim_cbor', 5)
    const lock = bytes(claim[1], 8, 'pool_output_locking_script')
    const buyerPublicKey = lock.slice(2, 35); const sellerPublicKey = lock.slice(36, 69); const arbiterPublicKey = lock.slice(70, 103)
    if (!equal(arbiterPublicKey, this.publicKey())) throw new WireError('unauthorized', 8, 'arbiter_public_key', 'Claim 未绑定当前仲裁工作流身份')
    verifyWireDocument(sellerPublicKey, 8, claimCBOR, bytes(outer[3], 8, 'seller_claim_signature'))
    const authorization = decodeAuthorization(bytes(claim[3], 8, 'payment_authorization_cbor'))
    const payloads = decodeByteArray(bytes(outer[4], 8, 'content_payloads_cbor'), 8, 'content_payloads_cbor')
    verifyPayloadHashes(payloads, authorization.contentHashes, 8)
    const poolOutputSatoshis = integer(claim[0], 8, 'pool_output_satoshis')
    return {
      claimCBOR: copy(claimCBOR), claimID: sha256(claimCBOR), buyerPublicKey, sellerPublicKey, arbiterPublicKey, payloads,
      refundTemplateRaw: copy(bytes(claim[2], 8, 'refund_template_raw')), poolOutputSatoshis,
      paymentSequence: BigInt(authorization.paymentSequence), sellerAmountAfterSatoshis: authorization.sellerAmountAfterSatoshis,
      deliveryDeadlineUnixSeconds: authorization.deliveryDeadlineUnixSeconds
    }
  }

  /**
   * 完整 Prepare 阶段：验证 Kind 8、角色、payload、deadline、退款锁和仲裁 candidate，
   * 但绝不调用 Signer。返回对象必须先持久化，再交给 signPreparedArbitration。
   */
  prepareArbitration (facts: Readonly<WorkflowFacts>, rawKind8: Uint8Array, feeSatoshis: bigint): PreparedArbitration {
    if (feeSatoshis <= 0n || feeSatoshis > BigInt(Number.MAX_SAFE_INTEGER)) invalid(8, 'fee_satoshis', '仲裁费必须是正安全整数')
    const custody = this.acceptArbitrationRequest(rawKind8)
    validateArbitrationFacts(facts, custody)
    const candidateRaw = buildArbitrationCandidate({ poolOutputSatoshis: custody.poolOutputSatoshis, refundTemplateRaw: custody.refundTemplateRaw, paymentSequence: custody.paymentSequence, sellerAmountSatoshis: custody.sellerAmountAfterSatoshis, arbiterAmountSatoshis: feeSatoshis })
    const commitment = arbitrationCommitment(rawKind8, candidateRaw, custody.claimID, feeSatoshis)
    return new PreparedArbitration(rawKind8, custody, candidateRaw, feeSatoshis, this.#owner, commitment, preparedArbitrationToken)
  }

  /** 只签署本 Workflow 的 PreparedArbitration；签名前重新验证全部冻结证据。 */
  async signPreparedArbitration (prepared: PreparedArbitration, facts: Readonly<WorkflowFacts>, signal?: AbortSignal): Promise<SignedArbitration> {
    if (!(prepared instanceof PreparedArbitration)) invalid(9, 'prepared', '必须先执行 prepareArbitration')
    const frozen = prepared.snapshot()
    if (frozen.owner !== this.#owner) throw new WireError('unauthorized', 9, 'prepared', 'PreparedArbitration 属于另一个 Workflow')
    const custody = this.acceptArbitrationRequest(frozen.requestRaw)
    validateArbitrationFacts(facts, custody)
    verifyArbitrationCandidate({ poolOutputSatoshis: custody.poolOutputSatoshis, refundTemplateRaw: custody.refundTemplateRaw, paymentSequence: custody.paymentSequence, sellerAmountSatoshis: custody.sellerAmountAfterSatoshis, arbiterAmountSatoshis: frozen.feeSatoshis }, frozen.candidateRaw)
    if (!equal(frozen.commitment, arbitrationCommitment(frozen.requestRaw, frozen.candidateRaw, custody.claimID, frozen.feeSatoshis))) throw new WireError('state_conflict', 9, 'evidence_commitment', 'Prepare 后仲裁证据发生变化')
    const engine = new MultisigPoolEngine({ buyerPublicKey: custody.buyerPublicKey, sellerPublicKey: custody.sellerPublicKey, arbiterPublicKey: custody.arbiterPublicKey })
    const poolOutputSatoshis = Number(custody.poolOutputSatoshis)
    if (!Number.isSafeInteger(poolOutputSatoshis)) invalid(9, 'pool_output_satoshis', '费用池金额超过 JavaScript 安全整数')
    const arbiterTransactionSignature = await engine.signState(this.#signer, frozen.candidateRaw, poolOutputSatoshis, signal)
    const receiptCBOR = encodeCanonical([copy(custody.claimID), frozen.feeSatoshis, copy(arbiterTransactionSignature)])
    const response = await createArbitrationResponse(this.#signer, receiptCBOR, signal)
    return { response, candidateRaw: copy(frozen.candidateRaw), arbiterTransactionSignature, engine, poolOutputSatoshis }
  }

  /** 验证 Kind 10 确实由原 Claim 的买方签署，并返回 request ID。 */
  authenticateRetrieval (rawKind10: Uint8Array, custody: Readonly<VerifiedArbitrationRequest>): Uint8Array {
    const outer = decodeOuter(parseAs(10, rawKind10), 4)
    const requestCBOR = bytes(outer[2], 10, 'content_retrieval_request_cbor')
    const request = child(requestCBOR, 10, 'content_retrieval_request_cbor', 2)
    if (!equal(bytes(request[0], 10, 'arbitration_claim_id'), custody.claimID)) throw new WireError('unauthorized', 10, 'arbitration_claim_id', '取回请求未引用当前托管 Claim')
    verifyWireDocument(custody.buyerPublicKey, 10, requestCBOR, bytes(outer[3], 10, 'buyer_retrieval_signature'))
    return sha256(requestCBOR)
  }

  /** 返回 Kind 11 available，并把 exact payload bundle 哈希纳入签名。 */
  buildAvailableRetrieval (requestID: Uint8Array, custody: Readonly<VerifiedArbitrationRequest>, signal?: AbortSignal): Promise<Artifact> {
    return createContentRetrievalAvailable(this.#signer, requestID, custody.payloads, signal)
  }

  /** 返回 Kind 11 unavailable；reason：0 未收到、1 未就绪、2 托管已丢失。 */
  buildUnavailableRetrieval (requestID: Uint8Array, reason: 0 | 1 | 2, signal?: AbortSignal): Promise<Artifact> {
    return createContentRetrievalUnavailable(this.#signer, requestID, reason, signal)
  }

  /** 使用 SignPreparedArbitration 已生成的签名合并 Seller/Arbiter 仲裁交易。 */
  completeArbitratedPayment (signed: Readonly<SignedArbitration>, sellerSignature: Uint8Array): Uint8Array {
    return signed.engine.mergeSellerArbiter(signed.candidateRaw, signed.poolOutputSatoshis, sellerSignature, signed.arbiterTransactionSignature)
  }
}

function decodeOuter (artifact: Artifact, length: number): CBORValue[] { return child(artifact.bytes(), artifact.kind, 'wire', length) }
function child (raw: Uint8Array, kind: number, field: string, length: number): CBORValue[] { const value = decodeCanonical(raw, field); if (!Array.isArray(value) || value.length !== length) throw new WireError('malformed_wire', kind, field, `CBOR array 长度必须为 ${length}`); return value }
function bytes (value: CBORValue | undefined, kind: number, field: string): Uint8Array { if (!(value instanceof Uint8Array)) throw new WireError('malformed_wire', kind, field, '字段必须为 CBOR bstr'); return value }
function integer (value: CBORValue | undefined, kind: number, field: string): bigint { if (typeof value !== 'bigint') throw new WireError('malformed_wire', kind, field, '字段必须为 CBOR integer'); return value }
function text (value: CBORValue | undefined, kind: number, field: string): string { if (typeof value !== 'string') throw new WireError('malformed_wire', kind, field, '字段必须为 CBOR tstr'); return value }
function decodeByteArray (raw: Uint8Array, kind: number, field: string): Uint8Array[] { const values = decodeCanonical(raw, field); if (!Array.isArray(values)) throw new WireError('malformed_wire', kind, field, '字段必须为 CBOR array'); return values.map((value, index) => copy(bytes(value, kind, `${field}[${index}]`))) }
function decodeQuoteTerms (raw: Uint8Array): FileQuoteTerms { const value = child(raw, 1, 'file_quote_terms_cbor', 8); return { seedHash: copy(bytes(value[0], 1, 'seed_hash')), buyerPublicKey: copy(bytes(value[1], 1, 'buyer_public_key')), seedPriceSatoshis: integer(value[2], 1, 'seed_price_satoshis'), fullBlockPriceSatoshis: integer(value[3], 1, 'full_block_price_satoshis'), fileSizeBytes: integer(value[4], 1, 'file_size_bytes'), quoteExpiresAtUnixSeconds: integer(value[5], 1, 'quote_expires_at_unix_seconds'), supportedArbiterPublicKeys: decodeByteArray(bytes(value[6], 1, 'supported_arbiters_cbor'), 1, 'supported_arbiters_cbor'), recommendedFilename: text(value[7], 1, 'recommended_filename') } }
function decodeAuthorization (raw: Uint8Array): PaymentAuthorization { const value = child(raw, 5, 'payment_authorization_cbor', 6); const sequence = integer(value[2], 5, 'payment_sequence'); if (sequence > BigInt(Number.MAX_SAFE_INTEGER)) invalid(5, 'payment_sequence', '付款序号超过 JavaScript 安全整数'); return { fileQuoteTermsID: copy(bytes(value[0], 5, 'file_quote_terms_id')), refundTemplateTxID: copy(bytes(value[1], 5, 'refund_template_txid')), paymentSequence: Number(sequence), sellerAmountAfterSatoshis: integer(value[3], 5, 'seller_amount_after_satoshis'), contentHashes: decodeByteArray(bytes(value[4], 5, 'content_hashes_cbor'), 5, 'content_hashes_cbor'), deliveryDeadlineUnixSeconds: integer(value[5], 5, 'delivery_deadline_unix_seconds') } }
function verifyPayloadHashes (payloads: readonly Uint8Array[], hashes: readonly Uint8Array[], kind: number): void { if (payloads.length !== hashes.length) invalid(kind, 'content_payloads_cbor', 'payload 数量与授权哈希数量不一致'); for (let index = 0; index < payloads.length; index++) if (!equal(sha256(payloads[index]!), hashes[index]!)) invalid(kind, `payload[${index}]`, 'payload SHA-256 与授权哈希不一致') }
function validateArbitrationFacts (facts: Readonly<WorkflowFacts>, custody: Readonly<VerifiedArbitrationRequest>): void {
  if (facts.nowUnixSeconds >= custody.deliveryDeadlineUnixSeconds) throw new WireError('expired', 8, 'delivery_deadline_unix_seconds', '交付截止时间已过')
  const lockTime = transactionLockTime(custody.refundTemplateRaw)
  if (lockTime < 500_000_000) {
    if (facts.blockHeight == null || !Number.isInteger(facts.blockHeight) || facts.blockHeight < 0) invalid(8, 'block_height', '高度型退款锁需要显式区块高度')
    if (facts.blockHeight >= lockTime) throw new WireError('expired', 8, 'refund_locktime', '退款模板已经到期')
  } else if (facts.nowUnixSeconds >= BigInt(lockTime)) throw new WireError('expired', 8, 'refund_locktime', '退款模板已经到期')
}
function arbitrationCommitment (requestRaw: Uint8Array, candidateRaw: Uint8Array, claimID: Uint8Array, fee: bigint): Uint8Array { return sha256(concat(requestRaw, candidateRaw, claimID, encodeCanonical(fee))) }
function cloneCustody (value: Readonly<VerifiedArbitrationRequest>): VerifiedArbitrationRequest { return { ...value, claimCBOR: copy(value.claimCBOR), claimID: copy(value.claimID), buyerPublicKey: copy(value.buyerPublicKey), sellerPublicKey: copy(value.sellerPublicKey), arbiterPublicKey: copy(value.arbiterPublicKey), payloads: value.payloads.map(copy), refundTemplateRaw: copy(value.refundTemplateRaw) } }
class FrozenSigner implements Signer {
  readonly #publicKey: Uint8Array
  constructor (readonly delegate: Signer, readonly field: string) { this.#publicKey = copy(delegate.publicKey()) }
  publicKey (): Uint8Array { return copy(this.#publicKey) }
  async sign (request: Parameters<Signer['sign']>[0], signal?: AbortSignal): Promise<Uint8Array> {
    this.#assertIdentity()
    const signature = new Uint8Array(await this.delegate.sign(request, signal))
    this.#assertIdentity()
    return signature
  }
  #assertIdentity (): void { if (!equal(this.delegate.publicKey(), this.#publicKey)) throw new WireError('unauthorized', 0, this.field, 'Signer 公钥在 Workflow 生命周期内发生变化') }
}
function freezeSigner (signer: Signer, field: string): FrozenSigner { if (signer == null) throw new WireError('signer_unavailable', 0, field, '角色工作流必须提供 Signer'); const key = signer.publicKey(); if (key.length !== 33 || !secp256k1.utils.isValidPublicKey(key, true)) invalid(0, field, 'Signer 必须返回有效的 33 字节压缩 secp256k1 公钥'); return new FrozenSigner(signer, field) }
function invalid (kind: number, field: string, message: string): never { throw new WireError('invalid_evidence', kind, field, message) }
function equal (left: Uint8Array, right: Uint8Array): boolean { return left.length === right.length && left.every((value, index) => value === right[index]) }
function copy (value: Uint8Array): Uint8Array { return new Uint8Array(value) }
function concat (...parts: Uint8Array[]): Uint8Array { const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0)); let offset = 0; for (const part of parts) { output.set(part, offset); offset += part.length } return output }
