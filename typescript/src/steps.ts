import { sha256 } from '@noble/hashes/sha2.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { decodeCanonical, encodeCanonical, type CBORValue } from './cbor.js'
import { WireError } from './errors.js'
import {
  checkContentRequestTiming,
  contentHashesPriceSatoshis,
  decodeContentHashes,
  decodeContentPayloads,
  decodePaymentAuthorization,
  sanitizeRecommendedFilename,
  validateFileQuoteTerms,
  verifyContentPayloads,
  verifyContentRequestEvidence,
  verifyQuote,
  verifyQuoteEvidence,
  verifyQuoteForBuyer,
  verifySignedContentRequestForOpening,
  type SignedContentRequest,
  type SignedFileQuote,
  type VerifiedQuote
} from './content.js'
import type {
  ArbitratedContentInput,
  RequestContentInput,
  BuyerAuthorizationEvidence,
  BuyerOpeningEvidence,
  BuyerPoolEvidence,
  CompleteArbitratedPaymentInput,
  CompleteCloseInput,
  CompletePaymentInput,
  DeliveryInput,
  OpeningProof,
  PrepareArbitrationInput,
  PrepareCloseInput,
  PrepareOpeningInput,
  PreparedArbitrationEvidence,
  RetrievalRequestInput,
  SellerDeliveryEvidence,
  SellerOpeningEvidence,
  SellerPoolEvidence,
  SignedArbitrationEvidence,
  VerifiedCustodyEvidence,
  VerifyCompletedCloseInput,
  VerifyDeliveryInput
} from './evidence.js'
import {
  createArbitrationRequest,
  createArbitrationResponse,
  createContentDelivery,
  createContentRequest,
  createContentRetrievalRequest,
  createFileQuote,
  encodeContentHashes,
  encodeFundingTransactionDelivery,
  encodePaymentUpdate,
  encodeRefundPresignRequest,
  encodeRefundPresignResponse,
  type FileQuoteTerms,
  type PaymentAuthorization
} from './messages.js'
import {
  buildArbitrationPaymentFromClaim,
  buildImmediateClose,
  buildPaymentUpdate,
  buildRefundSubmission,
  checkPaymentCapacity,
  completeArbitratedTransaction,
  deriveOpeningDetails,
  deriveRefundTemplateTxID,
  MultisigPoolEngine,
  parseArbitratedPoolLockingScript,
  parseFundingOutput,
  parsePaymentState,
  parseUnsignedPayment,
  refundTemplateLockTime,
  verifyAcceptedPayment,
  verifyArbitratedPayment,
  verifyOpening,
  verifyPaymentState,
  verifySignedTransaction,
  type PaymentState,
  type PoolPublicKeys
} from './pool.js'
import { signWireDocument, verifyWireDocument, type Signer } from './protocol.js'
import { transactionID, validateArbitrationClaimStructure } from './transaction.js'
import { Artifact, parse, parseAs } from './wire.js'

/** 调用方显式传入的确定性事实；SDK 不读取系统时钟，也不查询节点。 */
export interface PureFunctionFacts {
  /** 当前 UTC Unix 秒，由上层可信时钟显式传入。 */
  nowUnixSeconds: bigint
  /** 当前区块高度；退款模板使用高度锁时必须提供。 */
  blockHeight?: number
}

/** 买方取回验收结果：unavailable 是已验签协议结果而非 error。 */
export interface ArbitratedContentResult {
  /** 本应答对应的 exact Kind 10 请求文档哈希。 */
  contentRetrievalRequestID: Uint8Array
  /** 托管记录的仲裁 Claim 身份。 */
  arbitrationClaimID: Uint8Array
  /** 分支结果：true 为可交付。 */
  available: boolean
  /** 仅 available=false 时有意义：0 未收到、1 未就绪、2 托管已丢失。 */
  unavailableReason: 0 | 1 | 2
  /** 仅 available=true 时非空：按授权顺序的已验证内容字节。 */
  payloads: Uint8Array[]
}

const FINAL_POOL_SEQUENCE = 0xffffffff
const MAX_UINT64 = 0xffffffffffffffffn
const MAX_SAFE_AMOUNT = BigInt(Number.MAX_SAFE_INTEGER)
const TIMESTAMP_THRESHOLD = 500_000_000

// ---------------------------------------------------------------------------
// 卖方步骤（001–007）
// ---------------------------------------------------------------------------

/**
 * 以单一条款签署确定性 Kind 1：先 sanitize 文件名再编码与签名，返回待发送
 * exact Kind 1 与最终规范化 terms（展示实际签署值）。
 */
export async function createSellerQuote (facts: Readonly<PureFunctionFacts>, signer: Signer, terms: Readonly<FileQuoteTerms>): Promise<{ outbound: Artifact, terms: FileQuoteTerms }> {
  const bound = bindSigner(signer, 'seller_signer')
  const now = requireNow(facts)
  const finalTerms: FileQuoteTerms = { ...terms, supportedArbiterPublicKeys: terms.supportedArbiterPublicKeys.map(copyBytes), seedHash: copyBytes(terms.seedHash), buyerPublicKey: copyBytes(terms.buyerPublicKey), recommendedFilename: sanitizeRecommendedFilename(terms.recommendedFilename) }
  validateFileQuoteTerms(finalTerms)
  if (!(now < finalTerms.quoteExpiresAtUnixSeconds)) throw new WireError('expired', 1, 'quote_expires_at_unix_seconds', '报价在给定 facts.now 已失效')
  const outbound = await createFileQuote(bound, finalTerms)
  const verified = verifyQuoteEvidence(decodeKind1Quote(outbound.bytes()))
  return { outbound, terms: verified.terms }
}

/**
 * 卖方预签：解析 exact Kind 2 → 角色/模板/费率验证 → 买方退款签名验证 →
 * 才调用 Signer。金额从退款模板推导，不接收调用方金额。
 */
export async function prepareSellerPresign (rawKind2: Uint8Array, signer: Signer): Promise<{ outbound: Artifact, opening: SellerOpeningEvidence }> {
  const bound = bindSigner(signer, 'seller_signer')
  const request = decodeKind2Request(rawKind2)
  if (!equal(bound.publicKey(), request.sellerPublicKey)) throw new WireError('unauthorized', 2, 'seller_public_key', '开池请求未绑定当前卖方身份')
  const engine = new MultisigPoolEngine({ buyerPublicKey: request.buyerPublicKey, sellerPublicKey: request.sellerPublicKey, arbiterPublicKey: request.arbiterPublicKey })
  const terms = await engine.deriveRefundTerms(request.refundTemplateRaw, request.minerFeeRateSatoshisPerKilobyte)
  engine.verifyRole('buyer', request.refundTemplateRaw, terms.poolOutputSatoshis, request.buyerRefundSignature)
  const sellerRefundSignature = await engine.signRole(bound, 'seller', request.refundTemplateRaw, terms.poolOutputSatoshis)
  const outbound = encodeRefundPresignResponse(terms.refundTemplateTxId, sellerRefundSignature)
  return { outbound, opening: { rawKind2: copyBytes(rawKind2), rawKind3: outbound.bytes() } }
}

/**
 * 卖方验资：用预签证据包重建完整开池证明，验证资金交易 output[0] 金额/脚本
 * 与退款模板重建一致，并解析初始链上退款状态。
 */
export async function verifySellerFunding (rawKind4: Uint8Array, opening: SellerOpeningEvidence): Promise<{ fundingTransactionRaw: Uint8Array, pool: SellerPoolEvidence }> {
  const request = decodeKind2Request(opening.rawKind2)
  const response = decodeKind3Response(opening.rawKind3)
  const engine = new MultisigPoolEngine({ buyerPublicKey: request.buyerPublicKey, sellerPublicKey: request.sellerPublicKey, arbiterPublicKey: request.arbiterPublicKey })
  const terms = await engine.deriveRefundTerms(request.refundTemplateRaw, request.minerFeeRateSatoshisPerKilobyte)
  engine.verifyRole('buyer', request.refundTemplateRaw, terms.poolOutputSatoshis, request.buyerRefundSignature)
  if (!equal(terms.refundTemplateTxId, response.refundTemplateTxId)) throw new WireError('state_conflict', 3, 'refund_template_txid', '持久化响应与请求派生关联 ID 不一致')
  engine.verifyRole('seller', request.refundTemplateRaw, terms.poolOutputSatoshis, response.sellerRefundSignature)
  const proof: OpeningProof = {
    refundTemplateRaw: copyBytes(request.refundTemplateRaw),
    buyerPublicKey: copyBytes(request.buyerPublicKey),
    sellerPublicKey: copyBytes(request.sellerPublicKey),
    arbiterPublicKey: copyBytes(request.arbiterPublicKey),
    minerFeeRateSatoshisPerKilobyte: request.minerFeeRateSatoshisPerKilobyte,
    buyerRefundSignature: copyBytes(request.buyerRefundSignature),
    sellerRefundSignature: copyBytes(response.sellerRefundSignature),
    fundingTransactionRaw: new Uint8Array()
  }
  const delivery = decodeKind4Delivery(rawKind4)
  if (!equal(terms.refundTemplateTxId, delivery.refundTemplateTxId)) throw new WireError('state_conflict', 4, 'refund_template_txid', '资金交易未引用持久化预签证据')
  proof.fundingTransactionRaw = copyBytes(delivery.fundingTransactionRaw)
  await verifyOpening(proof)
  const initialRaw = await buildRefundSubmission(proof)
  const initial = await parsePaymentState(initialRaw, proof)
  await verifyAcceptedPayment(initial, proof)
  return {
    fundingTransactionRaw: copyBytes(delivery.fundingTransactionRaw),
    pool: { opening: proof, fundingTransactionRaw: copyBytes(delivery.fundingTransactionRaw) }
  }
}

/**
 * 卖方交付：完成 quote/opening/时序/序号/容量/价格/payload 全量校验后签署
 * exact Kind 6，返回待发送报文与普通证据包。Send 之前必须先持久化 payload
 * 与本证据包。
 */
export async function prepareSellerDelivery (facts: Readonly<PureFunctionFacts>, input: DeliveryInput, signer: Signer): Promise<{ outbound: Artifact, evidence: SellerDeliveryEvidence }> {
  const bound = bindSigner(signer, 'seller_signer')
  const now = requireNow(facts)
  const signedQuote = decodeKind1Quote(input.quoteRaw)
  const checkpoint = await sellerPoolCheckpoint(input.pool)
  const opening = checkpoint.opening
  const previous = checkpoint.payment
  if (!equal(bound.publicKey(), opening.sellerPublicKey)) throw new WireError('unauthorized', 0, 'seller_public_key', 'Signer 与开池卖方不一致')
  const details = await deriveOpeningDetails(opening)
  checkRefundNotExpired(facts, details.refundLockTime)
  const request = decodeKind5Request(input.requestRaw)
  const { authorization, quoteTerms } = await verifyContentRequestEvidence(request, signedQuote, opening)
  checkContentRequestTiming(authorization, quoteTerms, now)
  if (!equal(previous.refundTemplateTxId, details.refundTemplateTxId) || previous.paymentSequence + 1 !== authorization.paymentSequence) throw new WireError('state_conflict', 0, 'payment_sequence', '付款序号不是上一状态加一')
  await verifyAcceptedPayment(previous, opening)
  if (authorization.sellerAmountAfterSatoshis < previous.sellerAmountSatoshis) throw new WireError('invalid_evidence', 6, 'seller_amount_after_satoshis', '授权金额不能倒退')
  const expectedPrice = authorization.sellerAmountAfterSatoshis - previous.sellerAmountSatoshis
  await checkPaymentCapacity(opening, previous, authorization.paymentSequence, authorization.sellerAmountAfterSatoshis)
  const hashes = decodeValidatedHashes(authorization.contentHashes)
  const payloads = input.contentPayloads.map(copyBytes)
  const effectiveSeed = await verifyContentPayloads(quoteTerms, hashes, payloads, input.seed)
  const price = await contentHashesPriceSatoshis(quoteTerms, hashes, effectiveSeed)
  if (price !== expectedPrice || authorization.sellerAmountAfterSatoshis !== previous.sellerAmountSatoshis + price) throw new WireError('invalid_evidence', 6, 'seller_amount_after_satoshis', '授权金额或序号与已验证内容价格不一致')
  const authorizationID = sha256(request.paymentAuthorizationCBOR)
  const outbound = await createContentDelivery(bound, authorizationID, payloads)
  return {
    outbound,
    evidence: { rawKind1: copyBytes(input.quoteRaw), rawKind5: copyBytes(input.requestRaw), rawKind6: outbound.bytes() }
  }
}

/**
 * 卖方收款：验证 exact Kind 7 的授权 ID 与本方 exact Kind 5 一致、序号恰好
 * +1、金额不倒退、容量足够，验过买方签名后补签并合并完整交易。
 */
export async function completeSellerPayment (facts: Readonly<PureFunctionFacts>, input: CompletePaymentInput, signer: Signer): Promise<{ rawTransaction: Uint8Array, pool: SellerPoolEvidence }> {
  const bound = bindSigner(signer, 'seller_signer')
  const checkpoint = await sellerPoolCheckpoint(input.pool)
  const opening = checkpoint.opening
  const previous = checkpoint.payment
  if (!equal(input.delivery.rawKind5, input.requestRaw)) throw new WireError('state_conflict', 7, 'request_raw', '传入的 Kind 5 与已保存交付证据不一致')
  const { request, authorization } = decodeSignedContentRequest(input.requestRaw)
  const authorizationID = sha256(request.paymentAuthorizationCBOR)
  verifyStoredDelivery(opening, input.delivery, authorizationID)
  const update = decodeKind7Update(input.updateRaw)
  if (!equal(update.paymentAuthorizationId, authorizationID)) throw new WireError('state_conflict', 7, 'payment_authorization_id', '付款更新引用了不同授权')
  const details = await deriveOpeningDetails(opening)
  checkRefundNotExpired(facts, details.refundLockTime)
  if (!equal(previous.refundTemplateTxId, details.refundTemplateTxId)) throw new WireError('state_conflict', 0, 'payment_sequence', '付款状态属于另一个费用池')
  await verifyPreviousPayment(previous, opening)
  if (previous.paymentSequence + 1 !== authorization.paymentSequence || authorization.paymentSequence === FINAL_POOL_SEQUENCE) throw new WireError('state_conflict', 0, 'payment_sequence', '付款序号陈旧')
  if (authorization.sellerAmountAfterSatoshis < previous.sellerAmountSatoshis) throw new WireError('invalid_evidence', 7, 'seller_amount_after_satoshis', '授权卖方金额不能倒退')
  const unsigned = await buildPaymentUpdate(opening, previous, authorization.paymentSequence, authorization.sellerAmountAfterSatoshis)
  const engine = new MultisigPoolEngine({ buyerPublicKey: opening.buyerPublicKey, sellerPublicKey: opening.sellerPublicKey, arbiterPublicKey: opening.arbiterPublicKey })
  engine.verifyRole('buyer', unsigned, details.poolOutputSatoshis, update.buyerPaymentTransactionSignature)
  const sellerSignature = await engine.signRole(bound, 'seller', unsigned, details.poolOutputSatoshis)
  const rawTransaction = engine.mergeBuyerSeller(unsigned, Number(details.poolOutputSatoshis), update.buyerPaymentTransactionSignature, sellerSignature)
  await verifySignedTransaction(rawTransaction, opening)
  return {
    rawTransaction,
    pool: { opening: cloneOpening(opening), fundingTransactionRaw: copyBytes(opening.fundingTransactionRaw), latestPaymentRawTx: copyBytes(rawTransaction) }
  }
}

/**
 * 卖方关池：校验买方关闭 candidate 结构与角色签名后补签并合并完整交易。
 * 返回完整交易原文，是否广播由应用决定。
 */
export async function completeSellerClose (facts: Readonly<PureFunctionFacts>, input: CompleteCloseInput, signer: Signer): Promise<Uint8Array> {
  const bound = bindSigner(signer, 'seller_signer')
  const checkpoint = await sellerPoolCheckpoint(input.pool)
  const opening = checkpoint.opening
  const details = await deriveOpeningDetails(opening)
  if (!equal(bound.publicKey(), opening.sellerPublicKey)) throw new WireError('unauthorized', 0, 'seller_public_key', 'Signer 与开池卖方不一致')
  checkRefundNotExpired(facts, details.refundLockTime)
  const unsigned = await parseUnsignedPayment(input.unsignedRaw, opening)
  if (unsigned.paymentSequence !== FINAL_POOL_SEQUENCE) throw new WireError('invalid_evidence', 0, 'unsigned_close', '立即关闭必须使用最终 sequence')
  if (unsigned.sellerAmountSatoshis + unsigned.buyerAmountSatoshis + unsigned.arbiterAmountSatoshis > details.poolOutputSatoshis) throw new WireError('insufficient_balance', 0, 'outputs_satoshis', '立即关闭输出超过费用池容量')
  const engine = new MultisigPoolEngine({ buyerPublicKey: opening.buyerPublicKey, sellerPublicKey: opening.sellerPublicKey, arbiterPublicKey: opening.arbiterPublicKey })
  engine.verifyRole('buyer', input.unsignedRaw, details.poolOutputSatoshis, input.buyerSignature)
  const sellerSignature = await engine.signRole(bound, 'seller', input.unsignedRaw, details.poolOutputSatoshis)
  const rawTransaction = engine.mergeBuyerSeller(input.unsignedRaw, Number(details.poolOutputSatoshis), input.buyerSignature, sellerSignature)
  const state = await parsePaymentState(rawTransaction, opening)
  if (state.paymentSequence !== FINAL_POOL_SEQUENCE) throw new WireError('invalid_evidence', 0, 'payment_sequence', '卖方签名未保持最终 sequence')
  return await verifySignedTransaction(rawTransaction, opening)
}

/**
 * 卖方仲裁证据：验证本地开池、买方授权与本方已发交付后签署紧凑 Claim，
 * 返回 exact Kind 8 与独立计算的 Claim ID。
 */
export async function prepareSellerArbitration (facts: Readonly<PureFunctionFacts>, input: PrepareArbitrationInput, signer: Signer): Promise<{ outbound: Artifact, claimID: Uint8Array }> {
  const bound = bindSigner(signer, 'seller_signer')
  const now = requireNow(facts)
  const checkpoint = await sellerPoolCheckpoint(input.pool)
  const opening = checkpoint.opening
  if (!equal(bound.publicKey(), opening.sellerPublicKey)) throw new WireError('unauthorized', 0, 'seller_public_key', 'Signer 与开池卖方不一致')
  const { request } = decodeSignedContentRequest(input.requestRaw)
  const details = await deriveOpeningDetails(opening)
  checkRefundNotExpired(facts, details.refundLockTime)
  const built = await buildClaimFromAuthorization(opening, request)
  if (!(now < built.authorization.deliveryDeadlineUnixSeconds)) throw new WireError('expired', 8, 'delivery_deadline_unix_seconds', '交付截止时间已过')
  const authorizationID = sha256(request.paymentAuthorizationCBOR)
  const delivery = decodeKind6Delivery(input.deliveryRaw)
  const deliveryAuthorizationID = decodeContentDeliveryDocument(delivery.contentDeliveryCBOR)
  if (!equal(deliveryAuthorizationID, authorizationID)) throw new WireError('invalid_evidence', 8, 'content_delivery_cbor', '交付引用了不同授权')
  verifyWireDocument(opening.sellerPublicKey, 6, delivery.contentDeliveryCBOR, delivery.sellerContentDeliverySignature)
  const payloads = decodeContentPayloads(delivery.contentPayloadsCBOR)
  const hashes = decodeValidatedHashes(built.authorization.contentHashes)
  if (payloads.length !== hashes.length) throw new WireError('invalid_evidence', 8, 'payload_count', '交付 payload 数量与授权哈希不一致')
  for (let index = 0; index < payloads.length; index++) if (!equal(sha256(payloads[index]!), hashes[index]!)) throw new WireError('invalid_evidence', 8, `payload[${index}]`, `交付 payload #${index + 1} 与授权哈希不一致`)
  const outbound = await createArbitrationRequest(bound, built.claimCBOR, payloads)
  return { outbound, claimID: built.claimID }
}

/**
 * 卖方仲裁收款：从 exact Kind 8/9 完整验证托管收款路径，独立重建付费
 * candidate、验证回执消息签名与仲裁交易签名，然后补签卖方签名并合并。
 */
export async function completeSellerArbitratedPayment (facts: Readonly<PureFunctionFacts>, input: CompleteArbitratedPaymentInput, signer: Signer): Promise<Uint8Array> {
  const bound = bindSigner(signer, 'seller_signer')
  const request = decodeKind8Request(input.requestRaw)
  const response = decodeKind9Response(input.responseRaw)
  const receipt = unmarshalReceipt(response.arbitrationReceiptCBOR)
  const claim = unmarshalClaim(request.arbitrationClaimCBOR)
  const authorization = decodePaymentAuthorization(claim.paymentAuthorizationCBOR)
  const keys = parseArbitratedPoolLockingScript(claim.poolOutputLockingScript)
  if (!equal(bound.publicKey(), keys.sellerPublicKey)) throw new WireError('unauthorized', 9, 'seller_public_key', 'Signer 与 Claim 卖方不一致')
  try { verifyWireDocument(keys.buyerPublicKey, 5, claim.paymentAuthorizationCBOR, claim.buyerPaymentAuthorizationSignature) } catch (error) { throw rethrow(error, 'invalid_signature', 9, 'buyer_payment_authorization_signature') }
  try { verifyWireDocument(keys.sellerPublicKey, 8, request.arbitrationClaimCBOR, request.sellerArbitrationClaimSignature) } catch (error) { throw rethrow(error, 'invalid_signature', 9, 'seller_arbitration_claim_signature') }
  const payloads = decodeContentPayloads(request.contentPayloadsCBOR)
  if ((input.deliveryPayloadsCBOR?.byteLength ?? 0) > 0 && !equal(input.deliveryPayloadsCBOR!, request.contentPayloadsCBOR)) throw new WireError('state_conflict', 9, 'content_payloads_cbor', '已存交付 payload 与托管附件不一致')
  const hashes = decodeValidatedHashes(authorization.contentHashes)
  if (payloads.length !== hashes.length) throw new WireError('invalid_evidence', 9, 'payload_count', 'payload 数量与授权哈希不一致')
  for (let index = 0; index < payloads.length; index++) if (!equal(sha256(payloads[index]!), hashes[index]!)) throw new WireError('invalid_evidence', 9, `payload[${index}]`, `payload #${index + 1} 与授权哈希不一致`)
  const localClaimID = sha256(request.arbitrationClaimCBOR)
  if (!equal(receipt.arbitrationClaimID, localClaimID)) throw new WireError('state_conflict', 9, 'arbitration_claim_id', '回执 Claim ID 与独立重算值不一致')
  try { verifyWireDocument(keys.arbiterPublicKey, 9, response.arbitrationReceiptCBOR, response.arbiterArbitrationReceiptSignature) } catch (error) { throw rethrow(error, 'invalid_signature', 9, 'arbiter_arbitration_receipt_signature') }
  const unsigned = buildArbitrationPaymentFromClaim(claim.poolOutputSatoshis, claim.poolOutputLockingScript, claim.refundTemplateRaw, authorization.paymentSequence, authorization.sellerAmountAfterSatoshis, receipt.arbiterAmountSatoshis)
  checkRefundNotExpired(facts, refundTemplateLockTime(claim.refundTemplateRaw))
  const engine = new MultisigPoolEngine(keys)
  try { engine.verifyRole('arbiter', unsigned.unsignedRaw, unsigned.poolOutputSatoshis, receipt.arbiterPaymentTransactionSignature) } catch (error) { throw rethrow(error, 'invalid_signature', 9, 'arbiter_payment_transaction_signature') }
  const sellerSignature = await engine.signRole(bound, 'seller', unsigned.unsignedRaw, unsigned.poolOutputSatoshis)
  return await completeArbitratedTransaction(unsigned.unsignedRaw, unsigned.poolOutputSatoshis, unsigned.poolLockingScript, sellerSignature, receipt.arbiterPaymentTransactionSignature)
}

// ---------------------------------------------------------------------------
// 买方步骤（001–006 与 008 取回）
// ---------------------------------------------------------------------------

/**
 * 严格解析 exact Kind 1，验签与显式过期判断（唯一时间事实为 facts.now）通过后
 * 返回不可变 VerifiedQuote。本操作不绑定身份：买方应用自行比较返回 terms 的
 * BuyerPublicKey 与本地身份后再决定是否购买。
 */
export function acceptBuyerQuote (facts: Readonly<PureFunctionFacts>, rawKind1: Uint8Array): VerifiedQuote {
  const now = requireNow(facts)
  return verifyQuote(decodeKind1Quote(rawKind1), now)
}

/**
 * 买方开池：从资金交易 output[0] 构造退款模板、买方可信签名与 exact Kind 2。
 * 纯交易构造，不含时间/高度判断，因此不接收 facts。
 */
export async function prepareBuyerOpening (input: PrepareOpeningInput, signer: Signer): Promise<{ outbound: Artifact, opening: BuyerOpeningEvidence }> {
  const bound = bindSigner(signer, 'buyer_signer')
  const quote = verifyQuoteEvidence(decodeKind1Quote(input.quoteRaw))
  if (!equal(quote.terms.buyerPublicKey, bound.publicKey())) throw new WireError('unauthorized', 2, 'buyer_public_key', 'Signer 不是报价命名的买方')
  if (!equal(quote.sellerPublicKey, input.sellerPublicKey)) throw new WireError('invalid_evidence', 2, 'seller_public_key', '开池卖方与报价卖方不一致')
  if (!quote.allowsArbiter(input.arbiterPublicKey)) throw new WireError('invalid_evidence', 2, 'supported_arbiter_public_keys', '开池仲裁方不在报价允许列表内')
  if (input.expiryLockTime === 0) throw new WireError('invalid_evidence', 2, 'expiry_lock_time', '退款到期锁定时间不能为零')
  const engine = new MultisigPoolEngine({ buyerPublicKey: bound.publicKey(), sellerPublicKey: input.sellerPublicKey, arbiterPublicKey: input.arbiterPublicKey })
  const output = parseFundingOutput(input.fundingTransactionRaw, 0)
  if (!equal(output.lockingScript, engine.lockingScript())) throw new WireError('invalid_evidence', 2, 'funding_transaction_raw', '资金输出未使用配置的三方锁定脚本')
  if (output.satoshis > MAX_SAFE_AMOUNT || input.minerFeeRateSatoshisPerKilobyte > MAX_SAFE_AMOUNT) throw new WireError('invalid_evidence', 2, 'funding_transaction_raw', '金额或费率超过安全整数')
  const refundTemplateRaw = await engine.buildOpeningState(input.fundingTransactionRaw, Number(output.satoshis), input.expiryLockTime, Number(input.minerFeeRateSatoshisPerKilobyte))
  const buyerRefundSignature = await engine.signRole(bound, 'buyer', refundTemplateRaw, output.satoshis)
  const outbound = encodeRefundPresignRequest({
    refundTemplateRaw,
    buyerPublicKey: bound.publicKey(),
    sellerPublicKey: copyBytes(input.sellerPublicKey),
    arbiterPublicKey: copyBytes(input.arbiterPublicKey),
    minerFeeRateSatoshisPerKilobyte: input.minerFeeRateSatoshisPerKilobyte,
    buyerRefundTransactionSignature: buyerRefundSignature
  })
  return { outbound, opening: { rawKind2: outbound.bytes(), rawKind3: new Uint8Array(), fundingTransactionRaw: copyBytes(input.fundingTransactionRaw) } }
}

/**
 * 买方完成开池：用保存的普通证据包验收 exact Kind 3，验卖方预签并产出完整
 * 开池证据包与初始池证据包。
 */
export async function completeBuyerOpening (opening: BuyerOpeningEvidence, rawKind3: Uint8Array): Promise<{ opening: BuyerOpeningEvidence, pool: BuyerPoolEvidence }> {
  const request = decodeKind2Request(opening.rawKind2)
  const response = decodeKind3Response(rawKind3)
  const engine = new MultisigPoolEngine({ buyerPublicKey: request.buyerPublicKey, sellerPublicKey: request.sellerPublicKey, arbiterPublicKey: request.arbiterPublicKey })
  const terms = await engine.deriveRefundTerms(request.refundTemplateRaw, request.minerFeeRateSatoshisPerKilobyte)
  engine.verifyRole('buyer', request.refundTemplateRaw, terms.poolOutputSatoshis, request.buyerRefundSignature)
  if (opening.fundingTransactionRaw.byteLength === 0) throw new WireError('invalid_evidence', 2, 'funding_transaction_raw', '缺少资金交易原文')
  const fundingOutput = parseFundingOutput(opening.fundingTransactionRaw, 0)
  if (!equal(transactionID(opening.fundingTransactionRaw), terms.fundingTxId) || fundingOutput.satoshis !== terms.poolOutputSatoshis || !equal(fundingOutput.lockingScript, engine.lockingScript())) throw new WireError('invalid_evidence', 2, 'funding_transaction_raw', '资金交易与开池证据不一致')
  if (!equal(terms.refundTemplateTxId, response.refundTemplateTxId)) throw new WireError('state_conflict', 3, 'refund_template_txid', '预签响应与持久化开池证据不一致')
  engine.verifyRole('seller', request.refundTemplateRaw, terms.poolOutputSatoshis, response.sellerRefundSignature)
  const proof: OpeningProof = {
    refundTemplateRaw: copyBytes(request.refundTemplateRaw),
    buyerPublicKey: copyBytes(request.buyerPublicKey),
    sellerPublicKey: copyBytes(request.sellerPublicKey),
    arbiterPublicKey: copyBytes(request.arbiterPublicKey),
    minerFeeRateSatoshisPerKilobyte: request.minerFeeRateSatoshisPerKilobyte,
    buyerRefundSignature: copyBytes(request.buyerRefundSignature),
    sellerRefundSignature: copyBytes(response.sellerRefundSignature),
    fundingTransactionRaw: copyBytes(opening.fundingTransactionRaw)
  }
  await verifyOpening(proof)
  const initialRaw = await buildRefundSubmission(proof)
  const initial = await parsePaymentState(initialRaw, proof)
  await verifyAcceptedPayment(initial, proof)
  if (initial.paymentSequence !== 2 || initial.sellerAmountSatoshis !== 0n || initial.arbiterAmountSatoshis !== 0n) throw new WireError('invalid_evidence', 3, 'payment_state', '退款交易不是初始池状态')
  return {
    opening: { rawKind2: copyBytes(opening.rawKind2), rawKind3: copyBytes(rawKind3), fundingTransactionRaw: copyBytes(opening.fundingTransactionRaw) },
    pool: { opening: proof }
  }
}

/** 把完整开池证据包携带的资金交易打包成 exact Kind 4 Artifact。 */
export async function prepareBuyerFundingDelivery (pool: BuyerPoolEvidence): Promise<Artifact> {
  const checkpoint = await buyerPoolCheckpoint(pool)
  const opening = checkpoint.opening
  const refundTemplateTxID = await deriveRefundTemplateTxID(opening)
  if (opening.fundingTransactionRaw.byteLength === 0) throw new WireError('invalid_evidence', 4, 'funding_transaction_raw', '完整资金交易原文是必需的')
  return encodeFundingTransactionDelivery(refundTemplateTxID, opening.fundingTransactionRaw)
}

/**
 * 买方请求内容：验证报价/池/批次上下文/聚合价格/余额后签署 exact Kind 5，
 * 返回待发送 Artifact 与必须先持久化的普通授权证据包。
 */
export async function prepareBuyerContentRequest (facts: Readonly<PureFunctionFacts>, input: RequestContentInput, signer: Signer): Promise<{ outbound: Artifact, authorization: BuyerAuthorizationEvidence }> {
  const bound = bindSigner(signer, 'buyer_signer')
  const now = requireNow(facts)
  const signedQuote = decodeKind1Quote(input.quoteRaw)
  const verifiedQuote = verifyQuoteForBuyer(signedQuote, now, bound.publicKey())
  const checkpoint = await buyerPoolCheckpoint(input.pool)
  const opening = checkpoint.opening
  const previous = checkpoint.payment
  if (!equal(bound.publicKey(), opening.buyerPublicKey)) throw new WireError('unauthorized', 5, 'buyer_public_key', 'Signer 与开池买方不一致')
  const details = await deriveOpeningDetails(opening)
  checkRefundNotExpired(facts, details.refundLockTime)
  const terms = verifiedQuote.terms
  if (input.deliveryDeadline <= now) throw new WireError('expired', 5, 'delivery_deadline_unix_seconds', '交付截止时间不在未来')
  if (!(now < terms.quoteExpiresAtUnixSeconds)) throw new WireError('expired', 5, 'quote_expires_at_unix_seconds', '报价已经失效')
  if (input.deliveryDeadline > terms.quoteExpiresAtUnixSeconds) throw new WireError('invalid_evidence', 5, 'delivery_deadline_unix_seconds', '交付截止时间超过报价失效时间')
  if (!equal(opening.buyerPublicKey, terms.buyerPublicKey) || !equal(opening.sellerPublicKey, signedQuote.sellerPublicKey)) throw new WireError('invalid_evidence', 5, 'participant_public_keys', '费用池参与方与报价不一致')
  if (!verifiedQuote.allowsArbiter(opening.arbiterPublicKey)) throw new WireError('invalid_evidence', 5, 'supported_arbiter_public_keys', '开池仲裁方不在报价白名单内')
  if (!equal(previous.refundTemplateTxId, details.refundTemplateTxId) || previous.paymentSequence >= FINAL_POOL_SEQUENCE - 1) throw new WireError('state_conflict', 0, 'payment_sequence', '付款序号陈旧')
  await verifyAcceptedPayment(previous, opening)
  const targetSequence = previous.paymentSequence + 1
  const hashes = input.contentHashes.map(copyBytes)
  const price = await contentHashesPriceSatoshis(terms, hashes, input.seed)
  if (previous.sellerAmountSatoshis > MAX_UINT64 - price) throw new WireError('insufficient_balance', 5, 'seller_amount_after_satoshis', '聚合价格超过剩余池余额')
  const sellerAmountAfter = previous.sellerAmountSatoshis + price
  await checkPaymentCapacity(opening, previous, targetSequence, sellerAmountAfter)
  const authorization: PaymentAuthorization = {
    fileQuoteTermsID: copyBytes(verifiedQuote.termsID),
    refundTemplateTxID: copyBytes(details.refundTemplateTxId),
    paymentSequence: targetSequence,
    sellerAmountAfterSatoshis: sellerAmountAfter,
    contentHashes: hashes,
    deliveryDeadlineUnixSeconds: input.deliveryDeadline
  }
  const outbound = await createContentRequest(bound, authorization)
  return { outbound, authorization: { rawKind1: copyBytes(input.quoteRaw), rawKind5: outbound.bytes() } }
}

/**
 * 买方验货付款：验收 exact Kind 6 并产生整批唯一的最小 exact Kind 7 凭证。
 * 先验 payload 与 seed 归属，再签 Kind 7；不产生“已付款”状态。
 */
export async function verifyBuyerDelivery (facts: Readonly<PureFunctionFacts>, input: VerifyDeliveryInput, signer: Signer): Promise<{ payloads: Uint8Array[], outbound: Artifact }> {
  const bound = bindSigner(signer, 'buyer_signer')
  const now = requireNow(facts)
  const signedQuote = decodeKind1Quote(input.authorization.rawKind1)
  verifyQuoteForBuyer(signedQuote, now, bound.publicKey())
  const checkpoint = await buyerPoolCheckpoint(input.pool)
  const opening = checkpoint.opening
  const previous = checkpoint.payment
  if (!equal(bound.publicKey(), opening.buyerPublicKey)) throw new WireError('unauthorized', 6, 'buyer_public_key', 'Signer 与开池买方不一致')
  const details = await deriveOpeningDetails(opening)
  checkRefundNotExpired(facts, details.refundLockTime)
  const request = decodeKind5Request(input.authorization.rawKind5)
  const requestID = sha256(request.paymentAuthorizationCBOR)
  const { authorization, quoteTerms } = await verifyContentRequestEvidence(request, signedQuote, opening)
  if (!equal(previous.refundTemplateTxId, details.refundTemplateTxId)) throw new WireError('invalid_evidence', 6, 'refund_template_txid', '内容请求未绑定开池证明')
  checkContentRequestTiming(authorization, quoteTerms, now)
  const delivery = decodeKind6Delivery(input.deliveryRaw)
  const deliveryAuthorizationID = decodeContentDeliveryDocument(delivery.contentDeliveryCBOR)
  if (!equal(deliveryAuthorizationID, requestID)) throw new WireError('invalid_evidence', 6, 'content_delivery_cbor', '交付未引用给定请求')
  const hashes = decodeValidatedHashes(authorization.contentHashes)
  const payloads = decodeContentPayloads(delivery.contentPayloadsCBOR)
  const effectiveSeed = await verifyContentPayloads(quoteTerms, hashes, payloads, input.seed)
  if (previous.paymentSequence + 1 !== authorization.paymentSequence || previous.paymentSequence >= FINAL_POOL_SEQUENCE - 1) throw new WireError('state_conflict', 0, 'payment_sequence', '付款序号陈旧')
  await verifyAcceptedPayment(previous, opening)
  const price = await contentHashesPriceSatoshis(quoteTerms, hashes, effectiveSeed)
  if (previous.sellerAmountSatoshis > MAX_UINT64 - price || authorization.sellerAmountAfterSatoshis !== previous.sellerAmountSatoshis + price) throw new WireError('invalid_evidence', 7, 'seller_amount_after_satoshis', '卖方金额与聚合内容价格不一致')
  await checkPaymentCapacity(opening, previous, authorization.paymentSequence, authorization.sellerAmountAfterSatoshis)
  const unsigned = await buildPaymentUpdate(opening, previous, authorization.paymentSequence, authorization.sellerAmountAfterSatoshis)
  const engine = new MultisigPoolEngine({ buyerPublicKey: opening.buyerPublicKey, sellerPublicKey: opening.sellerPublicKey, arbiterPublicKey: opening.arbiterPublicKey })
  const buyerSignature = await engine.signRole(bound, 'buyer', unsigned, details.poolOutputSatoshis)
  const outbound = encodePaymentUpdate(requestID, buyerSignature)
  return { payloads: payloads.map(copyBytes), outbound }
}

/**
 * 买方关池准备：从调用方选定基准状态与目标金额构造未签名关闭 candidate 和
 * 买方 detached 签名；不声称基准是最新，也不判断目标金额是否符合订单。
 */
export async function prepareBuyerClose (facts: Readonly<PureFunctionFacts>, input: PrepareCloseInput, signer: Signer): Promise<{ unsignedRaw: Uint8Array, buyerSignature: Uint8Array }> {
  const bound = bindSigner(signer, 'buyer_signer')
  const checkpoint = await buyerPoolCheckpoint(input.pool)
  const opening = checkpoint.opening
  if (!equal(bound.publicKey(), opening.buyerPublicKey)) throw new WireError('unauthorized', 0, 'buyer_public_key', 'Signer 与开池买方不一致')
  const details = await deriveOpeningDetails(opening)
  checkRefundNotExpired(facts, details.refundLockTime)
  const unsignedRaw = await buildImmediateClose(opening, checkpoint.payment, input.targetSellerAmountSatoshis)
  const engine = new MultisigPoolEngine({ buyerPublicKey: opening.buyerPublicKey, sellerPublicKey: opening.sellerPublicKey, arbiterPublicKey: opening.arbiterPublicKey })
  const buyerSignature = await engine.signRole(bound, 'buyer', unsignedRaw, details.poolOutputSatoshis)
  const unsigned = await parseUnsignedPayment(unsignedRaw, opening)
  if (unsigned.paymentSequence !== FINAL_POOL_SEQUENCE) throw new WireError('invalid_evidence', 0, 'payment_sequence', '立即关闭不是最终状态')
  return { unsignedRaw, buyerSignature }
}

/** 买方验收卖方完整关闭交易，返回完整交易原文；不声称已广播或已确认。 */
export async function verifyBuyerCompletedClose (input: VerifyCompletedCloseInput): Promise<Uint8Array> {
  const checkpoint = await buyerPoolCheckpoint(input.pool)
  const opening = checkpoint.opening
  const state = await parsePaymentState(input.closeRaw, opening)
  if (state.paymentSequence !== FINAL_POOL_SEQUENCE) throw new WireError('invalid_evidence', 0, 'close_payment', '缺少最终签名关闭状态')
  await verifyPaymentState(state, opening)
  return await verifySignedTransaction(input.closeRaw, opening)
}

/** 买方到期退款：显式事实判定退款到期后合并双方退款签名，不调用 Signer。 */
export async function buildBuyerMaturedRefund (facts: Readonly<PureFunctionFacts>, pool: BuyerPoolEvidence): Promise<Uint8Array> {
  const checkpoint = await buyerPoolCheckpoint(pool)
  const opening = checkpoint.opening
  const details = await deriveOpeningDetails(opening)
  checkRefundMatured(facts, details.refundLockTime)
  const raw = await buildRefundSubmission(opening)
  const state = await parsePaymentState(raw, opening)
  if (!equal(state.refundTemplateTxId, details.refundTemplateTxId)) throw new WireError('invalid_evidence', 0, 'refund_template_txid', '退款交易与开池关联 ID 不一致')
  await verifyPaymentState(state, opening)
  return await verifySignedTransaction(raw, opening)
}

/**
 * 买方取回请求：为一条托管记录构造 exact Kind 10。省略 nonce 时由 SDK 生成
 * 安全随机 nonce；网络重试必须原样重放已持久化的 exact Kind 10。
 */
export async function requestBuyerArbitratedContent (input: RetrievalRequestInput, signer: Signer): Promise<Artifact> {
  const bound = bindSigner(signer, 'buyer_signer')
  const checkpoint = await buyerPoolCheckpoint(input.pool)
  const opening = checkpoint.opening
  if (!equal(bound.publicKey(), opening.buyerPublicKey)) throw new WireError('unauthorized', 10, 'buyer_public_key', 'Signer 与开池买方不一致')
  const request = decodeKind5Request(input.authorization.rawKind5)
  await verifySignedContentRequestForOpening(request, opening)
  const nonce = input.nonce == null || input.nonce.byteLength === 0 ? generateRetrievalNonce() : newRetrievalNonce(input.nonce)
  const built = await buildClaimFromAuthorization(opening, request)
  return await createContentRetrievalRequest(bound, built.claimID, nonce)
}

/**
 * 买方取回验收（时间无关）：available 分支复核 payload 归属与价格；
 * unavailable 分支作为已验签协议结果返回。过期报价、截止或退款锁定绝不拒绝
 * 已签托管证据。
 */
export async function verifyBuyerArbitratedContent (input: ArbitratedContentInput): Promise<ArbitratedContentResult> {
  if (input == null || input.authorization == null) throw new WireError('invalid_evidence', 11, 'authorization', '报价与授权证据包不能为空')
  const signedQuote = decodeKind1Quote(input.authorization.rawKind1)
  verifyQuoteEvidence(signedQuote)
  const checkpoint = await buyerPoolCheckpoint(input.pool)
  const opening = checkpoint.opening
  const previous = checkpoint.payment
  const request = decodeKind5Request(input.authorization.rawKind5)
  const { authorization, quoteTerms } = await verifyContentRequestEvidence(request, signedQuote, opening)
  const details = await deriveOpeningDetails(opening)
  if (!equal(previous.refundTemplateTxId, details.refundTemplateTxId)) throw new WireError('invalid_evidence', 11, 'refund_template_txid', '内容请求未绑定开池证明')
  const built = await buildClaimFromAuthorization(opening, request)
  const retrievalRequest = decodeKind10Request(input.retrievalRequestRaw)
  const document = decodeRetrievalRequestDocument(retrievalRequest.contentRetrievalRequestCBOR)
  if (!equal(document.arbitrationClaimID, built.claimID)) throw new WireError('invalid_evidence', 11, 'arbitration_claim_id', '取回请求未引用本地重建 Claim')
  verifyWireDocument(opening.buyerPublicKey, 10, retrievalRequest.contentRetrievalRequestCBOR, retrievalRequest.buyerContentRetrievalRequestSignature)
  const response = decodeKind11Response(input.retrievalResponseRaw)
  const result = verifyContentRetrievalResponseInternal(retrievalRequest.contentRetrievalRequestCBOR, opening.arbiterPublicKey, response)
  const outcome: ArbitratedContentResult = {
    contentRetrievalRequestID: result.contentRetrievalRequestID,
    arbitrationClaimID: built.claimID,
    available: result.available,
    unavailableReason: result.unavailableReason ?? 0,
    payloads: []
  }
  if (!result.available) return outcome
  const hashes = decodeValidatedHashes(authorization.contentHashes)
  const effectiveSeed = await verifyContentPayloads(quoteTerms, hashes, result.payloads, input.seed)
  const price = await contentHashesPriceSatoshis(quoteTerms, hashes, effectiveSeed)
  if (previous.paymentSequence + 1 !== authorization.paymentSequence || previous.paymentSequence >= FINAL_POOL_SEQUENCE - 1) throw new WireError('state_conflict', 0, 'payment_sequence', '付款序号陈旧')
  await verifyAcceptedPayment(previous, opening)
  if (previous.sellerAmountSatoshis > MAX_UINT64 - price || authorization.sellerAmountAfterSatoshis !== previous.sellerAmountSatoshis + price) throw new WireError('invalid_evidence', 11, 'seller_amount_after_satoshis', '卖方金额与聚合内容价格不一致')
  outcome.payloads = result.payloads.map(copyBytes)
  return outcome
}

/** 生成 32 字节安全随机取回 nonce；SDK 默认入口使用它。 */
export function generateRetrievalNonce (): Uint8Array {
  const nonce = new Uint8Array(32)
  globalThis.crypto.getRandomValues(nonce)
  if (nonce.every(byte => byte === 0)) return generateRetrievalNonce()
  return nonce
}

/** 从精确 32 字节构造取回 nonce；拒绝其他长度与全零哨兵。 */
export function newRetrievalNonce (raw: Uint8Array): Uint8Array {
  if (raw.byteLength !== 32) throw new WireError('invalid_evidence', 10, 'retrieval_nonce', 'nonce 必须是 32 bytes')
  if (raw.every(byte => byte === 0)) throw new WireError('invalid_evidence', 10, 'retrieval_nonce', 'nonce 禁止全零')
  return copyBytes(raw)
}

// ---------------------------------------------------------------------------
// 仲裁方步骤（007/008 边界一致性）
// ---------------------------------------------------------------------------

/**
 * 仲裁方准备：对 exact Kind 8 做完整时间相关证据验证但绝不签名；返回可持久化
 * 的普通证据包（exact Kind 8、独立重建 candidate、Claim ID 与冻结费用）。
 */
export function prepareArbiterArbitration (facts: Readonly<PureFunctionFacts>, rawKind8: Uint8Array, feeSatoshis: bigint): PreparedArbitrationEvidence {
  if (feeSatoshis <= 0n) throw new WireError('invalid_evidence', 8, 'fee_satoshis', '成功仲裁需要正仲裁费')
  const now = requireNow(facts)
  const request = decodeKind8Request(rawKind8)
  const validated = validateRequestEvidence(request, feeSatoshis)
  if (!(now < validated.authorization.deliveryDeadlineUnixSeconds)) throw new WireError('expired', 8, 'delivery_deadline_unix_seconds', '交付截止时间已过')
  checkRefundNotExpired(facts, refundTemplateLockTime(validated.claim.refundTemplateRaw))
  return { rawKind8: copyBytes(rawKind8), candidateRaw: copyBytes(validated.unsigned.unsignedRaw), arbitrationClaimID: validated.claimID, feeSatoshis }
}

/**
 * 仲裁方签署：从冻结的 exact Kind 8 独立重建交易与 digest，重新比较 Claim ID、
 * 费用、角色、deadline 与 candidate，然后按固定顺序签名——先仲裁交易签名，
 * 再编码回执，最后生成并自验统一回执消息签名。
 */
export async function signArbiterPreparedArbitration (facts: Readonly<PureFunctionFacts>, prepared: PreparedArbitrationEvidence, signer: Signer): Promise<SignedArbitrationEvidence> {
  const bound = bindSigner(signer, 'arbiter_signer')
  const now = requireNow(facts)
  const request = decodeKind8Request(prepared.rawKind8)
  const validated = validateRequestEvidence(request, prepared.feeSatoshis)
  if (!equal(validated.claimID, prepared.arbitrationClaimID)) throw new WireError('state_conflict', 9, 'claim_id', 'Prepare 证据 Claim ID 与重验结果不一致')
  if (!equal(validated.unsigned.unsignedRaw, prepared.candidateRaw)) throw new WireError('state_conflict', 9, 'unsigned_candidate', 'Prepare candidate 与独立重建交易不一致')
  if (!equal(bound.publicKey(), validated.keys.arbiterPublicKey)) throw new WireError('unauthorized', 9, 'arbiter_public_key', 'Claim 仲裁方与 Signer 不一致')
  if (!(now < validated.authorization.deliveryDeadlineUnixSeconds)) throw new WireError('expired', 9, 'delivery_deadline_unix_seconds', '签署前交付截止时间已过')
  checkRefundNotExpired(facts, refundTemplateLockTime(validated.claim.refundTemplateRaw))
  const engine = new MultisigPoolEngine(validated.keys)
  const arbiterTransactionSignature = await engine.signRole(bound, 'arbiter', validated.unsigned.unsignedRaw, validated.unsigned.poolOutputSatoshis)
  const receiptCBOR = marshalReceipt(validated.claimID, prepared.feeSatoshis, arbiterTransactionSignature)
  const outbound = await createArbitrationResponse(bound, receiptCBOR)
  return {
    prepared: clonePrepared(prepared),
    outbound,
    arbiterTransactionSignature: copyBytes(arbiterTransactionSignature)
  }
}

/** 仅完成 Buyer 鉴权：时间无关，不需要 Kind 9 存在。 */
export function authenticateArbiterRetrieval (rawKind10: Uint8Array, storedKind8: Uint8Array): void {
  const retrievalRequest = decodeKind10Request(rawKind10)
  const storedRequest = decodeKind8Request(storedKind8)
  const claim = unmarshalClaim(storedRequest.arbitrationClaimCBOR)
  const keys = parseArbitratedPoolLockingScript(claim.poolOutputLockingScript)
  const document = decodeRetrievalRequestDocument(retrievalRequest.contentRetrievalRequestCBOR)
  if (!equal(document.arbitrationClaimID, sha256(storedRequest.arbitrationClaimCBOR))) throw new WireError('invalid_evidence', 10, 'arbitration_claim_id', '取回 Claim ID 与托管记录不一致')
  verifyWireDocument(keys.buyerPublicKey, 10, retrievalRequest.contentRetrievalRequestCBOR, retrievalRequest.buyerContentRetrievalRequestSignature)
}

/** 返回 exact Kind 11 available，并把 exact payload 子文档哈希纳入签名。 */
export async function buildArbiterAvailableRetrieval (requestID: Uint8Array, custody: Readonly<VerifiedCustodyEvidence>, signer: Signer): Promise<Artifact> {
  const bound = bindSigner(signer, 'arbiter_signer')
  validateRequestID(requestID)
  if (custody == null || custody.payloadsCBOR.byteLength === 0) throw new WireError('invalid_evidence', 11, 'verified_custody', '需要带 exact payload 子文档的已验证托管证据')
  decodeContentPayloads(custody.payloadsCBOR)
  const resultCBOR = encodeRetrievalResultDocument(requestID, 1, sha256(custody.payloadsCBOR))
  const signature = await signWireDocument(bound, 11, resultCBOR)
  return parse(encodeCanonical([1n, 11n, resultCBOR, signature, copyBytes(custody.payloadsCBOR)]))
}

/** 返回 exact Kind 11 unavailable（reason：0 未收到、1 未就绪、2 托管已丢失）。 */
export async function buildArbiterUnavailableRetrieval (requestID: Uint8Array, reason: 0 | 1 | 2, signer: Signer): Promise<Artifact> {
  const bound = bindSigner(signer, 'arbiter_signer')
  validateRequestID(requestID)
  if (reason !== 0 && reason !== 1 && reason !== 2) throw new WireError('invalid_evidence', 11, 'unavailable_reason', '未知的 unavailable 原因')
  const resultCBOR = encodeCanonical([copyBytes(requestID), 0n, BigInt(reason)])
  const signature = await signWireDocument(bound, 11, resultCBOR)
  return parse(encodeCanonical([1n, 11n, resultCBOR, signature]))
}

/** 从签名证据包重建 candidate 并合并 Seller/Arbiter 双签名，返回完整交易原文。 */
export async function completeArbiterArbitratedPayment (signed: Readonly<SignedArbitrationEvidence>, sellerSignature: Uint8Array): Promise<Uint8Array> {
  const request = decodeKind8Request(signed.prepared.rawKind8)
  const validated = validateRequestEvidence(request, signed.prepared.feeSatoshis)
  if (!equal(validated.claimID, signed.prepared.arbitrationClaimID)) throw new WireError('state_conflict', 9, 'claim_id', '签名证据 Claim ID 与重验结果不一致')
  if (!equal(validated.unsigned.unsignedRaw, signed.prepared.candidateRaw)) throw new WireError('state_conflict', 9, 'unsigned_candidate', '签名证据 candidate 与独立重建交易不一致')
  const response = decodeKind9Response(signed.outbound.bytes())
  const receipt = unmarshalReceipt(response.arbitrationReceiptCBOR)
  if (!equal(receipt.arbitrationClaimID, signed.prepared.arbitrationClaimID)) throw new WireError('state_conflict', 9, 'arbitration_claim_id', '回执 Claim ID 与签名证据不一致')
  if (!equal(receipt.arbiterPaymentTransactionSignature, signed.arbiterTransactionSignature)) throw new WireError('state_conflict', 9, 'arbiter_payment_transaction_signature', '回执交易签名与签名证据不一致')
  verifyWireDocument(validated.keys.arbiterPublicKey, 9, response.arbitrationReceiptCBOR, response.arbiterArbitrationReceiptSignature)
  return await completeArbitratedTransaction(validated.unsigned.unsignedRaw, validated.unsigned.poolOutputSatoshis, validated.unsigned.poolLockingScript, sellerSignature, signed.arbiterTransactionSignature)
}

/** 从 exact Kind 8/9 完整验证托管证据并返回 verified custody。 */
export async function verifyArbiterCustody (rawKind8: Uint8Array, rawKind9: Uint8Array): Promise<VerifiedCustodyEvidence> {
  const request = decodeKind8Request(rawKind8)
  const response = decodeKind9Response(rawKind9)
  const receipt = unmarshalReceipt(response.arbitrationReceiptCBOR)
  const validated = validateRequestEvidence(request, receipt.arbiterAmountSatoshis)
  if (!equal(receipt.arbitrationClaimID, validated.claimID)) throw new WireError('invalid_evidence', 9, 'arbitration_claim_id', '回执 Claim ID 与托管 Claim 不一致')
  verifyWireDocument(validated.keys.arbiterPublicKey, 9, response.arbitrationReceiptCBOR, response.arbiterArbitrationReceiptSignature)
  const engine = new MultisigPoolEngine(validated.keys)
  try { engine.verifyRole('arbiter', validated.unsigned.unsignedRaw, validated.unsigned.poolOutputSatoshis, receipt.arbiterPaymentTransactionSignature) } catch (error) { throw rethrow(error, 'invalid_signature', 9, 'arbiter_payment_transaction_signature') }
  return { arbitrationClaimID: validated.claimID, payloadsCBOR: copyBytes(request.contentPayloadsCBOR), payloads: validated.payloads.map(copyBytes) }
}

// ---------------------------------------------------------------------------
// 证据包内部小工具
// ---------------------------------------------------------------------------

interface PoolCheckpoint {
  opening: OpeningProof
  payment: PaymentState
}

async function buyerPoolCheckpoint (evidence: BuyerPoolEvidence): Promise<PoolCheckpoint> {
  const opening = cloneOpening(evidence.opening)
  await verifyOpening(opening)
  if ((evidence.latestPaymentRawTx?.byteLength ?? 0) === 0) {
    const initialRaw = await buildRefundSubmission(opening)
    const initial = await parsePaymentState(initialRaw, opening)
    await verifyAcceptedPayment(initial, opening)
    return { opening, payment: initial }
  }
  const state = await parsePaymentState(evidence.latestPaymentRawTx!, opening)
  await verifyPreviousPayment(state, opening)
  return { opening, payment: state }
}

async function sellerPoolCheckpoint (evidence: SellerPoolEvidence): Promise<PoolCheckpoint> {
  const opening = cloneOpening(evidence.opening)
  if ((evidence.fundingTransactionRaw?.byteLength ?? 0) > 0) {
    if (opening.fundingTransactionRaw.byteLength > 0 && !equal(opening.fundingTransactionRaw, evidence.fundingTransactionRaw)) throw new WireError('state_conflict', 0, 'funding_transaction_raw', '池证据携带不一致的资金交易')
    opening.fundingTransactionRaw = copyBytes(evidence.fundingTransactionRaw)
  }
  await verifyOpening(opening)
  if ((evidence.latestPaymentRawTx?.byteLength ?? 0) === 0) {
    const initialRaw = await buildRefundSubmission(opening)
    const initial = await parsePaymentState(initialRaw, opening)
    await verifyAcceptedPayment(initial, opening)
    return { opening, payment: initial }
  }
  const state = await parsePaymentState(evidence.latestPaymentRawTx!, opening)
  await verifyPreviousPayment(state, opening)
  return { opening, payment: state }
}

async function verifyPreviousPayment (state: PaymentState, opening: OpeningProof): Promise<void> {
  try { await verifyAcceptedPayment(state, opening) } catch (error) {
    try { await verifyArbitratedPayment(state, opening) } catch { throw error }
  }
}

function cloneOpening (opening: OpeningProof): OpeningProof {
  return {
    refundTemplateRaw: copyBytes(opening.refundTemplateRaw),
    buyerPublicKey: copyBytes(opening.buyerPublicKey),
    sellerPublicKey: copyBytes(opening.sellerPublicKey),
    arbiterPublicKey: copyBytes(opening.arbiterPublicKey),
    minerFeeRateSatoshisPerKilobyte: opening.minerFeeRateSatoshisPerKilobyte,
    buyerRefundSignature: copyBytes(opening.buyerRefundSignature),
    sellerRefundSignature: copyBytes(opening.sellerRefundSignature),
    fundingTransactionRaw: copyBytes(opening.fundingTransactionRaw)
  }
}

function checkRefundNotExpired (facts: Readonly<PureFunctionFacts>, lockTime: number): void {
  if (lockTime < TIMESTAMP_THRESHOLD) {
    const height = facts?.blockHeight
    if (height == null || !Number.isInteger(height) || height <= 0) throw new WireError('invalid_evidence', 0, 'facts', '高度型退款锁需要显式区块高度')
    if (height >= lockTime) throw new WireError('expired', 0, 'refund_locktime', '退款模板已经到期')
  } else {
    const now = requireNow(facts)
    if (now >= BigInt(lockTime)) throw new WireError('expired', 0, 'refund_locktime', '退款模板已经到期')
  }
}

function checkRefundMatured (facts: Readonly<PureFunctionFacts>, lockTime: number): void {
  if (lockTime < TIMESTAMP_THRESHOLD) {
    const height = facts?.blockHeight
    if (height == null || !Number.isInteger(height) || height <= 0) throw new WireError('invalid_evidence', 0, 'facts', '高度型退款锁需要显式区块高度')
    if (height < lockTime) throw new WireError('not_matured', 0, 'refund_locktime', '退款锁定尚未到期')
  } else {
    const now = requireNow(facts)
    if (now < BigInt(lockTime)) throw new WireError('not_matured', 0, 'refund_locktime', '退款锁定尚未到期')
  }
}

// ---------------------------------------------------------------------------
// 仲裁领域内部实现（Kind 8/9 与 Claim/Receipt 编解码）
// ---------------------------------------------------------------------------

interface ArbitrationClaim {
  poolOutputSatoshis: bigint
  poolOutputLockingScript: Uint8Array
  refundTemplateRaw: Uint8Array
  paymentAuthorizationCBOR: Uint8Array
  buyerPaymentAuthorizationSignature: Uint8Array
}

interface ValidatedRequestEvidence {
  claim: ArbitrationClaim
  authorization: PaymentAuthorization
  payloads: Uint8Array[]
  unsigned: ReturnType<typeof buildArbitrationPaymentFromClaim>
  claimID: Uint8Array
  paymentAuthorizationID: Uint8Array
  keys: PoolPublicKeys
}

interface ArbitrationReceipt {
  arbitrationClaimID: Uint8Array
  arbiterAmountSatoshis: bigint
  arbiterPaymentTransactionSignature: Uint8Array
}

interface ContentRetrievalResponseView {
  contentRetrievalResultCBOR: Uint8Array
  arbiterContentRetrievalResultSignature: Uint8Array
  contentPayloadsCBOR?: Uint8Array
}

interface VerifiedRetrievalResult {
  contentRetrievalRequestID: Uint8Array
  available: boolean
  unavailableReason?: 0 | 1 | 2
  payloadsCBOR?: Uint8Array
  payloads: Uint8Array[]
}

async function buildClaimFromAuthorization (opening: OpeningProof, request: SignedContentRequest): Promise<{ claim: ArbitrationClaim, claimCBOR: Uint8Array, claimID: Uint8Array, authorization: PaymentAuthorization }> {
  const details = await deriveOpeningDetails(opening)
  const authorization = await verifySignedContentRequestForOpening(request, opening)
  const claim: ArbitrationClaim = {
    poolOutputSatoshis: details.poolOutputSatoshis,
    poolOutputLockingScript: copyBytes(details.poolLockingScript),
    refundTemplateRaw: copyBytes(opening.refundTemplateRaw),
    paymentAuthorizationCBOR: copyBytes(request.paymentAuthorizationCBOR),
    buyerPaymentAuthorizationSignature: copyBytes(request.buyerPaymentAuthorizationSignature)
  }
  const claimCBOR = marshalClaim(claim)
  return { claim, claimCBOR, claimID: sha256(claimCBOR), authorization }
}

function validateRequestEvidence (request: { arbitrationClaimCBOR: Uint8Array, sellerArbitrationClaimSignature: Uint8Array, contentPayloadsCBOR: Uint8Array }, feeSatoshis: bigint): ValidatedRequestEvidence {
  const claim = unmarshalClaim(request.arbitrationClaimCBOR)
  const authorization = decodePaymentAuthorization(claim.paymentAuthorizationCBOR)
  const keys = parseArbitratedPoolLockingScript(claim.poolOutputLockingScript)
  try { verifyWireDocument(keys.sellerPublicKey, 8, request.arbitrationClaimCBOR, request.sellerArbitrationClaimSignature) } catch (error) { throw rethrow(error, 'invalid_signature', 8, 'seller_arbitration_claim_signature') }
  const payloads = decodeContentPayloads(request.contentPayloadsCBOR)
  const hashes = decodeValidatedHashes(authorization.contentHashes)
  if (payloads.length !== hashes.length) throw new WireError('invalid_evidence', 8, 'content_payloads_cbor', 'payload 数量与授权哈希数量不一致')
  for (let index = 0; index < payloads.length; index++) if (!equal(sha256(payloads[index]!), hashes[index]!)) throw new WireError('invalid_evidence', 8, `payload[${index}]`, `payload #${index + 1} 与授权哈希不一致`)
  const unsigned = buildArbitrationPaymentFromClaim(claim.poolOutputSatoshis, claim.poolOutputLockingScript, claim.refundTemplateRaw, authorization.paymentSequence, authorization.sellerAmountAfterSatoshis, feeSatoshis)
  if (!equal(unsigned.refundTemplateTxId, authorization.refundTemplateTxID)) throw new WireError('invalid_evidence', 8, 'refund_template_txid', '退款模板交易 ID 与买方条款不一致')
  return { claim, authorization, payloads, unsigned, claimID: sha256(request.arbitrationClaimCBOR), paymentAuthorizationID: sha256(claim.paymentAuthorizationCBOR), keys }
}

function marshalClaim (claim: ArbitrationClaim): Uint8Array {
  validateClaim(claim)
  return encodeCanonical([
    claim.poolOutputSatoshis,
    copyBytes(claim.poolOutputLockingScript),
    copyBytes(claim.refundTemplateRaw),
    copyBytes(claim.paymentAuthorizationCBOR),
    copyBytes(claim.buyerPaymentAuthorizationSignature)
  ])
}

function unmarshalClaim (raw: Uint8Array): ArbitrationClaim {
  const values = fieldArray(raw, 5, 8, 'arbitration_claim_cbor')
  const claim: ArbitrationClaim = {
    poolOutputSatoshis: fieldUint(values[0], 8, 'pool_output_satoshis'),
    poolOutputLockingScript: fieldBytes(values[1], 8, 'pool_output_locking_script'),
    refundTemplateRaw: fieldBytes(values[2], 8, 'refund_template_raw'),
    paymentAuthorizationCBOR: fieldBytes(values[3], 8, 'payment_authorization_cbor'),
    buyerPaymentAuthorizationSignature: fieldBytes(values[4], 8, 'buyer_payment_authorization_signature')
  }
  validateClaim(claim)
  if (!equal(encodeCanonical([claim.poolOutputSatoshis, claim.poolOutputLockingScript, claim.refundTemplateRaw, claim.paymentAuthorizationCBOR, claim.buyerPaymentAuthorizationSignature]), raw)) throw new WireError('non_canonical', 8, 'arbitration_claim_cbor', 'Claim 不是确定性编码')
  return claim
}

function validateClaim (claim: ArbitrationClaim): void {
  if (claim.poolOutputSatoshis === 0n || claim.poolOutputLockingScript.byteLength === 0 || claim.refundTemplateRaw.byteLength === 0 || claim.paymentAuthorizationCBOR.byteLength === 0 || claim.buyerPaymentAuthorizationSignature.byteLength === 0) throw new WireError('invalid_evidence', 8, 'claim', 'Claim 不完整')
  if (claim.poolOutputLockingScript.byteLength !== 105) throw new WireError('invalid_evidence', 8, 'pool_output_locking_script', 'Claim 费用池脚本长度无效')
  if (claim.refundTemplateRaw.byteLength > 16 * 1024) throw new WireError('malformed_wire', 8, 'refund_template_raw', '退款模板超过协议上限')
  if (claim.paymentAuthorizationCBOR.byteLength > 16 * 1024) throw new WireError('malformed_wire', 8, 'payment_authorization_cbor', '付款授权超过协议上限')
  if (claim.buyerPaymentAuthorizationSignature.byteLength > 256) throw new WireError('malformed_wire', 8, 'buyer_payment_authorization_signature', '买方签名超过协议上限')
  const authorization = decodePaymentAuthorization(claim.paymentAuthorizationCBOR)
  const keys = parseArbitratedPoolLockingScript(claim.poolOutputLockingScript)
  validateArbitrationClaimStructure({ poolOutputSatoshis: claim.poolOutputSatoshis, poolOutputLockingScript: claim.poolOutputLockingScript, refundTemplateRaw: claim.refundTemplateRaw, paymentSequence: BigInt(authorization.paymentSequence), sellerAmountAfterSatoshis: authorization.sellerAmountAfterSatoshis })
  try { verifyWireDocument(keys.buyerPublicKey, 5, claim.paymentAuthorizationCBOR, claim.buyerPaymentAuthorizationSignature) } catch (error) { throw rethrow(error, 'invalid_signature', 8, 'buyer_payment_authorization_signature') }
}

function marshalReceipt (claimID: Uint8Array, feeSatoshis: bigint, signature: Uint8Array): Uint8Array {
  validateReceipt({ arbitrationClaimID: claimID, arbiterAmountSatoshis: feeSatoshis, arbiterPaymentTransactionSignature: signature })
  return encodeCanonical([copyBytes(claimID), feeSatoshis, copyBytes(signature)])
}

function unmarshalReceipt (raw: Uint8Array): ArbitrationReceipt {
  const values = fieldArray(raw, 3, 9, 'arbitration_receipt_cbor')
  const receipt: ArbitrationReceipt = {
    arbitrationClaimID: fieldBytes(values[0], 9, 'arbitration_claim_id'),
    arbiterAmountSatoshis: fieldUint(values[1], 9, 'arbiter_amount_satoshis'),
    arbiterPaymentTransactionSignature: fieldBytes(values[2], 9, 'arbiter_payment_transaction_signature')
  }
  validateReceipt(receipt)
  if (!equal(encodeCanonical([receipt.arbitrationClaimID, receipt.arbiterAmountSatoshis, receipt.arbiterPaymentTransactionSignature]), raw)) throw new WireError('non_canonical', 9, 'arbitration_receipt_cbor', '回执不是确定性编码')
  return receipt
}

function validateReceipt (receipt: ArbitrationReceipt): void {
  if (receipt.arbitrationClaimID.byteLength !== 32) throw new WireError('malformed_wire', 9, 'arbitration_claim_id', 'Claim ID 必须是 32 bytes')
  if (receipt.arbiterAmountSatoshis <= 0n) throw new WireError('invalid_evidence', 9, 'arbiter_amount_satoshis', '仲裁费必须为正数')
  if (receipt.arbiterPaymentTransactionSignature.byteLength === 0 || receipt.arbiterPaymentTransactionSignature.byteLength > 256) throw new WireError('malformed_wire', 9, 'arbiter_payment_transaction_signature', '仲裁交易签名长度无效')
}

function encodeRetrievalResultDocument (requestID: Uint8Array, result: 0 | 1, branchValue: Uint8Array): Uint8Array {
  if (result === 0) {
    const reason = BigInt(branchValue[0] ?? 0xff)
    if (branchValue.byteLength !== 1 || reason > 2n) throw new WireError('invalid_evidence', 11, 'unavailable_reason', '未知的 unavailable 原因')
    return encodeCanonical([copyBytes(requestID), 0n, reason])
  }
  if (branchValue.byteLength !== 32) throw new WireError('invalid_evidence', 11, 'content_payloads_id', 'available 分支需要 32 字节 content_payloads_id')
  return encodeCanonical([copyBytes(requestID), 1n, copyBytes(branchValue)])
}

function decodeRetrievalRequestDocument (raw: Uint8Array): { arbitrationClaimID: Uint8Array, nonce: Uint8Array } {
  const values = fieldArray(raw, 2, 10, 'content_retrieval_request_cbor')
  const arbitrationClaimID = fieldBytes(values[0], 10, 'arbitration_claim_id')
  if (arbitrationClaimID.byteLength !== 32) throw new WireError('malformed_wire', 10, 'arbitration_claim_id', 'Claim ID 必须是 32 bytes')
  const nonce = fieldBytes(values[1], 10, 'retrieval_nonce')
  if (nonce.byteLength !== 32) throw new WireError('invalid_evidence', 10, 'retrieval_nonce', 'nonce 必须是 32 bytes')
  if (nonce.every(byte => byte === 0)) throw new WireError('invalid_evidence', 10, 'retrieval_nonce', 'nonce 禁止全零')
  if (!equal(encodeCanonical([arbitrationClaimID, nonce]), raw)) throw new WireError('non_canonical', 10, 'content_retrieval_request_cbor', '取回请求不是确定性编码')
  return { arbitrationClaimID, nonce }
}

function decodeRetrievalResultDocument (raw: Uint8Array): { requestID: Uint8Array, result: 0 | 1, reason?: 0 | 1 | 2, payloadsID?: Uint8Array } {
  const values = fieldArray(raw, 3, 11, 'content_retrieval_result_cbor')
  const requestID = fieldBytes(values[0], 11, 'content_retrieval_request_id')
  if (requestID.byteLength !== 32) throw new WireError('malformed_wire', 11, 'content_retrieval_request_id', '请求 ID 必须是 32 bytes')
  const discriminator = fieldUint(values[1], 11, 'result')
  if (discriminator === 0n) {
    const reason = fieldUint(values[2], 11, 'reason')
    if (reason > 2n) throw new WireError('invalid_evidence', 11, 'unavailable_reason', '未知的 unavailable 原因')
    if (!equal(encodeCanonical([requestID, 0n, reason]), raw)) throw new WireError('non_canonical', 11, 'content_retrieval_result_cbor', '取回结果不是确定性编码')
    return { requestID, result: 0, reason: Number(reason) as 0 | 1 | 2 }
  }
  if (discriminator === 1n) {
    const payloadsID = fieldBytes(values[2], 11, 'content_payloads_id')
    if (payloadsID.byteLength !== 32) throw new WireError('malformed_wire', 11, 'content_payloads_id', 'payload ID 必须是 32 bytes')
    if (!equal(encodeCanonical([requestID, 1n, payloadsID]), raw)) throw new WireError('non_canonical', 11, 'content_retrieval_result_cbor', '取回结果不是确定性编码')
    return { requestID, result: 1, payloadsID }
  }
  throw new WireError('unsupported_kind', 11, 'result', `未知的取回结果 ${discriminator}`)
}

function verifyContentRetrievalResponseInternal (requestCBOR: Uint8Array, arbiterPublicKey: Uint8Array, response: ContentRetrievalResponseView): VerifiedRetrievalResult {
  const decoded = decodeRetrievalResultDocument(response.contentRetrievalResultCBOR)
  const requestID = sha256(requestCBOR)
  if (!equal(decoded.requestID, requestID)) throw new WireError('invalid_evidence', 11, 'content_retrieval_request_id', '取回结果未应答给定请求')
  try { verifyWireDocument(arbiterPublicKey, 11, response.contentRetrievalResultCBOR, response.arbiterContentRetrievalResultSignature) } catch (error) { throw rethrow(error, 'invalid_signature', 11, 'arbiter_content_retrieval_result_signature') }
  if (decoded.result === 0) return { contentRetrievalRequestID: requestID, available: false, ...(decoded.reason == null ? {} : { unavailableReason: decoded.reason }), payloads: [] }
  const attachment = response.contentPayloadsCBOR
  if (attachment == null || attachment.byteLength === 0) throw new WireError('invalid_evidence', 11, 'content_payloads_cbor', 'available 分支缺少 payload 附件')
  if (!equal(sha256(attachment), decoded.payloadsID!)) throw new WireError('invalid_evidence', 11, 'content_payloads_id', 'payload 附件与已签 content_payloads_id 不一致')
  const payloads = decodeContentPayloads(attachment)
  return { contentRetrievalRequestID: requestID, available: true, payloadsCBOR: copyBytes(attachment), payloads }
}

// ---------------------------------------------------------------------------
// wire 解码小工具
// ---------------------------------------------------------------------------

/** 解码单元素 content_delivery_cbor，返回其绑定的授权 ID。 */
function decodeDeliveryDocument (raw: Uint8Array): Uint8Array {
  const value = decodeCanonical(raw, 'content_delivery_cbor')
  if (!Array.isArray(value) || value.length !== 1 || !(value[0] instanceof Uint8Array)) throw new WireError('malformed_wire', 6, 'content_delivery_cbor', '交付文档必须是单元素数组')
  return copyBytes(value[0])
}

/** 交叉核对已保存交付证据：exact Kind 6 必须绑定同一授权，且卖方签名由本池卖方公钥验证。 */
function verifyStoredDelivery (opening: OpeningProof, deliveryEvidence: SellerDeliveryEvidence, authorizationID: Uint8Array): void {
  if (deliveryEvidence.rawKind6 == null || deliveryEvidence.rawKind6.byteLength === 0) throw new WireError('state_conflict', 7, 'delivery', '缺少已保存的内容交付证据')
  const delivery = decodeKind6Delivery(deliveryEvidence.rawKind6)
  const document = decodeDeliveryDocument(delivery.contentDeliveryCBOR)
  if (!equal(document, authorizationID)) throw new WireError('state_conflict', 7, 'content_delivery_cbor', '已保存交付引用了不同授权')
  try { verifyWireDocument(opening.sellerPublicKey, 6, delivery.contentDeliveryCBOR, delivery.sellerContentDeliverySignature) } catch (error) {
    if (error instanceof WireError) throw new WireError(error.code, 7, 'seller_content_delivery_signature', error.message)
    throw error
  }
  decodeContentPayloads(delivery.contentPayloadsCBOR)
}

function decodeKind1Quote (raw: Uint8Array): SignedFileQuote {
  const outer = outerFields(parseAs(1, raw), 5)
  return { fileQuoteTermsCBOR: fieldBytes(outer[2], 1, 'file_quote_terms_cbor'), sellerPublicKey: fieldBytes(outer[3], 1, 'seller_public_key'), sellerFileQuoteTermsSignature: fieldBytes(outer[4], 1, 'seller_file_quote_terms_signature') }
}

interface Kind2Request {
  refundTemplateRaw: Uint8Array
  buyerPublicKey: Uint8Array
  sellerPublicKey: Uint8Array
  arbiterPublicKey: Uint8Array
  minerFeeRateSatoshisPerKilobyte: bigint
  buyerRefundSignature: Uint8Array
}

function decodeKind2Request (raw: Uint8Array): Kind2Request {
  const outer = outerFields(parseAs(2, raw), 8)
  return {
    refundTemplateRaw: fieldBytes(outer[2], 2, 'refund_template_raw'),
    buyerPublicKey: fieldBytes(outer[3], 2, 'buyer_public_key'),
    sellerPublicKey: fieldBytes(outer[4], 2, 'seller_public_key'),
    arbiterPublicKey: fieldBytes(outer[5], 2, 'arbiter_public_key'),
    minerFeeRateSatoshisPerKilobyte: fieldUint(outer[6], 2, 'miner_fee_rate_satoshis_per_kilobyte'),
    buyerRefundSignature: fieldBytes(outer[7], 2, 'buyer_refund_signature')
  }
}

function decodeKind3Response (raw: Uint8Array): { refundTemplateTxId: Uint8Array, sellerRefundSignature: Uint8Array } {
  const outer = outerFields(parseAs(3, raw), 4)
  return { refundTemplateTxId: fieldBytes(outer[2], 3, 'refund_template_txid'), sellerRefundSignature: fieldBytes(outer[3], 3, 'seller_refund_signature') }
}

function decodeKind4Delivery (raw: Uint8Array): { refundTemplateTxId: Uint8Array, fundingTransactionRaw: Uint8Array } {
  const outer = outerFields(parseAs(4, raw), 4)
  return { refundTemplateTxId: fieldBytes(outer[2], 4, 'refund_template_txid'), fundingTransactionRaw: fieldBytes(outer[3], 4, 'funding_transaction_raw') }
}

function decodeKind5Request (raw: Uint8Array): SignedContentRequest {
  const outer = outerFields(parseAs(5, raw), 4)
  return { paymentAuthorizationCBOR: fieldBytes(outer[2], 5, 'payment_authorization_cbor'), buyerPaymentAuthorizationSignature: fieldBytes(outer[3], 5, 'buyer_authorization_signature') }
}

function decodeSignedContentRequest (raw: Uint8Array): { request: SignedContentRequest, authorization: PaymentAuthorization } {
  const request = decodeKind5Request(raw)
  return { request, authorization: decodePaymentAuthorization(request.paymentAuthorizationCBOR) }
}

function decodeKind6Delivery (raw: Uint8Array): { contentDeliveryCBOR: Uint8Array, sellerContentDeliverySignature: Uint8Array, contentPayloadsCBOR: Uint8Array } {
  const outer = outerFields(parseAs(6, raw), 5)
  return {
    contentDeliveryCBOR: fieldBytes(outer[2], 6, 'content_delivery_cbor'),
    sellerContentDeliverySignature: fieldBytes(outer[3], 6, 'seller_content_delivery_signature'),
    contentPayloadsCBOR: fieldBytes(outer[4], 6, 'content_payloads_cbor')
  }
}

function decodeKind7Update (raw: Uint8Array): { paymentAuthorizationId: Uint8Array, buyerPaymentTransactionSignature: Uint8Array } {
  const outer = outerFields(parseAs(7, raw), 4)
  return { paymentAuthorizationId: fieldBytes(outer[2], 7, 'payment_authorization_id'), buyerPaymentTransactionSignature: fieldBytes(outer[3], 7, 'buyer_payment_signature') }
}

function decodeKind8Request (raw: Uint8Array): { arbitrationClaimCBOR: Uint8Array, sellerArbitrationClaimSignature: Uint8Array, contentPayloadsCBOR: Uint8Array } {
  const outer = outerFields(parseAs(8, raw), 5)
  return {
    arbitrationClaimCBOR: fieldBytes(outer[2], 8, 'arbitration_claim_cbor'),
    sellerArbitrationClaimSignature: fieldBytes(outer[3], 8, 'seller_claim_signature'),
    contentPayloadsCBOR: fieldBytes(outer[4], 8, 'content_payloads_cbor')
  }
}

function decodeKind9Response (raw: Uint8Array): { arbitrationReceiptCBOR: Uint8Array, arbiterArbitrationReceiptSignature: Uint8Array } {
  const outer = outerFields(parseAs(9, raw), 4)
  return { arbitrationReceiptCBOR: fieldBytes(outer[2], 9, 'arbitration_receipt_cbor'), arbiterArbitrationReceiptSignature: fieldBytes(outer[3], 9, 'arbiter_receipt_signature') }
}

function decodeKind10Request (raw: Uint8Array): { contentRetrievalRequestCBOR: Uint8Array, buyerContentRetrievalRequestSignature: Uint8Array } {
  const outer = outerFields(parseAs(10, raw), 4)
  return { contentRetrievalRequestCBOR: fieldBytes(outer[2], 10, 'content_retrieval_request_cbor'), buyerContentRetrievalRequestSignature: fieldBytes(outer[3], 10, 'buyer_retrieval_signature') }
}

function decodeKind11Response (raw: Uint8Array): ContentRetrievalResponseView {
  const artifact = parseAs(11, raw)
  const value = decodeCanonical(artifact.bytes(), 'wire')
  if (!Array.isArray(value) || (value.length !== 4 && value.length !== 5)) throw new WireError('malformed_wire', 11, 'wire', 'Kind 11 只能是 unavailable 四元或 available 五元')
  return {
    contentRetrievalResultCBOR: fieldBytes(value[2], 11, 'content_retrieval_result_cbor'),
    arbiterContentRetrievalResultSignature: fieldBytes(value[3], 11, 'arbiter_result_signature'),
    ...(value.length === 5 ? { contentPayloadsCBOR: fieldBytes(value[4], 11, 'content_payloads_cbor') } : {})
  }
}

function decodeContentDeliveryDocument (raw: Uint8Array): Uint8Array {
  const values = fieldArray(raw, 1, 6, 'content_delivery_cbor')
  const paymentAuthorizationID = fieldBytes(values[0], 6, 'payment_authorization_id')
  if (paymentAuthorizationID.byteLength !== 32) throw new WireError('malformed_wire', 6, 'payment_authorization_id', '授权 ID 必须是 32 bytes')
  if (paymentAuthorizationID.every(byte => byte === 0)) throw new WireError('invalid_evidence', 6, 'payment_authorization_id', '授权 ID 禁止全零')
  return paymentAuthorizationID
}

function outerFields (artifact: Artifact, length: number): CBORValue[] {
  const value = decodeCanonical(artifact.bytes(), 'wire')
  if (!Array.isArray(value) || value.length !== length) throw new WireError('malformed_wire', artifact.kind, 'wire', `CBOR array 长度必须是 ${length}`)
  return value
}

function fieldArray (raw: Uint8Array, length: number, kind: number, field: string): CBORValue[] {
  let value: CBORValue
  try { value = decodeCanonical(raw, field) } catch (error) {
    if (error instanceof WireError) throw new WireError(error.code, kind, field, error.message)
    throw new WireError('malformed_wire', kind, field, 'CBOR 解码失败')
  }
  if (!Array.isArray(value) || value.length !== length) throw new WireError('malformed_wire', kind, field, `CBOR array 长度必须是 ${length}`)
  return value
}

function fieldBytes (value: CBORValue | undefined, kind: number, field: string): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new WireError('malformed_wire', kind, field, '字段必须是 CBOR bstr')
  return copyBytes(value)
}

function fieldUint (value: CBORValue | undefined, kind: number, field: string): bigint {
  if (typeof value !== 'bigint' || value < 0n) throw new WireError('malformed_wire', kind, field, '字段必须是 CBOR uint')
  return value
}

// ---------------------------------------------------------------------------
// 通用小工具
// ---------------------------------------------------------------------------

class BoundSigner implements Signer {
  readonly #delegate: Signer
  readonly #publicKey: Uint8Array
  constructor (delegate: Signer, field: string) {
    if (delegate == null) throw new WireError('signer_unavailable', 0, field, '本步骤需要受约束 Signer')
    const publicKey = new Uint8Array(delegate.publicKey())
    if (publicKey.byteLength !== 33 || !isValidCompressedKey(publicKey)) throw new WireError('invalid_evidence', 0, 'public_key', 'Signer 必须返回有效的 33 字节压缩 secp256k1 公钥')
    this.#delegate = delegate
    this.#publicKey = publicKey
  }
  publicKey (): Uint8Array { return copyBytes(this.#publicKey) }
  async sign (request: Parameters<Signer['sign']>[0], signal?: AbortSignal): Promise<Uint8Array> { return await this.#delegate.sign(request, signal) }
}

function bindSigner (signer: Signer | undefined, field: string): Signer { return new BoundSigner(signer as Signer, field) }

function isValidCompressedKey (key: Uint8Array): boolean {
  return key.byteLength === 33 && secp256k1.utils.isValidPublicKey(key, true)
}

function requireNow (facts: Readonly<PureFunctionFacts> | undefined): bigint {
  const now = facts?.nowUnixSeconds
  if (typeof now !== 'bigint') throw new WireError('invalid_evidence', 0, 'facts.now', '本时间敏感操作需要显式 facts.now')
  return now
}

function decodeValidatedHashes (hashes: readonly Uint8Array[]): Uint8Array[] {
  return decodeContentHashes(encodeContentHashes(hashes))
}

function validateRequestID (requestID: Uint8Array): void {
  if (requestID == null || requestID.byteLength !== 32) throw new WireError('invalid_evidence', 11, 'content_retrieval_request_id', '取回请求 ID 必须是 32 bytes')
  if (requestID.every(byte => byte === 0)) throw new WireError('invalid_evidence', 11, 'content_retrieval_request_id', '取回请求 ID 禁止全零')
}

function clonePrepared (evidence: PreparedArbitrationEvidence): PreparedArbitrationEvidence {
  return { rawKind8: copyBytes(evidence.rawKind8), candidateRaw: copyBytes(evidence.candidateRaw), arbitrationClaimID: copyBytes(evidence.arbitrationClaimID), feeSatoshis: evidence.feeSatoshis }
}

function rethrow (error: unknown, code: 'invalid_signature', kind: number, field: string): WireError {
  const message = error instanceof Error ? error.message : '签名或证据校验失败'
  return new WireError(code, kind, field, message)
}

function equal (left: Uint8Array, right: Uint8Array): boolean { return left.byteLength === right.byteLength && left.every((value, index) => value === right[index]) }
function copyBytes (value: Uint8Array): Uint8Array { return new Uint8Array(value) }
