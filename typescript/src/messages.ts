import { sha256 } from '@noble/hashes/sha2.js'
import { encodeCanonical, type CBORValue } from './cbor.js'
import { WIRE_VERSION } from './constants.js'
import { signWireDocument, type Signer } from './protocol.js'
import { Artifact, parse } from './wire.js'

/** Kind 1 报价的业务条款；金额单位均为 satoshi，时间单位为 UTC Unix 秒。 */
export interface FileQuoteTerms {
  /** MasterSeed 的 SHA-256，32 字节。 */
  seedHash: Uint8Array
  /** 唯一买方的 33 字节压缩公钥。 */
  buyerPublicKey: Uint8Array
  /** 完整 seed 的价格，单位 satoshi。 */
  seedPriceSatoshis: bigint
  /** 完整 256 KiB block 的价格，单位 satoshi。 */
  fullBlockPriceSatoshis: bigint
  /** 原始文件总字节数。 */
  fileSizeBytes: bigint
  /** 报价失效时间，UTC Unix 秒。 */
  quoteExpiresAtUnixSeconds: bigint
  /** 允许的仲裁方压缩公钥，保持调用方顺序且禁止重复。 */
  supportedArbiterPublicKeys: Uint8Array[]
  /** 已经过 sanitize 的单一展示文件名。 */
  recommendedFilename: string
}

/** Kind 5 买方累计付款授权。 */
export interface PaymentAuthorization {
  /** SHA-256(exact file_quote_terms_cbor)。 */
  fileQuoteTermsID: Uint8Array
  /** 费用池退款模板交易 ID，32 字节且禁止全零。 */
  refundTemplateTxID: Uint8Array
  /** 目标累计付款序号，范围 1..4294967294。 */
  paymentSequence: number
  /** 本次授权后的卖方累计金额，单位 satoshi。 */
  sellerAmountAfterSatoshis: bigint
  /** 有序且不重复的内容 SHA-256 数组。 */
  contentHashes: Uint8Array[]
  /** 交付截止时间，UTC Unix 秒。 */
  deliveryDeadlineUnixSeconds: bigint
}

/** Kind 2 退款预签请求字段。 */
export interface RefundPresignRequest {
  refundTemplateRaw: Uint8Array
  buyerPublicKey: Uint8Array
  sellerPublicKey: Uint8Array
  arbiterPublicKey: Uint8Array
  minerFeeRateSatoshisPerKilobyte: bigint
  buyerRefundTransactionSignature: Uint8Array
}

/** Kind 12 买方关池请求；池关联 ID 是首个业务字段。 */
export interface PoolCloseRequest {
  /** 由 opening 推导的费用池关联 ID，固定为第一个业务字段。 */
  refundTemplateTxID: Uint8Array
  /** 最终 sequence/locktime 的未签名关闭交易原文。 */
  unsignedCloseTransactionRaw: Uint8Array
  /** 买方对未签名关闭交易的分离式交易签名。 */
  buyerCloseTransactionSignature: Uint8Array
}

/** Kind 13 卖方关池响应；完整交易包含买卖双方的交易签名。 */
export interface PoolCloseResponse {
  /** 由 opening 推导的费用池关联 ID，固定为第一个业务字段。 */
  refundTemplateTxID: Uint8Array
  /** unlocking script 含买卖双方签名的完整关闭交易原文。 */
  completeCloseTransactionRaw: Uint8Array
}

export function encodeSupportedArbiterPublicKeys (keys: readonly Uint8Array[]): Uint8Array {
  return encodeCanonical(keys.map(key => copy(key)))
}

export function encodeFileQuoteTerms (terms: Readonly<FileQuoteTerms>): Uint8Array {
  return encodeCanonical([
    copy(terms.seedHash), copy(terms.buyerPublicKey), terms.seedPriceSatoshis,
    terms.fullBlockPriceSatoshis, terms.fileSizeBytes, terms.quoteExpiresAtUnixSeconds,
    encodeSupportedArbiterPublicKeys(terms.supportedArbiterPublicKeys), terms.recommendedFilename
  ])
}

export function fileQuoteTermsID (termsCBOR: Uint8Array): Uint8Array {
  // 用临时完整 Kind 1 做结构验证会要求真实公钥/签名，因此这里先由调用方构造函数
  // 验证；ID 算法只对 exact canonical 子文档做 SHA-256。
  return sha256(termsCBOR)
}

/** 创建、签署并严格自解析一个 Kind 1 Artifact。 */
export async function createFileQuote (signer: Signer, terms: Readonly<FileQuoteTerms>, signal?: AbortSignal): Promise<Artifact> {
  const document = encodeFileQuoteTerms(terms)
  const signature = await signWireDocument(signer, 1, document, signal)
  return artifact([1n, 1n, document, copy(signer.publicKey()), signature])
}

export function encodeContentHashes (hashes: readonly Uint8Array[]): Uint8Array {
  return encodeCanonical(hashes.map(hash => copy(hash)))
}

export function encodePaymentAuthorization (authorization: Readonly<PaymentAuthorization>): Uint8Array {
  return encodeCanonical([
    copy(authorization.fileQuoteTermsID), copy(authorization.refundTemplateTxID), BigInt(authorization.paymentSequence),
    authorization.sellerAmountAfterSatoshis, encodeContentHashes(authorization.contentHashes), authorization.deliveryDeadlineUnixSeconds
  ])
}

export function paymentAuthorizationID (authorizationCBOR: Uint8Array): Uint8Array { return sha256(authorizationCBOR) }

/** 创建买方签署的 Kind 5 ContentRequest。 */
export async function createContentRequest (signer: Signer, authorization: Readonly<PaymentAuthorization>, signal?: AbortSignal): Promise<Artifact> {
  const document = encodePaymentAuthorization(authorization)
  const signature = await signWireDocument(signer, 5, document, signal)
  return artifact([1n, 5n, document, signature])
}

export function encodeContentPayloads (payloads: readonly Uint8Array[]): Uint8Array {
  return encodeCanonical(payloads.map(payload => copy(payload)))
}

/** 创建卖方签署的 Kind 6 ContentDelivery；payload 通过 Kind 5 哈希间接绑定。 */
export async function createContentDelivery (signer: Signer, authorizationID: Uint8Array, payloads: readonly Uint8Array[], signal?: AbortSignal): Promise<Artifact> {
  const document = encodeCanonical([copy(authorizationID)])
  const signature = await signWireDocument(signer, 6, document, signal)
  return artifact([1n, 6n, document, signature, encodeContentPayloads(payloads)])
}

export function encodeRefundPresignRequest (request: Readonly<RefundPresignRequest>): Artifact {
  return artifact([1n, 2n, copy(request.refundTemplateRaw), copy(request.buyerPublicKey), copy(request.sellerPublicKey), copy(request.arbiterPublicKey), request.minerFeeRateSatoshisPerKilobyte, copy(request.buyerRefundTransactionSignature)])
}

export function encodeRefundPresignResponse (refundTemplateTxID: Uint8Array, sellerRefundTransactionSignature: Uint8Array): Artifact {
  return artifact([1n, 3n, copy(refundTemplateTxID), copy(sellerRefundTransactionSignature)])
}

export function encodeFundingTransactionDelivery (refundTemplateTxID: Uint8Array, fundingTransactionRaw: Uint8Array): Artifact {
  return artifact([1n, 4n, copy(refundTemplateTxID), copy(fundingTransactionRaw)])
}

/** 编码 Kind 12 买方关池请求；交易签名由卖方工作流按 opening 验证。 */
export function encodePoolCloseRequest (request: Readonly<PoolCloseRequest>): Artifact {
  return artifact([
    1n, 12n, copy(request.refundTemplateTxID),
    copy(request.unsignedCloseTransactionRaw), copy(request.buyerCloseTransactionSignature)
  ])
}

/** 编码 Kind 13 卖方关池响应；接收方仍须验证完整交易与费用池证据。 */
export function encodePoolCloseResponse (response: Readonly<PoolCloseResponse>): Artifact {
  return artifact([
    1n, 13n, copy(response.refundTemplateTxID), copy(response.completeCloseTransactionRaw)
  ])
}

export function encodePaymentUpdate (authorizationID: Uint8Array, buyerPaymentTransactionSignature: Uint8Array): Artifact {
  return artifact([1n, 7n, copy(authorizationID), copy(buyerPaymentTransactionSignature)])
}

/** 对已经构造并验证的 Kind 8 Claim 签名并附带托管 payload。 */
export async function createArbitrationRequest (signer: Signer, arbitrationClaimCBOR: Uint8Array, payloads: readonly Uint8Array[], signal?: AbortSignal): Promise<Artifact> {
  const signature = await signWireDocument(signer, 8, arbitrationClaimCBOR, signal)
  return artifact([1n, 8n, copy(arbitrationClaimCBOR), signature, encodeContentPayloads(payloads)])
}

/** 对 Kind 9 仲裁回执子文档签名。 */
export async function createArbitrationResponse (signer: Signer, arbitrationReceiptCBOR: Uint8Array, signal?: AbortSignal): Promise<Artifact> {
  const signature = await signWireDocument(signer, 9, arbitrationReceiptCBOR, signal)
  return artifact([1n, 9n, copy(arbitrationReceiptCBOR), signature])
}

/** 创建买方签署的 Kind 10 仲裁内容取回请求。 */
export async function createContentRetrievalRequest (signer: Signer, arbitrationClaimID: Uint8Array, nonce: Uint8Array, signal?: AbortSignal): Promise<Artifact> {
  const document = encodeCanonical([copy(arbitrationClaimID), copy(nonce)])
  const signature = await signWireDocument(signer, 10, document, signal)
  return artifact([1n, 10n, document, signature])
}

/** 创建 Kind 11 unavailable 结果；reason：0 未收到、1 未就绪、2 托管已丢失。 */
export async function createContentRetrievalUnavailable (signer: Signer, requestID: Uint8Array, reason: 0 | 1 | 2, signal?: AbortSignal): Promise<Artifact> {
  const document = encodeCanonical([copy(requestID), 0n, BigInt(reason)])
  const signature = await signWireDocument(signer, 11, document, signal)
  return artifact([1n, 11n, document, signature])
}

/** 创建 Kind 11 available 结果，并把 exact payload 子文档 SHA-256 写入签名文档。 */
export async function createContentRetrievalAvailable (signer: Signer, requestID: Uint8Array, payloads: readonly Uint8Array[], signal?: AbortSignal): Promise<Artifact> {
  const attachment = encodeContentPayloads(payloads)
  const document = encodeCanonical([copy(requestID), 1n, sha256(attachment)])
  const signature = await signWireDocument(signer, 11, document, signal)
  return artifact([1n, 11n, document, signature, attachment])
}

function artifact (values: CBORValue[]): Artifact {
  // parse 是全部 typed encoder 的共同末端门禁，防止构造 API 与 decoder 漂移。
  return parse(encodeCanonical(values))
}
function copy (value: Uint8Array): Uint8Array { return new Uint8Array(value) }

export { WIRE_VERSION }
