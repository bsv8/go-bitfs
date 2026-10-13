import { sha256 } from '@noble/hashes/sha2.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import {
  ERROR_CODES,
  blockCountForSourceSize,
  Digest,
  expectedBlockSize,
  findBlockHash,
  isMasterSeedError,
  verifyBlock,
  verifyBlockInSeed,
  verifySeedForSourceSize
} from 'masterseed'
import { decodeCanonical, encodeCanonical, type CBORValue } from './cbor.js'
import { MAX_CONTENT_BATCH_ITEMS, MAX_CONTENT_PAYLOAD_BYTES } from './constants.js'
import { WireError } from './errors.js'
import type { FileQuoteTerms, PaymentAuthorization } from './messages.js'
import { deriveRefundTemplateTxID } from './pool.js'
import { verifyWireDocument } from './protocol.js'
import type { OpeningProof } from './evidence.js'

/** MasterSeed 完整块字节数（256 KiB）。 */
export const CONTENT_BLOCK_SIZE = 262_144n
/** MasterSeed 摘要字节宽度。 */
export const CONTENT_DIGEST_SIZE = 32
/** 一个报价 seed 能描述的最大块数（一个 BitFS payload 可携带的摘要数）。 */
export const MAX_QUOTE_SEED_BLOCKS = CONTENT_BLOCK_SIZE / BigInt(CONTENT_DIGEST_SIZE)
/** 单个报价能描述的最大文件字节数。 */
export const MAX_QUOTE_FILE_SIZE = MAX_QUOTE_SEED_BLOCKS * CONTENT_BLOCK_SIZE
const MAX_UINT64 = 0xffffffffffffffffn
const MAX_INT64 = 0x7fffffffffffffffn

/** 已验证报价；所有字节字段均为防御性副本。 */
export interface VerifiedQuote {
  /** 从 exact file_quote_terms_cbor 严格解码的最终条款。 */
  readonly terms: FileQuoteTerms
  /** exact 规范条款字节（确定性 CBOR）。 */
  readonly termsCBOR: Uint8Array
  /** file_quote_terms_id = SHA-256(exact 条款字节)。 */
  readonly termsID: Uint8Array
  /** 卖方压缩公钥，用于恢复并验证条款统一签名。 */
  readonly sellerPublicKey: Uint8Array
  /** 报告指定仲裁公钥是否在报价允许列表内。 */
  allowsArbiter(publicKey: Uint8Array): boolean
}

/** 完整 Kind 1 报价证据（业务明文，不含 wire 外壳）。 */
export interface SignedFileQuote {
  /** exact 规范条款字节。 */
  fileQuoteTermsCBOR: Uint8Array
  /** 卖方压缩公钥。 */
  sellerPublicKey: Uint8Array
  /** 卖方对条款的统一消息签名。 */
  sellerFileQuoteTermsSignature: Uint8Array
}

/** 完整 Kind 5 付款授权证据（业务明文，不含 wire 外壳）。 */
export interface SignedContentRequest {
  /** exact 规范付款授权字节。 */
  paymentAuthorizationCBOR: Uint8Array
  /** 买方对付款授权的统一消息签名。 */
  buyerPaymentAuthorizationSignature: Uint8Array
}

/** 一个内容哈希的证据派生分类：类型与计价长度只来自报价与已验证 seed。 */
export interface ClassifiedContent {
  /** 该哈希是否等于报价 SeedHash（按整份 seed 计价，无 BlockSize）。 */
  isSeed: boolean
  /** 该块在 seed 中的协议期望长度（1..262144）；isSeed 为 true 时为 0。 */
  blockSize: bigint
}

/** 时间无关证据验证的结果：最终条款与验证后的卖方报价。 */
export interface VerifiedQuoteEvidence {
  /** 已验证的不可变报价视图。 */
  quote: VerifiedQuote
  /** 卖方公开的 exact Kind 1 证据（深拷贝）。 */
  signedQuote: SignedFileQuote
}

/**
 * 把卖方提供的展示文件名规范化为安全的单一文件名：反斜杠归一为斜杠、
 * 取 path.Base、控制字符替换为下划线、Unicode 空白裁剪，空/"."/".." 回退
 * "download"。卖方必须在编码与签名前调用；接收方用同一规则拒绝未 sanitize
 * 的字段，绝不静默改写已签字节。
 */
export function sanitizeRecommendedFilename (name: string): string {
  let normalized = name.replaceAll('\\', '/')
  if (/^\/+$/u.test(normalized)) normalized = '/'
  else normalized = normalized.replace(/\/+$/u, '')
  const parts = normalized.split('/')
  let result = (parts.at(-1) ?? '').replace(/\p{Cc}/gu, '_')
  result = result.replace(/^[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+/u, '')
  result = result.replace(/[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$/u, '')
  if (result === '' || result === '.' || result === '..') return 'download'
  return result
}

/** 严格解码受支持仲裁公钥子文档（确定性 CBOR bstr 数组）。 */
export function decodeSupportedArbiterPublicKeys (raw: Uint8Array): Uint8Array[] {
  const op = 'content.DecodeSupportedArbiterPublicKeys'
  let value: CBORValue
  try { value = decodeCanonical(raw, 'supported_arbiter_public_keys_cbor') } catch (error) { throw wrapMalformed(op, 'supported_arbiter_public_keys_cbor', error) }
  if (!Array.isArray(value)) throw malformed(op, 'supported_arbiter_public_keys_cbor', '字段必须是 CBOR array')
  const keys = value.map((item, index) => {
    if (!(item instanceof Uint8Array)) throw malformed(op, 'supported_arbiter_public_keys_cbor', '元素必须是 CBOR bstr')
    if (item.byteLength !== 33 || !secp256k1.utils.isValidPublicKey(item, true)) throw invalid(op, 'supported_arbiter_public_keys_cbor', `仲裁公钥 #${index + 1} 无效`)
    for (let previous = 0; previous < index; previous++) if (equalBytes(keys[previous]!, item)) throw invalid(op, 'supported_arbiter_public_keys_cbor', `仲裁公钥 #${index + 1} 重复`)
    return copyBytes(item)
  })
  if (!equalBytes(encodeArbiterKeys(keys), raw)) throw new WireError('non_canonical', 0, 'supported_arbiter_public_keys_cbor', '仲裁公钥子文档不是确定性编码')
  return keys
}

/** 校验报价条款的字段宽度、价格范围、文件名 sanitize 规则与仲裁白名单。 */
export function validateFileQuoteTerms (terms: FileQuoteTerms): void {
  const op = 'content.ValidateFileQuoteTerms'
  if (terms == null) throw invalid(op, 'terms', '报价条款不能为空')
  if (terms.seedHash.byteLength !== CONTENT_DIGEST_SIZE) throw malformed(op, 'seed_hash', `seed_hash 必须是 ${CONTENT_DIGEST_SIZE} bytes`)
  if (terms.buyerPublicKey.byteLength !== 33 || !secp256k1.utils.isValidPublicKey(terms.buyerPublicKey, true)) throw invalid(op, 'buyer_public_key', '报价买方公钥无效')
  validateUint64(terms.seedPriceSatoshis, op, 'seed_price_satoshis')
  validateUint64(terms.fullBlockPriceSatoshis, op, 'full_block_price_satoshis')
  validateUint64(terms.fileSizeBytes, op, 'file_size_bytes')
  if (terms.quoteExpiresAtUnixSeconds <= 0n || terms.quoteExpiresAtUnixSeconds > MAX_INT64) throw invalid(op, 'quote_expires_at_unix_seconds', '报价失效时间必须是正 Unix 秒')
  if (terms.fileSizeBytes === 0n && !equalBytes(terms.seedHash, emptySeedHash())) throw invalid(op, 'seed_hash', '空文件的 seed_hash 必须等于空 seed 的 SHA-256')
  if (blockCountForSourceSize(terms.fileSizeBytes) > MAX_QUOTE_SEED_BLOCKS) throw invalid(op, 'file_size_bytes', `文件大小超过上限 ${MAX_QUOTE_FILE_SIZE}`)
  validateArbiterPublicKeys(terms.supportedArbiterPublicKeys)
  if (terms.recommendedFilename !== sanitizeRecommendedFilename(terms.recommendedFilename) || terms.recommendedFilename.length === 0) throw invalid(op, 'recommended_filename', '推荐文件名不满足 sanitize 规则')
}

/** 严格解码 exact 规范报价条款字节。 */
export function decodeFileQuoteTerms (raw: Uint8Array): FileQuoteTerms {
  const op = 'content.DecodeFileQuoteTerms'
  const values = decodeStrictArray(raw, 8, op, 'file_quote_terms_cbor')
  const terms: FileQuoteTerms = {
    seedHash: bytesField(values[0], op, 'seed_hash'),
    buyerPublicKey: bytesField(values[1], op, 'buyer_public_key'),
    seedPriceSatoshis: uintField(values[2], op, 'seed_price_satoshis'),
    fullBlockPriceSatoshis: uintField(values[3], op, 'full_block_price_satoshis'),
    fileSizeBytes: uintField(values[4], op, 'file_size_bytes'),
    quoteExpiresAtUnixSeconds: uintField(values[5], op, 'quote_expires_at_unix_seconds'),
    supportedArbiterPublicKeys: decodeSupportedArbiterPublicKeys(bytesField(values[6], op, 'supported_arbiter_public_keys_cbor')),
    recommendedFilename: textField(values[7], op, 'recommended_filename')
  }
  validateFileQuoteTerms(terms)
  if (!equalBytes(encodeFileQuoteTerms(terms), raw)) throw new WireError('non_canonical', 1, 'file_quote_terms_cbor', '报价条款不是确定性编码')
  return terms
}

/** 编码 exact 规范报价条款字节（先校验后编码）。 */
function encodeFileQuoteTerms (terms: FileQuoteTerms): Uint8Array {
  validateFileQuoteTerms(terms)
  return encodeTerms(terms)
}

/** 时间无关的报价证据验证：结构、CBOR、压缩公钥与卖方统一签名。 */
export function verifyQuoteEvidence (quote: SignedFileQuote | undefined): VerifiedQuote {
  const op = 'content.VerifyFileQuoteEvidence'
  if (quote == null) throw invalid(op, 'quote', '已签报价不能为空')
  if (quote.sellerPublicKey.byteLength !== 33 || !secp256k1.utils.isValidPublicKey(quote.sellerPublicKey, true)) throw invalid(op, 'seller_public_key', '卖方公钥无效')
  if (quote.sellerFileQuoteTermsSignature.byteLength === 0) throw invalid(op, 'seller_file_quote_terms_signature', '缺少卖方条款签名')
  let terms: FileQuoteTerms
  try { terms = decodeFileQuoteTerms(quote.fileQuoteTermsCBOR) } catch (error) {
    if (error instanceof WireError) throw new WireError(error.code, 1, 'file_quote_terms_cbor', error.message)
    throw error
  }
  verifyWireDocument(quote.sellerPublicKey, 1, quote.fileQuoteTermsCBOR, quote.sellerFileQuoteTermsSignature)
  return newVerifiedQuote(quote, terms, sha256(quote.fileQuoteTermsCBOR))
}

/**
 * 时间无关证据 + 显式时间过期判断。零值/缺失时间直接拒绝，绝不回退系统时钟。
 */
export function verifyQuote (quote: SignedFileQuote | undefined, nowUnixSeconds: bigint): VerifiedQuote {
  const now = requireNow(nowUnixSeconds)
  const verified = verifyQuoteEvidence(quote)
  if (!(now < verified.terms.quoteExpiresAtUnixSeconds)) throw new WireError('expired', 1, 'quote_expires_at_unix_seconds', '报价已经失效')
  return verified
}

/** 在 VerifyQuote 基础上绑定买方归属：不符返回 unauthorized。 */
export function verifyQuoteForBuyer (quote: SignedFileQuote | undefined, nowUnixSeconds: bigint, buyerPublicKey: Uint8Array): VerifiedQuote {
  if (buyerPublicKey.byteLength !== 33) throw invalid('content.VerifyQuoteForBuyer', 'buyer_public_key', '买方公钥必须是压缩公钥')
  const verified = verifyQuote(quote, nowUnixSeconds)
  if (!equalBytes(verified.terms.buyerPublicKey, buyerPublicKey)) throw new WireError('unauthorized', 1, 'buyer_public_key', '报价绑定的买方不是当前身份')
  return verified
}

/** 编码内容哈希子文档：1..64 个有序、不重复的 32 字节哈希。 */
function encodeContentHashes (hashes: readonly Uint8Array[]): Uint8Array {
  validateContentHashes(hashes)
  return encodeCanonical(hashes.map(copyBytes))
}

/** 严格解码内容哈希子文档并检查确定性与批量约束。 */
export function decodeContentHashes (raw: Uint8Array): Uint8Array[] {
  const op = 'content.DecodeContentHashes'
  let value: CBORValue
  try { value = decodeCanonical(raw, 'content_hashes_cbor') } catch (error) { throw wrapMalformed(op, 'content_hashes_cbor', error) }
  if (!Array.isArray(value)) throw malformed(op, 'content_hashes_cbor', '字段必须是 CBOR array')
  const hashes = value.map(item => {
    if (!(item instanceof Uint8Array)) throw malformed(op, 'content_hashes_cbor', '元素必须是 CBOR bstr')
    return copyBytes(item)
  })
  validateContentHashes(hashes, op)
  if (!equalBytes(encodeCanonical(hashes), raw)) throw new WireError('non_canonical', 0, 'content_hashes_cbor', '内容哈希不是确定性编码')
  return hashes
}

/** 严格解码内容 payload 子文档（含 canonical 复编码比对）。 */
export function decodeContentPayloads (raw: Uint8Array): Uint8Array[] {
  const op = 'content.DecodeContentPayloads'
  if (raw.byteLength === 0) throw invalid(op, 'content_payloads_cbor', 'payload 子文档为空')
  let value: CBORValue
  try { value = decodeCanonical(raw, 'content_payloads_cbor') } catch (error) { throw wrapMalformed(op, 'content_payloads_cbor', error) }
  if (!Array.isArray(value)) throw malformed(op, 'content_payloads_cbor', '字段必须是 CBOR array')
  const payloads = value.map(item => {
    if (!(item instanceof Uint8Array)) throw malformed(op, 'content_payloads_cbor', '元素必须是 CBOR bstr')
    return copyBytes(item)
  })
  validateContentPayloads(payloads, op)
  if (!equalBytes(encodeCanonical(payloads), raw)) throw new WireError('non_canonical', 0, 'content_payloads_cbor', '内容 payload 不是确定性编码')
  return payloads
}

/** 严格解码付款授权子文档（Kind 5 六元业务字段）。 */
export function decodePaymentAuthorization (raw: Uint8Array): PaymentAuthorization {
  const op = 'content.DecodePaymentAuthorization'
  const values = decodeStrictArray(raw, 6, op, 'payment_authorization_cbor')
  const authorization: PaymentAuthorization = {
    fileQuoteTermsID: sizedBytes(bytesField(values[0], op, 'file_quote_terms_id'), 32, op, 'file_quote_terms_id'),
    refundTemplateTxID: bytesField(values[1], op, 'refund_template_txid'),
    paymentSequence: numberField(values[2], op, 'payment_sequence'),
    sellerAmountAfterSatoshis: uintField(values[3], op, 'seller_amount_after_satoshis'),
    contentHashes: decodeContentHashesFromField(values[4], op, 'content_hashes_cbor'),
    deliveryDeadlineUnixSeconds: uintField(values[5], op, 'delivery_deadline_unix_seconds')
  }
  validatePaymentAuthorization(authorization)
  if (!equalBytes(encodePaymentAuthorization(authorization), raw)) throw new WireError('non_canonical', 5, 'payment_authorization_cbor', '付款授权不是确定性编码')
  return authorization
}

/** 编码付款授权子文档（Kind 5 六元业务字段，先校验）。 */
function encodePaymentAuthorization (authorization: PaymentAuthorization): Uint8Array {
  validatePaymentAuthorization(authorization)
  return encodeAuthorization(authorization)
}

/** 校验 Kind 5 付款授权字段宽度、池引用、序号范围与 content hash 批次。 */
export function validatePaymentAuthorization (authorization: PaymentAuthorization | undefined): void {
  const op = 'content.ValidatePaymentAuthorization'
  if (authorization == null) throw invalid(op, 'authorization', '付款授权不能为空')
  if (authorization.fileQuoteTermsID.byteLength !== 32) throw malformed(op, 'file_quote_terms_id', 'file_quote_terms_id 必须是 32 bytes')
  if (allZero(authorization.fileQuoteTermsID)) throw invalid(op, 'file_quote_terms_id', 'file_quote_terms_id 禁止全零哨兵')
  if (authorization.refundTemplateTxID.byteLength !== 32) throw malformed(op, 'refund_template_txid', 'refund_template_txid 必须是 32 bytes')
  if (allZero(authorization.refundTemplateTxID)) throw invalid(op, 'refund_template_txid', 'refund_template_txid 禁止全零哨兵')
  if (!Number.isInteger(authorization.paymentSequence) || authorization.paymentSequence < 1 || authorization.paymentSequence > 0xfffffffe) throw invalid(op, 'payment_sequence', '付款序号必须在 1..4294967294')
  validateContentHashes(authorization.contentHashes, op)
  if (authorization.deliveryDeadlineUnixSeconds <= 0n || authorization.deliveryDeadlineUnixSeconds > MAX_INT64) throw invalid(op, 'delivery_deadline_unix_seconds', '交付截止时间必须是正 Unix 秒')
}

/**
 * 验证 Kind 5 的池绑定与买方签名：从 opening 重派生退款模板 ID 并要求精确
 * 匹配，再用 opening 买方公钥验证统一消息签名。报价/内容/时序不在此范围。
 */
export async function verifySignedContentRequestForOpening (request: SignedContentRequest | undefined, opening: OpeningProof): Promise<PaymentAuthorization> {
  const op = 'content.VerifySignedContentRequestForOpening'
  if (request == null || request.buyerPaymentAuthorizationSignature.byteLength === 0) throw invalid(op, 'request', '已签内容请求不能为空')
  if (opening == null) throw invalid(op, 'opening', '开池证据不能为空')
  const authorization = decodePaymentAuthorization(request.paymentAuthorizationCBOR)
  const derived = await deriveRefundTemplateTxID(opening)
  if (derived.byteLength !== 32 || !equalBytes(derived, authorization.refundTemplateTxID)) throw invalid(op, 'refund_template_txid', '内容请求未绑定到给定开池证明')
  verifyWireDocument(opening.buyerPublicKey, 5, request.paymentAuthorizationCBOR, request.buyerPaymentAuthorizationSignature)
  return authorization
}

/**
 * 时间无关的 Kind 5 完整证据验证：报价证据与卖方签名、池绑定、买方统一签名、
 * FileQuoteTermsID 比对以及三方公钥与开池证据的绑定。过期与交付截止由调用方
 * 用显式时间事实另行检查。
 */
export async function verifyContentRequestEvidence (request: SignedContentRequest, quote: SignedFileQuote, opening: OpeningProof): Promise<{ authorization: PaymentAuthorization, quoteTerms: FileQuoteTerms }> {
  const op = 'content.VerifyContentRequestEvidence'
  const verifiedQuote = verifyQuoteEvidence(quote)
  const quoteTerms = verifiedQuote.terms
  const authorization = await verifySignedContentRequestForOpening(request, opening)
  let quoteID: Uint8Array
  try { quoteID = paymentAuthorizationIDForTerms(quote.fileQuoteTermsCBOR) } catch (error) {
    if (error instanceof WireError) throw error
    throw error
  }
  if (!equalBytes(authorization.fileQuoteTermsID, quoteID)) throw invalid(op, 'file_quote_terms_id', '内容请求未引用给定报价')
  if (!equalBytes(opening.buyerPublicKey, quoteTerms.buyerPublicKey) || !equalBytes(opening.sellerPublicKey, quote.sellerPublicKey)) throw invalid(op, 'participant_public_keys', '内容请求参与方与报价不一致')
  if (!allowedArbiter(quoteTerms, opening.arbiterPublicKey)) throw invalid(op, 'supported_arbiter_public_keys', '开池仲裁方不在报价白名单内')
  return { authorization, quoteTerms }
}

/**
 * 应用 Kind 5 请求的两项显式时间比较：报价过期与交付截止。nowUnixSeconds 是
 * 调用方显式传入的本操作唯一时间事实。
 */
export function checkContentRequestTiming (authorization: PaymentAuthorization, quoteTerms: FileQuoteTerms, nowUnixSeconds: bigint): void {
  const op = 'content.CheckContentRequestTiming'
  const now = requireNow(nowUnixSeconds)
  if (!(now < quoteTerms.quoteExpiresAtUnixSeconds)) throw new WireError('expired', 5, 'quote_expires_at_unix_seconds', '报价已经失效')
  if (!(now < authorization.deliveryDeadlineUnixSeconds)) throw new WireError('expired', 5, 'delivery_deadline_unix_seconds', '交付截止时间已过')
  if (authorization.deliveryDeadlineUnixSeconds > quoteTerms.quoteExpiresAtUnixSeconds) throw invalid(op, 'delivery_deadline_unix_seconds', '交付截止时间超过报价失效时间')
}

/**
 * 验证交付批次：数量严格等于授权哈希数量、顺序一一对应、逐项 SHA-256、
 * seed/block 归属与协议期望长度。批次内携带与报价 SeedHash 对应的 seed
 * payload 时先完整验证它，再复用它做块成员校验；返回实际用于成员校验的
 * seed 深拷贝（无 seed 批次返回 undefined）。
 */
export async function verifyContentPayloads (terms: FileQuoteTerms, contentHashes: readonly Uint8Array[], payloads: readonly Uint8Array[], seed?: Uint8Array): Promise<Uint8Array | undefined> {
  const op = 'content.VerifyContentPayloads'
  validateContentHashes(contentHashes, op)
  validateContentPayloads(payloads, op)
  try { validateFileQuoteTerms(terms) } catch (error) {
    if (error instanceof WireError) throw new WireError(error.code, error.kind, error.field, `报价条款: ${error.message}`)
    throw error
  }
  if (payloads.length !== contentHashes.length) throw invalid(op, 'content_payloads_cbor', `payload 数量 ${payloads.length} 与授权哈希数量 ${contentHashes.length} 不一致`)
  let seedItemIndex = -1
  let requiresBlocks = false
  for (let index = 0; index < contentHashes.length; index++) {
    const hash = contentHashes[index]!
    const payload = payloads[index]!
    if (!equalBytes(sha256(payload), hash)) throw invalid(op, `payload[${index}]`, `payload #${index + 1} 与授权内容哈希不一致`)
    if (equalBytes(hash, terms.seedHash)) {
      try {
        await verifySeedForSourceSize([payload], Digest.fromBytes(hash), terms.fileSizeBytes)
      } catch (error) { throw mapMasterSeedError(error, op) }
      seedItemIndex = index
    } else {
      requiresBlocks = true
    }
  }
  let effectiveSeed: Uint8Array | undefined
  if (seed != null && seed.byteLength > 0) effectiveSeed = copyBytes(seed)
  else if (seedItemIndex >= 0) effectiveSeed = copyBytes(payloads[seedItemIndex]!)
  if (requiresBlocks && effectiveSeed == null) throw invalid(op, 'seed', '验证块 payload 需要已验证 seed')
  if (requiresBlocks) {
    const seedDigest = Digest.fromBytes(terms.seedHash)
    for (let index = 0; index < contentHashes.length; index++) {
      const hash = contentHashes[index]!
      if (equalBytes(hash, terms.seedHash)) continue
      try {
        verifyBlock(payloads[index]!, Digest.fromBytes(hash))
        await verifyBlockInSeed([effectiveSeed!], seedDigest, terms.fileSizeBytes, payloads[index]!)
      } catch (error) { throw mapMasterSeedError(error, op) }
    }
  }
  return effectiveSeed
}

/**
 * 把一个有序内容哈希批次映射为 seed 或已知协议期望长度的块：seed 条目直接按
 * SeedHash 判定；其余哈希必须在已验证 seed 的块列表中找到，同一哈希命中的
 * 位置不得给出冲突长度。纯证据函数，不读取发送方元数据。
 */
export async function classifyContentHashes (terms: FileQuoteTerms, contentHashes: readonly Uint8Array[], seed?: Uint8Array): Promise<ClassifiedContent[]> {
  const op = 'content.ClassifyContentHashes'
  validateContentHashes(contentHashes, op)
  return classifyContent(op, terms, contentHashes, seed ?? new Uint8Array())
}

/**
 * 按已验证报价与 seed 推导批次总价：seed 按 SeedPriceSatoshis；完整块按
 * FullBlockPriceSatoshis；末块按比例进位并享受 10% 卖方让利（整块价为 0 时
 * 末块为 0）；重复块位置只计一次；冲突长度整体拒绝；总额溢出 uint64 返回
 * insufficient_balance。
 */
export async function contentHashesPriceSatoshis (terms: FileQuoteTerms, contentHashes: readonly Uint8Array[], seed?: Uint8Array): Promise<bigint> {
  const op = 'content.ContentHashesPriceSatoshis'
  validateContentHashes(contentHashes, op)
  const items = await classifyContent(op, terms, contentHashes, seed ?? new Uint8Array())
  let total = 0n
  for (const item of items) {
    let price: bigint
    if (item.isSeed) price = terms.seedPriceSatoshis
    else price = blockPriceSatoshis(terms.fullBlockPriceSatoshis, item.blockSize)
    if (total > MAX_UINT64 - price) throw new WireError('insufficient_balance', 0, 'aggregate_price_satoshis', '聚合内容价格溢出 uint64')
    total += price
  }
  return total
}

async function classifyContent (op: string, terms: FileQuoteTerms, contentHashes: readonly Uint8Array[], seed: Uint8Array): Promise<ClassifiedContent[]> {
  try { validateFileQuoteTerms(terms) } catch (error) {
    if (error instanceof WireError) throw new WireError(error.code, error.kind, error.field, `报价条款: ${error.message}`)
    throw error
  }
  const result: ClassifiedContent[] = []
  for (let index = 0; index < contentHashes.length; index++) {
    const hash = contentHashes[index]!
    if (hash.byteLength !== CONTENT_DIGEST_SIZE) throw invalid(op, 'content_hash', `内容哈希 #${index + 1} 必须是 32 bytes`)
    if (equalBytes(hash, terms.seedHash)) { result.push({ isSeed: true, blockSize: 0n }); continue }
    if (seed.byteLength === 0) throw invalid(op, 'seed', '块内容需要已验证 seed')
    let matches: Awaited<ReturnType<typeof findBlockHash>>
    try {
      matches = await findBlockHash([seed], Digest.fromBytes(terms.seedHash), terms.fileSizeBytes, Digest.fromBytes(hash))
    } catch (error) { throw mapMasterSeedError(error, op, `内容哈希 #${index + 1}`) }
    if (matches.matchCount === 0n) throw invalid(op, 'content_hash', `内容哈希 #${index + 1} 不在已验证 seed 的块列表中`)
    let firstSize: bigint
    let lastSize: bigint
    try {
      firstSize = expectedBlockSize(terms.fileSizeBytes, matches.firstIndex)
      lastSize = expectedBlockSize(terms.fileSizeBytes, matches.lastIndex)
    } catch (error) { throw mapMasterSeedError(error, op) }
    if (firstSize !== lastSize) throw invalid(op, 'content_hash', `内容哈希 #${index + 1} 命中的位置长度不一致`)
    result.push({ isSeed: false, blockSize: firstSize })
  }
  return result
}

function blockPriceSatoshis (fullBlockPriceSatoshis: bigint, blockSize: bigint): bigint {
  if (blockSize === 0n || blockSize > CONTENT_BLOCK_SIZE) throw invalid('content.blockPriceSatoshis', 'block_size', `块长度 ${blockSize} 无效`)
  if (blockSize === CONTENT_BLOCK_SIZE) return fullBlockPriceSatoshis
  if (fullBlockPriceSatoshis === 0n) return 0n
  const numerator = fullBlockPriceSatoshis * blockSize * 90n
  const denominator = CONTENT_BLOCK_SIZE * 100n
  let price = (numerator + denominator - 1n) / denominator
  if (price === 0n) price = 1n
  if (price > MAX_UINT64) throw new WireError('insufficient_balance', 0, 'aggregate_price_satoshis', '内容价格溢出 uint64')
  return price
}

function newVerifiedQuote (quote: SignedFileQuote, terms: FileQuoteTerms, termsID: Uint8Array): VerifiedQuote {
  const arbiterKeys = validateArbiterPublicKeys(terms.supportedArbiterPublicKeys)
  return Object.freeze({
    terms: cloneTerms(terms),
    termsCBOR: copyBytes(quote.fileQuoteTermsCBOR),
    termsID: copyBytes(termsID),
    sellerPublicKey: copyBytes(quote.sellerPublicKey),
    allowsArbiter: (publicKey: Uint8Array): boolean => arbiterKeys.some(key => equalBytes(key, publicKey))
  })
}

function allowedArbiter (terms: FileQuoteTerms, publicKey: Uint8Array): boolean {
  try { return validateArbiterPublicKeys(terms.supportedArbiterPublicKeys).some(key => equalBytes(key, publicKey)) } catch { return false }
}

function paymentAuthorizationIDForTerms (termsCBOR: Uint8Array): Uint8Array {
  decodeFileQuoteTerms(termsCBOR)
  return sha256(termsCBOR)
}

function validateArbiterPublicKeys (keys: readonly Uint8Array[]): Uint8Array[] {
  const copies = keys.map(copyBytes)
  for (let index = 0; index < copies.length; index++) {
    const key = copies[index]!
    if (key.byteLength !== 33 || !secp256k1.utils.isValidPublicKey(key, true)) throw invalid('content.ValidateFileQuoteTerms', 'supported_arbiter_public_keys', `仲裁公钥 #${index + 1} 无效`)
    for (let previous = 0; previous < index; previous++) if (equalBytes(copies[previous]!, key)) throw invalid('content.ValidateFileQuoteTerms', 'supported_arbiter_public_keys', `仲裁公钥 #${index + 1} 重复`)
  }
  return copies
}

function encodeArbiterKeys (keys: readonly Uint8Array[]): Uint8Array { return encodeCanonical(keys.map(copyBytes)) }
function encodeTerms (terms: FileQuoteTerms): Uint8Array {
  return encodeCanonical([
    copyBytes(terms.seedHash), copyBytes(terms.buyerPublicKey), terms.seedPriceSatoshis,
    terms.fullBlockPriceSatoshis, terms.fileSizeBytes, terms.quoteExpiresAtUnixSeconds,
    encodeArbiterKeys(terms.supportedArbiterPublicKeys), terms.recommendedFilename
  ])
}
function encodeAuthorization (authorization: PaymentAuthorization): Uint8Array {
  return encodeCanonical([
    copyBytes(authorization.fileQuoteTermsID), copyBytes(authorization.refundTemplateTxID), BigInt(authorization.paymentSequence),
    authorization.sellerAmountAfterSatoshis, encodeContentHashes(authorization.contentHashes), authorization.deliveryDeadlineUnixSeconds
  ])
}

function validateContentHashes (hashes: readonly Uint8Array[], op = 'content.validateContentHashes'): void {
  if (hashes.length < 1 || hashes.length > MAX_CONTENT_BATCH_ITEMS) throw invalid(op, 'content_hashes_cbor', `内容哈希数量必须在 1..${MAX_CONTENT_BATCH_ITEMS}`)
  for (let index = 0; index < hashes.length; index++) {
    const hash = hashes[index]!
    if (hash.byteLength !== CONTENT_DIGEST_SIZE) throw invalid(op, 'content_hash', `内容哈希 #${index + 1} 必须是 32 bytes`)
    for (let previous = 0; previous < index; previous++) if (equalBytes(hashes[previous]!, hash)) throw invalid(op, 'content_hash', `内容哈希 #${index + 1} 与 #${previous + 1} 重复`)
  }
}

function validateContentPayloads (payloads: readonly Uint8Array[], op = 'content.validateContentPayloads'): void {
  if (payloads.length < 1 || payloads.length > MAX_CONTENT_BATCH_ITEMS) throw invalid(op, 'content_payloads_cbor', `payload 数量必须在 1..${MAX_CONTENT_BATCH_ITEMS}`)
  for (let index = 0; index < payloads.length; index++) {
    const payload = payloads[index]!
    if (payload.byteLength === 0) throw invalid(op, 'content_payload', `payload #${index + 1} 不能为空`)
    if (payload.byteLength > MAX_CONTENT_PAYLOAD_BYTES) throw invalid(op, 'content_payload', `payload #${index + 1} 超过 262144 bytes`)
  }
}

function decodeStrictArray (raw: Uint8Array, length: number, op: string, field: string): CBORValue[] {
  let value: CBORValue
  try { value = decodeCanonical(raw, field) } catch (error) { throw wrapMalformed(op, field, error) }
  if (!Array.isArray(value) || value.length !== length) throw malformed(op, field, `CBOR array 长度必须为 ${length}`)
  return value
}
function decodeContentHashesFromField (raw: CBORValue | undefined, op: string, field: string): Uint8Array[] {
  if (!(raw instanceof Uint8Array)) throw malformed(op, field, '字段必须是 CBOR bstr')
  return decodeContentHashes(raw)
}
function bytesField (value: CBORValue | undefined, op: string, field: string): Uint8Array {
  if (!(value instanceof Uint8Array)) throw malformed(op, field, '字段必须是 CBOR bstr')
  return copyBytes(value)
}
function sizedBytes (value: Uint8Array, length: number, op: string, field: string): Uint8Array {
  if (value.byteLength !== length) throw malformed(op, field, `字段必须是 ${length} bytes`)
  return value
}
function uintField (value: CBORValue | undefined, op: string, field: string): bigint {
  if (typeof value !== 'bigint' || value < 0n || value > MAX_UINT64) throw malformed(op, field, '字段必须是 CBOR uint64')
  return value
}
function numberField (value: CBORValue | undefined, op: string, field: string): number {
  const result = uintField(value, op, field)
  if (result > BigInt(Number.MAX_SAFE_INTEGER)) throw malformed(op, field, '整数超过安全范围')
  return Number(result)
}
function textField (value: CBORValue | undefined, op: string, field: string): string {
  if (typeof value !== 'string') throw malformed(op, field, '字段必须是 CBOR tstr')
  return value
}
function validateUint64 (value: bigint, op: string, field: string): void {
  if (value < 0n || value > MAX_UINT64) throw invalid(op, field, '字段必须是 uint64')
}
function requireNow (nowUnixSeconds: bigint): bigint {
  if (typeof nowUnixSeconds !== 'bigint') throw invalid('protocol.Facts.RequireNow', 'facts.now', '本操作需要显式 facts.now')
  return nowUnixSeconds
}
function emptySeedHash (): Uint8Array { return sha256(new Uint8Array()) }
function mapMasterSeedError (error: unknown, op: string, context?: string): WireError {
  const prefix = context == null ? op : context
  if (isMasterSeedError(error)) {
    if (error.code === ERROR_CODES.ABORTED) return new WireError('canceled', 0, '', `${op}: seed 扫描被取消`)
    const field = error.code === ERROR_CODES.BLOCK_NOT_IN_SEED ? 'payload' : ''
    return new WireError('invalid_evidence', 0, field, `${prefix}: ${error.message}`)
  }
  if (error instanceof WireError) return error
  return new WireError('invalid_evidence', 0, '', `${prefix}: seed 扫描失败`)
}
function wrapMalformed (op: string, field: string, error: unknown): WireError {
  if (error instanceof WireError) return new WireError(error.code, 0, field, `${op}: ${error.message}`)
  return new WireError('malformed_wire', 0, field, `${op}: CBOR 解码失败`)
}
function invalid (op: string, field: string, message: string): WireError { return new WireError('invalid_evidence', 0, field, `${op}: ${message}`) }
function malformed (op: string, field: string, message: string): WireError { return new WireError('malformed_wire', 0, field, `${op}: ${message}`) }
function allZero (value: Uint8Array): boolean { return value.every(byte => byte === 0) }
function equalBytes (left: Uint8Array, right: Uint8Array): boolean { return left.byteLength === right.byteLength && left.every((value, index) => value === right[index]) }
function copyBytes (value: Uint8Array): Uint8Array { return new Uint8Array(value) }
function cloneTerms (terms: FileQuoteTerms): FileQuoteTerms {
  return { ...terms, seedHash: copyBytes(terms.seedHash), buyerPublicKey: copyBytes(terms.buyerPublicKey), supportedArbiterPublicKeys: terms.supportedArbiterPublicKeys.map(copyBytes) }
}
