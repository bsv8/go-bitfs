import { sha256 } from '@noble/hashes/sha2.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { decodeCanonical, type CBORValue } from './cbor.js'
import { MAX_CONTENT_BATCH_ITEMS, MAX_CONTENT_PAYLOAD_BYTES, MAX_WIRE_FRAME_BYTES, WIRE_VERSION } from './constants.js'
import { WireError } from './errors.js'
import { verifyWireDocument } from './protocol.js'
import { validateArbitrationClaimStructure } from './transaction.js'

export type WireKind = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11
const artifactToken: unique symbol = Symbol('validated BitFS artifact')

/** 严格解析后的不可变完整报文；只证明结构规范，不代表业务证据已验收。 */
export class Artifact {
  readonly #raw: Uint8Array
  /** @internal 只能由 parse/typed encoder 在严格验证成功后调用。 */
  constructor (readonly kind: WireKind, raw: Uint8Array, token: typeof artifactToken) {
    if (token !== artifactToken) throw new TypeError('Artifact 只能由严格 parser 构造')
    this.#raw = new Uint8Array(raw)
  }
  /** 返回 exact CBOR 的副本，调用方无法修改 Artifact 内部状态。 */
  bytes (): Uint8Array { return new Uint8Array(this.#raw) }
}

/** 从完整 exact bytes 严格解析并按自描述 Kind 分派。 */
export function parse (rawInput: Uint8Array): Artifact {
  const raw = new Uint8Array(rawInput)
  if (raw.byteLength === 0 || raw.byteLength > MAX_WIRE_FRAME_BYTES) malformed(0, 'wire', '报文为空或超过协议上限')
  const outer = array(decodeCanonical(raw), 0, 'wire')
  if (outer.length < 3) malformed(0, 'wire', '完整报文至少包含 version、kind 和 payload')
  const version = uint(outer[0], 0, 'wire_version')
  const kindNumber = Number(uint(outer[1], 0, 'wire_kind'))
  if (version !== BigInt(WIRE_VERSION)) throw new WireError('unsupported_version', kindNumber, 'wire_version', `不支持 wire version ${version}`)
  if (!Number.isInteger(kindNumber) || kindNumber < 1 || kindNumber > 11) throw new WireError('unsupported_kind', kindNumber, 'wire_kind', `不支持 wire kind ${kindNumber}`)
  const kind = kindNumber as WireKind
  validateOuter(kind, outer)
  return new Artifact(kind, raw, artifactToken)
}

/** 除严格解析外，再交叉检查 transport 路由声明的 Kind。 */
export function parseAs (expectedKind: WireKind, raw: Uint8Array): Artifact {
  const artifact = parse(raw)
  if (artifact.kind !== expectedKind) throw new WireError('unsupported_kind', artifact.kind, 'wire_kind', `路由 Kind ${expectedKind} 与报文 Kind ${artifact.kind} 不一致`)
  return artifact
}

function validateOuter (kind: WireKind, value: CBORValue[]): void {
  switch (kind) {
    case 1: exact(value, 5, kind); validateQuote(bytes(value[2], kind, 'file_quote_terms_cbor')); pubkey(value[3], kind, 'seller_public_key'); signature(value[4], kind, 'seller_signature'); break
    case 2: exact(value, 8, kind); nonempty(value[2], kind, 'refund_template_raw'); pubkey(value[3], kind, 'buyer_public_key'); pubkey(value[4], kind, 'seller_public_key'); pubkey(value[5], kind, 'arbiter_public_key'); uint(value[6], kind, 'miner_fee_rate'); signature(value[7], kind, 'buyer_refund_signature'); break
    case 3: exact(value, 4, kind); nonzeroHash(value[2], kind, 'refund_template_txid'); signature(value[3], kind, 'seller_refund_signature'); break
    case 4: exact(value, 4, kind); nonzeroHash(value[2], kind, 'refund_template_txid'); nonempty(value[3], kind, 'funding_transaction_raw'); break
    case 5: exact(value, 4, kind); validateAuthorization(bytes(value[2], kind, 'payment_authorization_cbor')); signature(value[3], kind, 'buyer_authorization_signature'); break
    case 6: exact(value, 5, kind); validateDelivery(bytes(value[2], kind, 'content_delivery_cbor')); signature(value[3], kind, 'seller_delivery_signature'); validatePayloads(bytes(value[4], kind, 'content_payloads_cbor'), kind); break
    case 7: exact(value, 4, kind); nonzeroHash(value[2], kind, 'payment_authorization_id'); signature(value[3], kind, 'buyer_payment_signature'); break
    case 8: exact(value, 5, kind); validateClaim(bytes(value[2], kind, 'arbitration_claim_cbor')); signature(value[3], kind, 'seller_claim_signature'); validatePayloads(bytes(value[4], kind, 'content_payloads_cbor'), kind); break
    case 9: exact(value, 4, kind); validateReceipt(bytes(value[2], kind, 'arbitration_receipt_cbor')); signature(value[3], kind, 'arbiter_receipt_signature'); break
    case 10: exact(value, 4, kind); validateRetrievalRequest(bytes(value[2], kind, 'content_retrieval_request_cbor')); signature(value[3], kind, 'buyer_retrieval_signature'); break
    case 11: validateRetrievalResponse(value); break
  }
}

function validateQuote (raw: Uint8Array): void {
  const value = child(raw, 1, 'file_quote_terms_cbor', 8)
  hash(value[0], 1, 'seed_hash'); pubkey(value[1], 1, 'buyer_public_key')
  uint(value[2], 1, 'seed_price_satoshis'); uint(value[3], 1, 'full_block_price_satoshis'); const fileSize = uint(value[4], 1, 'file_size_bytes'); const expiry = integer(value[5], 1, 'quote_expires_at')
  if (fileSize > 8192n * 262144n) malformed(1, 'file_size_bytes', '文件大小超过单个 seed 可描述的上限')
  if (fileSize === 0n && !equal(value[0] as Uint8Array, sha256(new Uint8Array()))) malformed(1, 'seed_hash', '空文件的 seed_hash 必须是空 seed 的 SHA-256')
  if (expiry <= 0n) malformed(1, 'quote_expires_at', '报价失效时间必须为正 Unix 秒')
  const arbiters = array(decodeCanonical(bytes(value[6], 1, 'supported_arbiters_cbor'), 'supported_arbiters_cbor'), 1, 'supported_arbiters_cbor')
  const seen = new Set<string>()
  for (const item of arbiters) { const key = pubkey(item, 1, 'supported_arbiter_public_key'); const encoded = toHex(key); if (seen.has(encoded)) malformed(1, 'supported_arbiter_public_key', '仲裁公钥不能重复'); seen.add(encoded) }
  if (typeof value[7] !== 'string' || sanitizeRecommendedFilename(value[7]) !== value[7]) malformed(1, 'recommended_filename', '推荐文件名尚未按协议 sanitize')
}

function validateAuthorization (raw: Uint8Array): { paymentSequence: bigint, sellerAmountAfterSatoshis: bigint } {
  const value = child(raw, 5, 'payment_authorization_cbor', 6)
  const quoteID = hash(value[0], 5, 'file_quote_terms_id'); const templateID = hash(value[1], 5, 'refund_template_txid')
  if (allZero(quoteID) || allZero(templateID)) malformed(5, 'identifier', '协议 ID 禁止全零哨兵')
  const sequence = uint(value[2], 5, 'payment_sequence'); if (sequence < 1n || sequence > 4294967294n) invalid(5, 'payment_sequence', '付款序号必须为 1..4294967294')
  const sellerAmount = uint(value[3], 5, 'seller_amount_after_satoshis'); validateHashes(bytes(value[4], 5, 'content_hashes_cbor')); if (integer(value[5], 5, 'delivery_deadline') <= 0n) invalid(5, 'delivery_deadline', '交付截止时间必须为正 Unix 秒')
  return { paymentSequence: sequence, sellerAmountAfterSatoshis: sellerAmount }
}

function validateDelivery (raw: Uint8Array): void { const value = child(raw, 6, 'content_delivery_cbor', 1); nonzeroHash(value[0], 6, 'payment_authorization_id') }
function validateClaim (raw: Uint8Array): void {
  const value = child(raw, 8, 'arbitration_claim_cbor', 5)
  const poolOutputSatoshis = uint(value[0], 8, 'pool_output_satoshis'); if (poolOutputSatoshis === 0n) invalid(8, 'pool_output_satoshis', '池输出金额必须为正数')
  const lockingScript = sized(value[1], 105, 8, 'pool_output_locking_script')
  const refundTemplateRaw = nonempty(value[2], 8, 'refund_template_raw')
  const authorizationRaw = bytes(value[3], 8, 'payment_authorization_cbor')
  const authorization = validateAuthorization(authorizationRaw)
  const buyerSignature = signature(value[4], 8, 'buyer_authorization_signature')
  const keys = validateArbitrationClaimStructure({ poolOutputSatoshis, poolOutputLockingScript: lockingScript, refundTemplateRaw, paymentSequence: authorization.paymentSequence, sellerAmountAfterSatoshis: authorization.sellerAmountAfterSatoshis })
  try { verifyWireDocument(keys.buyerPublicKey, 5, authorizationRaw, buyerSignature) } catch (error) {
    if (error instanceof WireError) throw new WireError(error.code, 8, 'buyer_authorization_signature', error.message)
    throw error
  }
}
function validateReceipt (raw: Uint8Array): void { const value = child(raw, 9, 'arbitration_receipt_cbor', 3); hash(value[0], 9, 'arbitration_claim_id'); if (uint(value[1], 9, 'arbiter_amount_satoshis') === 0n) invalid(9, 'arbiter_amount_satoshis', '仲裁费必须为正数'); signature(value[2], 9, 'arbiter_payment_signature') }
function validateRetrievalRequest (raw: Uint8Array): void { const value = child(raw, 10, 'content_retrieval_request_cbor', 2); nonzeroHash(value[0], 10, 'arbitration_claim_id'); const nonce = sized(value[1], 32, 10, 'retrieval_nonce'); if (nonce.every(byte => byte === 0)) invalid(10, 'retrieval_nonce', 'nonce 禁止全零') }

function validateRetrievalResponse (value: CBORValue[]): void {
  if (value.length !== 4 && value.length !== 5) malformed(11, 'wire', 'Kind 11 只能是 unavailable 四元或 available 五元')
  const rawResult = bytes(value[2], 11, 'content_retrieval_result_cbor')
  const result = array(decodeCanonical(rawResult, 'content_retrieval_result_cbor'), 11, 'content_retrieval_result_cbor')
  exact(result, 3, 11); nonzeroHash(result[0], 11, 'content_retrieval_request_id'); signature(value[3], 11, 'arbiter_result_signature')
  const branch = uint(result[1], 11, 'result')
  if (branch === 0n) {
    if (value.length !== 4) malformed(11, 'wire', 'unavailable 分支禁止 attachment')
    const reason = uint(result[2], 11, 'reason'); if (reason > 2n) malformed(11, 'reason', '未知 unavailable 原因')
  } else if (branch === 1n) {
    if (value.length !== 5) malformed(11, 'wire', 'available 分支缺少 attachment')
    const expected = hash(result[2], 11, 'content_payloads_id')
    const payloads = bytes(value[4], 11, 'content_payloads_cbor'); validatePayloads(payloads, 11)
    if (!equal(expected, sha256(payloads))) malformed(11, 'content_payloads_id', 'attachment SHA-256 不匹配')
  } else malformed(11, 'result', '未知 retrieval result 分支')
}

function validateHashes (raw: Uint8Array): void { const values = array(decodeCanonical(raw, 'content_hashes_cbor'), 5, 'content_hashes_cbor'); if (values.length < 1 || values.length > MAX_CONTENT_BATCH_ITEMS) malformed(5, 'content_hashes_cbor', '内容哈希数量必须为 1..64'); const seen = new Set<string>(); for (const value of values) { const encoded = toHex(hash(value, 5, 'content_hash')); if (seen.has(encoded)) malformed(5, 'content_hash', '内容哈希不能重复'); seen.add(encoded) } }
function validatePayloads (raw: Uint8Array, kind: number): void { const values = array(decodeCanonical(raw, 'content_payloads_cbor'), kind, 'content_payloads_cbor'); if (values.length < 1 || values.length > MAX_CONTENT_BATCH_ITEMS) malformed(kind, 'content_payloads_cbor', 'payload 数量必须为 1..64'); for (const value of values) { const payload = nonempty(value, kind, 'content_payload'); if (payload.length > MAX_CONTENT_PAYLOAD_BYTES) malformed(kind, 'content_payload', '单块超过 262144 bytes') } }
function child (raw: Uint8Array, kind: number, field: string, length: number): CBORValue[] { const value = array(decodeCanonical(raw, field), kind, field); exact(value, length, kind); return value }
function array (value: CBORValue, kind: number, field: string): CBORValue[] { if (!Array.isArray(value)) malformed(kind, field, '字段必须是 CBOR array'); return value }
function uint (value: CBORValue | undefined, kind: number, field: string): bigint { if (typeof value !== 'bigint' || value < 0n) malformed(kind, field, '字段必须是 CBOR uint'); return value }
function integer (value: CBORValue | undefined, kind: number, field: string): bigint { if (typeof value !== 'bigint' || value < -0x8000000000000000n || value > 0x7fffffffffffffffn) malformed(kind, field, '字段必须是 int64 范围内的 CBOR int'); return value }
function bytes (value: CBORValue | undefined, kind: number, field: string): Uint8Array { if (!(value instanceof Uint8Array)) malformed(kind, field, '字段必须是 CBOR bstr'); return value }
function nonempty (value: CBORValue | undefined, kind: number, field: string): Uint8Array { const result = bytes(value, kind, field); if (result.length === 0) malformed(kind, field, '字段不能为空'); return result }
function sized (value: CBORValue | undefined, length: number, kind: number, field: string): Uint8Array { const result = bytes(value, kind, field); if (result.length !== length) malformed(kind, field, `字段必须是 ${length} bytes`); return result }
function hash (value: CBORValue | undefined, kind: number, field: string): Uint8Array { return sized(value, 32, kind, field) }
function nonzeroHash (value: CBORValue | undefined, kind: number, field: string): Uint8Array { const result = hash(value, kind, field); if (allZero(result)) invalid(kind, field, '协议 ID 禁止全零哨兵'); return result }
function pubkey (value: CBORValue | undefined, kind: number, field: string): Uint8Array { const result = sized(value, 33, kind, field); if (!secp256k1.utils.isValidPublicKey(result, true)) invalid(kind, field, '压缩 secp256k1 公钥无效'); return result }
function signature (value: CBORValue | undefined, kind: number, field: string): Uint8Array { const result = nonempty(value, kind, field); if (result.length > 256) malformed(kind, field, '签名超过 256 bytes'); return result }
function exact (value: CBORValue[], length: number, kind: number): void { if (value.length !== length) malformed(kind, 'wire', `数组长度必须是 ${length}`) }
function equal (left: Uint8Array, right: Uint8Array): boolean { return left.length === right.length && left.every((value, index) => value === right[index]) }
function allZero (value: Uint8Array): boolean { return value.every(byte => byte === 0) }
function toHex (value: Uint8Array): string { return Array.from(value, byte => byte.toString(16).padStart(2, '0')).join('') }
function sanitizeRecommendedFilename (name: string): string {
  let normalized = name.replaceAll('\\', '/')
  if (/^\/+$/u.test(normalized)) normalized = '/'
  else normalized = normalized.replace(/\/+$/u, '')
  const parts = normalized.split('/')
  let result = (parts.at(-1) ?? '').replace(/\p{Cc}/gu, '_').trim()
  if (result === '' || result === '.' || result === '..') result = 'download'
  return result
}
function malformed (kind: number, field: string, message: string): never { throw new WireError('malformed_wire', kind, field, message) }
function invalid (kind: number, field: string, message: string): never { throw new WireError('invalid_evidence', kind, field, message) }
