import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { PrivateKey, Transaction, UnlockingScript } from '@bsv/sdk'
import {
  buildArbitratedPoolLock, generateKGoStyle,
  mergeArbitratedPoolBuyerSellerSignatures, mergeArbitratedPoolSellerArbiterSignatures,
  Protocol as PoolProtocol, Version as PoolVersion,
  buildArbitratedPoolOpeningState, buildArbitratedPoolState,
  signArbitratedPoolAsArbiter, signArbitratedPoolAsBuyer, signArbitratedPoolAsSeller
} from 'keymaster-multisig-pool'
import { encodeUvarintFrame } from 'bitcoin-libp2p/stream'
import { describe, expect, it } from 'vitest'
import { decodeCanonical, encodeCanonical, type CBORValue } from '../src/cbor.js'
import {
  acceptBuyerQuote, buildArbiterAvailableRetrieval, buildArbiterUnavailableRetrieval, buildArbitrationCandidate,
  buildBuyerMaturedRefund, checkContentRequestTiming, classifyContentHashes, completeArbiterArbitratedPayment,
  completeBuyerOpening, completeSellerArbitratedPayment, completeSellerClose, completeSellerPayment,
  contentHashesPriceSatoshis, createArbitrationRequest, createArbitrationResponse, createContentDelivery,
  createContentRequest, createContentRetrievalAvailable, createContentRetrievalRequest,
  createContentRetrievalUnavailable, createFileQuote, createSellerQuote, decodeContentPayloads,
  decodeFileQuoteTerms, decodePaymentAuthorization, encodeFundingTransactionDelivery, encodePaymentUpdate,
  encodeRefundPresignRequest, encodeRefundPresignResponse, forkIDAllDigest, forkIDAllPreimage,
  generateRetrievalNonce, inspectSellerDeliveryRequest, MultisigPoolEngine, newRetrievalNonce, parse, parseArbitratedPoolLockingScript,
  parseAs, paymentAuthorizationID, prepareArbiterArbitration, prepareBuyerClose,
  prepareBuyerContentRequest, prepareBuyerFundingDelivery, prepareBuyerOpening, prepareSellerArbitration,
  prepareSellerDelivery, prepareSellerPresign, readArtifacts, requestBuyerArbitratedContent,
  authenticateArbiterRetrieval, signArbiterPreparedArbitration, signWireDocument, transactionID,
  verifyArbiterCustody, verifyArbitrationCandidate, verifyBuyerArbitratedContent, verifyBuyerCompletedClose,
  verifyBuyerDelivery, verifyContentPayloads, verifyContentRequestEvidence, verifySellerFunding,
  verifyWireDocument, wireSignatureDigest, writeArtifact,
  type FileQuoteTerms, type OpeningProof, type PureFunctionFacts, type Signer, type SigningRequest, type WireKind
} from '../src/index.js'

type FixtureIndex = {
  format: string
  wire_manifest: string
  transaction_manifest: string
  protocol_schema: string
  transport_profile: string
  invalid_wire: string
  role_manifest: string
}
type WireManifest = {
  protocol: string
  wire_version: number
  entries: Array<{ kind: WireKind, name: string, exact_hex: string, sha256: string, child_doc_hex?: string, child_id?: string }>
}
type TransactionManifest = {
  protocol: string
  wire_version: number
  entries: Array<{ name: string, raw_hex?: string, txid?: string, preimage?: string, sighash_digest?: string, signature_der_hex?: string }>
}
type RoleFixture = {
  protocol: string
  wire_version: number
  fixed_keys: string
  facts_now_unix_seconds: number
  facts_block_height: number
  delivery_deadline_unix_seconds: number
  expiry_lock_time: number
  pool_output_satoshis: number
  quote: {
    kind1_hex: string
    terms_cbor_hex: string
    terms_id: string
    recommended_filename: string
    seed_hash_hex: string
    seed_hex: string
    file_size_bytes: number
  }
  seller_opening_kind2: { hex: string }
  seller_presign_kind3: { hex: string }
  funding_delivery_kind4: { hex: string }
  buyer_request_kind5: { kind5_hex: string, authorization_id: string }
  seller_delivery_kind6: { hex: string }
  buyer_payment_kind7: { hex: string }
  payment_merged_raw: { hex: string }
  close_unsigned_raw: { hex: string }
  close_signed_raw: { hex: string }
  refund_matured_raw: { hex: string }
  arbitration: {
    kind8_hex: string
    kind9_hex: string
    claim_id: string
    retrieval_kind10_hex: string
    retrieval_request_id: string
    available_kind11_hex: string
    unavailable_kind11_hex: string
    unavailable_reason_code: number
  }
  price_vectors: Array<{
    name: string
    seed_price_satoshis: number | string
    full_block_price_satoshis: number | string
    file_size_bytes: number | string
    seed_hex: string
    hashes_hex: string[]
    expect_classification?: Array<{ is_seed: boolean, block_size: number }>
    expect_price_satoshis?: string
    expect_error_code?: string
  }>
  malicious: {
    kind5_decrease_hex: string
    kind6_decrease_hex: string
    kind7_decrease_hex: string
    kind5_capacity_hex: string
    kind6_capacity_hex: string
    kind7_capacity_hex: string
    kind5_price_mismatch_hex: string
    kind6_price_mismatch_hex: string
  }
  evidence_reject_vectors: Array<{ name: string, artifact: string, mutation: string, error_code: string, description_zh: string }>
}

const root = resolve(import.meta.dirname, '../..')
const json = <T>(path: string): T => JSON.parse(readFileSync(resolve(root, path), 'utf8')) as T
const fixtures = json<FixtureIndex>('fixtures/manifest.json')
const manifest = json<WireManifest>(fixtures.wire_manifest)
const transactionManifest = json<TransactionManifest>(fixtures.transaction_manifest)
const transportProfile = json<{ protocol_id: string, framing: string, max_wire_frame_bytes: number }>(fixtures.transport_profile)
const invalidWire = json<{ cases: Array<{ name: string, hex: string, error_code: string }> }>(fixtures.invalid_wire)
// role fixture 的计价向量包含 18446744073709551615 这类超出 IEEE754 安全整数
// 的 uint64；先把 16 位以上整数字面量转为字符串，保证 BigInt 解析精确。
const roleText = readFileSync(resolve(root, fixtures.role_manifest), 'utf8').replace(/:\s*(\d{16,})/g, ': "$1"')
const roleFixture = JSON.parse(roleText) as RoleFixture
const hex = (value: string): Uint8Array => Uint8Array.from(Buffer.from(value, 'hex'))
const toHex = (value: Uint8Array): string => Buffer.from(value).toString('hex')
const digest = (value: Uint8Array): string => createHash('sha256').update(value).digest('hex')
const copy = (value: Uint8Array): Uint8Array => new Uint8Array(value)
const flipLastByte = (value: Uint8Array): Uint8Array => { const result = copy(value); result[result.length - 1]! ^= 0x01; return result }
const flipFirstByte = (value: Uint8Array): Uint8Array => { const result = copy(value); result[0]! ^= 0x01; return result }
const outer = (raw: Uint8Array): CBORValue[] => { const value = decodeCanonical(raw); if (!Array.isArray(value)) throw new Error('fixture 外层不是 CBOR array'); return value }

class TestSigner implements Signer {
  readonly #privateKey: Uint8Array
  constructor (byte: number) { this.#privateKey = Uint8Array.from({ length: 32 }, () => byte) }
  publicKey (): Uint8Array { return secp256k1.getPublicKey(this.#privateKey, true) }
  async sign (request: Readonly<SigningRequest>): Promise<Uint8Array> {
    return secp256k1.sign(request.digest, this.#privateKey, { prehash: false, lowS: true, format: 'der' })
  }
}

// Go fixture 生成器把 64 字节的重复值交给 go-sdk PrivateKeyFromHex：公钥与 s
// 使用该大整数对 N 取模后的标量，RFC6979 nonce 则按 int2octets(D, 32) 取低
// 32 字节。这里逐位复现，保证与 Go 的 Kind 1–11 签名逐字节一致。
const CURVE_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n

function fixtureScalar (nibble: string): bigint { return BigInt('0x' + nibble.repeat(64)) % CURVE_ORDER }

function modInverse (value: bigint, modulus: bigint): bigint {
  let [oldR, r] = [value, modulus]
  let [oldS, s] = [1n, 0n]
  while (r !== 0n) {
    const quotient = oldR / r
    ;[oldR, r] = [r, oldR - quotient * r]
    ;[oldS, s] = [s, oldS - quotient * s]
  }
  return ((oldS % modulus) + modulus) % modulus
}

function derEncode (r: bigint, s: bigint): Uint8Array {
  const encodeInt = (value: bigint): Uint8Array => {
    let encoded = Buffer.from(value.toString(16).padStart(64, '0'), 'hex')
    while (encoded.length > 1 && encoded[0] === 0) encoded = encoded.subarray(1)
    if ((encoded[0]! & 0x80) !== 0) encoded = Buffer.concat([Buffer.from([0]), encoded])
    return Buffer.concat([Buffer.from([2, encoded.length]), encoded])
  }
  const body = Buffer.concat([encodeInt(r), encodeInt(s)])
  return Uint8Array.from(Buffer.concat([Buffer.from([0x30, body.length]), body]))
}

function goCompatibleSign (scalar: bigint, nonceKey: Uint8Array, messageDigest: Uint8Array): Uint8Array {
  const k = generateKGoStyle(Buffer.from(nonceKey), Buffer.from(messageDigest))
  const point = secp256k1.Point.BASE.multiply(k)
  const r = point.x % CURVE_ORDER
  const z = BigInt('0x' + toHex(messageDigest))
  const kInv = modInverse(k, CURVE_ORDER)
  let s = kInv * ((z + r * scalar) % CURVE_ORDER) % CURVE_ORDER
  if (s > CURVE_ORDER / 2n) s = CURVE_ORDER - s
  return derEncode(r, s)
}

class FixtureSigner implements Signer {
  readonly #scalar: bigint
  readonly #nonceKey: Uint8Array
  calls = 0
  constructor (nibble: string) {
    this.#scalar = fixtureScalar(nibble)
    this.#nonceKey = hex(nibble.repeat(32))
  }
  publicKey (): Uint8Array { return secp256k1.getPublicKey(hex(this.#scalar.toString(16).padStart(64, '0')), true) }
  async sign (request: Readonly<SigningRequest>): Promise<Uint8Array> {
    this.calls++
    return goCompatibleSign(this.#scalar, this.#nonceKey, request.digest)
  }
}

class FakeStream extends EventTarget {
  status = 'open'
  readBufferLength = 0
  readableEnded = false
  remoteWriteStatus = 'writable'
  sent: Uint8Array[] = []
  send (value: Uint8Array): boolean { this.sent.push(new Uint8Array(value)); return true }
  abort (): void { this.status = 'aborted' }
  message (value: Uint8Array): void {
    const event = new Event('message')
    Object.defineProperty(event, 'data', { value })
    this.dispatchEvent(event)
  }
  remoteClose (): void { this.remoteWriteStatus = 'closed'; this.readableEnded = true; this.dispatchEvent(new Event('remoteCloseWrite')) }
}

const buyer = new FixtureSigner('44')
const seller = new FixtureSigner('22')
const arbiter = new FixtureSigner('33')
const roleFacts: PureFunctionFacts = { nowUnixSeconds: BigInt(roleFixture.facts_now_unix_seconds), blockHeight: roleFixture.facts_block_height }
const seed = hex(roleFixture.quote.seed_hex)
const seedHash = hex(roleFixture.quote.seed_hash_hex)
const kind1 = hex(roleFixture.quote.kind1_hex)
const kind2 = hex(roleFixture.seller_opening_kind2.hex)
const kind3 = hex(roleFixture.seller_presign_kind3.hex)
const kind4 = hex(roleFixture.funding_delivery_kind4.hex)
const kind5 = hex(roleFixture.buyer_request_kind5.kind5_hex)
const kind6 = hex(roleFixture.seller_delivery_kind6.hex)
const kind7 = hex(roleFixture.buyer_payment_kind7.hex)
const kind8 = hex(roleFixture.arbitration.kind8_hex)
const kind9 = hex(roleFixture.arbitration.kind9_hex)
const kind10 = hex(roleFixture.arbitration.retrieval_kind10_hex)
const kind11Available = hex(roleFixture.arbitration.available_kind11_hex)
const kind11Unavailable = hex(roleFixture.arbitration.unavailable_kind11_hex)
const paymentMerged = hex(roleFixture.payment_merged_raw.hex)
const bsvRoles = {
  buyer: PrivateKey.fromHex(fixtureScalar('44').toString(16).padStart(64, '0')).toPublicKey(),
  seller: PrivateKey.fromHex(fixtureScalar('22').toString(16).padStart(64, '0')).toPublicKey(),
  arbiter: PrivateKey.fromHex(fixtureScalar('33').toString(16).padStart(64, '0')).toPublicKey()
}

function fixtureOpening (): OpeningProof {
  return {
    refundTemplateRaw: copy(outer(kind2)[2] as Uint8Array),
    buyerPublicKey: copy(outer(kind2)[3] as Uint8Array),
    sellerPublicKey: copy(outer(kind2)[4] as Uint8Array),
    arbiterPublicKey: copy(outer(kind2)[5] as Uint8Array),
    minerFeeRateSatoshisPerKilobyte: outer(kind2)[6] as bigint,
    buyerRefundSignature: copy(outer(kind2)[7] as Uint8Array),
    sellerRefundSignature: copy(outer(kind3)[3] as Uint8Array),
    fundingTransactionRaw: copy(outer(kind4)[3] as Uint8Array)
  }
}

const sellerPoolEvidence = (): { opening: OpeningProof, fundingTransactionRaw: Uint8Array } => ({ opening: fixtureOpening(), fundingTransactionRaw: copy(outer(kind4)[3] as Uint8Array) })
const sellerDeliveryEvidence = (): { rawKind1: Uint8Array, rawKind5: Uint8Array, rawKind6: Uint8Array } => ({ rawKind1: copy(kind1), rawKind5: copy(kind5), rawKind6: copy(kind6) })
const sellerPaidEvidence = (): { opening: OpeningProof, fundingTransactionRaw: Uint8Array, latestPaymentRawTx: Uint8Array } => ({ opening: fixtureOpening(), fundingTransactionRaw: copy(outer(kind4)[3] as Uint8Array), latestPaymentRawTx: copy(paymentMerged) })
const buyerPaidEvidence = (): { opening: OpeningProof, latestPaymentRawTx: Uint8Array } => ({ opening: fixtureOpening(), latestPaymentRawTx: copy(paymentMerged) })
const signedQuote = (): { fileQuoteTermsCBOR: Uint8Array, sellerPublicKey: Uint8Array, sellerFileQuoteTermsSignature: Uint8Array } => ({ fileQuoteTermsCBOR: copy(outer(kind1)[2] as Uint8Array), sellerPublicKey: copy(outer(kind1)[3] as Uint8Array), sellerFileQuoteTermsSignature: copy(outer(kind1)[4] as Uint8Array) })
const signedRequest = (): { paymentAuthorizationCBOR: Uint8Array, buyerPaymentAuthorizationSignature: Uint8Array } => ({ paymentAuthorizationCBOR: copy(outer(kind5)[2] as Uint8Array), buyerPaymentAuthorizationSignature: copy(outer(kind5)[3] as Uint8Array) })
const quoteTerms = (): FileQuoteTerms => decodeFileQuoteTerms(outer(kind1)[2] as Uint8Array)

function priceVectorTerms (vector: RoleFixture['price_vectors'][number]): FileQuoteTerms {
  const vectorSeed = vector.seed_hex === '' ? new Uint8Array() : hex(vector.seed_hex)
  return {
    seedHash: vector.name === 'seed_only' ? sha256(new Uint8Array()) : sha256(vectorSeed),
    buyerPublicKey: buyer.publicKey(),
    seedPriceSatoshis: BigInt(vector.seed_price_satoshis),
    fullBlockPriceSatoshis: BigInt(vector.full_block_price_satoshis),
    fileSizeBytes: BigInt(vector.file_size_bytes),
    quoteExpiresAtUnixSeconds: 2000000000n,
    supportedArbiterPublicKeys: [arbiter.publicKey()],
    recommendedFilename: 'file.bin'
  }
}

describe('Go 与 TypeScript 共享 wire 真值', () => {
  it('共享清单指向 wire、transaction 与 CDDL 三类唯一真值', () => {
    expect(fixtures.format).toBe('bitfs-cross-language-fixtures')
    expect(readFileSync(resolve(root, fixtures.transaction_manifest), 'utf8')).toContain('refund_template')
    expect(readFileSync(resolve(root, fixtures.protocol_schema), 'utf8')).toContain('bitfs-wire-message')
    expect(readFileSync(resolve(root, fixtures.role_manifest), 'utf8')).toContain('price_vectors')
  })

  it('TypeScript 网络常量读取与 Go 相同的 transport profile', async () => {
    const transport = await import('../src/transport.js')
    expect(transport.BITFS_PROTOCOL_ID).toBe(transportProfile.protocol_id)
    expect(transport.MAX_WIRE_FRAME_BYTES).toBe(transportProfile.max_wire_frame_bytes)
    expect(transportProfile.framing).toBe('unsigned-varint-byte-length-prefix')
  })

  it('bitcoin-libp2p uvarint stream 原样收发严格 Artifact', async () => {
    const frozen = manifest.entries.find(entry => entry.kind === 3)!
    const artifact = parse(hex(frozen.exact_hex))
    const stream = new FakeStream()
    expect(writeArtifact(stream as never, artifact)).toBe(true)
    expect(stream.sent).toEqual([encodeUvarintFrame(artifact.bytes())])
    const iterator = readArtifacts(stream as never)
    const pending = iterator.next()
    stream.message(stream.sent[0]!)
    expect((await pending).value?.bytes()).toEqual(artifact.bytes())
    stream.remoteClose()
    expect((await iterator.next()).done).toBe(true)
  })

  for (const item of invalidWire.cases) {
    it(`与 Go 一致拒绝畸形 wire：${item.name}`, () => {
      expect(() => parse(hex(item.hex))).toThrowError(expect.objectContaining({ code: item.error_code }))
    })
  }

  it('TypeScript 解析同一交易真值并复核所有已冻结 txid', () => {
    for (const item of transactionManifest.entries) {
      if (item.raw_hex == null) continue
      const transaction = Transaction.fromHex(item.raw_hex)
      expect(transaction.toHex()).toBe(item.raw_hex)
      // Go fixture 冻结的是 chainhash.CloneBytes()（内部小端字节）的 hex，
      // @bsv/sdk id('hex') 返回常见的人类展示顺序，因此这里显式翻转后比较。
      if (item.txid != null) expect(Buffer.from(transaction.id()).reverse().toString('hex')).toBe(item.txid)
      if (item.txid != null) expect(Buffer.from(transactionID(hex(item.raw_hex))).toString('hex')).toBe(item.txid)
    }
  })

  it('TypeScript 从同一 unsigned transaction 独立重建 ForkID|All preimage/digest', () => {
    const find = (name: string): TransactionManifest['entries'][number] => transactionManifest.entries.find(entry => entry.name === name)!
    const buyerKey = secp256k1.getPublicKey(Uint8Array.from({ length: 32 }, () => 0xb1), true)
    const sellerKey = secp256k1.getPublicKey(Uint8Array.from({ length: 32 }, () => 0x52), true)
    const arbiterKey = secp256k1.getPublicKey(Uint8Array.from({ length: 32 }, () => 0xa3), true)
    const lockingScript = Uint8Array.from([0x52, 0x21, ...buyerKey, 0x21, ...sellerKey, 0x21, ...arbiterKey, 0x53, 0xae])
    for (const prefix of ['payment', 'arbitration'] as const) {
      const raw = hex(find(`${prefix}_${prefix === 'payment' ? 'unsigned' : 'candidate'}`).raw_hex!)
      const preimage = forkIDAllPreimage(raw, 0, 20000n, lockingScript)
      expect(Buffer.from(preimage).toString('hex')).toBe(find(`${prefix}_preimage`).preimage)
      expect(Buffer.from(forkIDAllDigest(raw, 0, 20000n, lockingScript)).toString('hex')).toBe(find(`${prefix}_sighash_digest`).sighash_digest)
    }
  })

  it('TypeScript MultisigPool v4 从固定输入重建全部 Go 交易真值', async () => {
    const find = (name: string): TransactionManifest['entries'][number] => transactionManifest.entries.find(entry => entry.name === name)!
    const buyerKey = PrivateKey.fromHex('b1'.repeat(32))
    const sellerKey = PrivateKey.fromHex('52'.repeat(32))
    const arbiterKey = PrivateKey.fromHex('a3'.repeat(32))
    const roles = { buyer: buyerKey.toPublicKey(), seller: sellerKey.toPublicKey(), arbiter: arbiterKey.toPublicKey() }
    const funding = new Transaction()
    funding.addInput({ sourceTXID: '01'.repeat(32), sourceOutputIndex: 0, sequence: 0xffffffff, unlockingScript: new UnlockingScript() })
    funding.addOutput({ satoshis: 20000, lockingScript: buildArbitratedPoolLock(roles) })

    const refundTemplate = await buildArbitratedPoolOpeningState(funding, 20000, roles, 800000, 1)
    expect(refundTemplate.toHex()).toBe(find('refund_template').raw_hex)
    const buyerRefund = signArbitratedPoolAsBuyer(refundTemplate, 20000, roles, buyerKey)
    const sellerRefund = signArbitratedPoolAsSeller(refundTemplate, 20000, roles, sellerKey)
    expect(Buffer.from(buyerRefund).toString('hex')).toBe(find('opening_buyer_signature').signature_der_hex)
    expect(Buffer.from(sellerRefund).toString('hex')).toBe(find('opening_seller_signature').signature_der_hex)
    const refundMerged = mergeArbitratedPoolBuyerSellerSignatures(refundTemplate, 20000, roles, buyerRefund, sellerRefund)
    expect(refundMerged.toHex()).toBe(find('refund_merged').raw_hex)

    const build = (previousState: Transaction, sequence: number, sellerAmount: number, arbiterAmount: number) => buildArbitratedPoolState({
      protocol: PoolProtocol, version: PoolVersion, previousState, sequence, sellerAmount, arbiterAmount,
      poolAmount: 20000, roles, feeRate: 1
    })
    const payment = await build(refundMerged, 3, 100, 0)
    expect(payment.toHex()).toBe(find('payment_unsigned').raw_hex)
    const buyerPayment = signArbitratedPoolAsBuyer(payment, 20000, roles, buyerKey)
    expect(Buffer.from(buyerPayment).toString('hex')).toBe(find('payment_buyer_signature').signature_der_hex)
    const sellerPayment = signArbitratedPoolAsSeller(payment, 20000, roles, sellerKey)
    const paymentMergedTx = mergeArbitratedPoolBuyerSellerSignatures(payment, 20000, roles, buyerPayment, sellerPayment)
    expect(paymentMergedTx.toHex()).toBe(find('payment_merged').raw_hex)

    const close = await buildArbitratedPoolState({
      protocol: PoolProtocol, version: PoolVersion, previousState: paymentMergedTx, sequence: 0xffffffff,
      lockTime: 0xffffffff, sellerAmount: 150, arbiterAmount: 0, poolAmount: 20000, roles, feeRate: 1
    })
    expect(close.toHex()).toBe(find('close_unsigned').raw_hex)
    const closeMerged = mergeArbitratedPoolBuyerSellerSignatures(close, 20000, roles,
      signArbitratedPoolAsBuyer(close, 20000, roles, buyerKey), signArbitratedPoolAsSeller(close, 20000, roles, sellerKey))
    expect(closeMerged.toHex()).toBe(find('close_merged').raw_hex)

    const arbitration = await build(refundMerged, 7, 200, 500)
    expect(arbitration.toHex()).toBe(find('arbitration_candidate').raw_hex)
    const arbitrationSeller = signArbitratedPoolAsSeller(arbitration, 20000, roles, sellerKey)
    expect(Buffer.from(arbitrationSeller).toString('hex')).toBe(find('arbitration_seller_signature').signature_der_hex)
    const arbitrationMerged = mergeArbitratedPoolSellerArbiterSignatures(arbitration, 20000, roles, arbitrationSeller,
      signArbitratedPoolAsArbiter(arbitration, 20000, roles, arbiterKey))
    expect(arbitrationMerged.toHex()).toBe(find('arbitration_merged').raw_hex)
  })

  it('公开 PoolEngine 通过受约束 Signer 重建并合并共享付款真值', async () => {
    const find = (name: string): TransactionManifest['entries'][number] => transactionManifest.entries.find(entry => entry.name === name)!
    const buyerSigner = new TestSigner(0xb1)
    const sellerSigner = new TestSigner(0x52)
    const engine = new MultisigPoolEngine({
      buyerPublicKey: buyerSigner.publicKey(), sellerPublicKey: sellerSigner.publicKey(), arbiterPublicKey: new TestSigner(0xa3).publicKey()
    })
    const unsigned = await engine.buildState({
      previousRaw: hex(find('refund_merged').raw_hex!), poolOutputSatoshis: 20000,
      paymentSequence: 3, sellerAmountSatoshis: 100, minerFeeRateSatoshisPerKilobyte: 1
    })
    expect(Buffer.from(unsigned).toString('hex')).toBe(find('payment_unsigned').raw_hex)
    const buyerSignature = await engine.signState(buyerSigner, unsigned, 20000)
    const sellerSignature = await engine.signState(sellerSigner, unsigned, 20000)
    expect(Buffer.from(buyerSignature).toString('hex')).toBe(find('payment_buyer_signature').signature_der_hex)
    expect(Buffer.from(engine.mergeBuyerSeller(unsigned, 20000, buyerSignature, sellerSignature)).toString('hex')).toBe(find('payment_merged').raw_hex)
  })

  it('仲裁 candidate 由 Claim 唯一重建并逐字节等于 Go 真值', () => {
    const findTransaction = (name: string): TransactionManifest['entries'][number] => transactionManifest.entries.find(entry => entry.name === name)!
    const candidateInput = {
      poolOutputSatoshis: 20000n, refundTemplateRaw: hex(findTransaction('refund_template').raw_hex!),
      paymentSequence: 7n, sellerAmountSatoshis: 200n, arbiterAmountSatoshis: 500n
    }
    const rebuilt = buildArbitrationCandidate(candidateInput)
    expect(Buffer.from(rebuilt).toString('hex')).toBe(findTransaction('arbitration_candidate').raw_hex)
    const changedVersion = new Uint8Array(rebuilt); changedVersion[0] ^= 1
    expect(() => verifyArbitrationCandidate(candidateInput, changedVersion)).toThrowError(expect.objectContaining({ code: 'state_conflict' }))
    const changedLockTime = new Uint8Array(rebuilt); changedLockTime[changedLockTime.length - 1] ^= 1
    expect(() => verifyArbitrationCandidate(candidateInput, changedLockTime)).toThrowError(expect.objectContaining({ code: 'state_conflict' }))
  })

  for (const entry of manifest.entries) {
    it(`严格解析 ${entry.name}（Kind ${entry.kind}）`, () => {
      const raw = hex(entry.exact_hex)
      expect(digest(raw)).toBe(entry.sha256)
      const artifact = parseAs(entry.kind, raw)
      expect(artifact.kind).toBe(entry.kind)
      expect(artifact.bytes()).toEqual(raw)
      raw.fill(0)
      expect(digest(artifact.bytes())).toBe(entry.sha256)
      if (entry.child_doc_hex != null) expect(digest(hex(entry.child_doc_hex))).toBe(entry.child_id)
    })
  }

  it('拒绝路由 Kind 与报文自描述 Kind 不一致', () => {
    const raw = hex(manifest.entries[0]!.exact_hex)
    expect(() => parseAs(1, raw)).toThrowError(expect.objectContaining({ code: 'unsupported_kind' }))
  })

  it('拒绝非最短整数编码、trailing bytes 与未知版本', () => {
    expect(() => parse(hex('8418010241014101'))).toThrowError(expect.objectContaining({ code: 'non_canonical' }))
    const valid = hex(manifest.entries[0]!.exact_hex)
    expect(() => parse(Uint8Array.from([...valid, 0]))).toThrowError(expect.objectContaining({ code: 'malformed_wire' }))
    const wrongVersion = new Uint8Array(valid); wrongVersion[1] = 2
    expect(() => parse(wrongVersion)).toThrowError(expect.objectContaining({ code: 'unsupported_version' }))
  })

  it('错误对象提供稳定 code/kind/field，而不是要求匹配文本', () => {
    try { parse(new Uint8Array()) } catch (error) {
      expect(error).toMatchObject({ code: 'malformed_wire', kind: 0, field: 'wire' })
    }
  })

  it('用同一 frozen bytes 验证 Go 生成的普通消息签名域和 low-S DER', () => {
    const keys = new Map<number, Uint8Array>([
      [5, secp256k1.getPublicKey(Uint8Array.from({ length: 32 }, () => 0x44), true)],
      [6, secp256k1.getPublicKey(Uint8Array.from({ length: 32 }, () => 0x22), true)],
      [8, secp256k1.getPublicKey(Uint8Array.from({ length: 32 }, () => 0x22), true)],
      [9, secp256k1.getPublicKey(Uint8Array.from({ length: 32 }, () => 0x33), true)],
      [10, secp256k1.getPublicKey(Uint8Array.from({ length: 32 }, () => 0x55), true)],
      [11, secp256k1.getPublicKey(Uint8Array.from({ length: 32 }, () => 0x33), true)]
    ])
    for (const entry of manifest.entries) {
      if (![1, 5, 6, 8, 9, 10, 11].includes(entry.kind)) continue
      const outerValues = decodeCanonical(hex(entry.exact_hex))
      if (!Array.isArray(outerValues) || !(outerValues[2] instanceof Uint8Array) || !(outerValues[3] instanceof Uint8Array)) throw new Error('fixture 结构错误')
      const publicKey = entry.kind === 1 ? outerValues[3] : keys.get(entry.kind)!
      const signature = entry.kind === 1 ? outerValues[4] : outerValues[3]
      if (!(signature instanceof Uint8Array)) throw new Error('fixture 签名字段错误')
      expect(wireSignatureDigest(entry.kind, outerValues[2])).toHaveLength(32)
      expect(() => verifyWireDocument(publicKey, entry.kind, outerValues[2], signature)).not.toThrow()
    }
  })

  it('TypeScript typed encoder 重建 Kind 2/3/4/7 frozen bytes', () => {
    const byKind = (kind: WireKind): { exact_hex: string } => manifest.entries.find(entry => entry.kind === kind)!
    const outer2 = decodeCanonical(hex(byKind(2).exact_hex)); if (!Array.isArray(outer2)) throw new Error('fixture')
    expect(encodeRefundPresignRequest({
      refundTemplateRaw: outer2[2] as Uint8Array,
      buyerPublicKey: outer2[3] as Uint8Array,
      sellerPublicKey: outer2[4] as Uint8Array,
      arbiterPublicKey: outer2[5] as Uint8Array,
      minerFeeRateSatoshisPerKilobyte: outer2[6] as bigint,
      buyerRefundTransactionSignature: outer2[7] as Uint8Array
    }).bytes()).toEqual(hex(byKind(2).exact_hex))
    const outer3 = decodeCanonical(hex(byKind(3).exact_hex)); if (!Array.isArray(outer3)) throw new Error('fixture')
    expect(encodeRefundPresignResponse(outer3[2] as Uint8Array, outer3[3] as Uint8Array).bytes()).toEqual(hex(byKind(3).exact_hex))
    const outer4 = decodeCanonical(hex(byKind(4).exact_hex)); if (!Array.isArray(outer4)) throw new Error('fixture')
    expect(encodeFundingTransactionDelivery(outer4[2] as Uint8Array, outer4[3] as Uint8Array).bytes()).toEqual(hex(byKind(4).exact_hex))
    const outer7 = decodeCanonical(hex(byKind(7).exact_hex)); if (!Array.isArray(outer7)) throw new Error('fixture')
    expect(encodePaymentUpdate(outer7[2] as Uint8Array, outer7[3] as Uint8Array).bytes()).toEqual(hex(byKind(7).exact_hex))
  })

  it('TypeScript 用同一固定 signer 重建 Go Kind 1 exact bytes', async () => {
    const terms: FileQuoteTerms = {
      seedHash: Uint8Array.from({ length: 32 }, () => 1),
      buyerPublicKey: new TestSigner(0x44).publicKey(),
      seedPriceSatoshis: 100n,
      fullBlockPriceSatoshis: 1000n,
      fileSizeBytes: 4096n,
      quoteExpiresAtUnixSeconds: 2000000000n,
      supportedArbiterPublicKeys: [new TestSigner(0x33).publicKey()],
      recommendedFilename: 'file.bin'
    }
    const generated = await createFileQuote(new TestSigner(0x22), terms)
    const frozen = manifest.entries.find(entry => entry.kind === 1)!
    expect(generated.bytes()).toEqual(hex(frozen.exact_hex))
  })

  it('TypeScript 用共享子文档重建其余普通签名 Kind exact bytes', async () => {
    const entry = (name: string): WireManifest['entries'][number] => manifest.entries.find(value => value.name === name)!
    const outerOf = (name: string): any[] => {
      const value = decodeCanonical(hex(entry(name).exact_hex))
      if (!Array.isArray(value)) throw new Error('fixture')
      return value
    }
    const child = (raw: Uint8Array): any[] => {
      const value = decodeCanonical(raw)
      if (!Array.isArray(value)) throw new Error('fixture child')
      return value
    }
    const payloads = (raw: Uint8Array): Uint8Array[] => child(raw) as Uint8Array[]

    const kind5Outer = outerOf('content_request'); const authorization = child(kind5Outer[2] as Uint8Array)
    const hashes = child(authorization[4] as Uint8Array) as Uint8Array[]
    expect((await createContentRequest(new TestSigner(0x44), {
      fileQuoteTermsID: authorization[0] as Uint8Array,
      refundTemplateTxID: authorization[1] as Uint8Array,
      paymentSequence: Number(authorization[2]),
      sellerAmountAfterSatoshis: authorization[3] as bigint,
      contentHashes: hashes,
      deliveryDeadlineUnixSeconds: authorization[5] as bigint
    })).bytes()).toEqual(hex(entry('content_request').exact_hex))

    const kind6Outer = outerOf('content_delivery'); const delivery = child(kind6Outer[2] as Uint8Array)
    expect((await createContentDelivery(new TestSigner(0x22), delivery[0] as Uint8Array, payloads(kind6Outer[4] as Uint8Array))).bytes()).toEqual(hex(entry('content_delivery').exact_hex))

    const kind8Outer = outerOf('arbitration_request')
    expect((await createArbitrationRequest(new TestSigner(0x22), kind8Outer[2] as Uint8Array, payloads(kind8Outer[4] as Uint8Array))).bytes()).toEqual(hex(entry('arbitration_request').exact_hex))

    const kind9Outer = outerOf('arbitration_response')
    expect((await createArbitrationResponse(new TestSigner(0x33), kind9Outer[2] as Uint8Array)).bytes()).toEqual(hex(entry('arbitration_response').exact_hex))

    const kind10Outer = outerOf('content_retrieval_request'); const request = child(kind10Outer[2] as Uint8Array)
    expect((await createContentRetrievalRequest(new TestSigner(0x55), request[0] as Uint8Array, request[1] as Uint8Array)).bytes()).toEqual(hex(entry('content_retrieval_request').exact_hex))

    const unavailableOuter = outerOf('content_retrieval_unavailable'); const unavailable = child(unavailableOuter[2] as Uint8Array)
    expect((await createContentRetrievalUnavailable(new TestSigner(0x33), unavailable[0] as Uint8Array, Number(unavailable[2]) as 0 | 1 | 2)).bytes()).toEqual(hex(entry('content_retrieval_unavailable').exact_hex))

    const availableOuter = outerOf('content_retrieval_available'); const available = child(availableOuter[2] as Uint8Array)
    expect((await createContentRetrievalAvailable(new TestSigner(0x33), available[0] as Uint8Array, payloads(availableOuter[4] as Uint8Array))).bytes()).toEqual(hex(entry('content_retrieval_available').exact_hex))
  })
})

describe('角色纯函数跨语言真值（fixtures/role-v1.json）', () => {
  it('卖家用共享 Kind 1/5 真值预检授权 ID、序号与有序内容清单', async () => {
    const funded = await verifySellerFunding(kind4, { rawKind2: kind2, rawKind3: kind3 })
    const input = { quoteRaw: kind1, pool: funded.pool, requestRaw: kind5 }
    const summary = await inspectSellerDeliveryRequest(roleFacts, input)
    const authorization = decodePaymentAuthorization(outer(kind5)[2] as Uint8Array)

    expect(toHex(summary.paymentAuthorizationID)).toBe(roleFixture.buyer_request_kind5.authorization_id)
    expect(summary.paymentSequence).toBe(authorization.paymentSequence)
    expect(summary.sellerAmountAfterSatoshis).toBe(authorization.sellerAmountAfterSatoshis)
    expect(summary.deliveryDeadlineUnixSeconds).toBe(authorization.deliveryDeadlineUnixSeconds)
    expect(toHex(summary.fileQuoteTermsID)).toBe(toHex(authorization.fileQuoteTermsID))
    expect(toHex(summary.refundTemplateTxID)).toBe(toHex(authorization.refundTemplateTxID))
    expect(summary.contentHashes.map(toHex)).toEqual(authorization.contentHashes.map(toHex))

    const originalHash = toHex(summary.contentHashes[0]!)
    summary.contentHashes[0]![0]! ^= 0xff
    const repeated = await inspectSellerDeliveryRequest(roleFacts, input)
    expect(toHex(repeated.contentHashes[0]!)).toBe(originalHash)

    const kind5Outer = outer(kind5)
    const authorizationFields = decodeCanonical(kind5Outer[2] as Uint8Array)
    if (!Array.isArray(authorizationFields)) throw new Error('共享授权文档不是 CBOR array')
    authorizationFields[2] = BigInt(authorization.paymentSequence + 1)
    const badRequest = encodeCanonical([1n, 5n, encodeCanonical(authorizationFields), kind5Outer[3] as Uint8Array])
    await expect(inspectSellerDeliveryRequest(roleFacts, { ...input, requestRaw: badRequest }))
      .rejects.toMatchObject({ code: 'invalid_signature' })

    const stalePool = { ...funded.pool, latestPaymentRawTx: paymentMerged }
    await expect(inspectSellerDeliveryRequest(roleFacts, { ...input, pool: stalePool }))
      .rejects.toMatchObject({ code: 'state_conflict' })
  })

  it('固定 Signer 下 Kind 1–11 与全部交易逐字节复现', async () => {
    const funding = new Transaction()
    funding.addInput({ sourceTXID: '01'.repeat(32), sourceOutputIndex: 0, sequence: 0xffffffff, unlockingScript: new UnlockingScript() })
    funding.addOutput({ satoshis: roleFixture.pool_output_satoshis, lockingScript: buildArbitratedPoolLock(bsvRoles) })
    const fundingRaw = hex(funding.toHex())

    const quote = await createSellerQuote(roleFacts, seller, {
      seedHash,
      buyerPublicKey: buyer.publicKey(),
      seedPriceSatoshis: 100n,
      fullBlockPriceSatoshis: 1000n,
      fileSizeBytes: BigInt(roleFixture.quote.file_size_bytes),
      quoteExpiresAtUnixSeconds: 2000000000n,
      supportedArbiterPublicKeys: [arbiter.publicKey()],
      recommendedFilename: roleFixture.quote.recommended_filename
    })
    expect(toHex(quote.outbound.bytes())).toBe(roleFixture.quote.kind1_hex)
    expect(digest(outer(quote.outbound.bytes())[2] as Uint8Array)).toBe(roleFixture.quote.terms_id)
    const accepted = acceptBuyerQuote(roleFacts, quote.outbound.bytes())
    expect(toHex(accepted.termsID)).toBe(roleFixture.quote.terms_id)
    expect(accepted.allowsArbiter(arbiter.publicKey())).toBe(true)
    expect(accepted.allowsArbiter(buyer.publicKey())).toBe(false)

    const opening = await prepareBuyerOpening({
      quoteRaw: quote.outbound.bytes(),
      fundingTransactionRaw: fundingRaw,
      expiryLockTime: roleFixture.expiry_lock_time,
      minerFeeRateSatoshisPerKilobyte: 1n,
      sellerPublicKey: seller.publicKey(),
      arbiterPublicKey: arbiter.publicKey()
    }, buyer)
    expect(toHex(opening.outbound.bytes())).toBe(roleFixture.seller_opening_kind2.hex)
    expect(toHex(opening.opening.rawKind2)).toBe(roleFixture.seller_opening_kind2.hex)

    const presign = await prepareSellerPresign(opening.outbound.bytes(), seller)
    expect(toHex(presign.outbound.bytes())).toBe(roleFixture.seller_presign_kind3.hex)
    expect(toHex(presign.opening.rawKind2)).toBe(roleFixture.seller_opening_kind2.hex)

    const completed = await completeBuyerOpening(opening.opening, presign.outbound.bytes())
    expect(toHex(completed.opening.rawKind3)).toBe(roleFixture.seller_presign_kind3.hex)
    const fundingDelivery = await prepareBuyerFundingDelivery(completed.pool)
    expect(toHex(fundingDelivery.bytes())).toBe(roleFixture.funding_delivery_kind4.hex)

    const fundingVerified = await verifySellerFunding(fundingDelivery.bytes(), presign.opening)
    expect(toHex(fundingVerified.fundingTransactionRaw)).toBe(toHex(fundingRaw))

    const contentRequest = await prepareBuyerContentRequest(roleFacts, {
      quoteRaw: quote.outbound.bytes(),
      pool: completed.pool,
      contentHashes: [seedHash],
      deliveryDeadline: BigInt(roleFixture.delivery_deadline_unix_seconds),
      seed
    }, buyer)
    expect(toHex(contentRequest.outbound.bytes())).toBe(roleFixture.buyer_request_kind5.kind5_hex)
    expect(toHex(paymentAuthorizationID(outer(contentRequest.outbound.bytes())[2] as Uint8Array))).toBe(roleFixture.buyer_request_kind5.authorization_id)
    expect(toHex(contentRequest.authorization.rawKind5)).toBe(roleFixture.buyer_request_kind5.kind5_hex)

    const delivery = await prepareSellerDelivery(roleFacts, {
      quoteRaw: quote.outbound.bytes(),
      pool: fundingVerified.pool,
      requestRaw: contentRequest.outbound.bytes(),
      contentPayloads: [seed],
      seed
    }, seller)
    expect(toHex(delivery.outbound.bytes())).toBe(roleFixture.seller_delivery_kind6.hex)
    expect(toHex(delivery.evidence.rawKind6)).toBe(roleFixture.seller_delivery_kind6.hex)

    const verifiedDelivery = await verifyBuyerDelivery(roleFacts, {
      authorization: contentRequest.authorization,
      pool: completed.pool,
      deliveryRaw: delivery.outbound.bytes(),
      seed
    }, buyer)
    expect(toHex(verifiedDelivery.payloads[0]!)).toBe(toHex(seed))
    expect(toHex(verifiedDelivery.outbound.bytes())).toBe(roleFixture.buyer_payment_kind7.hex)

    const payment = await completeSellerPayment(roleFacts, {
      pool: fundingVerified.pool,
      delivery: delivery.evidence,
      requestRaw: contentRequest.outbound.bytes(),
      updateRaw: verifiedDelivery.outbound.bytes()
    }, seller)
    expect(toHex(payment.rawTransaction)).toBe(roleFixture.payment_merged_raw.hex)
    expect(toHex(payment.pool.latestPaymentRawTx!)).toBe(roleFixture.payment_merged_raw.hex)

    const buyerPaid = { opening: completed.pool.opening, latestPaymentRawTx: payment.rawTransaction }
    const close = await prepareBuyerClose(roleFacts, { pool: buyerPaid, targetSellerAmountSatoshis: 150n }, buyer)
    expect(toHex(close.unsignedRaw)).toBe(roleFixture.close_unsigned_raw.hex)

    const closeSigned = await completeSellerClose(roleFacts, {
      pool: payment.pool,
      unsignedRaw: close.unsignedRaw,
      buyerSignature: close.buyerSignature
    }, seller)
    expect(toHex(closeSigned)).toBe(roleFixture.close_signed_raw.hex)
    expect(toHex(await verifyBuyerCompletedClose({ pool: buyerPaid, closeRaw: closeSigned }))).toBe(roleFixture.close_signed_raw.hex)

    const refund = await buildBuyerMaturedRefund({ nowUnixSeconds: 2000000000n, blockHeight: roleFixture.facts_block_height }, buyerPaid)
    expect(toHex(refund)).toBe(roleFixture.refund_matured_raw.hex)

    const claim = await prepareSellerArbitration(roleFacts, {
      pool: payment.pool,
      requestRaw: contentRequest.outbound.bytes(),
      deliveryRaw: delivery.outbound.bytes()
    }, seller)
    expect(toHex(claim.outbound.bytes())).toBe(roleFixture.arbitration.kind8_hex)
    expect(toHex(claim.claimID)).toBe(roleFixture.arbitration.claim_id)

    const prepared = prepareArbiterArbitration(roleFacts, claim.outbound.bytes(), 500n)
    const signed = await signArbiterPreparedArbitration(roleFacts, prepared, arbiter)
    expect(toHex(signed.outbound.bytes())).toBe(roleFixture.arbitration.kind9_hex)

    const claimElements = outer(claim.outbound.bytes())
    const claimFields = outer(claimElements[2] as Uint8Array)
    const claimKeys = parseArbitratedPoolLockingScript(claimFields[1] as Uint8Array)
    const claimEngine = new MultisigPoolEngine(claimKeys)
    const sellerArbitrationSignature = await claimEngine.signRole(seller, 'seller', prepared.candidateRaw, claimFields[0] as bigint)
    const arbitrationPaid = await completeArbiterArbitratedPayment(signed, sellerArbitrationSignature)
    const sellerSide = await completeSellerArbitratedPayment(roleFacts, {
      requestRaw: claim.outbound.bytes(),
      responseRaw: signed.outbound.bytes(),
      deliveryPayloadsCBOR: copy(outer(delivery.outbound.bytes())[4] as Uint8Array)
    }, seller)
    expect(toHex(arbitrationPaid)).toBe(toHex(sellerSide))

    const retrieval = await requestBuyerArbitratedContent({
      pool: buyerPaid,
      authorization: contentRequest.authorization,
      nonce: hex('a7'.repeat(32))
    }, buyer)
    expect(toHex(retrieval.bytes())).toBe(roleFixture.arbitration.retrieval_kind10_hex)
    const requestID = sha256(outer(retrieval.bytes())[2] as Uint8Array)
    expect(toHex(requestID)).toBe(roleFixture.arbitration.retrieval_request_id)

    const unavailable = await buildArbiterUnavailableRetrieval(requestID, roleFixture.arbitration.unavailable_reason_code as 0 | 1 | 2, arbiter)
    expect(toHex(unavailable.bytes())).toBe(roleFixture.arbitration.unavailable_kind11_hex)
    await expect(verifyBuyerArbitratedContent({
      authorization: contentRequest.authorization,
      pool: buyerPaid,
      retrievalRequestRaw: retrieval.bytes(),
      retrievalResponseRaw: unavailable.bytes()
    })).resolves.toMatchObject({ available: false, unavailableReason: roleFixture.arbitration.unavailable_reason_code })

    expect(() => authenticateArbiterRetrieval(retrieval.bytes(), claim.outbound.bytes())).not.toThrow()

    const custody = await verifyArbiterCustody(claim.outbound.bytes(), signed.outbound.bytes())
    expect(toHex(custody.payloadsCBOR)).toBe(toHex(outer(kind8)[4] as Uint8Array))
    const available = await buildArbiterAvailableRetrieval(requestID, custody, arbiter)
    expect(toHex(available.bytes())).toBe(roleFixture.arbitration.available_kind11_hex)
    const availableResult = await verifyBuyerArbitratedContent({
      authorization: contentRequest.authorization,
      pool: completed.pool,
      retrievalRequestRaw: retrieval.bytes(),
      retrievalResponseRaw: available.bytes(),
      seed
    })
    expect(availableResult.available).toBe(true)
    expect(toHex(availableResult.payloads[0]!)).toBe(toHex(seed))

    const generatedNonce = generateRetrievalNonce()
    expect(generatedNonce).toHaveLength(32)
    expect(generatedNonce.every(byte => byte === 0)).toBe(false)
    expect(() => newRetrievalNonce(new Uint8Array(32))).toThrowError(expect.objectContaining({ code: 'invalid_evidence' }))
    expect(toHex(newRetrievalNonce(hex('a7'.repeat(32))))).toBe('a7'.repeat(32))
  })

  it('计价向量与 Go 的期望分类、价格和错误码一致', async () => {
    for (const vector of roleFixture.price_vectors) {
      const terms = priceVectorTerms(vector)
      const hashes = vector.hashes_hex.map(hex)
      const vectorSeed = vector.seed_hex === '' ? undefined : hex(vector.seed_hex)
      let classificationOk = false
      try {
        const classification = await classifyContentHashes(terms, hashes, vectorSeed)
        classificationOk = true
        if (vector.expect_classification != null) {
          expect(classification).toEqual(vector.expect_classification.map(item => ({ isSeed: item.is_seed, blockSize: BigInt(item.block_size) })))
        }
      } catch (error) {
        expect(error).toMatchObject({ code: vector.expect_error_code })
      }
      if (!classificationOk) continue
      try {
        const price = await contentHashesPriceSatoshis(terms, hashes, vectorSeed)
        expect(vector.expect_error_code).toBeUndefined()
        expect(price.toString()).toBe(vector.expect_price_satoshis)
      } catch (error) {
        expect(error).toMatchObject({ code: vector.expect_error_code })
      }
    }
  })

  it('语义拒绝向量与 Go 同码拒绝', async () => {
    const opening = fixtureOpening()
    const quote = signedQuote()
    const request = signedRequest()
    for (const vector of roleFixture.evidence_reject_vectors) {
      switch (vector.mutation) {
        case 'facts_at_expiry':
          expect(() => acceptBuyerQuote({ nowUnixSeconds: 2000000000n, blockHeight: roleFixture.facts_block_height }, kind1)).toThrowError(expect.objectContaining({ code: vector.error_code }))
          break
        case 'signature_last_byte_flip':
          await expect(verifyContentRequestEvidence({ ...request, buyerPaymentAuthorizationSignature: flipLastByte(request.buyerPaymentAuthorizationSignature) }, quote, opening)).rejects.toMatchObject({ code: vector.error_code })
          break
        case 'delivery_deadline_beyond_quote': {
          const baseline = outer(outer(kind5)[2] as Uint8Array)
          const document = encodeCanonical([baseline[0]!, baseline[1]!, baseline[2]!, baseline[3]!, baseline[4]!, 2000000001n])
          const signature = await signWireDocument(buyer, 5, document)
          await expect(verifyContentRequestEvidence({ paymentAuthorizationCBOR: document, buyerPaymentAuthorizationSignature: signature }, quote, opening)).resolves.toBeDefined()
          expect(() => checkContentRequestTiming(decodePaymentAuthorization(document), quoteTerms(), BigInt(roleFixture.facts_now_unix_seconds))).toThrowError(expect.objectContaining({ code: vector.error_code }))
          break
        }
        case 'payload_last_byte_flip': {
          const payloads = decodeContentPayloads(outer(kind6)[4] as Uint8Array)
          payloads[payloads.length - 1] = flipLastByte(payloads[payloads.length - 1]!)
          await expect(verifyContentPayloads(quoteTerms(), [seedHash], payloads, seed)).rejects.toMatchObject({ code: vector.error_code })
          break
        }
        case 'authorization_id_first_byte_flip': {
          const elements = outer(hex(roleFixture.buyer_payment_kind7.hex))
          const mutated = encodeCanonical([1n, 7n, flipFirstByte(elements[2] as Uint8Array), copy(elements[3] as Uint8Array)])
          await expect(completeSellerPayment(roleFacts, { pool: sellerPoolEvidence(), delivery: sellerDeliveryEvidence(), requestRaw: kind5, updateRaw: mutated }, seller)).rejects.toMatchObject({ code: vector.error_code })
          break
        }
        case 'receipt_signature_last_byte_flip': {
          const elements = outer(kind9)
          const mutated = encodeCanonical([1n, 9n, copy(elements[2] as Uint8Array), flipLastByte(elements[3] as Uint8Array)])
          await expect(completeSellerArbitratedPayment(roleFacts, { requestRaw: kind8, responseRaw: mutated }, seller)).rejects.toMatchObject({ code: vector.error_code })
          break
        }
        case 'zero_nonce': {
          const elements = outer(kind10)
          const document = outer(elements[2] as Uint8Array)
          const mutated = encodeCanonical([1n, 10n, encodeCanonical([document[0]!, new Uint8Array(32)]), copy(elements[3] as Uint8Array)])
          expect(() => parseAs(10, mutated)).toThrowError(expect.objectContaining({ code: vector.error_code }))
          break
        }
        case 'attachment_last_byte_flip': {
          const elements = outer(kind11Available)
          const mutated = encodeCanonical([1n, 11n, copy(elements[2] as Uint8Array), copy(elements[3] as Uint8Array), flipLastByte(elements[4] as Uint8Array)])
          await expect(verifyBuyerArbitratedContent({
            authorization: { rawKind1: kind1, rawKind5: kind5 },
            pool: buyerPaidEvidence(),
            retrievalRequestRaw: kind10,
            retrievalResponseRaw: mutated
          })).rejects.toMatchObject({ code: vector.error_code })
          break
        }
        case 'foreign_seller_signer':
          await expect(prepareSellerPresign(kind2, new FixtureSigner('99'))).rejects.toMatchObject({ code: vector.error_code })
          break
        case 'kind2_refund_template_flip': {
          const elements = outer(kind2)
          const tamperedTemplate = flipLastByte(elements[2] as Uint8Array)
          const mutated = encodeCanonical([1n, 2n, tamperedTemplate, copy(elements[3] as Uint8Array), copy(elements[4] as Uint8Array), copy(elements[5] as Uint8Array), elements[6]!, copy(elements[7] as Uint8Array)])
          await expect(prepareSellerPresign(mutated, seller)).rejects.toMatchObject({ code: vector.error_code })
          break
        }
        case 'stale_sequence_second_round':
          await expect(completeSellerPayment(roleFacts, { pool: sellerPaidEvidence(), delivery: sellerDeliveryEvidence(), requestRaw: kind5, updateRaw: kind7 }, seller)).rejects.toMatchObject({ code: vector.error_code })
          break
        case 'amount_decrease_second_round':
          await expect(completeSellerPayment(roleFacts, {
            pool: sellerPaidEvidence(),
            delivery: { rawKind1: copy(kind1), rawKind5: hex(roleFixture.malicious.kind5_decrease_hex), rawKind6: hex(roleFixture.malicious.kind6_decrease_hex) },
            requestRaw: hex(roleFixture.malicious.kind5_decrease_hex),
            updateRaw: hex(roleFixture.malicious.kind7_decrease_hex)
          }, seller)).rejects.toMatchObject({ code: vector.error_code })
          break
        case 'capacity_insufficient_second_round':
          await expect(completeSellerPayment(roleFacts, {
            pool: sellerPaidEvidence(),
            delivery: { rawKind1: copy(kind1), rawKind5: hex(roleFixture.malicious.kind5_capacity_hex), rawKind6: hex(roleFixture.malicious.kind6_capacity_hex) },
            requestRaw: hex(roleFixture.malicious.kind5_capacity_hex),
            updateRaw: hex(roleFixture.malicious.kind7_capacity_hex)
          }, seller)).rejects.toMatchObject({ code: vector.error_code })
          break
        case 'price_mismatch_second_round':
          await expect(verifyBuyerDelivery(roleFacts, {
            authorization: { rawKind1: copy(kind1), rawKind5: hex(roleFixture.malicious.kind5_price_mismatch_hex) },
            pool: buyerPaidEvidence(),
            deliveryRaw: hex(roleFixture.malicious.kind6_price_mismatch_hex),
            seed
          }, buyer)).rejects.toMatchObject({ code: vector.error_code })
          break
        default:
          throw new Error(`未实现的拒绝向量 mutation: ${vector.mutation}`)
      }
    }
  })

  it('每个签名入口在验证失败时不调用 Signer', async () => {
    const invalidSigner: Signer = {
      publicKey: () => new Uint8Array(33),
      sign: async () => { throw new Error('无效身份不得进入签名') }
    }
    await expect(createSellerQuote(roleFacts, invalidSigner, {} as never)).rejects.toMatchObject({ code: 'invalid_evidence' })
    await expect(prepareSellerPresign(kind2, invalidSigner)).rejects.toMatchObject({ code: 'invalid_evidence' })
    await expect(prepareSellerDelivery(roleFacts, {} as never, invalidSigner)).rejects.toMatchObject({ code: 'invalid_evidence' })
    await expect(completeSellerPayment(roleFacts, {} as never, invalidSigner)).rejects.toMatchObject({ code: 'invalid_evidence' })
    await expect(completeSellerClose(roleFacts, {} as never, invalidSigner)).rejects.toMatchObject({ code: 'invalid_evidence' })
    await expect(prepareSellerArbitration(roleFacts, {} as never, invalidSigner)).rejects.toMatchObject({ code: 'invalid_evidence' })
    await expect(completeSellerArbitratedPayment(roleFacts, {} as never, invalidSigner)).rejects.toMatchObject({ code: 'invalid_evidence' })
    await expect(prepareBuyerOpening({} as never, invalidSigner)).rejects.toMatchObject({ code: 'invalid_evidence' })
    await expect(prepareBuyerContentRequest(roleFacts, {} as never, invalidSigner)).rejects.toMatchObject({ code: 'invalid_evidence' })
    await expect(verifyBuyerDelivery(roleFacts, {} as never, invalidSigner)).rejects.toMatchObject({ code: 'invalid_evidence' })
    await expect(prepareBuyerClose(roleFacts, {} as never, invalidSigner)).rejects.toMatchObject({ code: 'invalid_evidence' })
    await expect(requestBuyerArbitratedContent({} as never, invalidSigner)).rejects.toMatchObject({ code: 'invalid_evidence' })
    await expect(verifyBuyerArbitratedContent({} as never)).rejects.toMatchObject({ code: 'invalid_evidence' })
    await expect(signArbiterPreparedArbitration(roleFacts, {} as never, invalidSigner)).rejects.toMatchObject({ code: 'invalid_evidence' })
    await expect(buildArbiterAvailableRetrieval(new Uint8Array(32), {} as never, invalidSigner)).rejects.toMatchObject({ code: 'invalid_evidence' })
    await expect(buildArbiterUnavailableRetrieval(new Uint8Array(32), 1, invalidSigner)).rejects.toMatchObject({ code: 'invalid_evidence' })

    const countingSeller = new FixtureSigner('22')
    const tamperedKind2 = encodeCanonical(outer(kind2).map((value, index) => index === 7 ? flipLastByte(value as Uint8Array) : value))
    await expect(prepareSellerPresign(tamperedKind2, countingSeller)).rejects.toMatchObject({ code: 'invalid_evidence' })
    expect(countingSeller.calls).toBe(0)

    const countingBuyer = new FixtureSigner('44')
    const tamperedKind1 = encodeCanonical(outer(kind1).map((value, index) => index === 4 ? flipLastByte(value as Uint8Array) : value))
    await expect(prepareBuyerContentRequest(roleFacts, { quoteRaw: tamperedKind1, pool: buyerPaidEvidence(), contentHashes: [seedHash], deliveryDeadline: BigInt(roleFixture.delivery_deadline_unix_seconds), seed }, countingBuyer)).rejects.toMatchObject({ code: 'invalid_signature' })
    expect(countingBuyer.calls).toBe(0)

    const countingArbiter = new FixtureSigner('33')
    const tamperedPrepared = { rawKind8: kind8, candidateRaw: flipLastByte(outer(kind8)[2] as Uint8Array), arbitrationClaimID: hex(roleFixture.arbitration.claim_id), feeSatoshis: 500n }
    await expect(signArbiterPreparedArbitration(roleFacts, tamperedPrepared, countingArbiter)).rejects.toMatchObject({ code: 'state_conflict' })
    expect(countingArbiter.calls).toBe(0)

    expect(() => prepareArbiterArbitration(roleFacts, kind9, 500n)).toThrowError(expect.objectContaining({ code: 'unsupported_kind' }))
    expect(() => prepareArbiterArbitration(roleFacts, kind8, 0n)).toThrowError(expect.objectContaining({ code: 'invalid_evidence' }))
    expect(() => authenticateArbiterRetrieval(encodeCanonical([1n, 10n, encodeCanonical([outer(outer(kind10)[2] as Uint8Array)[0]!, new Uint8Array(32)]), copy(outer(kind10)[3] as Uint8Array)]), kind8)).toThrowError(expect.objectContaining({ code: 'invalid_evidence' }))
    await expect(buildBuyerMaturedRefund(roleFacts, buyerPaidEvidence())).rejects.toMatchObject({ code: 'not_matured' })
  })

  it('同一输入重复调用结果稳定，公开面无跨步骤对象', async () => {
    const first = await prepareSellerPresign(kind2, seller)
    const second = await prepareSellerPresign(kind2, seller)
    expect(toHex(first.outbound.bytes())).toBe(toHex(second.outbound.bytes()))
    const mix = roleFixture.price_vectors.find(vector => vector.name === 'combination')!
    const terms = priceVectorTerms(mix)
    const hashes = mix.hashes_hex.map(hex)
    const vectorSeed = hex(mix.seed_hex)
    expect((await contentHashesPriceSatoshis(terms, hashes, vectorSeed)).toString()).toBe((await contentHashesPriceSatoshis(terms, hashes, vectorSeed)).toString())

    const surface = await import('../src/index.js') as unknown as Record<string, unknown>
    expect(surface.BuyerWorkflow).toBeUndefined()
    expect(surface.SellerWorkflow).toBeUndefined()
    expect(surface.ArbiterWorkflow).toBeUndefined()
    expect(surface.PreparedArbitration).toBeUndefined()
    expect(surface.WorkflowFacts).toBeUndefined()
    await expect(import('../src/roles.js')).rejects.toThrow()
  })
})
