import { createHash } from 'node:crypto'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { PrivateKey, Transaction, UnlockingScript } from '@bsv/sdk'
import {
  Protocol as PoolProtocol, Version as PoolVersion, buildArbitratedPoolLock,
  buildArbitratedPoolOpeningState, buildArbitratedPoolState,
  mergeArbitratedPoolBuyerSellerSignatures, mergeArbitratedPoolSellerArbiterSignatures,
  signArbitratedPoolAsArbiter, signArbitratedPoolAsBuyer, signArbitratedPoolAsSeller
} from 'keymaster-multisig-pool'
import { encodeUvarintFrame } from 'bitcoin-libp2p/stream'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { decodeCanonical } from '../src/cbor.js'
import {
  WireError, createFileQuote, encodeFundingTransactionDelivery, encodePaymentUpdate,
  encodeRefundPresignRequest, encodeRefundPresignResponse, parse, parseAs,
  createArbitrationRequest, createArbitrationResponse, createContentDelivery,
  createContentRequest, createContentRetrievalAvailable, createContentRetrievalRequest,
  createContentRetrievalUnavailable,
  verifyWireDocument, wireSignatureDigest, type FileQuoteTerms, type Signer,
  forkIDAllDigest, forkIDAllPreimage, transactionID, MultisigPoolEngine,
  readArtifacts, writeArtifact,
  BuyerWorkflow, SellerWorkflow, ArbiterWorkflow,
  buildArbitrationCandidate, verifyArbitrationCandidate,
  type SigningRequest, type WireKind
} from '../src/index.js'

type FixtureIndex = {
  format: string
  wire_manifest: string
  transaction_manifest: string
  protocol_schema: string
  transport_profile: string
  invalid_wire: string
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

const root = resolve(import.meta.dirname, '../..')
const json = <T>(path: string): T => JSON.parse(readFileSync(resolve(root, path), 'utf8')) as T
const fixtures = json<FixtureIndex>('fixtures/manifest.json')
const manifest = json<WireManifest>(fixtures.wire_manifest)
const transactionManifest = json<TransactionManifest>(fixtures.transaction_manifest)
const transportProfile = json<{ protocol_id: string, framing: string, max_wire_frame_bytes: number }>(fixtures.transport_profile)
const invalidWire = json<{ cases: Array<{ name: string, hex: string, error_code: string }> }>(fixtures.invalid_wire)
const hex = (value: string): Uint8Array => Uint8Array.from(Buffer.from(value, 'hex'))
const digest = (value: Uint8Array): string => createHash('sha256').update(value).digest('hex')

class TestSigner implements Signer {
  readonly #privateKey: Uint8Array
  constructor (byte: number) { this.#privateKey = Uint8Array.from({ length: 32 }, () => byte) }
  publicKey (): Uint8Array { return secp256k1.getPublicKey(this.#privateKey, true) }
  async sign (request: Readonly<SigningRequest>): Promise<Uint8Array> {
    return secp256k1.sign(request.digest, this.#privateKey, { prehash: false, lowS: true, format: 'der' })
  }
}

class RotatingSigner implements Signer {
  byte: number
  calls = 0
  constructor (byte: number) { this.byte = byte }
  publicKey (): Uint8Array { return secp256k1.getPublicKey(Uint8Array.from({ length: 32 }, () => this.byte), true) }
  async sign (request: Readonly<SigningRequest>): Promise<Uint8Array> {
    this.calls++
    return secp256k1.sign(request.digest, Uint8Array.from({ length: 32 }, () => this.byte), { prehash: false, lowS: true, format: 'der' })
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

describe('Go 与 TypeScript 共享 wire 真值', () => {
  it('共享清单指向 wire、transaction 与 CDDL 三类唯一真值', () => {
    expect(fixtures.format).toBe('bitfs-cross-language-fixtures')
    expect(readFileSync(resolve(root, fixtures.transaction_manifest), 'utf8')).toContain('refund_template')
    expect(readFileSync(resolve(root, fixtures.protocol_schema), 'utf8')).toContain('bitfs-wire-message')
  })

  it('TypeScript 网络常量读取与 Go 相同的 transport profile', async () => {
    const transport = await import('../src/transport.js')
    expect(transport.BITFS_PROTOCOL_ID).toBe(transportProfile.protocol_id)
    expect(transport.MAX_WIRE_FRAME_BYTES).toBe(transportProfile.max_wire_frame_bytes)
    expect(transportProfile.framing).toBe('unsigned-varint-byte-length-prefix')
  })

  it('买方、卖方、仲裁方角色 API 完成签名、验签与 payload 绑定', async () => {
    const byKind = (kind: WireKind): Uint8Array => hex(manifest.entries.find(entry => entry.kind === kind)!.exact_hex)
    const buyer = new BuyerWorkflow(new TestSigner(0x44))
    const quote = buyer.acceptQuote({ nowUnixSeconds: 1_900_000_000n }, byKind(1))
    expect(quote.terms.buyerPublicKey).toEqual(buyer.publicKey())

    const seller = new SellerWorkflow(new TestSigner(0x22))
    const payload = new TextEncoder().encode('role-api-payload')
    const requestArtifact = await buyer.requestContent({
      fileQuoteTermsID: quote.termsID, refundTemplateTxID: Uint8Array.from({ length: 32 }, () => 9),
      paymentSequence: 3, sellerAmountAfterSatoshis: 100n, contentHashes: [sha256(payload)],
      deliveryDeadlineUnixSeconds: 2_000_000_000n
    })
    const request = seller.acceptContentRequest(requestArtifact.bytes(), buyer.publicKey())
    const deliveryArtifact = await seller.deliverContent(request.authorizationID, [payload])
    const delivery = buyer.verifyDelivery(deliveryArtifact.bytes(), request, seller.publicKey())
    expect(delivery.authorizationID).toEqual(request.authorizationID)
    expect(delivery.payloads[0]).toEqual(payload)

    const arbiter = new ArbiterWorkflow(new TestSigner(0x33))
    const custody = arbiter.acceptArbitrationRequest(byKind(8))
    expect(custody.arbiterPublicKey).toEqual(arbiter.publicKey())
    expect(Buffer.from(custody.payloads[0]!).toString()).toBe('payload')
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
    const buyer = secp256k1.getPublicKey(Uint8Array.from({ length: 32 }, () => 0xb1), true)
    const seller = secp256k1.getPublicKey(Uint8Array.from({ length: 32 }, () => 0x52), true)
    const arbiter = secp256k1.getPublicKey(Uint8Array.from({ length: 32 }, () => 0xa3), true)
    const lockingScript = Uint8Array.from([0x52, 0x21, ...buyer, 0x21, ...seller, 0x21, ...arbiter, 0x53, 0xae])
    for (const prefix of ['payment', 'arbitration'] as const) {
      const raw = hex(find(`${prefix}_${prefix === 'payment' ? 'unsigned' : 'candidate'}`).raw_hex!)
      const preimage = forkIDAllPreimage(raw, 0, 20000n, lockingScript)
      expect(Buffer.from(preimage).toString('hex')).toBe(find(`${prefix}_preimage`).preimage)
      expect(Buffer.from(forkIDAllDigest(raw, 0, 20000n, lockingScript)).toString('hex')).toBe(find(`${prefix}_sighash_digest`).sighash_digest)
    }
  })

  it('TypeScript MultisigPool v4 从固定输入重建全部 Go 交易真值', async () => {
    const find = (name: string): TransactionManifest['entries'][number] => transactionManifest.entries.find(entry => entry.name === name)!
    const buyer = PrivateKey.fromHex('b1'.repeat(32))
    const seller = PrivateKey.fromHex('52'.repeat(32))
    const arbiter = PrivateKey.fromHex('a3'.repeat(32))
    const roles = { buyer: buyer.toPublicKey(), seller: seller.toPublicKey(), arbiter: arbiter.toPublicKey() }
    const funding = new Transaction()
    funding.addInput({ sourceTXID: '01'.repeat(32), sourceOutputIndex: 0, sequence: 0xffffffff, unlockingScript: new UnlockingScript() })
    funding.addOutput({ satoshis: 20000, lockingScript: buildArbitratedPoolLock(roles) })

    const refundTemplate = await buildArbitratedPoolOpeningState(funding, 20000, roles, 800000, 1)
    expect(refundTemplate.toHex()).toBe(find('refund_template').raw_hex)
    const buyerRefund = signArbitratedPoolAsBuyer(refundTemplate, 20000, roles, buyer)
    const sellerRefund = signArbitratedPoolAsSeller(refundTemplate, 20000, roles, seller)
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
    const buyerPayment = signArbitratedPoolAsBuyer(payment, 20000, roles, buyer)
    expect(Buffer.from(buyerPayment).toString('hex')).toBe(find('payment_buyer_signature').signature_der_hex)
    const sellerPayment = signArbitratedPoolAsSeller(payment, 20000, roles, seller)
    const paymentMerged = mergeArbitratedPoolBuyerSellerSignatures(payment, 20000, roles, buyerPayment, sellerPayment)
    expect(paymentMerged.toHex()).toBe(find('payment_merged').raw_hex)

    const close = await buildArbitratedPoolState({
      protocol: PoolProtocol, version: PoolVersion, previousState: paymentMerged, sequence: 0xffffffff,
      lockTime: 0xffffffff, sellerAmount: 150, arbiterAmount: 0, poolAmount: 20000, roles, feeRate: 1
    })
    expect(close.toHex()).toBe(find('close_unsigned').raw_hex)
    const closeMerged = mergeArbitratedPoolBuyerSellerSignatures(close, 20000, roles,
      signArbitratedPoolAsBuyer(close, 20000, roles, buyer), signArbitratedPoolAsSeller(close, 20000, roles, seller))
    expect(closeMerged.toHex()).toBe(find('close_merged').raw_hex)

    const arbitration = await build(refundMerged, 7, 200, 500)
    expect(arbitration.toHex()).toBe(find('arbitration_candidate').raw_hex)
    const arbitrationSeller = signArbitratedPoolAsSeller(arbitration, 20000, roles, seller)
    expect(Buffer.from(arbitrationSeller).toString('hex')).toBe(find('arbitration_seller_signature').signature_der_hex)
    const arbitrationMerged = mergeArbitratedPoolSellerArbiterSignatures(arbitration, 20000, roles, arbitrationSeller,
      signArbitratedPoolAsArbiter(arbitration, 20000, roles, arbiter))
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

  it('买卖双方角色 API 完成开池、资金交付和累计付款', async () => {
    const find = (name: string): TransactionManifest['entries'][number] => transactionManifest.entries.find(entry => entry.name === name)!
    const buyer = new BuyerWorkflow(new TestSigner(0xb1))
    const seller = new SellerWorkflow(new TestSigner(0x52))
    const arbiterKey = new TestSigner(0xa3).publicKey()
    const funding = new Transaction()
    funding.addInput({ sourceTXID: '01'.repeat(32), sourceOutputIndex: 0, sequence: 0xffffffff, unlockingScript: new UnlockingScript() })
    funding.addOutput({ satoshis: 20000, lockingScript: buildArbitratedPoolLock({
      buyer: PrivateKey.fromHex('b1'.repeat(32)).toPublicKey(), seller: PrivateKey.fromHex('52'.repeat(32)).toPublicKey(), arbiter: PrivateKey.fromHex('a3'.repeat(32)).toPublicKey()
    }) })
    const fundingRaw = hex(funding.toHex())

    const buyerPrepared = await buyer.preparePoolOpening(fundingRaw, 20000, 800000, 1, seller.publicKey(), arbiterKey)
    expect(Buffer.from(buyerPrepared.refundTemplateRaw).toString('hex')).toBe(find('refund_template').raw_hex)
    const sellerPrepared = await seller.preparePoolOpening(buyerPrepared.request.bytes(), 20000)
    const opening = buyer.completePoolOpening(buyerPrepared, sellerPrepared.response.bytes())
    expect(Buffer.from(opening.mergedRefundRaw).toString('hex')).toBe(find('refund_merged').raw_hex)
    const forgedFunding = new Transaction()
    forgedFunding.addInput({ sourceTXID: '01'.repeat(32), sourceOutputIndex: 0, sequence: 0xffffffff, unlockingScript: new UnlockingScript() })
    forgedFunding.addOutput({ satoshis: 19999, lockingScript: buildArbitratedPoolLock({
      buyer: PrivateKey.fromHex('b1'.repeat(32)).toPublicKey(), seller: PrivateKey.fromHex('52'.repeat(32)).toPublicKey(), arbiter: PrivateKey.fromHex('a3'.repeat(32)).toPublicKey()
    }) })
    const forgedKind4 = encodeFundingTransactionDelivery(opening.refundTemplateTxID, hex(forgedFunding.toHex()))
    await expect(seller.acceptFundingTransaction(sellerPrepared, forgedKind4.bytes())).rejects.toMatchObject({ code: 'invalid_evidence' })
    expect(await seller.acceptFundingTransaction(sellerPrepared, buyer.deliverFundingTransaction(opening, fundingRaw).bytes())).toEqual(fundingRaw)

    const authorizationID = Uint8Array.from({ length: 32 }, () => 1)
    const state = { previousRaw: opening.mergedRefundRaw, poolOutputSatoshis: 20000, paymentSequence: 3, sellerAmountSatoshis: 100, minerFeeRateSatoshisPerKilobyte: 1 }
    const payment = await buyer.preparePayment(opening.engine, state, authorizationID)
    expect(Buffer.from(payment.unsignedRaw).toString('hex')).toBe(find('payment_unsigned').raw_hex)
    const merged = await seller.completePayment(sellerPrepared.engine, state, payment.paymentUpdate.bytes(), authorizationID)
    expect(Buffer.from(merged).toString('hex')).toBe(find('payment_merged').raw_hex)
  })

  it('Workflow 冻结 Signer 身份并在换钥后零次调用签名能力', async () => {
    const signer = new RotatingSigner(0x44)
    const buyer = new BuyerWorkflow(signer)
    signer.byte = 0x45
    await expect(buyer.requestContent({
      fileQuoteTermsID: Uint8Array.from({ length: 32 }, () => 1), refundTemplateTxID: Uint8Array.from({ length: 32 }, () => 2),
      paymentSequence: 1, sellerAmountAfterSatoshis: 1n, contentHashes: [Uint8Array.from({ length: 32 }, () => 3)],
      deliveryDeadlineUnixSeconds: 2_000_000_000n
    })).rejects.toMatchObject({ code: 'unauthorized', field: 'buyer_signer' })
    expect(signer.calls).toBe(0)
  })

  it('三个 Workflow 在构造时拒绝无效压缩公钥且不调用签名能力', () => {
    const invalidSigner: Signer = {
      publicKey: () => new Uint8Array(33),
      sign: async () => { throw new Error('无效身份不得进入签名') }
    }
    for (const create of [
      () => new BuyerWorkflow(invalidSigner),
      () => new SellerWorkflow(invalidSigner),
      () => new ArbiterWorkflow(invalidSigner)
    ]) expect(create).toThrowError(expect.objectContaining({ code: 'invalid_evidence' }))
  })

  it('Kind 9 只能消费当前 ArbiterWorkflow 的 Prepare 产物', async () => {
    const arbiter = new ArbiterWorkflow(new TestSigner(0x33))
    expect((arbiter as unknown as Record<string, unknown>).signArbitrationReceipt).toBeUndefined()
    await expect(arbiter.signPreparedArbitration({} as never, { nowUnixSeconds: 1_900_000_000n, blockHeight: 1 })).rejects.toMatchObject({ code: 'invalid_evidence', field: 'prepared' })
  })

  it('仲裁 candidate 由 Claim 唯一重建并逐字节等于 Go 真值', async () => {
    const findTransaction = (name: string): TransactionManifest['entries'][number] => transactionManifest.entries.find(entry => entry.name === name)!
    const candidateInput = {
      poolOutputSatoshis: 20000n, refundTemplateRaw: hex(findTransaction('refund_template').raw_hex!),
      paymentSequence: 7n, sellerAmountSatoshis: 200n, arbiterAmountSatoshis: 500n
    }
    const rebuilt = buildArbitrationCandidate(candidateInput)
    expect(Buffer.from(rebuilt).toString('hex')).toBe(findTransaction('arbitration_candidate').raw_hex)

    const signer = new RotatingSigner(0x33)
    const changedVersion = new Uint8Array(rebuilt); changedVersion[0] ^= 1
    expect(() => verifyArbitrationCandidate(candidateInput, changedVersion)).toThrowError(expect.objectContaining({ code: 'state_conflict' }))
    const changedLockTime = new Uint8Array(rebuilt); changedLockTime[changedLockTime.length - 1] ^= 1
    expect(() => verifyArbitrationCandidate(candidateInput, changedLockTime)).toThrowError(expect.objectContaining({ code: 'state_conflict' }))
    expect(signer.calls).toBe(0)

    const kind8 = manifest.entries.find(entry => entry.kind === 8)!
    const arbiter = new ArbiterWorkflow(signer)
    const prepared = arbiter.prepareArbitration({ nowUnixSeconds: 1_900_000_000n }, hex(kind8.exact_hex), 500n)
    const signed = await arbiter.signPreparedArbitration(prepared, { nowUnixSeconds: 1_900_000_000n })
    expect(signed.response.kind).toBe(9)
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
      expect(error).toBeInstanceOf(WireError)
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
      const outer = decodeCanonical(hex(entry.exact_hex))
      if (!Array.isArray(outer) || !(outer[2] instanceof Uint8Array) || !(outer[3] instanceof Uint8Array)) throw new Error('fixture 结构错误')
      const publicKey = entry.kind === 1 ? outer[3] : keys.get(entry.kind)!
      const signature = entry.kind === 1 ? outer[4] : outer[3]
      if (!(signature instanceof Uint8Array)) throw new Error('fixture 签名字段错误')
      expect(wireSignatureDigest(entry.kind, outer[2])).toHaveLength(32)
      expect(() => verifyWireDocument(publicKey, entry.kind, outer[2], signature)).not.toThrow()
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
    const outer = (name: string): any[] => {
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

    const kind5 = outer('content_request'); const authorization = child(kind5[2] as Uint8Array)
    const hashes = child(authorization[4] as Uint8Array) as Uint8Array[]
    expect((await createContentRequest(new TestSigner(0x44), {
      fileQuoteTermsID: authorization[0] as Uint8Array,
      refundTemplateTxID: authorization[1] as Uint8Array,
      paymentSequence: Number(authorization[2]),
      sellerAmountAfterSatoshis: authorization[3] as bigint,
      contentHashes: hashes,
      deliveryDeadlineUnixSeconds: authorization[5] as bigint
    })).bytes()).toEqual(hex(entry('content_request').exact_hex))

    const kind6 = outer('content_delivery'); const delivery = child(kind6[2] as Uint8Array)
    expect((await createContentDelivery(new TestSigner(0x22), delivery[0] as Uint8Array, payloads(kind6[4] as Uint8Array))).bytes()).toEqual(hex(entry('content_delivery').exact_hex))

    const kind8 = outer('arbitration_request')
    expect((await createArbitrationRequest(new TestSigner(0x22), kind8[2] as Uint8Array, payloads(kind8[4] as Uint8Array))).bytes()).toEqual(hex(entry('arbitration_request').exact_hex))

    const kind9 = outer('arbitration_response')
    expect((await createArbitrationResponse(new TestSigner(0x33), kind9[2] as Uint8Array)).bytes()).toEqual(hex(entry('arbitration_response').exact_hex))

    const kind10 = outer('content_retrieval_request'); const request = child(kind10[2] as Uint8Array)
    expect((await createContentRetrievalRequest(new TestSigner(0x55), request[0] as Uint8Array, request[1] as Uint8Array)).bytes()).toEqual(hex(entry('content_retrieval_request').exact_hex))

    const unavailableOuter = outer('content_retrieval_unavailable'); const unavailable = child(unavailableOuter[2] as Uint8Array)
    expect((await createContentRetrievalUnavailable(new TestSigner(0x33), unavailable[0] as Uint8Array, Number(unavailable[2]) as 0 | 1 | 2)).bytes()).toEqual(hex(entry('content_retrieval_unavailable').exact_hex))

    const availableOuter = outer('content_retrieval_available'); const available = child(availableOuter[2] as Uint8Array)
    expect((await createContentRetrievalAvailable(new TestSigner(0x33), available[0] as Uint8Array, payloads(availableOuter[4] as Uint8Array))).bytes()).toEqual(hex(entry('content_retrieval_available').exact_hex))
  })
})
