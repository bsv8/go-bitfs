import { LockingScript, PublicKey, Transaction } from '@bsv/sdk'
import {
  Protocol as MultisigPoolProtocol,
  Version as MultisigPoolVersion,
  buildArbitratedPoolLock,
  buildArbitratedPoolOpeningState,
  buildArbitratedPoolState,
  mergeArbitratedPoolBuyerSellerSignatures,
  mergeArbitratedPoolSellerArbiterSignatures,
  verifyArbitratedPoolArbiterSignature,
  verifyArbitratedPoolBuyerSignature,
  verifyArbitratedPoolSellerSignature,
  type ArbitratedPoolRoles
} from 'keymaster-multisig-pool'
import { WireError } from './errors.js'
import { type Signer, verifyDigestSignature } from './protocol.js'
import { forkIDAllDigest, SIGHASH_FORKID_ALL } from './transaction.js'

/** 费用池三方角色公钥，顺序固定为买方、卖方、仲裁方。 */
export interface PoolPublicKeys {
  buyerPublicKey: Uint8Array
  sellerPublicKey: Uint8Array
  arbiterPublicKey: Uint8Array
}

/** 构造下一笔累计状态交易的输入。金额均为绝对 satoshi，不是增量。 */
export interface PoolStateInput {
  previousRaw: Uint8Array
  poolOutputSatoshis: number
  paymentSequence: number
  sellerAmountSatoshis: number
  arbiterAmountSatoshis?: number
  minerFeeRateSatoshisPerKilobyte: number
  /** 可选 nLockTime；立即关闭传 4294967295。 */
  lockTime?: number
}

/** 完整开池证据；用于卖方接收 Kind 4 时重建并验证 funding/refund 关系。 */
export interface OpeningEvidenceInput {
  fundingTransactionRaw: Uint8Array
  refundTemplateRaw: Uint8Array
  buyerRefundSignature: Uint8Array
  sellerRefundSignature: Uint8Array
  poolOutputSatoshis: number
  minerFeeRateSatoshisPerKilobyte: number
}

/** TypeScript 到 keymaster-multisig-pool v4 的无状态适配边界。 */
export class MultisigPoolEngine {
  readonly #roles: ArbitratedPoolRoles
  readonly #keys: PoolPublicKeys
  readonly #lockingScript: Uint8Array

  constructor (keys: Readonly<PoolPublicKeys>) {
    this.#keys = { buyerPublicKey: copy(keys.buyerPublicKey), sellerPublicKey: copy(keys.sellerPublicKey), arbiterPublicKey: copy(keys.arbiterPublicKey) }
    this.#roles = {
      buyer: PublicKey.fromDER(Array.from(this.#keys.buyerPublicKey)),
      seller: PublicKey.fromDER(Array.from(this.#keys.sellerPublicKey)),
      arbiter: PublicKey.fromDER(Array.from(this.#keys.arbiterPublicKey))
    }
    if (equal(this.#keys.buyerPublicKey, this.#keys.sellerPublicKey) || equal(this.#keys.buyerPublicKey, this.#keys.arbiterPublicKey) || equal(this.#keys.sellerPublicKey, this.#keys.arbiterPublicKey)) throw new WireError('invalid_evidence', 0, 'participant_public_keys', '买方、卖方、仲裁方公钥必须互不相同')
    this.#lockingScript = Uint8Array.from(buildArbitratedPoolLock(this.#roles).toBinary())
  }

  /** 返回角色顺序固定的 2-of-3 locking script 副本（105 字节）。 */
  lockingScript (): Uint8Array { return copy(this.#lockingScript) }

  /** 返回创建 engine 时固定的三方角色公钥副本。 */
  publicKeys (): PoolPublicKeys { return { buyerPublicKey: copy(this.#keys.buyerPublicKey), sellerPublicKey: copy(this.#keys.sellerPublicKey), arbiterPublicKey: copy(this.#keys.arbiterPublicKey) } }

  /** 从资金交易 output[0] 构造未签名退款模板。 */
  async buildOpeningState (fundingTransactionRaw: Uint8Array, poolOutputSatoshis: number, expiryLockTime: number, minerFeeRateSatoshisPerKilobyte: number): Promise<Uint8Array> {
    const funding = Transaction.fromHex(toHex(fundingTransactionRaw))
    const transaction = await buildArbitratedPoolOpeningState(funding, poolOutputSatoshis, this.#roles, expiryLockTime, minerFeeRateSatoshisPerKilobyte)
    return fromHex(transaction.toHex())
  }

  /**
   * 验证完整 Opening：funding output[0] 的金额/脚本、退款模板 funding outpoint、
   * locktime/fee 重建字节，以及 Buyer/Seller 两个 detached 退款签名。
   */
  async verifyOpeningEvidence (evidence: Readonly<OpeningEvidenceInput>): Promise<void> {
    let funding: Transaction
    try { funding = Transaction.fromHex(toHex(evidence.fundingTransactionRaw)) } catch { throw new WireError('invalid_evidence', 4, 'funding_transaction_raw', '资金交易无法解析') }
    if (funding.toHex() !== toHex(evidence.fundingTransactionRaw)) throw new WireError('non_canonical', 4, 'funding_transaction_raw', '资金交易不是规范序列化')
    const poolOutput = funding.outputs[0]
    if (poolOutput == null || poolOutput.satoshis !== evidence.poolOutputSatoshis || !equal(Uint8Array.from(poolOutput.lockingScript.toBinary()), this.#lockingScript)) throw new WireError('invalid_evidence', 4, 'funding_transaction_raw', '资金交易 output[0] 与开池金额或三方锁定脚本不一致')
    let refund: Transaction
    try { refund = Transaction.fromHex(toHex(evidence.refundTemplateRaw)) } catch { throw new WireError('invalid_evidence', 4, 'refund_template_raw', '退款模板无法解析') }
    const rebuilt = await this.buildOpeningState(evidence.fundingTransactionRaw, evidence.poolOutputSatoshis, refund.lockTime, evidence.minerFeeRateSatoshisPerKilobyte)
    if (!equal(rebuilt, evidence.refundTemplateRaw)) throw new WireError('invalid_evidence', 4, 'refund_template_raw', '退款模板未消费当前 funding output 或交易规则不一致')
    this.mergeBuyerSeller(evidence.refundTemplateRaw, evidence.poolOutputSatoshis, evidence.buyerRefundSignature, evidence.sellerRefundSignature)
  }

  /** 从上一完整状态确定性构造下一笔未签名付款/关闭/仲裁 candidate。 */
  async buildState (input: Readonly<PoolStateInput>): Promise<Uint8Array> {
    const previous = this.#withPoolSource(input.previousRaw, input.poolOutputSatoshis)
    const transaction = await buildArbitratedPoolState({
      protocol: MultisigPoolProtocol, version: MultisigPoolVersion, previousState: previous,
      sequence: input.paymentSequence, sellerAmount: input.sellerAmountSatoshis,
      arbiterAmount: input.arbiterAmountSatoshis ?? 0, poolAmount: input.poolOutputSatoshis,
      roles: this.#roles, feeRate: input.minerFeeRateSatoshisPerKilobyte,
      ...(input.lockTime == null ? {} : { lockTime: input.lockTime })
    })
    return fromHex(transaction.toHex())
  }

  /** 请求受约束 Signer 对确定性 ForkID|All digest 签名，并返回 DER || 0x41。 */
  async signState (signer: Signer, unsignedRaw: Uint8Array, poolOutputSatoshis: number, signal?: AbortSignal): Promise<Uint8Array> {
    const publicKey = signer.publicKey()
    if (!this.#isParticipant(publicKey)) throw new WireError('unauthorized', 0, 'signer_public_key', 'Signer 不是本费用池参与方')
    const digest = forkIDAllDigest(unsignedRaw, 0, BigInt(poolOutputSatoshis), this.#lockingScript)
    let der: Uint8Array
    try { der = new Uint8Array(await signer.sign({ purpose: 'transaction', wireKind: 0, digest: copy(digest) }, signal)) } catch { throw new WireError('signer_unavailable', 0, 'signature', 'Signer 无法完成交易签名') }
    verifyDigestSignature(publicKey, digest, der)
    const output = new Uint8Array(der.byteLength + 1); output.set(der); output[der.byteLength] = SIGHASH_FORKID_ALL
    return output
  }

  /** 验证并按 Buyer/Seller 顺序合并两个 detached 交易签名。 */
  mergeBuyerSeller (unsignedRaw: Uint8Array, poolOutputSatoshis: number, buyerSignature: Uint8Array, sellerSignature: Uint8Array): Uint8Array {
    const state = this.#withPoolSource(unsignedRaw, poolOutputSatoshis)
    if (!verifyArbitratedPoolBuyerSignature(state, poolOutputSatoshis, this.#roles, Array.from(buyerSignature)) || !verifyArbitratedPoolSellerSignature(state, poolOutputSatoshis, this.#roles, Array.from(sellerSignature))) throw new WireError('invalid_signature', 0, 'transaction_signature', '买方或卖方交易签名无效')
    return fromHex(mergeArbitratedPoolBuyerSellerSignatures(state, poolOutputSatoshis, this.#roles, Array.from(buyerSignature), Array.from(sellerSignature)).toHex())
  }

  /** 验证并按 Seller/Arbiter 顺序合并仲裁付款签名。 */
  mergeSellerArbiter (unsignedRaw: Uint8Array, poolOutputSatoshis: number, sellerSignature: Uint8Array, arbiterSignature: Uint8Array): Uint8Array {
    const state = this.#withPoolSource(unsignedRaw, poolOutputSatoshis)
    if (!verifyArbitratedPoolSellerSignature(state, poolOutputSatoshis, this.#roles, Array.from(sellerSignature)) || !verifyArbitratedPoolArbiterSignature(state, poolOutputSatoshis, this.#roles, Array.from(arbiterSignature))) throw new WireError('invalid_signature', 0, 'transaction_signature', '卖方或仲裁方交易签名无效')
    return fromHex(mergeArbitratedPoolSellerArbiterSignatures(state, poolOutputSatoshis, this.#roles, Array.from(sellerSignature), Array.from(arbiterSignature)).toHex())
  }

  #withPoolSource (raw: Uint8Array, poolOutputSatoshis: number): Transaction {
    const state = Transaction.fromHex(toHex(raw))
    const input = state.inputs[0]
    if (input == null || state.inputs.length !== 1) throw new WireError('invalid_evidence', 0, 'raw_transaction', '池状态必须恰好一个输入')
    const source = new Transaction()
    source.addOutput({ satoshis: poolOutputSatoshis, lockingScript: LockingScript.fromHex(toHex(this.#lockingScript)) })
    input.sourceTransaction = source
    return state
  }

  #isParticipant (key: Uint8Array): boolean { return equal(key, this.#keys.buyerPublicKey) || equal(key, this.#keys.sellerPublicKey) || equal(key, this.#keys.arbiterPublicKey) }
}

function copy (value: Uint8Array): Uint8Array { return new Uint8Array(value) }
function equal (left: Uint8Array, right: Uint8Array): boolean { return left.byteLength === right.byteLength && left.every((value, index) => value === right[index]) }
function toHex (value: Uint8Array): string { return Array.from(value, byte => byte.toString(16).padStart(2, '0')).join('') }
function fromHex (value: string): Uint8Array {
  if (value.length % 2 !== 0 || !/^[0-9a-f]*$/iu.test(value)) throw new TypeError('hex 字符串无效')
  const output = new Uint8Array(value.length / 2)
  for (let index = 0; index < output.length; index++) output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16)
  return output
}

export { MultisigPoolProtocol, MultisigPoolVersion }
