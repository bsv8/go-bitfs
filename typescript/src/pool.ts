import { LockingScript, PublicKey, Transaction, UnlockingScript } from '@bsv/sdk'
import {
  Protocol as MultisigPoolProtocol,
  Version as MultisigPoolVersion,
  buildArbitratedPoolLock,
  buildArbitratedPoolOpeningState,
  buildArbitratedPoolOutputScripts,
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
import { buildArbitrationCandidate, forkIDAllDigest, preflightTransactionRaw, SIGHASH_FORKID_ALL, transactionID, validateArbitrationClaimStructure } from './transaction.js'
import type { OpeningProof } from './evidence.js'

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

/** 从开池证据即时派生的只读视图；不属于协议字段，不参与编码或持久化。 */
export interface OpeningDetails {
  /** 费用池统一关联 ID：规范退款模板交易的 TxID（内部字节序）。 */
  refundTemplateTxId: Uint8Array
  /** 退款模板所花费的资金交易 outpoint TxID（内部字节序）。 */
  fundingTxId: Uint8Array
  /** 资金池输出聪数；重建 candidate 时作为输入金额。 */
  poolOutputSatoshis: bigint
  /** 角色顺序固定 [Buyer, Seller, Arbiter] 的 105 字节 2-of-3 锁定脚本。 */
  poolLockingScript: Uint8Array
  /** 退款模板 nLockTime 原始值（uint32）。 */
  refundLockTime: number
}

/** 角色签名完整合并后的付款状态。 */
export interface PaymentState {
  /** 所属费用池统一关联 ID（规范退款模板 TxID，内部字节序）。 */
  refundTemplateTxId: Uint8Array
  /** 签名完整的付款状态交易原文。 */
  rawTx: Uint8Array
  /** 该状态在资金池付款链中的序号。 */
  paymentSequence: number
  /** 交易向买方分配的金额（绝对聪数）。 */
  buyerAmountSatoshis: bigint
  /** 交易向卖方分配的累计金额（绝对聪数）。 */
  sellerAmountSatoshis: bigint
  /** 交易向仲裁方分配的绝对金额（聪）；普通付款恒为零。 */
  arbiterAmountSatoshis: bigint
  /** 买方 detached 交易签名；非买方路径为空。 */
  buyerTransactionSignature: Uint8Array
  /** 卖方 detached 交易签名。 */
  sellerTransactionSignature: Uint8Array
  /** 仲裁方 detached 交易签名；非仲裁路径为空。 */
  arbiterTransactionSignature: Uint8Array
  /** 创建该状态时引用的资金池输出金额（绝对聪数）。 */
  poolOutputSatoshis: bigint
  /** 创建该状态时引用的资金池输出锁定脚本。 */
  poolLockingScript: Uint8Array
}

/** 未签名费用池状态：交易原文与公开元数据（unlocking script 必须为空）。 */
export interface UnsignedPaymentState {
  /** 未签名交易原文。 */
  rawTx: Uint8Array
  /** 目标付款序号。 */
  paymentSequence: number
  /** 买方绝对分配额（聪）。 */
  buyerAmountSatoshis: bigint
  /** 卖方绝对累计金额（聪）。 */
  sellerAmountSatoshis: bigint
  /** 仲裁方绝对分配额（聪）。 */
  arbiterAmountSatoshis: bigint
  /** 被花费费用池输出金额（聪）。 */
  poolOutputSatoshis: bigint
  /** 被花费费用池输出锁定脚本。 */
  poolLockingScript: Uint8Array
}

/** 独立的仲裁 candidate：未签名交易原文与重建所需的全部公开元数据。 */
export interface ArbitrationCandidate {
  /** 未签名仲裁交易原文（输入 unlocking script 为空）。 */
  unsignedRaw: Uint8Array
  /** 仲裁所属费用池统一关联 ID。 */
  refundTemplateTxId: Uint8Array
  /** 被花费的资金 outpoint TxID（内部字节序）。 */
  fundingTxId: Uint8Array
  /** 仲裁后买方的绝对分配额（聪）。 */
  buyerAmountSatoshis: bigint
  /** 仲裁后卖方的绝对累计金额（聪）。 */
  sellerAmountSatoshis: bigint
  /** 仲裁方的绝对仲裁费（正数，聪）。 */
  arbiterAmountSatoshis: bigint
  /** 被花费费用池输出金额（聪）。 */
  poolOutputSatoshis: bigint
  /** 被花费费用池输出锁定脚本。 */
  poolLockingScript: Uint8Array
}

const FINAL_POOL_SEQUENCE = 0xffffffff
const MAX_SAFE_AMOUNT = BigInt(Number.MAX_SAFE_INTEGER)
const FEE_PROBE_AMOUNT = (1n << 48n) - 1n

type PoolRole = 'buyer' | 'seller' | 'arbiter'

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
    const funding = parseCanonical(fundingTransactionRaw)
    const transaction = await buildArbitratedPoolOpeningState(funding, poolOutputSatoshis, this.#roles, expiryLockTime, minerFeeRateSatoshisPerKilobyte)
    return fromHex(transaction.toHex())
  }

  /**
   * 验证完整 Opening：funding output[0] 的金额/脚本、退款模板 funding outpoint、
   * locktime/fee 重建字节，以及 Buyer/Seller 两个 detached 退款签名。
   */
  async verifyOpeningEvidence (evidence: Readonly<OpeningEvidenceInput>): Promise<void> {
    const funding = parseCanonical(evidence.fundingTransactionRaw)
    const poolOutput = funding.outputs[0]
    if (poolOutput == null || poolOutput.satoshis !== evidence.poolOutputSatoshis || !equal(Uint8Array.from(poolOutput.lockingScript.toBinary()), this.#lockingScript)) throw new WireError('invalid_evidence', 4, 'funding_transaction_raw', '资金交易 output[0] 与开池金额或三方锁定脚本不一致')
    const refund = parseCanonical(evidence.refundTemplateRaw)
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

  /** 以指定角色签署未签名交易：先校验 Signer 公钥等于该角色，再签名并自验。 */
  async signRole (signer: Signer, role: PoolRole, unsignedRaw: Uint8Array, poolOutputSatoshis: bigint, signal?: AbortSignal): Promise<Uint8Array> {
    const expected = this.#roleKey(role)
    const publicKey = new Uint8Array(signer.publicKey())
    if (!equal(publicKey, expected)) throw new WireError('unauthorized', 0, `${role}_public_key`, `${role} Signer 公钥与本费用池角色不一致`)
    const amount = amountNumber(poolOutputSatoshis, 'pool_output_satoshis')
    const signature = await this.signState(signer, unsignedRaw, amount, signal)
    try { this.verifyRole(role, unsignedRaw, poolOutputSatoshis, signature) } catch { throw new WireError('invalid_signature', 0, `${role}_transaction_signature`, `${role} 签名自验失败`) }
    return signature
  }

  /** 验证指定角色的 detached 交易签名覆盖精确未签名交易。 */
  verifyRole (role: PoolRole, unsignedRaw: Uint8Array, poolOutputSatoshis: bigint, signature: Uint8Array): void {
    if (signature.byteLength < 2 || signature[signature.byteLength - 1] !== SIGHASH_FORKID_ALL) throw new WireError('invalid_signature', 0, `${role}_transaction_signature`, '交易签名必须使用固定 ForkID|All 标记')
    const state = parseCanonical(unsignedRaw)
    const amount = amountNumber(poolOutputSatoshis, 'pool_output_satoshis')
    setPoolSource(state, poolOutputSatoshis, this.#lockingScript)
    const digest = forkIDAllDigest(unsignedRaw, 0, poolOutputSatoshis, this.#lockingScript)
    try { verifyDigestSignature(this.#roleKey(role), digest, signature.subarray(0, signature.byteLength - 1)) } catch {
      throw new WireError('invalid_signature', 0, `${role}_transaction_signature`, '交易签名不是有效的 low-S DER 或与角色公钥不匹配')
    }
    let valid = false
    try {
      if (role === 'buyer') valid = verifyArbitratedPoolBuyerSignature(state, amount, this.#roles, Array.from(signature))
      else if (role === 'seller') valid = verifyArbitratedPoolSellerSignature(state, amount, this.#roles, Array.from(signature))
      else valid = verifyArbitratedPoolArbiterSignature(state, amount, this.#roles, Array.from(signature))
    } catch {
      throw new WireError('invalid_signature', 0, `${role}_transaction_signature`, '交易签名无效')
    }
    if (!valid) throw new WireError('invalid_signature', 0, `${role}_transaction_signature`, '交易签名无效')
  }

  /** 验证并按 Buyer/Seller 顺序合并两个 detached 交易签名。 */
  mergeBuyerSeller (unsignedRaw: Uint8Array, poolOutputSatoshis: number, buyerSignature: Uint8Array, sellerSignature: Uint8Array): Uint8Array {
    const state = this.#withPoolSource(unsignedRaw, poolOutputSatoshis)
    this.verifyRole('buyer', unsignedRaw, BigInt(poolOutputSatoshis), buyerSignature)
    this.verifyRole('seller', unsignedRaw, BigInt(poolOutputSatoshis), sellerSignature)
    if (!verifyArbitratedPoolBuyerSignature(state, poolOutputSatoshis, this.#roles, Array.from(buyerSignature)) || !verifyArbitratedPoolSellerSignature(state, poolOutputSatoshis, this.#roles, Array.from(sellerSignature))) throw new WireError('invalid_signature', 0, 'transaction_signature', '买方或卖方交易签名无效')
    return fromHex(mergeArbitratedPoolBuyerSellerSignatures(state, poolOutputSatoshis, this.#roles, Array.from(buyerSignature), Array.from(sellerSignature)).toHex())
  }

  /** 验证并按 Seller/Arbiter 顺序合并仲裁付款签名。 */
  mergeSellerArbiter (unsignedRaw: Uint8Array, poolOutputSatoshis: number, sellerSignature: Uint8Array, arbiterSignature: Uint8Array): Uint8Array {
    const state = this.#withPoolSource(unsignedRaw, poolOutputSatoshis)
    this.verifyRole('seller', unsignedRaw, BigInt(poolOutputSatoshis), sellerSignature)
    this.verifyRole('arbiter', unsignedRaw, BigInt(poolOutputSatoshis), arbiterSignature)
    if (!verifyArbitratedPoolSellerSignature(state, poolOutputSatoshis, this.#roles, Array.from(sellerSignature)) || !verifyArbitratedPoolArbiterSignature(state, poolOutputSatoshis, this.#roles, Array.from(arbiterSignature))) throw new WireError('invalid_signature', 0, 'transaction_signature', '卖方或仲裁方交易签名无效')
    return fromHex(mergeArbitratedPoolSellerArbiterSignatures(state, poolOutputSatoshis, this.#roles, Array.from(sellerSignature), Array.from(arbiterSignature)).toHex())
  }

  /**
   * 从退款模板原文唯一重建规范开池状态并推导池金额：模板 output[0] 加上按
   * 费率重建的规范矿工费；重建字节必须与模板逐字节一致。
   */
  async deriveRefundTerms (refundTemplateRaw: Uint8Array, minerFeeRateSatoshisPerKilobyte: bigint): Promise<{ refundTemplateTxId: Uint8Array, fundingTxId: Uint8Array, poolOutputSatoshis: bigint, refund: Transaction }> {
    const refund = parseCanonical(refundTemplateRaw)
    if (refund.inputs.length !== 1 || refund.outputs.length !== 3) throw poolInvalid('退款模板必须恰好一个输入三个输出')
    const input = refund.inputs[0]!
    if (input.sourceOutputIndex !== 0) throw poolInvalid('退款模板必须花费资金输出索引 0')
    if ((input.unlockingScript?.toBinary().length ?? 0) !== 0) throw poolInvalid('退款模板 unlocking script 必须为空')
    if (input.sequence === FINAL_POOL_SEQUENCE) throw poolInvalid('退款模板不能使用最终 sequence')
    const sourceTXID = input.sourceTXID
    if (sourceTXID == null || !/^[0-9a-fA-F]{64}$/u.test(sourceTXID)) throw poolInvalid('退款模板 funding outpoint 无效')
    const fundingTxId = reverse(fromHex(sourceTXID))
    const lockTime = refund.lockTime
    const feeRate = amountNumber(minerFeeRateSatoshisPerKilobyte, 'miner_fee_rate_satoshis_per_kilobyte')
    const probe = await this.#buildCanonicalOpeningState(sourceTXID, FEE_PROBE_AMOUNT, lockTime, feeRate)
    const canonicalFee = FEE_PROBE_AMOUNT - outputAmount(probe.outputs[0]!)
    const poolOutputSatoshis = outputAmount(refund.outputs[0]!) + canonicalFee
    if (poolOutputSatoshis <= 0n || poolOutputSatoshis > MAX_SAFE_AMOUNT) throw poolInvalid('开池金额无效或超过安全整数')
    const expected = await this.#buildCanonicalOpeningState(sourceTXID, poolOutputSatoshis, lockTime, feeRate)
    if (expected.toHex() !== refund.toHex()) throw poolInvalid('退款模板不是规范 MultisigPool v4 状态')
    return { refundTemplateTxId: transactionID(refundTemplateRaw), fundingTxId, poolOutputSatoshis, refund }
  }

  /** 从完整开池证据即时推导关联 ID、outpoint、金额、脚本与 nLockTime。 */
  async deriveOpeningDetails (proof: OpeningProof): Promise<OpeningDetails> {
    validateOpeningProofFields(proof)
    const terms = await this.deriveRefundTerms(proof.refundTemplateRaw, proof.minerFeeRateSatoshisPerKilobyte)
    if (proof.fundingTransactionRaw.byteLength > 0) {
      const funding = parseCanonical(proof.fundingTransactionRaw)
      if (!equal(transactionID(proof.fundingTransactionRaw), terms.fundingTxId)) throw poolInvalid('资金交易与退款 outpoint 不一致')
      const output = funding.outputs[0]
      if (output == null || outputAmount(output) !== terms.poolOutputSatoshis || !equal(Uint8Array.from(output.lockingScript.toBinary()), this.#lockingScript)) throw poolInvalid('资金池输出与退款证据不一致')
    }
    return { refundTemplateTxId: terms.refundTemplateTxId, fundingTxId: terms.fundingTxId, poolOutputSatoshis: terms.poolOutputSatoshis, poolLockingScript: this.lockingScript(), refundLockTime: terms.refund.lockTime }
  }

  /** 完整验证开池证据：规范模板重建、资金交易关系与买卖双方退款签名。 */
  async verifyOpening (proof: OpeningProof): Promise<void> {
    validateOpeningProofFields(proof)
    if (proof.fundingTransactionRaw.byteLength === 0) throw poolInvalid('完整开池验证需要资金交易原文')
    const details = await this.deriveOpeningDetails(proof)
    const refund = parseCanonical(proof.refundTemplateRaw)
    const input = refund.inputs[0]!
    if (!equal(serializedTxId(input), details.fundingTxId) || input.sourceOutputIndex !== 0) throw poolInvalid('退款交易未花费开池 outpoint')
    setPoolSource(refund, details.poolOutputSatoshis, details.poolLockingScript)
    this.verifyRole('buyer', proof.refundTemplateRaw, details.poolOutputSatoshis, proof.buyerRefundSignature)
    this.verifyRole('seller', proof.refundTemplateRaw, details.poolOutputSatoshis, proof.sellerRefundSignature)
  }

  /** 合并双方退款签名，返回可广播的完整退款交易原文。 */
  async buildRefundSubmission (proof: OpeningProof): Promise<Uint8Array> {
    await this.verifyOpening(proof)
    const details = await this.deriveOpeningDetails(proof)
    return this.mergeBuyerSeller(proof.refundTemplateRaw, Number(details.poolOutputSatoshis), proof.buyerRefundSignature, proof.sellerRefundSignature)
  }

  /** 解析完整签名付款状态并分类角色签名。 */
  async parsePaymentState (rawTx: Uint8Array, opening: OpeningProof): Promise<PaymentState> {
    const { state, details } = await this.#parseAndCheckState(rawTx, opening)
    const input = state.inputs[0]!
    if ((input.unlockingScript?.toBinary().length ?? 0) === 0) throw poolInvalid('付款状态必须是完整签名交易')
    const signatures = extractSignatures(input.unlockingScript!)
    const poolAmount = details.poolOutputSatoshis
    const cleared = parseCanonical(fromHex(state.toHex()))
    cleared.inputs[0]!.unlockingScript = new UnlockingScript()
    setPoolSource(cleared, poolAmount, details.poolLockingScript)
    const result: PaymentState = {
      refundTemplateTxId: details.refundTemplateTxId,
      rawTx: copy(fromHex(state.toHex())),
      paymentSequence: input.sequence ?? 0,
      buyerAmountSatoshis: outputAmount(state.outputs[0]!),
      sellerAmountSatoshis: outputAmount(state.outputs[1]!),
      arbiterAmountSatoshis: outputAmount(state.outputs[2]!),
      buyerTransactionSignature: new Uint8Array(),
      sellerTransactionSignature: new Uint8Array(),
      arbiterTransactionSignature: new Uint8Array(),
      poolOutputSatoshis: poolAmount,
      poolLockingScript: copy(details.poolLockingScript)
    }
    for (const signature of signatures) {
      const matches: PoolRole[] = []
      const unsignedRaw = fromHex(cleared.toHex())
      for (const role of ['buyer', 'seller', 'arbiter'] as const) {
        try { this.verifyRole(role, unsignedRaw, poolAmount, signature); matches.push(role) } catch {}
      }
      if (matches.length === 0) throw new WireError('invalid_signature', 0, 'transaction_signature', '付款签名不是有效的 low-S 角色签名')
      if (matches.length > 1) throw new WireError('invalid_signature', 0, 'transaction_signature', '付款签名同时匹配多个费用池角色')
      const role = matches[0]!
      if (role === 'buyer') {
        if (result.buyerTransactionSignature.byteLength !== 0) throw poolInvalid('买方签名重复')
        result.buyerTransactionSignature = copy(signature)
      } else if (role === 'seller') {
        if (result.sellerTransactionSignature.byteLength !== 0) throw poolInvalid('卖方签名重复')
        result.sellerTransactionSignature = copy(signature)
      } else {
        if (result.arbiterTransactionSignature.byteLength !== 0) throw poolInvalid('仲裁方签名重复')
        result.arbiterTransactionSignature = copy(signature)
      }
    }
    const hasBuyer = result.buyerTransactionSignature.byteLength !== 0
    const hasArbiter = result.arbiterTransactionSignature.byteLength !== 0
    if (result.sellerTransactionSignature.byteLength === 0 || hasBuyer === hasArbiter) throw poolInvalid('付款签名必须构成 Buyer+Seller 或 Seller+Arbiter')
    return result
  }

  /** 完整验证未签名普通池候选，并返回由交易原文派生的只读元数据。 */
  async parseUnsignedPaymentState (rawTx: Uint8Array, opening: OpeningProof): Promise<UnsignedPaymentState> {
    const { state, details } = await this.#parseAndCheckState(rawTx, opening)
    if ((state.inputs[0]!.unlockingScript?.toBinary().length ?? 0) !== 0) throw poolInvalid('未签名付款必须具有空 unlocking script')
    const arbiterAmountSatoshis = outputAmount(state.outputs[2]!)
    if (arbiterAmountSatoshis !== 0n) throw poolInvalid('普通池候选不能向仲裁方付款')
    return {
      rawTx: copy(rawTx),
      paymentSequence: state.inputs[0]!.sequence ?? 0,
      buyerAmountSatoshis: outputAmount(state.outputs[0]!),
      sellerAmountSatoshis: outputAmount(state.outputs[1]!),
      arbiterAmountSatoshis,
      poolOutputSatoshis: details.poolOutputSatoshis,
      poolLockingScript: copy(details.poolLockingScript)
    }
  }

  /** 验证普通（Buyer+Seller）已接受付款状态。 */
  async verifyAcceptedPayment (state: PaymentState, opening: OpeningProof): Promise<void> {
    await this.#verifyComplete(state, opening, false)
  }

  /** 验证仲裁（Seller+Arbiter）付款状态。 */
  async verifyArbitratedPayment (state: PaymentState, opening: OpeningProof): Promise<void> {
    await this.#verifyComplete(state, opening, true)
  }

  /** 验证最终关闭状态（sequence = 0xffffffff，Buyer+Seller）。 */
  async verifyCompletedFinalPayment (state: PaymentState, opening: OpeningProof): Promise<void> {
    if (state.paymentSequence !== FINAL_POOL_SEQUENCE) throw poolInvalid('付款状态不是最终结算')
    await this.#verifyComplete(state, opening, false)
  }

  /** 验证已保存付款是否对应指定未签名候选。 */
  async paymentStateMatchesUnsigned (state: PaymentState, unsignedRaw: Uint8Array, opening: OpeningProof): Promise<boolean> {
    try { await this.verifyAcceptedPayment(state, opening) } catch {
      await this.verifyArbitratedPayment(state, opening)
    }
    const { state: parsed, details } = await this.#parseAndCheckState(state.rawTx, opening)
    parsed.inputs[0]!.unlockingScript = new UnlockingScript()
    setPoolSource(parsed, details.poolOutputSatoshis, details.poolLockingScript)
    return equal(fromHex(parsed.toHex()), unsignedRaw)
  }

  /** 从上一已接受状态构造下一笔未签名累计付款交易。 */
  async buildPaymentUpdate (opening: OpeningProof, previous: PaymentState, paymentSequence: number, sellerAmountAfterSatoshis: bigint): Promise<Uint8Array> {
    await this.verifyOpening(opening)
    const details = await this.deriveOpeningDetails(opening)
    await this.#verifyPrevious(previous, opening)
    if (previous.paymentSequence === FINAL_POOL_SEQUENCE || paymentSequence !== previous.paymentSequence + 1 || paymentSequence === FINAL_POOL_SEQUENCE) throw new WireError('state_conflict', 0, 'payment_sequence', '付款序号必须恰好扩展上一状态')
    await this.#checkPaymentCapacity(details, previous, paymentSequence, sellerAmountAfterSatoshis)
    const previousTx = parseCanonical(previous.rawTx)
    setPoolSource(previousTx, details.poolOutputSatoshis, details.poolLockingScript)
    const state = await buildArbitratedPoolState({
      protocol: MultisigPoolProtocol, version: MultisigPoolVersion, previousState: previousTx,
      sequence: paymentSequence, sellerAmount: amountNumber(sellerAmountAfterSatoshis, 'seller_amount_after_satoshis'),
      arbiterAmount: 0, poolAmount: amountNumber(details.poolOutputSatoshis, 'pool_output_satoshis'),
      roles: this.#roles, feeRate: amountNumber(opening.minerFeeRateSatoshisPerKilobyte, 'miner_fee_rate_satoshis_per_kilobyte')
    })
    return fromHex(state.toHex())
  }

  /** 从调用方选定基准状态构造最终关闭未签名 candidate（lockTime = final）。 */
  async buildImmediateClose (opening: OpeningProof, base: PaymentState, sellerAmountSatoshis: bigint): Promise<Uint8Array> {
    await this.verifyOpening(opening)
    const details = await this.deriveOpeningDetails(opening)
    await this.#verifyPrevious(base, opening)
    if (base.paymentSequence >= FINAL_POOL_SEQUENCE) throw poolInvalid('基准状态已经是最终状态')
    if (sellerAmountSatoshis > details.poolOutputSatoshis) throw poolInvalid('关闭卖方金额超过费用池容量')
    if (sellerAmountSatoshis + base.buyerAmountSatoshis + base.arbiterAmountSatoshis > details.poolOutputSatoshis && sellerAmountSatoshis > details.poolOutputSatoshis - base.arbiterAmountSatoshis) throw poolInvalid('关闭卖方金额溢出费用池输出')
    const previousTx = parseCanonical(base.rawTx)
    setPoolSource(previousTx, details.poolOutputSatoshis, details.poolLockingScript)
    const state = await buildArbitratedPoolState({
      protocol: MultisigPoolProtocol, version: MultisigPoolVersion, previousState: previousTx,
      sequence: FINAL_POOL_SEQUENCE, lockTime: FINAL_POOL_SEQUENCE,
      sellerAmount: amountNumber(sellerAmountSatoshis, 'seller_amount_after_satoshis'), arbiterAmount: 0,
      poolAmount: amountNumber(details.poolOutputSatoshis, 'pool_output_satoshis'),
      roles: this.#roles, feeRate: amountNumber(opening.minerFeeRateSatoshisPerKilobyte, 'miner_fee_rate_satoshis_per_kilobyte')
    })
    return fromHex(state.toHex())
  }

  /** 验证一份付款状态在给定开池证据下由 Buyer+Seller 或 Seller+Arbiter 双签成立。 */
  async verifyPaymentState (state: PaymentState, opening: OpeningProof): Promise<PaymentState> {
    try { await this.verifyAcceptedPayment(state, opening) } catch (error) {
      try { await this.verifyArbitratedPayment(state, opening) } catch { throw error }
    }
    return clonePaymentState(state)
  }

  /** 解析并完整验证一笔 opening 约束下的完整签名交易。 */
  async verifySignedTransaction (rawTx: Uint8Array, opening: OpeningProof): Promise<Uint8Array> {
    const state = await this.parsePaymentState(rawTx, opening)
    try { await this.verifyAcceptedPayment(state, opening) } catch (error) {
      try { await this.verifyArbitratedPayment(state, opening) } catch { throw error }
    }
    const details = await this.deriveOpeningDetails(opening)
    if (!equal(state.refundTemplateTxId, details.refundTemplateTxId)) throw new WireError('state_conflict', 0, 'refund_template_txid', '交易属于另一个费用池')
    return copy(rawTx)
  }

  async #parseAndCheckState (rawTx: Uint8Array, opening: OpeningProof): Promise<{ state: Transaction, details: OpeningDetails }> {
    await this.verifyOpening(opening)
    const details = await this.deriveOpeningDetails(opening)
    const state = parseCanonical(rawTx)
    if (state.inputs.length !== 1 || state.outputs.length !== 3) throw poolInvalid('费用池状态必须恰好一个输入三个输出')
    const input = state.inputs[0]!
    if (!equal(serializedTxId(input), details.fundingTxId) || input.sourceOutputIndex !== 0) throw poolInvalid('费用池状态未花费开池 outpoint')
    setPoolSource(state, details.poolOutputSatoshis, details.poolLockingScript)
    const cleared = freshTransaction(state)
    cleared.inputs[0]!.unlockingScript = new UnlockingScript()
    await this.#verifyCanonicalState(cleared, details, outputAmount(state.outputs[1]!), outputAmount(state.outputs[2]!), input.sequence ?? 0, state.lockTime, opening.minerFeeRateSatoshisPerKilobyte)
    return { state, details }
  }

  async #verifyComplete (state: PaymentState, opening: OpeningProof, arbitration: boolean): Promise<void> {
    if (state == null || opening == null || state.rawTx.byteLength === 0) throw poolInvalid('完整付款状态与开池证据不能为空')
    const { state: parsed, details } = await this.#parseAndCheckState(state.rawTx, opening)
    if (!equal(state.refundTemplateTxId, details.refundTemplateTxId) ||
      state.paymentSequence !== (parsed.inputs[0]!.sequence ?? 0) ||
      state.buyerAmountSatoshis !== outputAmount(parsed.outputs[0]!) ||
      state.sellerAmountSatoshis !== outputAmount(parsed.outputs[1]!) ||
      state.arbiterAmountSatoshis !== outputAmount(parsed.outputs[2]!)) throw poolInvalid('付款状态元数据与交易输出不一致')
    if (arbitration && state.arbiterAmountSatoshis === 0n) throw poolInvalid('仲裁付款必须携带正仲裁金额')
    if (!arbitration && state.arbiterAmountSatoshis !== 0n) throw poolInvalid('普通付款不能向仲裁方付款')
    if ((parsed.inputs[0]!.unlockingScript?.toBinary().length ?? 0) === 0) throw poolInvalid('完整付款必须包含两个签名')
    const signatures = extractSignatures(parsed.inputs[0]!.unlockingScript!)
    if (signatures.length !== 2) throw poolInvalid('完整付款必须恰好两个签名')
    const cleared = parseCanonical(fromHex(parsed.toHex()))
    cleared.inputs[0]!.unlockingScript = new UnlockingScript()
    setPoolSource(cleared, details.poolOutputSatoshis, details.poolLockingScript)
    const amount = amountNumber(details.poolOutputSatoshis, 'pool_output_satoshis')
    const unsignedRaw = fromHex(cleared.toHex())
    if (arbitration) {
      this.verifyRole('seller', unsignedRaw, details.poolOutputSatoshis, signatures[0]!)
      this.verifyRole('arbiter', unsignedRaw, details.poolOutputSatoshis, signatures[1]!)
    } else {
      this.verifyRole('buyer', unsignedRaw, details.poolOutputSatoshis, signatures[0]!)
      this.verifyRole('seller', unsignedRaw, details.poolOutputSatoshis, signatures[1]!)
    }
    const merged = arbitration
      ? mergeArbitratedPoolSellerArbiterSignatures(cleared, amount, this.#roles, Array.from(signatures[0]!), Array.from(signatures[1]!))
      : mergeArbitratedPoolBuyerSellerSignatures(cleared, amount, this.#roles, Array.from(signatures[0]!), Array.from(signatures[1]!))
    if (merged.toHex() !== parsed.toHex()) throw poolInvalid('付款签名与规范 MultisigPool v4 合并结果不一致')
  }

  async #checkPaymentCapacity (details: OpeningDetails, previous: PaymentState, sequence: number, sellerAmountAfterSatoshis: bigint): Promise<void> {
    if (sellerAmountAfterSatoshis < previous.sellerAmountSatoshis || sellerAmountAfterSatoshis > details.poolOutputSatoshis) throw new WireError('insufficient_balance', 0, 'seller_amount_after_satoshis', '付款超过费用池余额')
    if (sequence <= previous.paymentSequence || sequence === FINAL_POOL_SEQUENCE) throw new WireError('state_conflict', 0, 'payment_sequence', '付款序号未扩展当前状态')
  }

  async #verifyPrevious (previous: PaymentState, opening: OpeningProof): Promise<void> {
    if (previous == null) throw poolInvalid('上一付款状态不能为空')
    try { await this.verifyAcceptedPayment(previous, opening) } catch (error) {
      try { await this.verifyArbitratedPayment(previous, opening) } catch { throw poolInvalid('上一付款状态不是有效的已接受状态') }
    }
  }

  async #buildCanonicalOpeningState (sourceTXID: string, poolOutputSatoshis: bigint, lockTime: number, feeRate: number): Promise<Transaction> {
    const scripts = buildArbitratedPoolOutputScripts(this.#roles)
    const previous = new Transaction()
    previous.addInput({ sourceTXID, sourceOutputIndex: 0, sequence: 1, unlockingScript: new UnlockingScript() })
    previous.addOutput({ satoshis: amountNumber(poolOutputSatoshis, 'pool_output_satoshis'), lockingScript: scripts.buyer })
    previous.addOutput({ satoshis: 0, lockingScript: scripts.seller })
    previous.addOutput({ satoshis: 0, lockingScript: scripts.arbiter })
    previous.lockTime = lockTime
    setPoolSource(previous, poolOutputSatoshis, this.#lockingScript)
    return await buildArbitratedPoolState({
      protocol: MultisigPoolProtocol, version: MultisigPoolVersion, previousState: previous,
      sequence: 2, sellerAmount: 0, arbiterAmount: 0,
      poolAmount: amountNumber(poolOutputSatoshis, 'pool_output_satoshis'),
      roles: this.#roles, feeRate, lockTime
    })
  }

  async #verifyCanonicalState (state: Transaction, details: OpeningDetails, sellerAmount: bigint, arbiterAmount: bigint, sequence: number, lockTime: number, feeRateSatoshisPerKilobyte: bigint): Promise<void> {
    if (state.outputs[2] == null || outputAmount(state.outputs[2]) !== arbiterAmount) throw poolInvalid('付款状态仲裁输出与其记录金额不一致')
    if (sequence === 0) throw poolInvalid('付款序号无效')
    if (sequence === FINAL_POOL_SEQUENCE && lockTime !== FINAL_POOL_SEQUENCE) throw new WireError('invalid_evidence', 0, 'lock_time', '最终关闭必须使用最终 nLockTime')
    const previous = parseCanonical(fromHex(state.toHex()))
    previous.inputs[0]!.unlockingScript = new UnlockingScript()
    previous.inputs[0]!.sequence = sequence - 1
    setPoolSource(previous, details.poolOutputSatoshis, details.poolLockingScript)
    const expected = await buildArbitratedPoolState({
      protocol: MultisigPoolProtocol, version: MultisigPoolVersion, previousState: previous,
      sequence, lockTime, sellerAmount: amountNumber(sellerAmount, 'seller_amount_satoshis'),
      arbiterAmount: amountNumber(arbiterAmount, 'arbiter_amount_satoshis'),
      poolAmount: amountNumber(details.poolOutputSatoshis, 'pool_output_satoshis'),
      roles: this.#roles, feeRate: amountNumber(feeRateSatoshisPerKilobyte, 'miner_fee_rate_satoshis_per_kilobyte')
    })
    if (expected.toHex() !== state.toHex()) throw poolInvalid('付款状态不是规范 MultisigPool v4 状态')
  }

  #withPoolSource (raw: Uint8Array, poolOutputSatoshis: number): Transaction {
    const state = parseCanonical(raw)
    setPoolSource(state, BigInt(poolOutputSatoshis), this.#lockingScript)
    return state
  }

  #roleKey (role: PoolRole): Uint8Array {
    return role === 'buyer' ? this.#keys.buyerPublicKey : role === 'seller' ? this.#keys.sellerPublicKey : this.#keys.arbiterPublicKey
  }

  #isParticipant (key: Uint8Array): boolean { return equal(key, this.#keys.buyerPublicKey) || equal(key, this.#keys.sellerPublicKey) || equal(key, this.#keys.arbiterPublicKey) }
}

/** 严格解析角色顺序固定的 2-of-3 P2MS 锁定脚本并恢复三方公钥。 */
export function parseArbitratedPoolLockingScript (raw: Uint8Array): PoolPublicKeys {
  if (raw.byteLength !== 105 || raw[0] !== 0x52 || raw[1] !== 33 || raw[35] !== 33 || raw[69] !== 33 || raw[103] !== 0x53 || raw[104] !== 0xae) throw poolInvalid('费用池脚本不是规范的角色顺序 2-of-3 P2MS')
  const keys = [copy(raw.slice(2, 35)), copy(raw.slice(36, 69)), copy(raw.slice(70, 103))]
  const engine = new MultisigPoolEngine({ buyerPublicKey: keys[0]!, sellerPublicKey: keys[1]!, arbiterPublicKey: keys[2]! })
  if (!equal(engine.lockingScript(), raw)) throw poolInvalid('费用池脚本不是规范的角色顺序脚本')
  return { buyerPublicKey: keys[0]!, sellerPublicKey: keys[1]!, arbiterPublicKey: keys[2]! }
}

/** 从退款模板原文提取 nLockTime（uint32）；模板必须是规范交易编码。 */
export function refundTemplateLockTime (refundTemplateRaw: Uint8Array): number {
  return parseCanonical(refundTemplateRaw).lockTime
}

/** 从完整开池证据派生费用池统一关联 ID（规范退款模板 TxID）。 */
export async function deriveRefundTemplateTxID (opening: OpeningProof): Promise<Uint8Array> {
  const engine = engineFromOpening(opening)
  const details = await engine.deriveOpeningDetails(opening)
  return details.refundTemplateTxId
}

/** 从完整开池证据即时推导 outpoint、金额、脚本与 nLockTime。 */
export async function deriveOpeningDetails (opening: OpeningProof): Promise<OpeningDetails> {
  return await engineFromOpening(opening).deriveOpeningDetails(opening)
}

/** 完整验证开池证据（规范模板、资金关系与双方退款签名）。 */
export async function verifyOpening (opening: OpeningProof): Promise<void> {
  await engineFromOpening(opening).verifyOpening(opening)
}

/** 合并双方退款签名并返回完整退款交易原文。 */
export async function buildRefundSubmission (opening: OpeningProof): Promise<Uint8Array> {
  return await engineFromOpening(opening).buildRefundSubmission(opening)
}

/** 解析完整签名付款状态并分类角色签名。 */
export async function parsePaymentState (rawTx: Uint8Array, opening: OpeningProof): Promise<PaymentState> {
  return await engineFromOpening(opening).parsePaymentState(rawTx, opening)
}

/** 解析未签名费用池状态：形状、outpoint、空 unlocking script 与公开金额。 */
export async function parseUnsignedPayment (rawTx: Uint8Array, opening: OpeningProof): Promise<UnsignedPaymentState> {
  return await engineFromOpening(opening).parseUnsignedPaymentState(rawTx, opening)
}

/** 检查付款更新只做确定性容量与序号边界判断（不读取节点或存储）。 */
export async function checkPaymentCapacity (opening: OpeningProof, previous: PaymentState, paymentSequence: number, sellerAmountAfterSatoshis: bigint): Promise<void> {
  const details = await engineFromOpening(opening).deriveOpeningDetails(opening)
  if (sellerAmountAfterSatoshis < previous.sellerAmountSatoshis || sellerAmountAfterSatoshis > details.poolOutputSatoshis) throw new WireError('insufficient_balance', 0, 'seller_amount_after_satoshis', '付款超过费用池余额')
  if (paymentSequence <= previous.paymentSequence || paymentSequence === FINAL_POOL_SEQUENCE) throw new WireError('state_conflict', 0, 'payment_sequence', '付款序号未扩展当前状态')
}

/** 解析资金交易指定输出的金额与锁定脚本（规范交易校验）。 */
export function parseFundingOutput (rawTx: Uint8Array, outputIndex: number): { satoshis: bigint, lockingScript: Uint8Array } {
  const funding = parseCanonical(rawTx)
  const output = funding.outputs[outputIndex]
  if (output == null) throw poolInvalid('资金交易缺少指定输出')
  return { satoshis: outputAmount(output), lockingScript: Uint8Array.from(output.lockingScript.toBinary()) }
}

/** 验证付款状态由 Buyer+Seller 或 Seller+Arbiter 双签成立。 */
export async function verifyPaymentState (state: PaymentState, opening: OpeningProof): Promise<PaymentState> {
  return await engineFromOpening(opening).verifyPaymentState(state, opening)
}

/** 验证普通（Buyer+Seller）已接受付款状态。 */
export async function verifyAcceptedPayment (state: PaymentState, opening: OpeningProof): Promise<void> {
  await engineFromOpening(opening).verifyAcceptedPayment(state, opening)
}

/** 验证仲裁（Seller+Arbiter）付款状态。 */
export async function verifyArbitratedPayment (state: PaymentState, opening: OpeningProof): Promise<void> {
  await engineFromOpening(opening).verifyArbitratedPayment(state, opening)
}

/** 验证已保存付款是否对应指定未签名候选。 */
export async function paymentStateMatchesUnsigned (state: PaymentState, unsignedRaw: Uint8Array, opening: OpeningProof): Promise<boolean> {
  return await engineFromOpening(opening).paymentStateMatchesUnsigned(state, unsignedRaw, opening)
}

/** 验证最终关闭状态并返回完整交易原文。 */
export async function verifySignedTransaction (rawTx: Uint8Array, opening: OpeningProof): Promise<Uint8Array> {
  return await engineFromOpening(opening).verifySignedTransaction(rawTx, opening)
}

/** 从上一已接受状态构造下一笔未签名累计付款交易。 */
export async function buildPaymentUpdate (opening: OpeningProof, previous: PaymentState, paymentSequence: number, sellerAmountAfterSatoshis: bigint): Promise<Uint8Array> {
  return await engineFromOpening(opening).buildPaymentUpdate(opening, previous, paymentSequence, sellerAmountAfterSatoshis)
}

/** 从调用方选定基准状态构造最终关闭未签名 candidate。 */
export async function buildImmediateClose (opening: OpeningProof, base: PaymentState, sellerAmountSatoshis: bigint): Promise<Uint8Array> {
  return await engineFromOpening(opening).buildImmediateClose(opening, base, sellerAmountSatoshis)
}

/** 验证 Seller/Arbiter 双签名并原子合并仲裁交易。 */
export async function completeArbitratedTransaction (unsignedRaw: Uint8Array, poolOutputSatoshis: bigint, poolLockingScript: Uint8Array, sellerSignature: Uint8Array, arbiterSignature: Uint8Array): Promise<Uint8Array> {
  const keys = parseArbitratedPoolLockingScript(poolLockingScript)
  const engine = new MultisigPoolEngine(keys)
  const unsigned = parseCanonical(unsignedRaw)
  if (unsigned.inputs.length !== 1 || unsigned.outputs.length !== 3) throw poolInvalid('仲裁付款必须恰好一个输入三个输出')
  const input = unsigned.inputs[0]!
  if ((input.unlockingScript?.toBinary().length ?? 0) !== 0) throw poolInvalid('仲裁付款必须未签名')
  if (input.sourceOutputIndex !== 0) throw poolInvalid('仲裁付款必须花费资金输出索引 0')
  const sourceTxId = serializedTxId(input)
  if (sourceTxId.every(byte => byte === 0)) throw poolInvalid('仲裁付款 funding txid 禁止全零')
  const roles: ArbitratedPoolRoles = { buyer: PublicKey.fromDER(Array.from(keys.buyerPublicKey)), seller: PublicKey.fromDER(Array.from(keys.sellerPublicKey)), arbiter: PublicKey.fromDER(Array.from(keys.arbiterPublicKey)) }
  const expectedScripts = buildArbitratedPoolOutputScripts(roles)
  for (const [index, expected] of [expectedScripts.buyer, expectedScripts.seller, expectedScripts.arbiter].entries()) {
    const output = unsigned.outputs[index]
    if (output == null || !equal(Uint8Array.from(output.lockingScript.toBinary()), Uint8Array.from(expected.toBinary()))) throw poolInvalid(`仲裁付款 output[${index}] 与角色脚本不匹配`)
  }
  try {
    engine.verifyRole('seller', unsignedRaw, poolOutputSatoshis, sellerSignature)
    engine.verifyRole('arbiter', unsignedRaw, poolOutputSatoshis, arbiterSignature)
  } catch (error) { throw new WireError('invalid_signature', 9, '', error instanceof Error ? error.message : '仲裁双签名无效') }
  return engine.mergeSellerArbiter(unsignedRaw, amountNumber(poolOutputSatoshis, 'pool_output_satoshis'), sellerSignature, arbiterSignature)
}

/**
 * 从 Claim primitives 唯一重建付费仲裁 candidate：只有显式正仲裁费、绝对
 * 卖方金额与冻结退款模板参与构造，绝不接收调用方 candidate 字节。
 */
export function buildArbitrationPaymentFromClaim (poolOutputSatoshis: bigint, poolOutputLockingScript: Uint8Array, refundTemplateRaw: Uint8Array, paymentSequence: number, sellerAmountAfterSatoshis: bigint, arbiterAmountSatoshis: bigint): ArbitrationCandidate {
  validateArbitrationClaimStructure({ poolOutputSatoshis, poolOutputLockingScript, refundTemplateRaw, paymentSequence: BigInt(paymentSequence), sellerAmountAfterSatoshis })
  const refund = parseCanonical(refundTemplateRaw)
  const refundOutputs = refund.outputs.reduce((sum, output) => sum + outputAmount(output), 0n)
  const refundFee = poolOutputSatoshis - refundOutputs
  const spendable = poolOutputSatoshis - refundFee
  const remainingAfterSeller = spendable - sellerAmountAfterSatoshis
  if (arbiterAmountSatoshis === 0n) throw poolInvalid('仲裁付款必须携带正仲裁金额')
  if (arbiterAmountSatoshis > remainingAfterSeller) throw new WireError('insufficient_balance', 0, 'seller_amount_after_satoshis', '仲裁金额超过可花费余额')
  const buyerAmountSatoshis = remainingAfterSeller - arbiterAmountSatoshis
  const unsignedRaw = buildArbitrationCandidate({ poolOutputSatoshis, refundTemplateRaw, paymentSequence: BigInt(paymentSequence), sellerAmountSatoshis: sellerAmountAfterSatoshis, arbiterAmountSatoshis })
  const input = refund.inputs[0]!
  return {
    unsignedRaw,
    refundTemplateTxId: transactionID(refundTemplateRaw),
    fundingTxId: serializedTxId(input),
    buyerAmountSatoshis,
    sellerAmountSatoshis: sellerAmountAfterSatoshis,
    arbiterAmountSatoshis,
    poolOutputSatoshis,
    poolLockingScript: copy(poolOutputLockingScript)
  }
}

function engineFromOpening (opening: OpeningProof): MultisigPoolEngine {
  if (opening == null) throw poolInvalid('开池证据不能为空')
  return new MultisigPoolEngine({ buyerPublicKey: opening.buyerPublicKey, sellerPublicKey: opening.sellerPublicKey, arbiterPublicKey: opening.arbiterPublicKey })
}

function validateOpeningProofFields (proof: OpeningProof | undefined): void {
  if (proof == null) throw poolInvalid('开池证据不能为空')
  if (proof.refundTemplateRaw.byteLength === 0 || proof.buyerRefundSignature.byteLength === 0 || proof.sellerRefundSignature.byteLength === 0) throw poolInvalid('开池证据不完整')
}

function clonePaymentState (state: PaymentState): PaymentState {
  return {
    ...state,
    refundTemplateTxId: copy(state.refundTemplateTxId),
    rawTx: copy(state.rawTx),
    buyerTransactionSignature: copy(state.buyerTransactionSignature),
    sellerTransactionSignature: copy(state.sellerTransactionSignature),
    arbiterTransactionSignature: copy(state.arbiterTransactionSignature),
    poolLockingScript: copy(state.poolLockingScript)
  }
}

function parseCanonical (raw: Uint8Array): Transaction {
  preflightTransactionRaw(raw)
  const hex = toHex(raw)
  let transaction: Transaction
  try { transaction = Transaction.fromHex(hex) } catch { throw new WireError('invalid_evidence', 0, 'raw_transaction', '交易原文无法解析') }
  if (transaction.toHex() !== hex) throw new WireError('non_canonical', 0, 'raw_transaction', '交易原文不是规范序列化')
  // @bsv/sdk 会缓存 fromHex 的序列化结果；返回无缓存的新对象，保证字段修改后
  // 的 toHex() 反映真实字节，而不是旧缓存。
  return freshTransaction(transaction)
}


function freshTransaction (transaction: Transaction): Transaction {
  return new Transaction(
    transaction.version,
    transaction.inputs.map(input => ({ ...input })),
    transaction.outputs.map(output => ({ ...output })),
    transaction.lockTime,
    transaction.metadata,
    transaction.merklePath
  )
}

function serializedTxId (input: { sourceTXID?: string }): Uint8Array {
  const sourceTXID = input.sourceTXID
  if (sourceTXID == null || !/^[0-9a-fA-F]{64}$/u.test(sourceTXID)) throw poolInvalid('交易 outpoint 无效')
  return reverse(fromHex(sourceTXID))
}

function extractSignatures (script: UnlockingScript): Uint8Array[] {
  const chunks = script.chunks
  if (chunks.length !== 3 || chunks[0]!.op !== 0 || chunks[1]!.data == null || chunks[2]!.data == null) throw poolInvalid('多重签名 unlocking script 形状无效')
  return [Uint8Array.from(chunks[1]!.data!), Uint8Array.from(chunks[2]!.data!)]
}

function setPoolSource (state: Transaction, amount: bigint, lock: Uint8Array): void {
  if (state.inputs.length !== 1) return
  const source = new Transaction()
  source.addOutput({ satoshis: amountNumber(amount, 'source_satoshis'), lockingScript: LockingScript.fromHex(toHex(lock)) })
  state.inputs[0]!.sourceTransaction = source
}

function amountNumber (value: bigint, field: string): number {
  if (value < 0n || value > MAX_SAFE_AMOUNT) throw new WireError('invalid_evidence', 0, field, '金额超过 JavaScript 安全整数')
  return Number(value)
}

function outputAmount (output: { satoshis?: number }): bigint {
  if (output.satoshis == null || !Number.isSafeInteger(output.satoshis) || output.satoshis < 0) throw poolInvalid('交易输出金额无效')
  return BigInt(output.satoshis)
}

function poolInvalid (message: string): WireError { return new WireError('invalid_evidence', 0, '', message) }

function copy (value: Uint8Array): Uint8Array { return new Uint8Array(value) }
function equal (left: Uint8Array, right: Uint8Array): boolean { return left.byteLength === right.byteLength && left.every((value, index) => value === right[index]) }
function reverse (value: Uint8Array): Uint8Array { return Uint8Array.from(value).reverse() }
function toHex (value: Uint8Array): string { return Array.from(value, byte => byte.toString(16).padStart(2, '0')).join('') }
function fromHex (value: string): Uint8Array {
  if (value.length % 2 !== 0 || !/^[0-9a-f]*$/iu.test(value)) throw new TypeError('hex 字符串无效')
  const output = new Uint8Array(value.length / 2)
  for (let index = 0; index < output.length; index++) output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16)
  return output
}

export { MultisigPoolProtocol, MultisigPoolVersion }
