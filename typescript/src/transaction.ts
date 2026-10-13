import { sha256 } from '@noble/hashes/sha2.js'
import { ripemd160 } from '@noble/hashes/legacy.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { WireError } from './errors.js'

/** 在 SDK 解析前扫描 CompactSize；10,000 个输入/输出是 SDK 资源上限，不是共识规则。 */
export function preflightTransactionRaw (raw: Uint8Array): { inputs: number, outputs: number } {
  const invalid = (): never => { throw new WireError('invalid_evidence', 0, 'raw_transaction', '交易长度或元素数量无效') }
  const maxElements = 10000
  let offset = 4
  if (raw.byteLength < offset) invalid()
  const remaining = (): number => raw.byteLength - offset
  const skip = (length: number): void => {
    if (!Number.isSafeInteger(length) || length < 0 || length > remaining()) invalid()
    offset += length
  }
  const compact = (): number => {
    if (remaining() < 1) invalid()
    const prefix = raw[offset++]!
    if (prefix < 0xfd) return prefix
    const length = prefix === 0xfd ? 2 : prefix === 0xfe ? 4 : 8
    if (remaining() < length) invalid()
    let value = 0n
    for (let index = 0; index < length; index++) value |= BigInt(raw[offset + index]!) << BigInt(index * 8)
    offset += length
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) invalid()
    return Number(value)
  }
  let inputs = compact()
  if (inputs > maxElements) invalid()
  let outputs = 0
  let extended = false
  if (inputs === 0) {
    outputs = compact()
    if (outputs === 0) {
      if (remaining() < 4) invalid()
      const marker = raw[offset]! * 0x1000000 + (raw[offset + 1]! << 16) + (raw[offset + 2]! << 8) + raw[offset + 3]!
      offset += 4
      if (marker !== 0xef) {
        if (remaining() !== 0) invalid()
        return { inputs: 0, outputs: 0 }
      }
      extended = true
      inputs = compact()
      if (inputs > maxElements) invalid()
    }
  }
  if (inputs > Math.floor(remaining() / (extended ? 50 : 41))) invalid()
  for (let index = 0; index < inputs; index++) {
    skip(36)
    skip(compact())
    skip(4)
    if (extended) { skip(8); skip(compact()) }
  }
  if (inputs > 0 || extended) outputs = compact()
  if (remaining() < 4 || outputs > maxElements || outputs > Math.floor((remaining() - 4) / 9)) invalid()
  for (let index = 0; index < outputs; index++) { skip(8); skip(compact()) }
  skip(4)
  if (remaining() !== 0) invalid()
  return { inputs, outputs }
}

/** 关池候选专用边界：小报文且恰好花费一个费用池输入、产生三个角色输出。 */
export function validatePoolCloseTransactionRaw (raw: Uint8Array): void {
  if (raw.byteLength === 0) throw new WireError('invalid_evidence', 0, 'close_transaction_raw', '关池交易不能为空')
  if (raw.byteLength > 65536) throw new WireError('malformed_wire', 0, 'close_transaction_raw', '关池交易超过 65536 bytes')
  const shape = preflightTransactionRaw(raw)
  if (shape.inputs !== 1 || shape.outputs !== 3) throw new WireError('invalid_evidence', 0, 'close_transaction_raw', '关池交易必须恰好一个输入和三个输出')
}

/** Bitcoin SV ForkID|All sighash 类型（低字节 0x41）。 */
export const SIGHASH_FORKID_ALL = 0x41

/** 双 SHA-256；返回内部 digest 字节顺序，与 Go chainhash.CloneBytes 真值一致。 */
export function hash256 (value: Uint8Array): Uint8Array { return sha256(sha256(value)) }

/** 从规范交易原文派生 fixture 使用的 32 字节 TxID（内部 digest 顺序）。 */
export function transactionID (rawTransaction: Uint8Array): Uint8Array {
  parseTransaction(rawTransaction) // 先拒绝截断、trailing 与非最短 varint。
  return hash256(rawTransaction)
}

/**
 * 为指定输入构造 Bitcoin SV ForkID|All preimage。
 *
 * `sourceSatoshis` 是被花费输出金额（satoshi）；`sourceLockingScript` 是该输出
 * exact locking script。二者来自已验证 OpeningProof，不从当前交易猜测。
 */
export function forkIDAllPreimage (
  rawTransaction: Uint8Array,
  inputIndex: number,
  sourceSatoshis: bigint,
  sourceLockingScript: Uint8Array
): Uint8Array {
  const transaction = parseTransaction(rawTransaction)
  if (!Number.isSafeInteger(inputIndex) || inputIndex < 0 || inputIndex >= transaction.inputs.length) throw new RangeError('inputIndex 超出交易输入范围')
  if (sourceSatoshis < 0n || sourceSatoshis > 0xffffffffffffffffn) throw new RangeError('sourceSatoshis 超出 uint64')
  const input = transaction.inputs[inputIndex]!
  const prevouts = concat(...transaction.inputs.map(value => concat(value.txid, u32(value.outputIndex))))
  const sequences = concat(...transaction.inputs.map(value => u32(value.sequence)))
  const outputs = concat(...transaction.outputs.map(value => concat(u64(value.satoshis), varBytes(value.lockingScript))))
  return concat(
    u32(transaction.version), hash256(prevouts), hash256(sequences),
    input.txid, u32(input.outputIndex), varBytes(sourceLockingScript), u64(sourceSatoshis),
    u32(input.sequence), hash256(outputs), u32(transaction.lockTime), u32(SIGHASH_FORKID_ALL)
  )
}

/** ForkID|All 签名摘要 = hash256(preimage)。 */
export function forkIDAllDigest (rawTransaction: Uint8Array, inputIndex: number, sourceSatoshis: bigint, sourceLockingScript: Uint8Array): Uint8Array {
  return hash256(forkIDAllPreimage(rawTransaction, inputIndex, sourceSatoshis, sourceLockingScript))
}

type Input = { txid: Uint8Array, outputIndex: number, unlockingScript: Uint8Array, sequence: number }
type Output = { satoshis: bigint, lockingScript: Uint8Array }
type ParsedTransaction = { version: number, inputs: Input[], outputs: Output[], lockTime: number }

/** Kind 8 Claim 对退款模板的纯结构验证输入；字段含义与 Go ValidateArbitrationClaimStructure 一致。 */
export interface ArbitrationClaimStructure {
  /** 被花费费用池输出金额，单位 satoshi。 */
  poolOutputSatoshis: bigint
  /** 角色顺序固定为 Buyer、Seller、Arbiter 的 105 字节 2-of-3 P2MS。 */
  poolOutputLockingScript: Uint8Array
  /** 未签名规范退款模板交易。 */
  refundTemplateRaw: Uint8Array
  /** 仲裁付款目标序号，必须严格大于退款模板序号。 */
  paymentSequence: bigint
  /** 仲裁后的卖方绝对累计金额。 */
  sellerAmountAfterSatoshis: bigint
}

/** 仲裁 Prepare 阶段验证 candidate 与 Claim 的绑定参数。 */
export interface ArbitrationCandidateInput {
  poolOutputSatoshis: bigint
  refundTemplateRaw: Uint8Array
  paymentSequence: bigint
  sellerAmountSatoshis: bigint
  arbiterAmountSatoshis: bigint
}

/** 返回规范交易的 nLockTime。 */
export function transactionLockTime (rawTransaction: Uint8Array): number { return parseTransaction(rawTransaction).lockTime }

/**
 * 从 Claim 唯一确定性重建仲裁 candidate。算法逐项等价于 Go
 * BuildArbitrationPaymentFromClaim：复制规范退款模板，仅替换 sequence 和三个
 * output 金额；version、outpoint、脚本、nLockTime 以及冻结矿工费均继承模板。
 */
export function buildArbitrationCandidate (input: Readonly<ArbitrationCandidateInput>): Uint8Array {
  const refund = parseTransaction(input.refundTemplateRaw)
  if (refund.inputs.length !== 1 || refund.outputs.length !== 3) invalidClaim('refund_template_raw', '退款模板必须是一输入三输出')
  if (input.paymentSequence <= BigInt(refund.inputs[0]!.sequence) || input.paymentSequence >= 0xffffffffn) invalidClaim('payment_sequence', '仲裁付款 sequence 无效')
  const refundTotal = refund.outputs.reduce((sum, output) => sum + output.satoshis, 0n)
  if (refundTotal > input.poolOutputSatoshis) invalidClaim('pool_output_satoshis', '退款模板输出超过费用池金额')
  if (input.arbiterAmountSatoshis <= 0n || input.sellerAmountSatoshis < 0n || input.sellerAmountSatoshis + input.arbiterAmountSatoshis > refundTotal) invalidClaim('arbiter_amount_satoshis', '仲裁金额超过冻结可花费余额')
  const candidate: ParsedTransaction = {
    version: refund.version,
    inputs: refund.inputs.map(value => ({ txid: value.txid.slice(), outputIndex: value.outputIndex, unlockingScript: value.unlockingScript.slice(), sequence: Number(input.paymentSequence) })),
    outputs: refund.outputs.map(value => ({ satoshis: value.satoshis, lockingScript: value.lockingScript.slice() })),
    lockTime: refund.lockTime
  }
  candidate.outputs[0]!.satoshis = refundTotal - input.sellerAmountSatoshis - input.arbiterAmountSatoshis
  candidate.outputs[1]!.satoshis = input.sellerAmountSatoshis
  candidate.outputs[2]!.satoshis = input.arbiterAmountSatoshis
  return serializeTransaction(candidate)
}

/** 恢复/审计路径使用：候选字节必须与内部唯一重建结果逐字节相等。 */
export function verifyArbitrationCandidate (input: Readonly<ArbitrationCandidateInput>, candidateRaw: Uint8Array): void {
  if (!equal(buildArbitrationCandidate(input), candidateRaw)) throw new WireError('state_conflict', 9, 'unsigned_candidate', '仲裁 candidate 不是 Claim 的唯一确定性构造结果')
}

/**
 * 验证 Kind 8 Claim 内费用池脚本、退款交易和付款授权的互相绑定。
 * 该函数不验证仲裁费，也不读取时钟，因而可以安全用于 wire 严格解析。
 * 返回从锁定脚本恢复出的三方压缩公钥。
 */
export function validateArbitrationClaimStructure (claim: Readonly<ArbitrationClaimStructure>): { buyerPublicKey: Uint8Array, sellerPublicKey: Uint8Array, arbiterPublicKey: Uint8Array } {
  const lock = claim.poolOutputLockingScript
  if (lock.length !== 105 || lock[0] !== 0x52 || lock[1] !== 33 || lock[35] !== 33 || lock[69] !== 33 || lock[103] !== 0x53 || lock[104] !== 0xae) invalidClaim('pool_output_locking_script', '费用池脚本不是规范的角色顺序 2-of-3 P2MS')
  const keys = [lock.slice(2, 35), lock.slice(36, 69), lock.slice(70, 103)]
  if (keys.some(key => !secp256k1.utils.isValidPublicKey(key, true)) || keys.some((key, index) => keys.some((other, otherIndex) => index !== otherIndex && equal(key, other)))) invalidClaim('pool_output_locking_script', '费用池三方公钥必须有效且互不相同')

  let refund: ParsedTransaction
  try { refund = parseTransaction(claim.refundTemplateRaw) } catch (error) {
    if (error instanceof WireError) throw error
    invalidClaim('refund_template_raw', '退款模板不是规范交易')
  }
  if (refund.inputs.length !== 1 || refund.outputs.length !== 3) invalidClaim('refund_template_raw', '退款模板必须恰好包含一个输入和三个输出')
  const input = refund.inputs[0]!
  if (allZero(input.txid) || input.outputIndex !== 0 || input.sequence === 0xffffffff || input.unlockingScript.length !== 0) invalidClaim('refund_template_raw', '退款模板 funding outpoint、unlocking script 或 sequence 无效')
  if (claim.paymentSequence <= BigInt(input.sequence) || claim.paymentSequence >= 0xffffffffn) invalidClaim('payment_sequence', '仲裁付款序号必须大于退款序号且不是 final')
  const expectedScripts = keys.map(p2pkhLock)
  for (let index = 0; index < expectedScripts.length; index++) {
    if (!equal(refund.outputs[index]!.lockingScript, expectedScripts[index]!)) invalidClaim('refund_template_raw', `退款模板 output[${index}] 与角色公钥不匹配`)
  }
  if (refund.outputs[1]!.satoshis !== 0n || refund.outputs[2]!.satoshis !== 0n) invalidClaim('refund_template_raw', '退款模板初始卖方和仲裁方金额必须为零')
  const outputTotal = refund.outputs.reduce((sum, output) => sum + output.satoshis, 0n)
  if (outputTotal > claim.poolOutputSatoshis || claim.sellerAmountAfterSatoshis > outputTotal) invalidClaim('seller_amount_after_satoshis', '卖方累计金额超过退款模板可花费余额')
  return { buyerPublicKey: keys[0]!, sellerPublicKey: keys[1]!, arbiterPublicKey: keys[2]! }
}

function parseTransaction (raw: Uint8Array): ParsedTransaction {
  preflightTransactionRaw(raw)
  const reader = new Reader(raw)
  const version = reader.u32()
  const inputCount = reader.varIntNumber('input count')
  const inputs: Input[] = []
  for (let index = 0; index < inputCount; index++) {
    const txid = reader.take(32)
    const outputIndex = reader.u32()
    const unlockingScript = reader.varBytes() // 当前输入 unlocking script 不进入对应 source scriptCode。
    const sequence = reader.u32()
    inputs.push({ txid, outputIndex, unlockingScript, sequence })
  }
  const outputCount = reader.varIntNumber('output count')
  const outputs: Output[] = []
  for (let index = 0; index < outputCount; index++) outputs.push({ satoshis: reader.u64(), lockingScript: reader.varBytes() })
  const lockTime = reader.u32()
  if (!reader.done()) throw new WireError('malformed_wire', 0, 'raw_transaction', '交易原文含 trailing bytes')
  return { version, inputs, outputs, lockTime }
}

function serializeTransaction (transaction: ParsedTransaction): Uint8Array {
  return concat(
    u32(transaction.version), varInt(BigInt(transaction.inputs.length)),
    ...transaction.inputs.map(input => concat(input.txid, u32(input.outputIndex), varBytes(input.unlockingScript), u32(input.sequence))),
    varInt(BigInt(transaction.outputs.length)),
    ...transaction.outputs.map(output => concat(u64(output.satoshis), varBytes(output.lockingScript))),
    u32(transaction.lockTime)
  )
}

class Reader {
  #offset = 0
  constructor (readonly raw: Uint8Array) {}
  done (): boolean { return this.#offset === this.raw.byteLength }
  take (length: number): Uint8Array {
    if (!Number.isSafeInteger(length) || length < 0 || this.#offset + length > this.raw.byteLength) throw new WireError('malformed_wire', 0, 'raw_transaction', '交易原文被截断')
    const result = this.raw.slice(this.#offset, this.#offset + length); this.#offset += length; return result
  }
  u32 (): number { const value = this.take(4); return (value[0]! | (value[1]! << 8) | (value[2]! << 16) | (value[3]! << 24)) >>> 0 }
  u64 (): bigint { const value = this.take(8); let result = 0n; for (let index = 7; index >= 0; index--) result = (result << 8n) | BigInt(value[index]!); return result }
  varInt (): bigint {
    const first = this.take(1)[0]!
    if (first < 0xfd) return BigInt(first)
    const size = first === 0xfd ? 2 : first === 0xfe ? 4 : 8
    const value = this.take(size); let result = 0n
    for (let index = size - 1; index >= 0; index--) result = (result << 8n) | BigInt(value[index]!)
    const minimum = size === 2 ? 0xfdn : size === 4 ? 0x10000n : 0x100000000n
    if (result < minimum) throw new WireError('non_canonical', 0, 'raw_transaction', '交易 varint 不是最短编码')
    return result
  }
  varIntNumber (field: string): number { const value = this.varInt(); if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new WireError('malformed_wire', 0, field, '数量超过安全整数'); return Number(value) }
  varBytes (): Uint8Array { return this.take(this.varIntNumber('script length')) }
}

function varBytes (value: Uint8Array): Uint8Array { return concat(varInt(BigInt(value.byteLength)), value) }
function varInt (value: bigint): Uint8Array {
  if (value < 0xfdn) return Uint8Array.of(Number(value))
  if (value <= 0xffffn) return concat(Uint8Array.of(0xfd), little(value, 2))
  if (value <= 0xffffffffn) return concat(Uint8Array.of(0xfe), little(value, 4))
  return concat(Uint8Array.of(0xff), little(value, 8))
}
function u32 (value: number): Uint8Array { if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new RangeError('uint32 超出范围'); return little(BigInt(value), 4) }
function u64 (value: bigint): Uint8Array { return little(value, 8) }
function little (value: bigint, length: number): Uint8Array { const output = new Uint8Array(length); let rest = value; for (let index = 0; index < length; index++) { output[index] = Number(rest & 0xffn); rest >>= 8n } if (rest !== 0n) throw new RangeError('整数超出序列化宽度'); return output }
function concat (...parts: Uint8Array[]): Uint8Array { const output = new Uint8Array(parts.reduce((sum, part) => sum + part.byteLength, 0)); let offset = 0; for (const part of parts) { output.set(part, offset); offset += part.byteLength } return output }
function p2pkhLock (publicKey: Uint8Array): Uint8Array { return concat(Uint8Array.of(0x76, 0xa9, 0x14), ripemd160(sha256(publicKey)), Uint8Array.of(0x88, 0xac)) }
function equal (left: Uint8Array, right: Uint8Array): boolean { return left.length === right.length && left.every((value, index) => value === right[index]) }
function allZero (value: Uint8Array): boolean { return value.every(byte => byte === 0) }
function invalidClaim (field: string, message: string): never { throw new WireError('invalid_evidence', 8, field, message) }
