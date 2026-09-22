import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { encodeCanonical } from './cbor.js'
import { WIRE_VERSION } from './constants.js'
import { WireError } from './errors.js'
import type { WireKind } from './wire.js'

/** 普通 wire 消息与交易摘要签名使用的固定用途，供 HSM/KMS 审计。 */
export type SigningPurpose = 'wire_message' | 'transaction'

/** SDK 已构造好的签名请求；Signer 只能签 32 字节 digest，不能自行选择哈希。 */
export interface SigningRequest {
  purpose: SigningPurpose
  /** 普通消息为 1..11，交易签名固定为 0。 */
  wireKind: number
  /** 已构造好的 32 字节摘要。 */
  digest: Uint8Array
}

/** 唯一密钥操作端口；不暴露私钥、seed、WIF 或自定义 verifier。 */
export interface Signer {
  /** 生命周期内固定的 33 字节压缩 secp256k1 公钥。 */
  publicKey(): Uint8Array
  /** 返回不带 sighash flag 的 strict low-S DER 签名。 */
  sign(request: Readonly<SigningRequest>, signal?: AbortSignal): Promise<Uint8Array>
}

export const WIRE_SIGNATURE_DOMAIN = 'bitfs/wire-signature'

/** deterministic-CBOR([域, 版本, Kind, exact document_cbor])。 */
export function wireSignatureInput (wireKind: WireKind, documentCBOR: Uint8Array, wireVersion = WIRE_VERSION): Uint8Array {
  if (documentCBOR.byteLength === 0) throw new WireError('invalid_evidence', wireKind, 'document_cbor', '认证子文档不能为空')
  return encodeCanonical([WIRE_SIGNATURE_DOMAIN, BigInt(wireVersion), BigInt(wireKind), new Uint8Array(documentCBOR)])
}

/** SHA-256(wireSignatureInput)，是 Signer 唯一接触的普通消息摘要。 */
export function wireSignatureDigest (wireKind: WireKind, documentCBOR: Uint8Array, wireVersion = WIRE_VERSION): Uint8Array {
  return sha256(wireSignatureInput(wireKind, documentCBOR, wireVersion))
}

/** 验证压缩公钥、strict DER、low-S 与摘要级 ECDSA 签名。 */
export function verifyDigestSignature (publicKey: Uint8Array, digest: Uint8Array, signature: Uint8Array, kind = 0): void {
  if (publicKey.byteLength !== 33 || !secp256k1.utils.isValidPublicKey(publicKey, true)) throw new WireError('invalid_evidence', kind, 'public_key', '压缩 secp256k1 公钥无效')
  if (digest.byteLength !== 32) throw new WireError('invalid_evidence', kind, 'digest', '签名摘要必须是 32 bytes')
  try {
    const parsed = secp256k1.Signature.fromBytes(signature, 'der')
    if (parsed.hasHighS() || !equal(parsed.toBytes('der'), signature)) throw new Error('DER 非规范或 high-S')
    if (!secp256k1.verify(signature, digest, publicKey, { prehash: false, lowS: true, format: 'der' })) throw new Error('签名不匹配')
  } catch {
    throw new WireError('invalid_signature', kind, 'signature', '签名不是有效的 strict low-S DER 或与公钥不匹配')
  }
}

/** 用统一域重建摘要并验证普通消息签名。 */
export function verifyWireDocument (publicKey: Uint8Array, kind: WireKind, documentCBOR: Uint8Array, signature: Uint8Array): void {
  verifyDigestSignature(publicKey, wireSignatureDigest(kind, documentCBOR), signature, kind)
}

/** 通过受约束 Signer 签署并用构造时公钥立即自验。 */
export async function signWireDocument (signer: Signer, kind: WireKind, documentCBOR: Uint8Array, signal?: AbortSignal): Promise<Uint8Array> {
  if (signal?.aborted === true) throw new WireError('canceled', kind, '', '签名操作已取消')
  const publicKey = new Uint8Array(signer.publicKey())
  if (publicKey.byteLength !== 33 || !secp256k1.utils.isValidPublicKey(publicKey, true)) throw new WireError('invalid_evidence', kind, 'public_key', 'Signer 公钥无效')
  const digest = wireSignatureDigest(kind, documentCBOR)
  let signature: Uint8Array
  try {
    signature = new Uint8Array(await signer.sign({ purpose: 'wire_message', wireKind: kind, digest: new Uint8Array(digest) }, signal))
  } catch (error) {
    if (isAborted(signal) || (error instanceof DOMException && error.name === 'AbortError')) throw new WireError('canceled', kind, 'signature', '签名操作已取消')
    // Workflow 的冻结 Signer 会用结构化 unauthorized 报告生命周期内换钥；
    // 这是安全门禁结果，不得被降格为不透明 signer_unavailable。
    if (error instanceof WireError) throw error
    throw new WireError('signer_unavailable', kind, 'signature', 'Signer 无法完成签名')
  }
  verifyDigestSignature(publicKey, digest, signature, kind)
  return signature
}

function equal (left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && left.every((value, index) => value === right[index])
}

function isAborted (signal?: AbortSignal): boolean { return signal?.aborted === true }
