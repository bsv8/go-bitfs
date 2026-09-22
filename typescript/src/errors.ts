/** 应用可稳定分支的错误分类；不要匹配英文错误文本。 */
export type ErrorCode =
  | 'malformed_wire'
  | 'non_canonical'
  | 'unsupported_version'
  | 'unsupported_kind'
  | 'invalid_signature'
  | 'invalid_evidence'
  | 'unauthorized'
  | 'expired'
  | 'not_matured'
  | 'state_conflict'
  | 'insufficient_balance'
  | 'canceled'
  | 'signer_unavailable'

/** WireError 不携带 payload、签名或私钥，仅暴露安全诊断字段。 */
export class WireError extends Error {
  constructor (
    readonly code: ErrorCode,
    readonly kind: number,
    readonly field: string,
    message: string
  ) {
    super(message)
    this.name = 'WireError'
  }
}
