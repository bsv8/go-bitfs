import { WireError } from './errors.js'

export type CBORValue = bigint | Uint8Array | string | CBORValue[]

type Length = { value: bigint, next: number }

/** 仅解码 BitFS 使用的确定性 CBOR 子集：整数、bstr、tstr、定长数组。 */
export function decodeCanonical (input: Uint8Array, field = 'wire'): CBORValue {
  if (input.byteLength === 0) fail('malformed_wire', field, 'CBOR 为空')
  const [value, next] = decodeAt(input, 0, field, 0)
  if (next !== input.byteLength) fail('malformed_wire', field, 'CBOR 含 trailing bytes')
  return value
}

/** 按 RFC 8949 deterministic 规则编码 BitFS 使用的 CBOR 子集。 */
export function encodeCanonical (value: CBORValue): Uint8Array {
  if (typeof value === 'bigint') {
    if (value >= 0n) return encodeHead(0, value)
    return encodeHead(1, -1n - value)
  }
  if (value instanceof Uint8Array) return concat(encodeHead(2, BigInt(value.byteLength)), value)
  if (typeof value === 'string') {
    const utf8 = new TextEncoder().encode(value)
    return concat(encodeHead(3, BigInt(utf8.byteLength)), utf8)
  }
  if (Array.isArray(value)) return concat(encodeHead(4, BigInt(value.length)), ...value.map(encodeCanonical))
  throw new TypeError('不支持的 CBOR 值类型')
}

function encodeHead (major: number, value: bigint): Uint8Array {
  if (value < 0n || value > 0xffffffffffffffffn) throw new RangeError('CBOR 整数超出 uint64')
  if (value < 24n) return Uint8Array.of((major << 5) | Number(value))
  const byteCount = value <= 0xffn ? 1 : value <= 0xffffn ? 2 : value <= 0xffffffffn ? 4 : 8
  const output = new Uint8Array(1 + byteCount)
  output[0] = (major << 5) | (byteCount === 1 ? 24 : byteCount === 2 ? 25 : byteCount === 4 ? 26 : 27)
  let remaining = value
  for (let index = byteCount; index > 0; index--) {
    output[index] = Number(remaining & 0xffn)
    remaining >>= 8n
  }
  return output
}

function concat (...parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.byteLength, 0))
  let offset = 0
  for (const part of parts) { output.set(part, offset); offset += part.byteLength }
  return output
}

function decodeAt (input: Uint8Array, offset: number, field: string, depth: number): [CBORValue, number] {
  if (depth > 16) fail('malformed_wire', field, 'CBOR 嵌套超过 16 层')
  const initial = input[offset]
  if (initial == null) fail('malformed_wire', field, 'CBOR 被截断')
  const major = initial >>> 5
  const additional = initial & 31
  if (additional === 31) fail('malformed_wire', field, '禁止 indefinite-length CBOR')
  const length = readLength(input, offset + 1, additional, field)
  switch (major) {
    case 0:
      return [length.value, length.next]
    case 1:
      return [-1n - length.value, length.next]
    case 2: {
      const size = safeLength(length.value, field)
      const end = length.next + size
      if (end > input.byteLength) fail('malformed_wire', field, 'bstr 被截断')
      return [input.slice(length.next, end), end]
    }
    case 3: {
      const size = safeLength(length.value, field)
      const end = length.next + size
      if (end > input.byteLength) fail('malformed_wire', field, 'tstr 被截断')
      try {
        return [new TextDecoder('utf-8', { fatal: true }).decode(input.subarray(length.next, end)), end]
      } catch {
        fail('malformed_wire', field, 'tstr 不是合法 UTF-8')
      }
    }
    case 4: {
      const count = safeLength(length.value, field)
      if (count > 64) fail('malformed_wire', field, '数组元素超过 64 个')
      const values: CBORValue[] = []
      let cursor = length.next
      for (let index = 0; index < count; index++) {
        const decoded = decodeAt(input, cursor, `${field}[${index}]`, depth + 1)
        values.push(decoded[0])
        cursor = decoded[1]
      }
      return [values, cursor]
    }
    default:
      fail('malformed_wire', field, `禁止的 CBOR major type ${major}`)
  }
}

function readLength (input: Uint8Array, offset: number, additional: number, field: string): Length {
  if (additional < 24) return { value: BigInt(additional), next: offset }
  const bytes = additional === 24 ? 1 : additional === 25 ? 2 : additional === 26 ? 4 : additional === 27 ? 8 : 0
  if (bytes === 0 || offset + bytes > input.byteLength) fail('malformed_wire', field, 'CBOR 长度字段无效或被截断')
  let value = 0n
  for (let index = 0; index < bytes; index++) value = (value << 8n) | BigInt(input[offset + index]!)
  const minimum = bytes === 1 ? 24n : bytes === 2 ? 256n : bytes === 4 ? 65536n : 4294967296n
  if (value < minimum) fail('non_canonical', field, 'CBOR 整数/长度不是最短编码')
  return { value, next: offset + bytes }
}

function safeLength (value: bigint, field: string): number {
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) fail('malformed_wire', field, 'CBOR 长度超过安全整数')
  return Number(value)
}

function fail (code: 'malformed_wire' | 'non_canonical', field: string, message: string): never {
  throw new WireError(code, 0, field, message)
}
