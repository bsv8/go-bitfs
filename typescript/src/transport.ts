import { readUvarintFrames, writeUvarintFrame, type UvarintFramingOptions } from 'bitcoin-libp2p/stream'
import { BITFS_PROTOCOL_ID, MAX_WIRE_FRAME_BYTES } from './constants.js'
import { Artifact, parse } from './wire.js'

/** bitcoin-libp2p Stream 所需的最小结构类型，实际调用应传原生 libp2p Stream。 */
type BitFSStream = Parameters<typeof writeUvarintFrame>[0]

/** 向一个长期 libp2p stream 写入一条完整 Artifact frame。 */
export function writeArtifact (stream: BitFSStream, artifact: Artifact): boolean {
  return writeUvarintFrame(stream, artifact.bytes())
}

/** 从 stream 连续读取、限长并严格解析 BitFS Artifact。 */
export async function * readArtifacts (stream: BitFSStream, options: UvarintFramingOptions = {}): AsyncIterableIterator<Artifact> {
  const configured = options.maxInboundFrameBytes
  if (configured != null && configured > MAX_WIRE_FRAME_BYTES) throw new RangeError('maxInboundFrameBytes 不能高于 BitFS 协议上限')
  const inboundLimit = configured ?? MAX_WIRE_FRAME_BYTES
  // bitcoin-libp2p 的 buffered 上限包含 uvarint 前缀；默认 4 MiB 小于 BitFS
  // 合法满载 Kind 8，因此 BitFS profile 必须显式容纳 payload + 最长前缀。
  const bufferedLimit = options.maxBufferedBytes ?? inboundLimit + 10
  for await (const frame of readUvarintFrames(stream, { ...options, maxInboundFrameBytes: inboundLimit, maxBufferedBytes: bufferedLimit })) yield parse(frame)
}

export { BITFS_PROTOCOL_ID, MAX_WIRE_FRAME_BYTES }
