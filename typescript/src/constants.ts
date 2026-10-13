/** BitFS 外部协议族名称；wire bytes 中不重复编码该字符串。 */
export const PROTOCOL_FAMILY = 'bitfs.protocol.v1'
/** 所有完整 wire 报文的首项版本。 */
export const WIRE_VERSION = 1
/** libp2p stream 的业务协议标识。 */
export const BITFS_PROTOCOL_ID = '/bitfs/wire/1.0.0'
/** 一批最多包含的内容块数。 */
export const MAX_CONTENT_BATCH_ITEMS = 64
/** 单块最大字节数（MasterSeed block size）。 */
export const MAX_CONTENT_PAYLOAD_BYTES = 262_144
/** 完整 BitFS frame 的传输上限；覆盖合法满载 Kind 8。 */
export const MAX_WIRE_FRAME_BYTES = 64 * (MAX_CONTENT_PAYLOAD_BYTES + 9) + 9 + 64 * 1024 + 256 + 16
